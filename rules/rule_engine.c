// ============================================================================
// rules/rule_engine.c — Rule evaluation (classify hot path) + statistics +
// RATE_LIMIT token buckets.
// Verdict (semantics pinned by rule_types.h): scan the snapshot (pre-sorted
// by priority desc / action strength / ruleId); the first fully matching
// enabled rule is the verdict. No match => snapshot defaultPolicy; snap==NULL
// (store closed) => default PERMIT (permit never flips on store state;
// unload-time traffic is not killed by mistake).
// RATE_LIMIT: one reference-counted SK_RATE_BUCKET object per RATE_LIMIT
//   rule, carried by the snapshot (snap->buckets[i], rule_store.h) and
//   shared across publishes for unchanged rules — no global table, no ruleId
//   slot scan, no 64-slot ceiling and no table-full fail-open. Buckets are
//   allocated by the writer (allocation failure aborts the publish; the old
//   policy stays); this file only consumes them under the per-bucket spin
//   lock. Refill uses saturating unsigned 64-bit arithmetic
//   (intervals*rateTokens, tokens+add, intervals*rateIntervalMs, QPC ticks*1000,
//   ticks*1000000000); overflow clamps to UINT64_MAX instead of wrapping.
//   Refill rateTokens per rateIntervalMs, cap burst; within bucket permit as
//   AUDIT, over limit BLOCK (rateLimited=1).
// Statistics: g_SkRuleStats (read by GET_STATS); timing is QPC deltas in ns;
// all counters atomic (classify may run on multiple cores). No allocation,
// no Sleep; any-IRQL safe (short spin-lock sections only).
// ============================================================================
#include <ntddk.h>
#include "../runtime/sk_atomic.h"
#include "rule_engine.h"

// Provided by rule_match.c (module-internal interface, not in public headers)
BOOLEAN SkRuleMatch(const SK_RULE *rule, const SK_CLASSIFY_TUPLE *tuple);

SK_RULE_STATS g_SkRuleStats;

// ---------------------------------------------------------------------------
// Saturating unsigned 64-bit arithmetic (non-paged, no float, DISPATCH_LEVEL)
// All token-bucket and QPC conversions use these helpers so that overflow
// cannot wrap around and change the rate-limit decision. On overflow the
// result clamps to UINT64_MAX (a safe upper bound).
// ---------------------------------------------------------------------------
static __forceinline UINT64 SkSatMulU64(UINT64 a, UINT64 b) {
    if (a == 0 || b == 0)
        return 0;
    if (a > ((UINT64)(-1)) / b)
        return (UINT64)(-1);
    return a * b;
}

static __forceinline UINT64 SkSatAddU64(UINT64 a, UINT64 b) {
    if (b > ((UINT64)(-1)) - a)
        return (UINT64)(-1);
    return a + b;
}

// ---------------------------------------------------------------------------
// QPC time base (frequency lazily cached; QPC is any-IRQL safe)
// ---------------------------------------------------------------------------
static UINT64 g_QpcFreq; // 0 = uninitialized (lazy; benign race: same value written)

static UINT64 SkQpcNow(void) {
    LARGE_INTEGER t = KeQueryPerformanceCounter(NULL);
    return (UINT64)t.QuadPart;
}

static UINT64 SkQpcFreq(void) {
    UINT64 f = g_QpcFreq;
    if (f == 0) {
        LARGE_INTEGER li;
        KeQueryPerformanceCounter(&li); // frequency returned via out-param
        f = (UINT64)li.QuadPart;
        if (f == 0)
            f = 1; // defensive: never divide by zero
        g_QpcFreq = f;
    }
    return f;
}

// ticks -> ms: ticks*1000 saturates to UINT64_MAX before division so the
// multiply can never wrap and change the result.
static UINT64 SkQpcMs(void) {
    return SkSatMulU64(SkQpcNow(), 1000ULL) / SkQpcFreq();
}

static UINT64 SkTicksToNs(UINT64 ticks) {
    return SkSatMulU64(ticks, 1000000000ULL) / SkQpcFreq();
}

// ---------------------------------------------------------------------------
// RATE_LIMIT token buckets (per-rule objects; allocation/ownership and the
// share-across-publishes rules live in rule_store.c)
// ---------------------------------------------------------------------------

// TRUE = within bucket; FALSE = over limit. The bucket always exists
// (snapshot invariant: buckets[i] != NULL for a RATE_LIMIT rule) — no
// allocation here and no fail-open path. A fresh bucket starts full; its
// first evaluation anchors the refill clock rather than counting from boot.
static BOOLEAN SkRateAllow(const SK_RULE *rule, SK_RATE_BUCKET *bucket) {
    KIRQL irql;
    UINT64 now, intervals, add, tokens;
    BOOLEAN allowed;
    now = SkQpcMs();
    irql = ShOps.LockAcquireExclusive(&bucket->lock);
    tokens = bucket->tokens;
    // Refill: rateTokens per rateIntervalMs, capped at the rule's burst.
    if (!bucket->started) {
        bucket->lastRefillMs = now;
        bucket->started = TRUE;
    } else if (now > bucket->lastRefillMs) {
        intervals = (now - bucket->lastRefillMs) / rule->rateIntervalMs;
        if (intervals != 0) {
            add = SkSatMulU64(intervals, rule->rateTokens);
            tokens = SkSatAddU64(tokens, add);
            if (tokens > rule->burst)
                tokens = rule->burst;
            bucket->lastRefillMs = SkSatAddU64(bucket->lastRefillMs,
                                               SkSatMulU64(intervals, rule->rateIntervalMs));
        }
    }
    if (tokens > 0) {
        bucket->tokens = tokens - 1;
        allowed = TRUE;
    } else {
        bucket->tokens = tokens;
        allowed = FALSE;
    }
    ShOps.LockReleaseExclusive(&bucket->lock, irql);
    return allowed;
}

// ---------------------------------------------------------------------------
// Evaluation (never fails; out is always fully filled)
// ---------------------------------------------------------------------------
VOID SkRuleEvaluate(const SK_RULE_SNAPSHOT *snap, const SK_CLASSIFY_TUPLE *tuple,
                    SK_VERDICT *out) {
    UINT64 t0, ns, curMax;
    UINT32 i;
    const SK_RULE *hit;

    t0 = SkQpcNow();
    SkAtAdd64((volatile LONG64 *)&g_SkRuleStats.classifyCalls, 1);

    out->action = (UINT32)SkVerdictPermit;
    out->ruleId = 0;
    out->rateLimited = 0;
    out->hardBlock = 0;
    // reason tri-state (rule_types.h SK_VERDICT_REASON): default NoMatch;
    // overwritten below for snapshot-unavailable and rule-match.
    out->reason = (UINT32)SkVerdictReasonNoMatch;

    hit = NULL;
    if (snap != NULL) {
        for (i = 0; i < snap->count; i++) {
            if (SkRuleMatch(&snap->rules[i], tuple)) {
                hit = &snap->rules[i]; // snapshot pre-sorted: first match is the final verdict
                break;
            }
        }
    } else {
        // Store closed / no usable snapshot: take the default PERMIT path
        // below, but reason must differ from "snapshot present, fields
        // mismatched".
        out->reason = (UINT32)SkVerdictReasonSnapshotUnavailable;
    }

    if (hit != NULL) {
        out->reason = (UINT32)SkVerdictReasonRuleMatch; // incl. RATE_LIMIT over limit
        SkAtAdd64((volatile LONG64 *)&g_SkRuleStats.ruleHits, 1);
        out->ruleId = hit->ruleId;
        switch (hit->action) {
        case SkRuleActionBlock:
            out->action = (UINT32)SkVerdictBlock;
            out->hardBlock = 1; // classify may write hard BLOCK only while holding
                                // FWPS_RIGHT_ACTION_WRITE (then clears it; never grants it)
            break;
        case SkRuleActionAudit:
            out->action = (UINT32)SkVerdictAudit; // permit + telemetry
            break;
        case SkRuleActionRateLimit:
            if (SkRateAllow(hit, snap->buckets[i])) {
                out->action = (UINT32)SkVerdictAudit; // within bucket: permit with AUDIT semantics
            } else {
                out->action = (UINT32)SkVerdictBlock;
                out->rateLimited = 1;
                out->hardBlock = 1;
                SkAtAdd64((volatile LONG64 *)&g_SkRuleStats.rateLimited, 1);
            }
            break;
        default: // SkRuleActionAllow
            out->action = (UINT32)SkVerdictPermit;
            break;
        }
    } else {
        UINT32 pol = snap ? snap->defaultPolicy : (UINT32)SkVerdictPermit;
        SkAtAdd64((volatile LONG64 *)&g_SkRuleStats.defaultHits, 1);
        if (pol == (UINT32)SkVerdictBlock) {
            out->action = (UINT32)SkVerdictBlock;
            out->hardBlock = 1;
        }
    }

    // verdict counters
    if (out->action == (UINT32)SkVerdictBlock)
        SkAtAdd64((volatile LONG64 *)&g_SkRuleStats.verdictBlock, 1);
    else if (out->action == (UINT32)SkVerdictAudit)
        SkAtAdd64((volatile LONG64 *)&g_SkRuleStats.verdictAudit, 1);
    else
        SkAtAdd64((volatile LONG64 *)&g_SkRuleStats.verdictPermit, 1);

    // timing stats (QPC delta in ns; cumulative + worst)
    ns = SkTicksToNs(SkQpcNow() - t0);
    SkAtAdd64((volatile LONG64 *)&g_SkRuleStats.matchNsTotal, (LONG64)ns);
    SkAtAdd64((volatile LONG64 *)&g_SkRuleStats.matchNsSamples, 1);
    for (;;) {
        curMax = g_SkRuleStats.matchNsMax;
        if (ns <= curMax)
            break;
        if (SkAtCas64((volatile LONG64 *)&g_SkRuleStats.matchNsMax, (LONG64)ns, (LONG64)curMax) == (LONG64)curMax)
            break;
    }
}

VOID SkRuleStatsReset(void) {
    UINT64 *f = (UINT64 *)&g_SkRuleStats;
    UINT32 i;
    for (i = 0; i < sizeof(g_SkRuleStats) / sizeof(UINT64); i++)
        SkAtXchg64((volatile LONG64 *)&f[i], 0); // atomic per-field zeroing (control-plane call)
}
