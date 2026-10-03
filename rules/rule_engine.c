// ============================================================================
// rules/rule_engine.c — Rule evaluation (classify hot path) + statistics +
// RATE_LIMIT token buckets.
// Verdict (semantics pinned by rule_types.h): scan the snapshot (pre-sorted
// by priority desc / action strength / ruleId); the first fully matching
// enabled rule is the verdict. No match => snapshot defaultPolicy; snap==NULL
// (store closed) => default PERMIT (permit never flips on store state;
// unload-time traffic is not killed by mistake).
// RATE_LIMIT: fixed 64-slot token-bucket table (ruleId -> {tokens,
//   lastRefillMs, rateSig}, EX_SPIN_LOCK). Buckets are keyed by ruleId and a
//   rate-parameter signature (rateTokens/rateIntervalMs). When a rule's rate
//   parameters change, the signature mismatch resets the bucket on the next
//   classify; delete/disable/replaced-away rules are zeroed by rule_store via
//   SkRuleRateReset. Refill uses saturating unsigned 64-bit arithmetic
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
// RATE_LIMIT token bucket table (fixed 64 slots; documented demo-scale limit)
// ---------------------------------------------------------------------------
#define SK_RATE_TABLE_SIZE 64
typedef struct _SK_RATE_ENTRY {
    UINT64 ruleId;
    UINT64 tokens;       // current token count (<= burst)
    UINT64 lastRefillMs; // last refill time, QPC ms
    UINT64 rateSig;      // signature of rateTokens/rateIntervalMs; mismatch => reset bucket
    UINT32 inUse;
} SK_RATE_ENTRY;

static SK_RATE_ENTRY g_RateTable[SK_RATE_TABLE_SIZE];
static EX_SPIN_LOCK g_RateLock;

// Rate-parameter signature: detects when a rule's refill parameters change so
// the bucket can be reset. Derived from rateTokens and rateIntervalMs only;
// burst-only changes are handled by SkRuleRateClampBurst.
static UINT64 SkRateParamsSig(const SK_RULE *rule) {
    UINT64 sig = 14695981039346656037ULL; // FNV-1a64 offset basis
    sig ^= rule->rateTokens;
    sig *= 1099511628211ULL;              // FNV-1a64 prime
    sig ^= rule->rateIntervalMs;
    sig *= 1099511628211ULL;
    return sig;
}

// TRUE = within bucket; FALSE = over limit. Table full (all 64 slots used) =>
// fail-open permit: losing rate-limiter state beats killing traffic by
// mistake (documented demo-scale limit; the table is image-level state, not
// freed with snapshots).
static BOOLEAN SkRateAllow(const SK_RULE *rule) {
    KIRQL irql;
    UINT32 i, slot;
    UINT64 now, intervals, add, sig;
    SK_RATE_ENTRY *e;
    BOOLEAN allowed;
    now = SkQpcMs();
    slot = SK_RATE_TABLE_SIZE;
    irql = ShOps.LockAcquireExclusive(&g_RateLock);
    for (i = 0; i < SK_RATE_TABLE_SIZE; i++) {
        if (g_RateTable[i].inUse && g_RateTable[i].ruleId == rule->ruleId) {
            slot = i;
            break;
        }
        if (!g_RateTable[i].inUse && slot == SK_RATE_TABLE_SIZE)
            slot = i; // remember first free slot
    }
    if (slot == SK_RATE_TABLE_SIZE) {
        allowed = TRUE; // fail-open
    } else {
        e = &g_RateTable[slot];
        sig = SkRateParamsSig(rule);
        if (!e->inUse) {
            e->inUse = 1;
            e->ruleId = rule->ruleId;
            e->tokens = rule->burst; // new bucket starts full
            e->lastRefillMs = now;
            e->rateSig = sig;
        } else if (e->rateSig != sig) {
            // Rate parameters changed (rateTokens/rateIntervalMs); reset bucket
            // so a reused/changed ruleId never inherits the old refill schedule.
            e->tokens = rule->burst;
            e->lastRefillMs = now;
            e->rateSig = sig;
        }
        // Refill: rateTokens per rateIntervalMs, capped at burst
        if (now > e->lastRefillMs) {
            intervals = (now - e->lastRefillMs) / rule->rateIntervalMs;
            if (intervals != 0) {
                add = SkSatMulU64(intervals, rule->rateTokens);
                e->tokens = SkSatAddU64(e->tokens, add);
                if (e->tokens > rule->burst)
                    e->tokens = rule->burst;
                e->lastRefillMs = SkSatAddU64(e->lastRefillMs,
                                              SkSatMulU64(intervals, rule->rateIntervalMs));
            }
        }
        if (e->tokens > 0) {
            e->tokens--;
            allowed = TRUE;
        } else {
            allowed = FALSE;
        }
    }
    ShOps.LockReleaseExclusive(&g_RateLock, irql);
    return allowed;
}

// Zero the whole slot (not just inUse): a reused ruleId never inherits any
// residue (tokens/lastRefillMs/rateSig cleared too; reuse also starts a fresh
// full bucket in SkRateAllow — belt and braces).
VOID SkRuleRateReset(UINT64 ruleId) {
    KIRQL irql;
    UINT32 i;
    irql = ShOps.LockAcquireExclusive(&g_RateLock);
    for (i = 0; i < SK_RATE_TABLE_SIZE; i++) {
        if (g_RateTable[i].inUse && g_RateTable[i].ruleId == ruleId) {
            g_RateTable[i].inUse = 0;
            g_RateTable[i].ruleId = 0;
            g_RateTable[i].tokens = 0;
            g_RateTable[i].lastRefillMs = 0;
            g_RateTable[i].rateSig = 0;
            break;
        }
    }
    ShOps.LockReleaseExclusive(&g_RateLock, irql);
}

// Clamp an existing bucket to a reduced burst. Called by the Update path when
// a rule's burst shrinks; if the bucket does not exist this is a no-op.
VOID SkRuleRateClampBurst(UINT64 ruleId, UINT32 newBurst) {
    KIRQL irql;
    UINT32 i;
    irql = ShOps.LockAcquireExclusive(&g_RateLock);
    for (i = 0; i < SK_RATE_TABLE_SIZE; i++) {
        if (g_RateTable[i].inUse && g_RateTable[i].ruleId == ruleId) {
            if (g_RateTable[i].tokens > (UINT64)newBurst)
                g_RateTable[i].tokens = (UINT64)newBurst;
            break;
        }
    }
    ShOps.LockReleaseExclusive(&g_RateLock, irql);
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
            if (SkRateAllow(hit)) {
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
