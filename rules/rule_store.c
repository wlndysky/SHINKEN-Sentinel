// ============================================================================
// rules/rule_store.c — Rule store: immutable snapshots + atomic publish +
// deferred reclaim.
// Snapshot lifecycle concurrency contract (linearization points / ownership).
// Notation: g_PublishLock = one EX_SPIN_LOCK; reader section = R, writer
// section = W.
//   Reader (classify hot path, up to DISPATCH): R = { read g_Current; check
//     g_StoreClosed; ShRundownAcquire(&snap->readers) } entirely under
//     g_PublishLock; on exit the reference is counted, so the snapshot cannot
//     be freed while held. R is very short (no Sleep/alloc/paged calls);
//     spin lock is legal at DISPATCH.
//   Writer linearization point (PASSIVE; writers mutually serialized by
//     storeLock): W = { swap g_Current; BeginStop the displaced; enqueue to
//     retire list } entirely under g_PublishLock. R and W are mutually
//     exclusive: a reader either enters R before W (old pointer not yet
//     BeginStop, much less drained/freed => Acquire always succeeds) or
//     after W (sees the new pointer or NULL). No "read pointer, snapshot
//     freed before Acquire" interleaving exists.
//   Free point: SkSnapFree runs only after drain observes readers ==
//     STOP_BIT (BeginStop set and count zero). BeginStop happens only after
//     the snapshot was removed from g_Current (same W), so no new reader can
//     reach it afterwards; all counted readers Release before drain succeeds
//     => no live pointer at free, UAF impossible.
//   Reclaim point (drain+free always outside the lock, PASSIVE): each
//     publish bounded-retries SkRetireDrain (leftovers retry at the next
//     publish); Shutdown forces drain and any timeout =>
//     ShRuntimeRecordBlock + ShRuntimeEnterUnloadBlocked
//     (ShinkenBlockRundownStuck); failed snapshots stay on the retire list
//     (leak over UAF; tracking never lost), shutdown returns FALSE without
//     resetting store state.
//   Rollback slot: displaced current goes to g_RollbackSlot (no BeginStop;
//     content immutable; writers only, under storeLock; readers never reach
//     it). When the slot is replaced/consumed/closed it is retired under the
//     exact same reference protocol as current (BeginStop+retire in W,
//     drain/free outside), never read-and-freed directly. ROLLBACK copies
//     slot content into a new snapshot (rundown stop bit is irreversible and
//     versions must stay monotonic); the slot is consumed once.
//   Shutdown: W = { g_StoreClosed=TRUE; detach current/rollbackSlot to the
//     retire list; BeginStop both } in one lock section; the retire list is
//     never cleared; drain/free proceeds outside the lock one by one and
//     failures are re-queued. TRUE (reinstall allowed) only when all are
//     drained; any failure => UNLOAD_BLOCKED terminal state + FALSE
//     (reinstall forbidden, cleanup must stop). Afterwards readers see NULL.
//   Snapshots are immutable: every write copies->validates->sorts->publishes
//     a new snapshot (version+1); failure paths never touch g_Current — the
//     old rule set stays in effect.
//   Write gate: after teardown (ShRuntimeIsActive()==FALSE) or store close,
//     all writes return STATUS_INVALID_DEVICE_STATE.
// ============================================================================
#include <ntddk.h>
#include "../runtime/sk_atomic.h"
#include "rule_store.h"
#include "rule_engine.h"          // SkRuleRateReset (bucket cleanup on delete/disable)
#include "../wfp/wfp_callouts.h"  // SK_LAYER_COUNT (layerId range validation)
#include "../control/protocol.h"  // SK_RULE_MAX / SK_REPLACE_MAX_BYTES

// ---- NTSTATUS values used here but not defined by the shim ----
#ifndef STATUS_RETRY
#define STATUS_RETRY ((NTSTATUS)0xC000022DL)
#endif
#ifndef STATUS_OBJECTID_EXISTS
#define STATUS_OBJECTID_EXISTS ((NTSTATUS)0xC00002A8L)
#endif
#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif

#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(addr, type, field) \
    ((type *)((char *)(addr) - __builtin_offsetof(type, field)))
#endif

#define SK_RULE_POOL_TAG 'lRuS' // 'SuRl' rule snapshot pool

// Pre-publish retire drain: 50 x 1ms bounded retries (readers at DISPATCH
// hold only a very short path; normally drained on round 0; leftovers retry
// at the next publish)
#define SK_RETIRE_DRAIN_RETRIES 50
// Shutdown forced drain: 1000 x 1ms; exhausted => RundownStuck block reason +
// UNLOAD_BLOCKED terminal state (shutdown returns FALSE, snapshots stay on
// the retire list)
#define SK_SHUTDOWN_DRAIN_RETRIES 1000

// ---- Store global state ----
static volatile SK_RULE_SNAPSHOT *g_Current; // published snapshot (atomic pointer access)
static SK_RULE_SNAPSHOT *g_RollbackSlot;     // previous version (rollback slot; writers only)
static LIST_ENTRY g_RetireList;              // retired snapshots awaiting drain
static EX_SPIN_LOCK g_PublishLock;           // short-section spin lock (no Sleep)
static volatile LONG g_WriterBusy;           // PASSIVE writer mutex (storeLock)
static BOOLEAN g_StoreInited;
static BOOLEAN g_StoreClosed;                // cannot revive after Shutdown

#ifdef SHINKEN_HOST_TEST
// Host-test barrier hook (test builds only; unreferenced in kernel builds):
// called inside reader section R after g_Current was read but before
// ShRundownAcquire, to force the most dangerous "reader vs publish/close"
// interleaving (see tests/test_snapshot.c; same pattern as telemetry's
// ShEventTestBarrier).
VOID (*ShRuleStoreTestBarrier)(const SK_RULE_SNAPSHOT *snap);
#endif

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------
static VOID SkListRemove(PLIST_ENTRY e) {
    e->Blink->Flink = e->Flink;
    e->Flink->Blink = e->Blink;
}

// storeLock: PASSIVE sleep mutex (writers only; readers never touch it)
static VOID SkStoreLock(void) {
    while (SkAtCas32(&g_WriterBusy, 1, 0) != 0)
        ShOps.SleepMs(1);
}
static VOID SkStoreUnlock(void) {
    SkAtFence();
    g_WriterBusy = 0;
}

static BOOLEAN SkStoreWritableNoLock(void) {
    return (BOOLEAN)(g_StoreInited && !g_StoreClosed && ShRuntimeIsActive());
}

// Snapshot alloc/free (two pool blocks: array + header; rules is NULL when
// count==0)
static SK_RULE_SNAPSHOT *SkSnapAlloc(void) {
    SK_RULE_SNAPSHOT *s = (SK_RULE_SNAPSHOT *)ShOps.AllocPool(sizeof(SK_RULE_SNAPSHOT),
                                                              SK_RULE_POOL_TAG);
    if (s == NULL)
        return NULL;
    RtlZeroMemory(s, sizeof(*s));
    ShRundownInit(&s->readers, "SkRuleSnap");
    InitializeListHead(&s->retireLink);
    return s;
}

static VOID SkSnapFree(SK_RULE_SNAPSHOT *s) {
    if (s->rules != NULL)
        ShOps.FreePool(s->rules, SK_RULE_POOL_TAG);
    ShOps.FreePool(s, SK_RULE_POOL_TAG);
}

// Verdict-order comparison (contract: priority desc -> action strength
// BLOCK>RATE_LIMIT>AUDIT>ALLOW -> ruleId asc). TRUE if a precedes b.
static UINT32 SkActionRank(UINT32 action) {
    switch (action) {
    case SkRuleActionBlock:
        return 3;
    case SkRuleActionRateLimit:
        return 2;
    case SkRuleActionAudit:
        return 1;
    default:
        return 0; // SkRuleActionAllow
    }
}

static BOOLEAN SkRulePrecedes(const SK_RULE *a, const SK_RULE *b) {
    UINT32 ra, rb;
    if (a->priority != b->priority)
        return (BOOLEAN)(a->priority > b->priority);
    ra = SkActionRank(a->action);
    rb = SkActionRank(b->action);
    if (ra != rb)
        return (BOOLEAN)(ra > rb);
    return (BOOLEAN)(a->ruleId < b->ruleId);
}

// Insertion sort (write path PASSIVE, count <= SK_RULE_MAX=4096; low update
// rate, simple and stable beats fancy). A sorted snapshot makes the first
// match during a classify scan the verdict.
static VOID SkSortRules(SK_RULE *a, UINT32 n) {
    UINT32 i, j;
    for (i = 1; i < n; i++) {
        SK_RULE t = a[i];
        for (j = i; j > 0 && SkRulePrecedes(&t, &a[j - 1]); j--)
            a[j] = a[j - 1];
        a[j] = t;
    }
}

// Retire list drain: detach and free drained snapshots (readers==STOP_BIT
// and zero). Bounded retries with SleepMs(1) between rounds; the spin lock
// covers only list detachment, Sleep happens outside.
static VOID SkRetireDrain(ULONG retries) {
    ULONG round;
    for (round = 0;; round++) {
        KIRQL irql;
        LIST_ENTRY drained;
        PLIST_ENTRY e, next;
        BOOLEAN remaining;
        InitializeListHead(&drained);
        irql = ShOps.LockAcquireExclusive(&g_PublishLock);
        e = g_RetireList.Flink;
        while (e != &g_RetireList) {
            SK_RULE_SNAPSHOT *s;
            next = e->Flink;
            s = CONTAINING_RECORD(e, SK_RULE_SNAPSHOT, retireLink);
            if (ShRundownActiveCount(&s->readers) == -1) {
                SkListRemove(e);
                InsertTailList(&drained, e);
            }
            e = next;
        }
        remaining = !IsListEmpty(&g_RetireList);
        ShOps.LockReleaseExclusive(&g_PublishLock, irql);
        while (!IsListEmpty(&drained)) {
            e = drained.Flink;
            SkListRemove(e);
            SkSnapFree(CONTAINING_RECORD(e, SK_RULE_SNAPSHOT, retireLink));
        }
        if (!remaining || round >= retries)
            return;
        ShOps.SleepMs(1);
    }
}

// Free RATE_LIMIT buckets of removed rules (snapshot-independent mutable
// state; cleared as soon as the rule disappears)
static VOID SkRateResetRemoved(const SK_RULE_SNAPSHOT *oldSnap, const SK_RULE_SNAPSHOT *newSnap) {
    UINT32 i, j;
    if (oldSnap == NULL)
        return;
    for (i = 0; i < oldSnap->count; i++) {
        UINT64 id = oldSnap->rules[i].ruleId;
        BOOLEAN present = FALSE;
        if (newSnap != NULL) {
            for (j = 0; j < newSnap->count; j++) {
                if (newSnap->rules[j].ruleId == id) {
                    present = TRUE;
                    break;
                }
            }
        }
        if (!present)
            SkRuleRateReset(id);
    }
}

// Atomic publish (caller holds storeLock; ownership of rules transfers and
// failure paths free it here too). version = old current->version + 1
// (monotonic); old current goes to the rollback slot; old slot retires.
static NTSTATUS SkPublish(SK_RULE *rules, UINT32 count, UINT32 defaultPolicy) {
    SK_RULE_SNAPSHOT *snap, *old, *rb;
    KIRQL irql;
    snap = SkSnapAlloc();
    if (snap == NULL) {
        if (rules != NULL)
            ShOps.FreePool(rules, SK_RULE_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    snap->rules = rules;
    snap->count = count;
    snap->defaultPolicy = defaultPolicy;

    // Reclaim point: free already-drained snapshots from the retire list
    // before publishing (outside the lock, PASSIVE)
    SkRetireDrain(SK_RETIRE_DRAIN_RETRIES);

    // ---- Writer section W (publish linearization point; proof in the file
    // header) ----
    // g_Current swap / displaced BeginStop / retire-list insert all happen in
    // this one g_PublishLock section: mutually exclusive with reader section
    // R, forming a single linearization point.
    irql = ShOps.LockAcquireExclusive(&g_PublishLock);
    if (!SkStoreWritableNoLock()) {
        ShOps.LockReleaseExclusive(&g_PublishLock, irql);
        SkSnapFree(snap);
        return STATUS_INVALID_DEVICE_STATE;
    }
    old = (SK_RULE_SNAPSHOT *)g_Current;
    snap->version = old->version + 1;
    rb = g_RollbackSlot;
    g_RollbackSlot = old; // displaced snapshot kept for ROLLBACK (no BeginStop)
    if (rb != NULL) {
        // Old rollback slot retires: it stopped being g_Current long ago, so
        // no new reader can reach it; in-flight readers (Acquire'd while it
        // was current) are counted and waited on by drain.
        ShRundownBeginStop(&rb->readers);
        rb->retired = 1;
        InsertTailList(&g_RetireList, &rb->retireLink);
    }
    SkAtFence(); // snapshot content visible before pointer publish (release semantics)
    g_Current = snap;
    ShOps.LockReleaseExclusive(&g_PublishLock, irql);

    SkRateResetRemoved(old, snap);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// Rule validation (shared by ioctl and store; any failure =>
// STATUS_INVALID_PARAMETER)
// ---------------------------------------------------------------------------
#define SK_RULE_M_ALL                                                                             \
    (SK_RULE_M_FAMILY | SK_RULE_M_DIRECTION | SK_RULE_M_PROTOCOL | SK_RULE_M_LOCALADDR |          \
     SK_RULE_M_REMOTEADDR | SK_RULE_M_LOCALPORT | SK_RULE_M_REMOTEPORT | SK_RULE_M_PID |          \
     SK_RULE_M_APPID | SK_RULE_M_LAYER | SK_RULE_M_IFINDEX | SK_RULE_M_SID | SK_RULE_M_TIME)

NTSTATUS SkRuleValidate(const SK_RULE *rule) {
    UINT32 m;
    if (rule == NULL)
        return STATUS_INVALID_PARAMETER;
    if (rule->ruleId == 0)
        return STATUS_INVALID_PARAMETER; // 0 is invalid (reserved by the allocator)
    if (rule->mask & ~((UINT32)SK_RULE_M_ALL))
        return STATUS_INVALID_PARAMETER; // unknown mask bits (forward-compat reject)
    // Reserved conditions: SK_RULE_M_IFINDEX / SK_RULE_M_SID are kept as known
    // mask bits (wire-format stability) but were never implemented in the
    // classify data plane — no code path reliably fills tuple->ifIndex, and
    // tuple->userId is always NULL — so rules conditioned on them could never
    // match honestly. Reject them at validation instead of accepting rules
    // that silently never fire. (STATUS_NOT_SUPPORTED is not defined in
    // shim/wdk_shim.h; all validation failures report STATUS_INVALID_PARAMETER.)
    if (rule->mask & (SK_RULE_M_IFINDEX | SK_RULE_M_SID))
        return STATUS_INVALID_PARAMETER;
    if (rule->enabled > 1)
        return STATUS_INVALID_PARAMETER;
    if (rule->action > (UINT32)SkRuleActionRateLimit)
        return STATUS_INVALID_PARAMETER;
    // RATE_LIMIT parameters must be non-zero (bucket semantics otherwise void)
    if (rule->action == (UINT32)SkRuleActionRateLimit &&
        (rule->rateTokens == 0 || rule->rateIntervalMs == 0 || rule->burst == 0))
        return STATUS_INVALID_PARAMETER;
    if (rule->sidLength != 0 && (rule->sidLength < 8 || rule->sidLength > 32))
        return STATUS_INVALID_PARAMETER;
    m = rule->mask;
    if ((m & SK_RULE_M_FAMILY) && rule->family != AF_INET && rule->family != AF_INET6)
        return STATUS_INVALID_PARAMETER;
    if ((m & SK_RULE_M_DIRECTION) && rule->direction > SK_RULE_DIR_IN)
        return STATUS_INVALID_PARAMETER;
    if ((m & SK_RULE_M_LAYER) && rule->layerId >= SK_LAYER_COUNT)
        return STATUS_INVALID_PARAMETER; // layer must be a known internal id
    if ((m & SK_RULE_M_PROTOCOL) && rule->protocol > 255)
        return STATUS_INVALID_PARAMETER;
    // prefix bound: by family when known (v4<=32/v6<=128); 128 when family is wildcard
    if (m & SK_RULE_M_LOCALADDR) {
        UINT32 lim = ((m & SK_RULE_M_FAMILY) && rule->family == AF_INET) ? 32u : 128u;
        if ((UINT32)rule->localPrefix > lim)
            return STATUS_INVALID_PARAMETER;
    }
    if (m & SK_RULE_M_REMOTEADDR) {
        UINT32 lim = ((m & SK_RULE_M_FAMILY) && rule->family == AF_INET) ? 32u : 128u;
        if ((UINT32)rule->remotePrefix > lim)
            return STATUS_INVALID_PARAMETER;
    }
    // ports are 16-bit closed intervals: min<=max
    if ((m & SK_RULE_M_LOCALPORT) &&
        (rule->localPortMin > rule->localPortMax || rule->localPortMax > 65535))
        return STATUS_INVALID_PARAMETER;
    if ((m & SK_RULE_M_REMOTEPORT) &&
        (rule->remotePortMin > rule->remotePortMax || rule->remotePortMax > 65535))
        return STATUS_INVALID_PARAMETER;
    // validity: notBefore<=notAfter (0/0 permanent also satisfies)
    if ((m & SK_RULE_M_TIME) && rule->notBefore > rule->notAfter)
        return STATUS_INVALID_PARAMETER;
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------
NTSTATUS SkRuleStoreInit(void) {
    SK_RULE_SNAPSHOT *snap;
    if (ShRuntimeState() == ShinkenUnloadBlocked)
        return STATUS_DEVICE_BUSY; // UNLOAD_BLOCKED terminal state: reinstall forbidden (failure scene preserved)
    if (g_StoreInited) {
        // Idempotent reinit (host-test reset scenario): requires a complete
        // prior shutdown — refuse if any snapshot failed to drain (readers
        // remain); never overwrite g_RetireList/g_Current/g_RollbackSlot
        // tracking.
        if (!SkRuleStoreShutdown())
            return STATUS_DEVICE_BUSY;
    }
    snap = SkSnapAlloc();
    if (snap == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    snap->rules = NULL;
    snap->count = 0;
    snap->version = 0; // empty snapshot version 0
    snap->defaultPolicy = (UINT32)SkVerdictPermit; // factory PERMIT
    InitializeListHead(&g_RetireList); // only after a complete shutdown: tracking is empty
    g_RollbackSlot = NULL;
    g_PublishLock = 0;
    SkAtFence();
    g_Current = snap;
    g_StoreClosed = FALSE;
    g_StoreInited = TRUE;
    return STATUS_SUCCESS;
}

BOOLEAN SkRuleStoreShutdown(void) {
    LIST_ENTRY stuck; // snapshots that failed drain (re-queued to retire list at the end)
    SK_RULE_SNAPSHOT *cur, *rb;
    KIRQL irql;
    BOOLEAN failed = FALSE;
    SkStoreLock();
    if (!g_StoreInited) {
        SkStoreUnlock();
        return TRUE; // already closed and fully freed: idempotent
    }
    if (ShRuntimeState() == ShinkenUnloadBlocked) {
        // Already in UNLOAD_BLOCKED (prior drain failure or another
        // subsystem): do not touch tracking, no double free, do not overwrite
        // the first cause; the failure scene is fully preserved.
        SkStoreUnlock();
        return FALSE;
    }
    InitializeListHead(&stuck);
    // ---- Writer section W (shutdown linearization point; proof in the file
    // header) ----
    // Close write gate + detach current/rollbackSlot to retire list +
    // BeginStop, all in one g_PublishLock section: afterwards readers see
    // NULL; readers already Acquire'd inside R are counted and waited on by
    // the off-lock drain. The retire list itself is never cleared — it is the
    // only tracking of retired snapshots, and drain failures must stay on it.
    irql = ShOps.LockAcquireExclusive(&g_PublishLock);
    g_StoreClosed = TRUE; // close write gate (Acquire returns NULL afterwards)
    cur = (SK_RULE_SNAPSHOT *)g_Current;
    g_Current = NULL;
    rb = g_RollbackSlot;
    g_RollbackSlot = NULL;
    if (cur != NULL) {
        ShRundownBeginStop(&cur->readers);
        cur->retired = 1;
        InsertTailList(&g_RetireList, &cur->retireLink);
    }
    if (rb != NULL) {
        ShRundownBeginStop(&rb->readers);
        rb->retired = 1;
        InsertTailList(&g_RetireList, &rb->retireLink);
    }
    ShOps.LockReleaseExclusive(&g_PublishLock, irql);
    // Forced drain outside the lock, one by one: free on success; on failure
    // record RundownStuck first cause + enter UNLOAD_BLOCKED, and move the
    // snapshot to stuck (tracking never lost; leak over UAF — the holder may
    // still be on a DISPATCH evaluation path).
    for (;;) {
        PLIST_ENTRY e;
        SK_RULE_SNAPSHOT *s;
        NTSTATUS st;
        irql = ShOps.LockAcquireExclusive(&g_PublishLock);
        if (IsListEmpty(&g_RetireList)) {
            ShOps.LockReleaseExclusive(&g_PublishLock, irql);
            break;
        }
        e = g_RetireList.Flink;
        SkListRemove(e);
        ShOps.LockReleaseExclusive(&g_PublishLock, irql);
        s = CONTAINING_RECORD(e, SK_RULE_SNAPSHOT, retireLink);
        st = ShRundownDrain(&s->readers, SK_SHUTDOWN_DRAIN_RETRIES, 1);
        // SHINKEN_STATUS_TIMEOUT (0x102) is a positive value, so NT_SUCCESS
        // would be TRUE — must compare exactly against STATUS_SUCCESS, or a
        // timeout is misjudged as drained.
        if (st == STATUS_SUCCESS) {
            SkSnapFree(s);
        } else {
            failed = TRUE;
            ShRuntimeRecordBlock(ShinkenBlockRundownStuck);
            ShRuntimeEnterUnloadBlocked(ShinkenBlockRundownStuck);
            InsertTailList(&stuck, e); // not re-queued yet: avoid re-draining in the same pass
        }
    }
    if (!IsListEmpty(&stuck)) {
        // Re-queue failed snapshots to the retire list: keep the only
        // tracking (diagnosable; a shutdown retry after reset can reclaim
        // them); never drop them from every tracking structure.
        irql = ShOps.LockAcquireExclusive(&g_PublishLock);
        while (!IsListEmpty(&stuck)) {
            PLIST_ENTRY e = stuck.Flink;
            SkListRemove(e);
            InsertTailList(&g_RetireList, e);
        }
        ShOps.LockReleaseExclusive(&g_PublishLock, irql);
    }
    if (failed) {
        // At least one snapshot still has readers: keep g_StoreInited TRUE
        // (tracking valid), SkRuleStoreInit will refuse reinstall; cleanup
        // depending on this store must stop.
        SkStoreUnlock();
        return FALSE;
    }
    g_StoreInited = FALSE; // all drained+freed: store can be reinstalled
    SkStoreUnlock();
    return TRUE;
}

BOOLEAN SkRuleStoreWritable(void) {
    return SkStoreWritableNoLock();
}

// ---------------------------------------------------------------------------
// Reader API (classify hot path; no alloc/Sleep, very short spin sections
// only)
// ---------------------------------------------------------------------------
// Reader section R (linearization point; proof in the file header): read
// g_Current + closed check + readers Acquire, all under g_PublishLock.
// Writers detach pointers and BeginStop under the same lock => the snapshot
// g_Current points to inside R has not been BeginStop, so Acquire always
// succeeds; on exit the reference is counted and the snapshot cannot be
// freed while held.
const SK_RULE_SNAPSHOT *SkRuleStoreAcquire(void) {
    const SK_RULE_SNAPSHOT *s;
    KIRQL irql;
    irql = ShOps.LockAcquireExclusive(&g_PublishLock);
    s = (const SK_RULE_SNAPSHOT *)g_Current;
#ifdef SHINKEN_HOST_TEST
    if (ShRuleStoreTestBarrier != NULL)
        ShRuleStoreTestBarrier(s); // barrier: pause inside R after read, before Acquire (forced test interleaving)
#endif
    if (s == NULL || g_StoreClosed) {
        s = NULL; // store closed
    } else if (!ShRundownAcquire((SHINKEN_RUNDOWN *)&s->readers)) {
        // Unreachable by the invariant above; defensively treat as closed and
        // never use an uncounted reference.
        s = NULL;
    }
    ShOps.LockReleaseExclusive(&g_PublishLock, irql);
    return s;
}

VOID SkRuleStoreRelease(const SK_RULE_SNAPSHOT *snap) {
    if (snap != NULL)
        ShRundownRelease((SHINKEN_RUNDOWN *)&snap->readers);
}

// Scalar reads also avoid bare g_Current dereference (the pointer may have
// just been detached and freed by shutdown): read under g_PublishLock;
// g_Current==NULL inside the lock means "closed" defaults.
UINT64 SkRuleStoreVersion(void) {
    UINT64 v;
    KIRQL irql;
    irql = ShOps.LockAcquireExclusive(&g_PublishLock);
    v = (g_Current != NULL) ? g_Current->version : 0;
    ShOps.LockReleaseExclusive(&g_PublishLock, irql);
    return v;
}

UINT32 SkRuleStoreDefaultPolicy(void) {
    UINT32 p;
    KIRQL irql;
    irql = ShOps.LockAcquireExclusive(&g_PublishLock);
    p = (g_Current != NULL) ? g_Current->defaultPolicy : (UINT32)SkVerdictPermit;
    ShOps.LockReleaseExclusive(&g_PublishLock, irql);
    return p;
}

// ---------------------------------------------------------------------------
// Writer API (PASSIVE; all copy->validate->sort->publish; failure leaves the
// old rule set in effect)
// ---------------------------------------------------------------------------
NTSTATUS SkRuleStoreAdd(const SK_RULE *rule) {
    NTSTATUS st;
    SK_RULE *arr;
    UINT32 n, i;
    const SK_RULE_SNAPSHOT *cur;
    st = SkRuleValidate(rule);
    if (!NT_SUCCESS(st))
        return st;
    SkStoreLock();
    if (!SkStoreWritableNoLock()) {
        SkStoreUnlock();
        return STATUS_INVALID_DEVICE_STATE;
    }
    cur = (const SK_RULE_SNAPSHOT *)g_Current;
    n = cur->count;
    if (n >= SK_RULE_MAX) {
        SkStoreUnlock();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    for (i = 0; i < n; i++) {
        if (cur->rules[i].ruleId == rule->ruleId) {
            SkStoreUnlock();
            return STATUS_OBJECTID_EXISTS; // id conflict
        }
    }
    arr = (SK_RULE *)ShOps.AllocPool((n + 1) * sizeof(SK_RULE), SK_RULE_POOL_TAG);
    if (arr == NULL) {
        SkStoreUnlock();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (n != 0)
        RtlCopyMemory(arr, cur->rules, n * sizeof(SK_RULE));
    arr[n] = *rule;
    SkSortRules(arr, n + 1);
    st = SkPublish(arr, n + 1, cur->defaultPolicy);
    if (NT_SUCCESS(st))
        SkRuleRateReset(rule->ruleId); // rule id reuse guard: a new rule never inherits an old token bucket
    SkStoreUnlock();
    return st;
}

NTSTATUS SkRuleStoreUpdate(const SK_RULE *rule) {
    NTSTATUS st;
    SK_RULE *arr;
    UINT32 n, i;
    const SK_RULE_SNAPSHOT *cur;
    st = SkRuleValidate(rule);
    if (!NT_SUCCESS(st))
        return st;
    SkStoreLock();
    if (!SkStoreWritableNoLock()) {
        SkStoreUnlock();
        return STATUS_INVALID_DEVICE_STATE;
    }
    cur = (const SK_RULE_SNAPSHOT *)g_Current;
    n = cur->count;
    for (i = 0; i < n; i++) {
        if (cur->rules[i].ruleId == rule->ruleId)
            break;
    }
    if (i == n) {
        SkStoreUnlock();
        return STATUS_NOT_FOUND; // id not found
    }
    arr = (SK_RULE *)ShOps.AllocPool((n ? n : 1) * sizeof(SK_RULE), SK_RULE_POOL_TAG);
    if (arr == NULL) {
        SkStoreUnlock();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (n != 0)
        RtlCopyMemory(arr, cur->rules, n * sizeof(SK_RULE));
    arr[i] = *rule;
    SkSortRules(arr, n);
    st = SkPublish(arr, n, cur->defaultPolicy);
    // Update keeps the token bucket: the bucket belongs to the ruleId
    // lifetime, not to a snapshot generation — a content update of the same
    // rule does not clear rate state (only delete/disable/replaced-away does,
    // via the SkPublish diff or the caller).
    SkStoreUnlock();
    return st;
}

NTSTATUS SkRuleStoreDelete(UINT64 ruleId) {
    NTSTATUS st;
    SK_RULE *arr;
    UINT32 n, i;
    const SK_RULE_SNAPSHOT *cur;
    SkStoreLock();
    if (!SkStoreWritableNoLock()) {
        SkStoreUnlock();
        return STATUS_INVALID_DEVICE_STATE;
    }
    cur = (const SK_RULE_SNAPSHOT *)g_Current;
    n = cur->count;
    for (i = 0; i < n; i++) {
        if (cur->rules[i].ruleId == ruleId)
            break;
    }
    if (i == n) {
        SkStoreUnlock();
        return STATUS_NOT_FOUND;
    }
    if (n == 1) {
        st = SkPublish(NULL, 0, cur->defaultPolicy); // deleting the last rule => empty snapshot
    } else {
        arr = (SK_RULE *)ShOps.AllocPool((n - 1) * sizeof(SK_RULE), SK_RULE_POOL_TAG);
        if (arr == NULL) {
            SkStoreUnlock();
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (i != 0)
            RtlCopyMemory(arr, cur->rules, i * sizeof(SK_RULE));
        if (i + 1 < n)
            RtlCopyMemory(arr + i, cur->rules + i + 1, (n - i - 1) * sizeof(SK_RULE));
        st = SkPublish(arr, n - 1, cur->defaultPolicy); // delete keeps order; no re-sort needed
    }
    SkStoreUnlock();
    return st;
}

NTSTATUS SkRuleStoreSetEnabled(UINT64 ruleId, BOOLEAN enabled) {
    NTSTATUS st;
    SK_RULE *arr;
    UINT32 n, i;
    const SK_RULE_SNAPSHOT *cur;
    SkStoreLock();
    if (!SkStoreWritableNoLock()) {
        SkStoreUnlock();
        return STATUS_INVALID_DEVICE_STATE;
    }
    cur = (const SK_RULE_SNAPSHOT *)g_Current;
    n = cur->count;
    for (i = 0; i < n; i++) {
        if (cur->rules[i].ruleId == ruleId)
            break;
    }
    if (i == n) {
        SkStoreUnlock();
        return STATUS_NOT_FOUND;
    }
    arr = (SK_RULE *)ShOps.AllocPool(n * sizeof(SK_RULE), SK_RULE_POOL_TAG);
    if (arr == NULL) {
        SkStoreUnlock();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(arr, cur->rules, n * sizeof(SK_RULE));
    arr[i].enabled = enabled ? 1 : 0; // sort keys (priority/action/id) unchanged; no re-sort
    st = SkPublish(arr, n, cur->defaultPolicy);
    if (NT_SUCCESS(st) && !enabled)
        SkRuleRateReset(ruleId); // disabling clears the bucket (delete is covered by the SkPublish diff)
    SkStoreUnlock();
    return st;
}

NTSTATUS SkRuleStoreReplace(const SK_RULE *rules, UINT32 count, UINT64 expectedVersion) {
    NTSTATUS st;
    SK_RULE *arr;
    UINT32 i, j;
    // Capacity/integer-overflow re-check (ioctl checked wire bytes; the store
    // re-checks the kernel array)
    if (count > SK_RULE_MAX)
        return STATUS_INVALID_PARAMETER;
    if ((UINT64)count * sizeof(SK_RULE) > SK_REPLACE_MAX_BYTES)
        return STATUS_INVALID_PARAMETER;
    if (count != 0 && rules == NULL)
        return STATUS_INVALID_PARAMETER;
    for (i = 0; i < count; i++) {
        st = SkRuleValidate(&rules[i]);
        if (!NT_SUCCESS(st))
            return st; // publish surface untouched until full validation passes
    }
    for (i = 0; i < count; i++) { // ids unique within the set (O(n^2), count<=4096 bounded)
        for (j = i + 1; j < count; j++) {
            if (rules[i].ruleId == rules[j].ruleId)
                return STATUS_OBJECTID_EXISTS;
        }
    }
    SkStoreLock();
    if (!SkStoreWritableNoLock()) {
        SkStoreUnlock();
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (expectedVersion != 0 && g_Current->version != expectedVersion) {
        SkStoreUnlock();
        return STATUS_RETRY; // optimistic concurrency conflict
    }
    arr = NULL;
    if (count != 0) {
        arr = (SK_RULE *)ShOps.AllocPool(count * sizeof(SK_RULE), SK_RULE_POOL_TAG);
        if (arr == NULL) {
            SkStoreUnlock();
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(arr, rules, count * sizeof(SK_RULE));
        SkSortRules(arr, count);
    }
    st = SkPublish(arr, count, g_Current->defaultPolicy);
    SkStoreUnlock();
    return st;
}

NTSTATUS SkRuleStoreClear(void) {
    NTSTATUS st;
    SkStoreLock();
    if (!SkStoreWritableNoLock()) {
        SkStoreUnlock();
        return STATUS_INVALID_DEVICE_STATE;
    }
    st = SkPublish(NULL, 0, g_Current->defaultPolicy);
    SkStoreUnlock();
    return st;
}

NTSTATUS SkRuleStoreRollback(void) {
    NTSTATUS st;
    SK_RULE_SNAPSHOT *snap, *old, *rb;
    SK_RULE *arr;
    KIRQL irql;
    SkStoreLock();
    if (!SkStoreWritableNoLock()) {
        SkStoreUnlock();
        return STATUS_INVALID_DEVICE_STATE;
    }
    // Rollback slot read safety: snapshot content is immutable under the
    // reader protocol, and g_RollbackSlot is writers-only — all writers
    // (including shutdown) are serialized by storeLock, so reading the slot
    // content outside the spin lock is stable; the slot body retires strictly
    // under the same reference protocol below, never read-and-freed directly.
    rb = g_RollbackSlot;
    if (rb == NULL) {
        SkStoreUnlock();
        return STATUS_NOT_FOUND; // no previous version
    }
    // The slot snapshot cannot be republished as-is (the rundown stop bit is
    // irreversible once set by a future operation, and versions must be
    // monotonic) => copy its content into a new snapshot; slot consumed once.
    arr = NULL;
    if (rb->count != 0) {
        arr = (SK_RULE *)ShOps.AllocPool(rb->count * sizeof(SK_RULE), SK_RULE_POOL_TAG);
        if (arr == NULL) {
            SkStoreUnlock();
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(arr, rb->rules, rb->count * sizeof(SK_RULE)); // already sorted
    }
    snap = SkSnapAlloc();
    if (snap == NULL) {
        if (arr != NULL)
            ShOps.FreePool(arr, SK_RULE_POOL_TAG);
        SkStoreUnlock();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    snap->rules = arr;
    snap->count = rb->count;
    snap->defaultPolicy = rb->defaultPolicy;

    SkRetireDrain(SK_RETIRE_DRAIN_RETRIES);
    // ---- Writer section W (rollback publish linearization point) ----
    // g_Current swap / BeginStop of old current and slot body / retire
    // insert, all in one g_PublishLock section — the same linearization point
    // as a normal publish/shutdown.
    irql = ShOps.LockAcquireExclusive(&g_PublishLock);
    if (!SkStoreWritableNoLock()) {
        ShOps.LockReleaseExclusive(&g_PublishLock, irql);
        SkSnapFree(snap);
        SkStoreUnlock();
        return STATUS_INVALID_DEVICE_STATE;
    }
    old = (SK_RULE_SNAPSHOT *)g_Current;
    snap->version = old->version + 1; // rollback is also a publish; version increments
    g_RollbackSlot = NULL;            // slot consumed
    SkAtFence();
    g_Current = snap;
    ShRundownBeginStop(&old->readers);
    old->retired = 1;
    InsertTailList(&g_RetireList, &old->retireLink);
    ShRundownBeginStop(&rb->readers); // content copied; slot body retires
    rb->retired = 1;
    InsertTailList(&g_RetireList, &rb->retireLink);
    ShOps.LockReleaseExclusive(&g_PublishLock, irql);

    SkRateResetRemoved(old, snap);
    SkStoreUnlock();
    st = STATUS_SUCCESS;
    return st;
}

NTSTATUS SkRuleStoreSetDefaultPolicy(UINT32 policy) {
    NTSTATUS st;
    SK_RULE *arr;
    UINT32 n;
    const SK_RULE_SNAPSHOT *cur;
    if (policy != (UINT32)SkVerdictPermit && policy != (UINT32)SkVerdictBlock)
        return STATUS_INVALID_PARAMETER; // default policy is PERMIT/BLOCK only
    SkStoreLock();
    if (!SkStoreWritableNoLock()) {
        SkStoreUnlock();
        return STATUS_INVALID_DEVICE_STATE;
    }
    cur = (const SK_RULE_SNAPSHOT *)g_Current;
    n = cur->count;
    arr = NULL;
    if (n != 0) {
        arr = (SK_RULE *)ShOps.AllocPool(n * sizeof(SK_RULE), SK_RULE_POOL_TAG);
        if (arr == NULL) {
            SkStoreUnlock();
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(arr, cur->rules, n * sizeof(SK_RULE)); // already sorted
    }
    st = SkPublish(arr, n, policy);
    SkStoreUnlock();
    return st;
}

// ---------------------------------------------------------------------------
// Enumeration/find (PASSIVE control plane)
// Safety: storeLock is held for the whole walk => all writers (publish,
// rollback, shutdown all go through storeLock first) are excluded, so
// g_Current is stable for the duration — it cannot be replaced or freed, and
// no reader reference is needed to walk it. Callback contract: the const
// SK_RULE* handed to onRule points inside the snapshot and is valid only
// during the callback; SK_RULE is value-copy semantics — to keep it across
// callbacks the caller must copy it; never store the pointer.
// ---------------------------------------------------------------------------
NTSTATUS SkRuleStoreEnum(BOOLEAN (*onRule)(const SK_RULE *, PVOID), PVOID ctx) {
    const SK_RULE_SNAPSHOT *cur;
    UINT32 i, n;
    if (onRule == NULL)
        return STATUS_INVALID_PARAMETER;
    SkStoreLock();
    if (!g_StoreInited || g_Current == NULL) {
        SkStoreUnlock();
        return STATUS_INVALID_DEVICE_STATE;
    }
    cur = (const SK_RULE_SNAPSHOT *)g_Current; // stable under storeLock (see above)
    n = cur->count;
    for (i = 0; i < n; i++) {
        if (!onRule(&cur->rules[i], ctx))
            break; // callback-initiated stop is not an error
    }
    SkStoreUnlock();
    return STATUS_SUCCESS;
}

NTSTATUS SkRuleStoreFind(UINT64 ruleId, SK_RULE *out) {
    const SK_RULE_SNAPSHOT *cur;
    UINT32 i, n;
    NTSTATUS st;
    if (out == NULL)
        return STATUS_INVALID_PARAMETER;
    SkStoreLock();
    if (!g_StoreInited || g_Current == NULL) {
        SkStoreUnlock();
        return STATUS_INVALID_DEVICE_STATE;
    }
    cur = (const SK_RULE_SNAPSHOT *)g_Current; // stable under storeLock (see Enum comment)
    st = STATUS_NOT_FOUND;
    n = cur->count;
    for (i = 0; i < n; i++) {
        if (cur->rules[i].ruleId == ruleId) {
            *out = cur->rules[i]; // value-copied out-parameter; the caller gets a copy
            st = STATUS_SUCCESS;
            break;
        }
    }
    SkStoreUnlock();
    return st;
}
