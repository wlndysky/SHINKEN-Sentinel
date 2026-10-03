// ============================================================================
// packet/flow_context.c — flow context table (refcount + spinlock)
//
// Refs: table ref (held while linked; returned exactly once by the single
// unlink authority) + caller ref (SkFlowAttach return; caller must
// SkFlowRelease). New attach: ref=2. Duplicate flowId: reuse + AddRef.
// Lock: g_SkFlowLock protects list, entry count, and every assocState
// transition; never held across FwpsFlowAssociateContext0 /
// FwpsFlowRemoveContext0 (WFP may synchronously call flowDeleteFn, which
// takes the same non-recursive spinlock -> self-deadlock).
//
// Attach gate: one SHINKEN_RUNDOWN per callout runtime id. SkFlowAttach
// acquires the gate around the whole check/insert/associate sequence;
// SkFlowGateStopAndDrain (WFP teardown, before callout unregister)
// closes the gate and waits for in-flight attaches, so a late Attach can
// never start after teardown began and in-flight ones always settle
// before FwpsCalloutUnregisterById0 runs.
//
// RemoveContext result discipline (per FwpsFlowRemoveContext0 contract):
//   STATUS_SUCCESS      removal confirmed; the synchronous flowDeleteFn,
//                       if one was pending, already ran (it skips entries
//                       already off the list) -> table ref returned here.
//   STATUS_PENDING      removal is asynchronous; a flowDeleteFn is still
//                       owed -> the table ref stays with that callback;
//                       entry re-linked (linked=TRUE) so the callback
//                       finds and unlinks it. NOT a failure.
//   STATUS_UNSUCCESSFUL nothing was associated; no callback will come ->
//                       table ref returned here (never re-link).
//   anything else       removal state untrusted; entry kept resident and
//                       FALSE returned (upper layer blocks unload).
// ============================================================================
#include <ntddk.h>
#include "../runtime/sk_atomic.h"
#include "../runtime/runtime.h" // ShRuntimeRecordBlock (attach-gate abandon)
#include "flow_context.h"
#include "injection.h"
#include "../wfp/wfp_callouts.h"

#define SK_FLOW_POOL_TAG 0x78746366u /* 'fctx' pool tag */

// CONTAINING_RECORD: real WDK provides it via wdm.h; the shim does not.
#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(addr, type, field) \
    ((type *)((char *)(addr) - (size_t)&((type *)0)->field))
#endif

// Internal layer id -> WFP runtime layer id (fwpsk.h: ALE_FLOW_ESTABLISHED
// V4=52 / V6=53), for FwpsFlowAssociateContext0 / FwpsFlowRemoveContext0.
static UINT16 skFlowWfpLayerId(UINT32 layerId) {
    if (layerId == SkLayerFlowEstablishedV4)
        return 52;
    if (layerId == SkLayerFlowEstablishedV6)
        return 53;
    return 0;
}

// Per-callout attach gates (image-static storage; never freed — same
// discipline as rundown.h invariant 9). Index: callout runtime id.
#define SK_FLOW_MAX_GATES 256
static SHINKEN_RUNDOWN g_SkFlowGates[SK_FLOW_MAX_GATES];

// Image-static storage (rundown.h point 9: global sync structures never freed)
static LIST_ENTRY g_SkFlowList;
static EX_SPIN_LOCK g_SkFlowLock;
static ULONG g_SkFlowEntries;
static LONG g_SkFlowInited;

NTSTATUS SkFlowInit(void) {
    UINT32 i;
    if (SkAtOr32(&g_SkFlowInited, 1))
        return STATUS_SUCCESS; // idempotent
    InitializeListHead(&g_SkFlowList);
    g_SkFlowLock = 0;
    g_SkFlowEntries = 0;
    for (i = 0; i < SK_FLOW_MAX_GATES; i++)
        ShRundownInit(&g_SkFlowGates[i], "flowAttachGate");
    return STATUS_SUCCESS;
}

VOID SkFlowAddRef(SK_FLOW_CTX *ctx) {
    SkAtAdd32(&ctx->ref, 1);
}

VOID SkFlowRelease(SK_FLOW_CTX *ctx) {
    if (SkAtSub32(&ctx->ref, 1) == 1)
        ShOps.FreePool(ctx, SK_FLOW_POOL_TAG); // zero: non-paged free (legal in-lock)
}

// Find by flowId, caller holds the lock
static SK_FLOW_CTX *skFlowFindLocked(UINT64 flowId) {
    LIST_ENTRY *e;
    for (e = g_SkFlowList.Flink; e != &g_SkFlowList; e = e->Flink) {
        SK_FLOW_CTX *c = CONTAINING_RECORD(e, SK_FLOW_CTX, link);
        if (c->flowId == flowId)
            return c;
    }
    return NULL;
}

// The single unlink authority: caller holds the lock, entry must be linked.
// Clears membership first (a concurrent flowDelete scan then skips the
// entry), detaches the LIST_ENTRY, drops the count, returns the table ref.
// Use skFlowDetachLocked instead when ownership of the table ref transfers
// to a later verdict (RemoveContext result handling).
static VOID skFlowDetachLocked(SK_FLOW_CTX *ctx) {
    ctx->linked = FALSE; // ordering: membership cleared before detach
    ctx->link.Blink->Flink = ctx->link.Flink;
    ctx->link.Flink->Blink = ctx->link.Blink;
    ctx->link.Flink = ctx->link.Blink = NULL;
    g_SkFlowEntries--;
}
static VOID skFlowUnlinkLocked(SK_FLOW_CTX *ctx) {
    skFlowDetachLocked(ctx);
    SkFlowRelease(ctx); // table ref returned here
}

// Attach: new flowId -> ctx (table 1 + caller 1), linked, then associated with
// WFP. Duplicate flowId -> reuse + AddRef. Runs entirely under the
// per-callout attach gate: after SkFlowGateStopAndDrain (or an abandon after
// a failed gate acquire) no FwpsFlowAssociateContext0 for this callout is
// ever issued, so teardown never races a half-finished attach.
SK_FLOW_CTX *SkFlowAttach(UINT64 flowId, UINT32 layerId, UINT32 calloutId) {
    SK_FLOW_CTX *ctx;
    SK_FLOW_CTX *old;
    KIRQL irql;
    NTSTATUS st;

    if (flowId == 0 || !g_SkFlowInited)
        return NULL;
    if (calloutId >= SK_FLOW_MAX_GATES)
        return NULL; // no gate for this runtime id: refuse (defensive; ids are small)
    // Attach gate: FALSE = teardown in progress (or stuck) — do not touch WFP.
    if (!ShRundownAcquire(&g_SkFlowGates[calloutId])) {
        ShRuntimeRecordBlock(ShinkenBlockFlowContextDrain); // late attach after teardown began
        return NULL;
    }
    ctx = (SK_FLOW_CTX *)ShOps.AllocPool(sizeof(SK_FLOW_CTX), SK_FLOW_POOL_TAG);
    if (!ctx) {
        ShRundownRelease(&g_SkFlowGates[calloutId]);
        return NULL;
    }
    ctx->ref = 2; // table 1 + caller 1
    ctx->flowId = flowId;
    ctx->layerId = layerId;
    ctx->calloutId = calloutId;
    ctx->packetsSeen = 0;
    ctx->linked = FALSE;
    ctx->assocState = SkFlowAssocFree;

    irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
    old = skFlowFindLocked(flowId);
    if (old) {
        SkFlowAddRef(old); // +1 under lock: cannot be freed before return
        ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
        ShOps.FreePool(ctx, SK_FLOW_POOL_TAG);
        ShRundownRelease(&g_SkFlowGates[calloutId]);
        return old;
    }
    // take table ownership BEFORE the association: a concurrent
    // RemoveAll/flowDelete only ever sees a fully-formed owner
    ctx->assocState = SkFlowAssocPending;
    ctx->linked = TRUE;
    InsertTailList(&g_SkFlowList, &ctx->link);
    g_SkFlowEntries++;
    ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);

    // WFP association outside the lock: WFP may synchronously call
    // flowDeleteFn, which takes the same non-recursive spinlock.
    // Failure (any status other than exact STATUS_SUCCESS, incl. positive
    // codes) -> association does not exist.
    st = FwpsFlowAssociateContext0(flowId, skFlowWfpLayerId(layerId), calloutId,
                                   (UINT64)ctx);
    if (st != STATUS_SUCCESS) {
        BOOLEAN unlinkedHere = FALSE;
        // Attach after a concurrent RemoveAll succeeded: the entry is off
        // the table and the callout is gone; the failed associate is the
        // ONLY ownership evidence — nothing else will ever release it.
        // Return the table ref right here.
        irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
        if (!ctx->linked) {
            unlinkedHere = TRUE;
        } else {
            skFlowUnlinkLocked(ctx);
            ctx->assocState = SkFlowAssocFree;
        }
        ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
        ShRundownRelease(&g_SkFlowGates[calloutId]);
        if (unlinkedHere)
            SkFlowRelease(ctx); // table ref (RemoveAll unlinked it; nobody else will return it)
        SkFlowRelease(ctx);     // caller ref (returning NULL: nobody holds it)
        return NULL;
    }
    // Associate succeeded: publish. If a concurrent RemoveAll won the race
    // (unlinked while the associate was in flight), tear the late
    // association down immediately — WFP must not keep a flowContext
    // pointing at a context the table no longer owns.
    irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
    if (ctx->linked && ctx->assocState == SkFlowAssocPending) {
        ctx->assocState = SkFlowAssocAssociated;
        ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
        ShRundownRelease(&g_SkFlowGates[calloutId]);
        return ctx;
    }
    ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
    // RemoveAll/flowDelete already disowned the entry: WFP still holds the
    // association we just created — remove it (its result is moot; a stale
    // delete either succeeds or reports not-found) and release the caller
    // ref. The table ref was already returned at unlink, so only the
    // caller ref is ours here.
    (VOID)ShOps.FlowRemoveContext(ctx->flowId, skFlowWfpLayerId(ctx->layerId),
                                  ctx->calloutId);
    ShRundownRelease(&g_SkFlowGates[calloutId]);
    SkFlowRelease(ctx); // caller ref (table ref was returned at unlink)
    return NULL;
}

// flowDeleteFn (WFP flow-end callback, <= DISPATCH): flowContext is the ctx.
// The lock is the single unlink authority: only a linked entry is a valid
// table ref, and exactly one actor (this callback, a confirmed strip, or an
// attach rollback) unlinks it, so the table ref is returned exactly once.
VOID NTAPI SkFlowDeleteNotify(UINT16 layerId, UINT32 calloutId, UINT64 flowContext) {
    SK_FLOW_CTX *ctx = (SK_FLOW_CTX *)flowContext;
    KIRQL irql;

    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    if (ctx == NULL || !g_SkFlowInited)
        return;
    irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
    if (ctx->linked) // membership test is the explicit field, never link pointers
        skFlowUnlinkLocked(ctx);
    ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
}

// Remove all associations of one callout (root fix for FwpsCalloutUnregisterById0
// BUSY; called between bounded BUSY retries and at teardown).
// Two-phase: unlink under lock, RemoveContext outside the lock (see header).
// Returns TRUE only when every entry of this callout is confirmed removed:
//   SUCCESS     removal confirmed -> table ref returned here.
//   PENDING     async flowDelete still owed -> table ref stays with that
//               callback; entry re-linked so the callback can unlink it;
//               FALSE (strip not complete — the BUSY loop must retry, and at
//               final teardown the residual entry blocks unload).
//   UNSUCCESSFUL nothing associated, no callback owed -> table ref returned
//               here (re-linking would wait forever for a callback that can
//               never arrive).
//   other       removal state untrusted -> entry kept resident, FALSE.
BOOLEAN SkFlowRemoveAll(UINT32 calloutId) {
    LIST_ENTRY stale;
    LIST_ENTRY *e;
    KIRQL irql;
    BOOLEAN clean = TRUE;

    if (!g_SkFlowInited)
        return TRUE;
    InitializeListHead(&stale);

    // 1) under lock: move matching ASSOCIATED entries to a local list,
    //    disowning the table (membership cleared; no new associate can
    //    publish on them). Pending entries are SKIPPED: they are owned by
    //    an in-flight attach under the attach gate (teardown drains the
    //    gate first, so this is defense in depth) — stripping one would
    //    free memory the still-running associate later publishes on.
    //    Removing entries (async PENDING re-linked) are likewise owned by
    //    their promised flowDelete callback.
    irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
    e = g_SkFlowList.Flink;
    while (e != &g_SkFlowList) {
        SK_FLOW_CTX *ctx = CONTAINING_RECORD(e, SK_FLOW_CTX, link);
        LIST_ENTRY *next = e->Flink;
        if (ctx->calloutId == calloutId &&
            ctx->assocState == SkFlowAssocAssociated) {
            // Ownership of the table ref transfers to the RemoveContext
            // verdict below (returned here on SUCCESS/UNSUCCESSFUL, kept by
            // the entry while an async flowDelete is owed) — NOT returned.
            skFlowDetachLocked(ctx);
            ctx->assocState = SkFlowAssocRemoving;
            InsertTailList(&stale, &ctx->link);
        }
        e = next;
    }
    ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);

    // 2) outside the lock: RemoveContext one by one and transfer ownership
    //    per the documented result contract
    while (!IsListEmpty(&stale)) {
        SK_FLOW_CTX *ctx;
        NTSTATUS st;
        e = RemoveHeadList(&stale);
        ctx = CONTAINING_RECORD(e, SK_FLOW_CTX, link);
        ctx->link.Flink = ctx->link.Blink = NULL;
        st = ShOps.FlowRemoveContext(ctx->flowId,
                                     skFlowWfpLayerId(ctx->layerId),
                                     calloutId);
        if (st == STATUS_SUCCESS || st == STATUS_UNSUCCESSFUL) {
            // exact SUCCESS: confirmed removed (sync flowDelete, if any,
            // already ran and skipped this off-list entry); UNSUCCESSFUL:
            // nothing was associated, no callback owed — never re-link.
            ctx->assocState = SkFlowAssocFree;
            SkFlowRelease(ctx); // table ref returned here
            continue;
        }
        if (st == STATUS_PENDING) {
            // Async removal: a flowDeleteFn is still owed and owns the
            // table ref. Re-link (under the lock) so the callback's
            // membership test finds the entry and unlinks it exactly once.
            irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
            ctx->assocState = SkFlowAssocRemoving; // still awaiting the callback
            ctx->linked = TRUE;
            InsertTailList(&g_SkFlowList, &ctx->link);
            g_SkFlowEntries++;
            ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
            clean = FALSE; // strip not confirmed complete
            continue;
        }
        // Unknown error: removal state untrusted. Keep the entry resident
        // (re-linked) so nothing is freed while WFP may still hold the
        // flowContext; mark it Associated again so a later strip retries
        // the removal. The caller must keep the image alive (LEAKED /
        // UNLOAD_BLOCKED semantics via the FALSE return + residual count).
        irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
        ctx->assocState = SkFlowAssocAssociated;
        ctx->linked = TRUE;
        InsertTailList(&g_SkFlowList, &ctx->link);
        g_SkFlowEntries++;
        ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
        clean = FALSE;
    }
    return clean;
}

ULONG SkFlowCount(void) {
    ULONG n;
    KIRQL irql;
    if (!g_SkFlowInited)
        return 0;
    irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
    n = g_SkFlowEntries;
    ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
    return n;
}

ULONG SkFlowCountFor(UINT32 calloutId) {
    ULONG n = 0;
    LIST_ENTRY *e;
    KIRQL irql;
    if (!g_SkFlowInited)
        return 0;
    irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
    for (e = g_SkFlowList.Flink; e != &g_SkFlowList; e = e->Flink) {
        SK_FLOW_CTX *c = CONTAINING_RECORD(e, SK_FLOW_CTX, link);
        if (c->calloutId == calloutId)
            n++;
    }
    ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
    return n;
}

VOID SkFlowGateRearm(UINT32 calloutId) {
    if (g_SkFlowInited && calloutId < SK_FLOW_MAX_GATES)
        ShRundownInit(&g_SkFlowGates[calloutId], "flowAttachGate");
}

// WFP teardown helper: close the per-callout attach gate and wait (bounded)
// for in-flight attaches. Must run BEFORE FwpsCalloutUnregisterById0 so no
// associate can start or remain in flight while the callout is unregistered.
// FALSE = an attach failed to drain within the bound (recorded here as
// ShinkenBlockFlowContextDrain); the caller must not unregister the callout
// and must keep the image resident.
BOOLEAN SkFlowGateStopAndDrain(UINT32 calloutId, ULONG retries, ULONG delayMs) {
    if (!g_SkFlowInited || calloutId >= SK_FLOW_MAX_GATES)
        return TRUE; // table never initialized / no gate: nothing in flight
    ShRundownBeginStop(&g_SkFlowGates[calloutId]);
    if (ShRundownDrain(&g_SkFlowGates[calloutId], retries, delayMs) != STATUS_SUCCESS) {
        ShRuntimeRecordBlock(ShinkenBlockFlowContextDrain); // in-flight attach stuck: residency
        return FALSE;
    }
    return TRUE;
}

// Destroy after quiescent: all callouts unregistered (no more flowDelete) and
// all associations drained. Residual entries mean the drain invariant was
// broken; caller (runtime gate) guarantees no concurrent access here.
VOID SkFlowDestroy(void) {
    if (!g_SkFlowInited)
        return;
    if (!IsListEmpty(&g_SkFlowList)) {
        // residual = invariant broken (destroy reached without full drain);
        // diagnose and force-free: better than dangling into a freed image.
        ShOps.Diag("SkFlowDestroy: residual flow contexts");
        while (!IsListEmpty(&g_SkFlowList)) {
            LIST_ENTRY *e = g_SkFlowList.Flink;
            SK_FLOW_CTX *ctx = CONTAINING_RECORD(e, SK_FLOW_CTX, link);
            e->Flink->Blink = &g_SkFlowList;
            g_SkFlowList.Flink = e->Flink;
            g_SkFlowEntries--;
            ShOps.FreePool(ctx, SK_FLOW_POOL_TAG);
        }
    }
    g_SkFlowInited = 0;
}
