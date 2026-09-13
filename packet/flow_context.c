// ============================================================================
// packet/flow_context.c — flow context table (refcount + spinlock)
//
// Refs: table ref (held while linked; returned by flowDeleteNotify /
// SkFlowRemoveAll unlink) + caller ref (SkFlowAttach return; caller must
// SkFlowRelease). New attach: ref=2. Duplicate flowId: reuse + AddRef.
// Lock: g_SkFlowLock protects list + entry count only; never held across
// FwpsFlowRemoveContext0 (WFP may synchronously call flowDeleteFn, which
// takes the same non-recursive spinlock -> self-deadlock).
// ============================================================================
#include <ntddk.h>
#include "../runtime/sk_atomic.h"
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

// Image-static storage (rundown.h point 9: global sync structures never freed)
static LIST_ENTRY g_SkFlowList;
static EX_SPIN_LOCK g_SkFlowLock;
static ULONG g_SkFlowEntries;
static LONG g_SkFlowInited;

NTSTATUS SkFlowInit(void) {
    if (SkAtOr32(&g_SkFlowInited, 1))
        return STATUS_SUCCESS; // idempotent
    InitializeListHead(&g_SkFlowList);
    g_SkFlowLock = 0;
    g_SkFlowEntries = 0;
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

// Attach: new flowId -> ctx (table 1 + caller 1), linked, then associated with
// WFP. Associate failure -> unlink and return both refs (no orphan entry: it
// would never see flowDelete). Duplicate flowId -> reuse + AddRef.
SK_FLOW_CTX *SkFlowAttach(UINT64 flowId, UINT32 layerId, UINT32 calloutId) {
    SK_FLOW_CTX *ctx;
    SK_FLOW_CTX *old;
    KIRQL irql;
    NTSTATUS st;

    if (flowId == 0 || !g_SkFlowInited)
        return NULL;
    ctx = (SK_FLOW_CTX *)ShOps.AllocPool(sizeof(SK_FLOW_CTX), SK_FLOW_POOL_TAG);
    if (!ctx)
        return NULL;
    ctx->ref = 2; // table 1 + caller 1
    ctx->flowId = flowId;
    ctx->layerId = layerId;
    ctx->calloutId = calloutId;
    ctx->packetsSeen = 0;

    irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
    old = skFlowFindLocked(flowId);
    if (old) {
        SkFlowAddRef(old); // +1 under lock: cannot be freed before return
        ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
        ShOps.FreePool(ctx, SK_FLOW_POOL_TAG);
        return old;
    }
    InsertTailList(&g_SkFlowList, &ctx->link);
    g_SkFlowEntries++;
    ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);

    // WFP association: flowContext = ctx; WFP calls flowDeleteFn at flow end.
    // Failure (any status other than exact STATUS_SUCCESS, incl. positive
    // codes) -> roll back the link; the association does not exist.
    st = FwpsFlowAssociateContext0(flowId, skFlowWfpLayerId(layerId), calloutId,
                                   (UINT64)ctx);
    if (st != STATUS_SUCCESS) {
        BOOLEAN unlinkedHere = FALSE;
        irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
        if (ctx->link.Flink != NULL) { // a concurrent RemoveAll may have unlinked it
            ctx->link.Blink->Flink = ctx->link.Flink;
            ctx->link.Flink->Blink = ctx->link.Blink;
            ctx->link.Flink = ctx->link.Blink = NULL;
            g_SkFlowEntries--;
            unlinkedHere = TRUE;
        }
        ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
        if (unlinkedHere)
            SkFlowRelease(ctx); // table ref (if RemoveAll unlinked, it already returned it)
        SkFlowRelease(ctx);     // caller ref (returning NULL: nobody holds it)
        return NULL;
    }
    return ctx;
}

// flowDeleteFn (WFP flow-end callback, <= DISPATCH): flowContext is the ctx.
// Validates the entry is still linked (stale/double-callback defense), then
// unlinks and returns the table ref. Runs at <= DISPATCH: no waits here.
VOID NTAPI SkFlowDeleteNotify(UINT16 layerId, UINT32 calloutId, UINT64 flowContext) {
    SK_FLOW_CTX *ctx = (SK_FLOW_CTX *)flowContext;
    LIST_ENTRY *e;
    KIRQL irql;

    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    if (ctx == NULL || !g_SkFlowInited)
        return;
    irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
    for (e = g_SkFlowList.Flink; e != &g_SkFlowList; e = e->Flink) {
        if (e == &ctx->link) { // still linked => valid table ref
            ctx->link.Blink->Flink = ctx->link.Flink;
            ctx->link.Flink->Blink = ctx->link.Blink;
            ctx->link.Flink = ctx->link.Blink = NULL;
            g_SkFlowEntries--;
            SkFlowRelease(ctx);
            break;
        }
    }
    ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
}

// Remove all associations of one callout (root fix for FwpsCalloutUnregisterById0
// BUSY; called between bounded BUSY retries):
//   FlowRemoveContext == STATUS_SUCCESS -> WFP guarantees no more flowDeleteFn
//   for it -> unlink stays, table ref returned.
//   Any other status (STATUS_TIMEOUT and unknown positive codes included) ->
//   drain NOT confirmed -> re-link the entry (kept for the next BUSY retry;
//   if retries exhaust, manager records ShinkenBlockFlowContextDrain and the
//   entries stay resident with the image).
// Two-phase: unlink under lock, RemoveContext outside the lock (see header).
// Concurrency: flowDeleteNotify skips entries already off the list, so the
// table ref is returned exactly once per entry.
VOID SkFlowRemoveAll(UINT32 calloutId) {
    LIST_ENTRY stale;
    LIST_ENTRY *e;
    KIRQL irql;

    if (!g_SkFlowInited)
        return;
    InitializeListHead(&stale);

    // 1) under lock: move matching entries to a local list (table refs retained here)
    irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
    e = g_SkFlowList.Flink;
    while (e != &g_SkFlowList) {
        SK_FLOW_CTX *ctx = CONTAINING_RECORD(e, SK_FLOW_CTX, link);
        LIST_ENTRY *next = e->Flink;
        if (ctx->calloutId == calloutId) {
            RemoveEntryList(&ctx->link);
            g_SkFlowEntries--;
            InsertTailList(&stale, &ctx->link);
        }
        e = next;
    }
    ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);

    // 2) outside the lock: RemoveContext one by one (concurrent flowDeleteNotify
    //    skips off-list entries; failures are re-linked for the next BUSY retry)
    while (!IsListEmpty(&stale)) {
        SK_FLOW_CTX *ctx;
        NTSTATUS st;
        e = RemoveHeadList(&stale);
        ctx = CONTAINING_RECORD(e, SK_FLOW_CTX, link);
        ctx->link.Flink = ctx->link.Blink = NULL;
        st = ShOps.FlowRemoveContext(ctx->flowId,
                                     skFlowWfpLayerId(ctx->layerId),
                                     calloutId);
        if (st == STATUS_SUCCESS) { // exact: positive codes are not success
            SkFlowRelease(ctx); // return the table ref
        } else {
            irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
            InsertTailList(&g_SkFlowList, &ctx->link);
            g_SkFlowEntries++;
            ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
        }
    }
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
