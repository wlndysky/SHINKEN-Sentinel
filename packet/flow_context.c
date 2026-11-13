// Flow associations carry one table reference, returned by flowDeleteFn.
// Attach and explicit removal each hold an independent actor reference.
// Entries stay in the hash table until the callback unlinks them: an early
// asynchronous delete cannot be lost, and an in-flight remove never frees a
// context still visible to WFP. All WFP calls run outside the spin lock.
#include <ntddk.h>
#include "../runtime/sk_atomic.h"
#include "../runtime/runtime.h" // ShRuntimeRecordBlock (attach-gate abandon)
#include "flow_context.h"
#include "../wfp/wfp_callouts.h"

#define SK_FLOW_POOL_TAG 0x78746366u /* 'fctx' pool tag */

// CONTAINING_RECORD: real WDK provides it via wdm.h; the shim does not.
#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(addr, type, field) \
    ((type *)((char *)(addr) - (size_t)&((type *)0)->field))
#endif

// WFP runtime layer ids for FwpsFlowAssociateContext0 /
// FwpsFlowRemoveContext0 (NOT the FWPM_* management GUIDs). Real WDK:
// fwpsk.h enum constants (forced-include chain, wdk/shinken_wfp.props).
// Shim build has no fwpsk.h: define the documented values here and only
// here (V4=52, V6=54).
#ifdef SHINKEN_HOST_SHIM
#ifndef FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4
#define FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4 ((UINT16)52)
#define FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6 ((UINT16)54)
#endif
#endif

// Internal layer id -> WFP runtime layer id; 0 = not a flow layer.
static UINT16 skFlowWfpLayerId(UINT32 layerId) {
    if (layerId == SkLayerFlowEstablishedV4)
        return (UINT16)FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4;
    if (layerId == SkLayerFlowEstablishedV6)
        return (UINT16)FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6;
    return 0;
}

// Fixed hash table: power-of-two bucket count, key
// (flowId, layerId, calloutId). The attach path walks exactly one bucket.
#define SK_FLOW_BUCKETS 1024u
#define SK_FLOW_BUCKET_LIMIT 256u // bound lookup/teardown work while holding the lock

// Per-layer attach gate + the layer's live callout runtime id (recorded at
// SkFlowGateRearm). Index: INTERNAL layer id (fixed SK_LAYER_COUNT);
// runtime callout ids are WFP-assigned numbers and never index arrays.
typedef struct _SK_FLOW_LAYER {
    SHINKEN_RUNDOWN gate;
    volatile LONG calloutId; // 0 = no live registration recorded
} SK_FLOW_LAYER;
static SK_FLOW_LAYER g_SkFlowLayers[SK_LAYER_COUNT];

// Image-static storage (rundown.h point 9: global sync structures never freed)
static LIST_ENTRY g_SkFlowBuckets[SK_FLOW_BUCKETS];
static EX_SPIN_LOCK g_SkFlowLock;
static ULONG g_SkFlowEntries;
static ULONG g_SkFlowBucketEntries[SK_FLOW_BUCKETS];
static LONG g_SkFlowInited;


NTSTATUS SkFlowInit(void) {
    UINT32 i;
    if (SkAtOr32(&g_SkFlowInited, 1))
        return STATUS_SUCCESS; // idempotent
    for (i = 0; i < SK_FLOW_BUCKETS; i++)
        InitializeListHead(&g_SkFlowBuckets[i]);
    g_SkFlowLock = 0;
    g_SkFlowEntries = 0;
    RtlZeroMemory(g_SkFlowBucketEntries, sizeof(g_SkFlowBucketEntries));
    for (i = 0; i < SK_LAYER_COUNT; i++) {
        g_SkFlowLayers[i].calloutId = 0;
        ShRundownInit(&g_SkFlowLayers[i].gate, "flowAttachGate");
    }
    return STATUS_SUCCESS;
}

VOID SkFlowAddRef(SK_FLOW_CTX *ctx) {
    SkAtAdd32(&ctx->ref, 1);
}

VOID SkFlowRelease(SK_FLOW_CTX *ctx) {
    if (SkAtSub32(&ctx->ref, 1) == 1)
        ShOps.FreePool(ctx, SK_FLOW_POOL_TAG); // zero: non-paged free (legal in-lock)
}

// Key hash -> bucket index (fixed table; multiplicative mix)
static ULONG skFlowBucketOf(UINT64 flowId, UINT32 layerId, UINT32 calloutId) {
    UINT64 h = flowId;
    h ^= (UINT64)layerId * 0x9E3779B97F4A7C15ull;
    h ^= (UINT64)calloutId * 0xC2B2AE3D27D4EB4Full;
    h ^= h >> 29;
    h *= 0xBF58476D1CE4E5B9ull;
    h ^= h >> 32;
    return (ULONG)(h & (UINT64)(SK_FLOW_BUCKETS - 1));
}

// Find by full key, caller holds the lock
static SK_FLOW_CTX *skFlowFindLocked(UINT64 flowId, UINT32 layerId, UINT32 calloutId) {
    LIST_ENTRY *head = &g_SkFlowBuckets[skFlowBucketOf(flowId, layerId, calloutId)];
    LIST_ENTRY *e;
    for (e = head->Flink; e != head; e = e->Flink) {
        SK_FLOW_CTX *c = CONTAINING_RECORD(e, SK_FLOW_CTX, link);
        if (c->flowId == flowId && c->layerId == layerId && c->calloutId == calloutId)
            return c;
    }
    return NULL;
}

// Remove global membership under the lock. The table reference belongs to
// flowDeleteFn after a successful associate; failed associate owns rollback.
static VOID skFlowDetachLocked(SK_FLOW_CTX *ctx) {
    ctx->linked = FALSE; // ordering: membership cleared before detach
    ctx->link.Blink->Flink = ctx->link.Flink;
    ctx->link.Flink->Blink = ctx->link.Blink;
    ctx->link.Flink = ctx->link.Blink = NULL;
    g_SkFlowEntries--;
    g_SkFlowBucketEntries[skFlowBucketOf(ctx->flowId, ctx->layerId, ctx->calloutId)]--;
}
static VOID skFlowUnlinkLocked(SK_FLOW_CTX *ctx) {
    skFlowDetachLocked(ctx);
    SkFlowRelease(ctx); // table ref returned here
}


// Attach: new key -> ctx (table 1 + caller 1), linked, then associated with
// WFP. Duplicate key -> reuse + AddRef, no allocation on that path. Runs
// entirely under the layer's attach gate with the runtime id validated
// against the recorded registration: after SkFlowGateStopAndDrain (or a
// gate-abandon / id mismatch) no FwpsFlowAssociateContext0 of a retired
// registration is ever issued, so teardown never races a half-finished
// attach.
SK_FLOW_CTX *SkFlowAttach(UINT64 flowId, UINT32 layerId, UINT32 calloutId) {
    SK_FLOW_LAYER *gateLayer;
    SK_FLOW_CTX *ctx;
    SK_FLOW_CTX *old;
    KIRQL irql;
    NTSTATUS st;

    if (flowId == 0 || !g_SkFlowInited)
        return NULL;
    if (layerId >= SK_LAYER_COUNT || skFlowWfpLayerId(layerId) == 0)
        return NULL;
    gateLayer = &g_SkFlowLayers[layerId];
    // Attach gate: FALSE = teardown in progress (or stuck) — do not touch WFP.
    if (!ShRundownAcquire(&gateLayer->gate))
        return NULL; // a late classify during shutdown is expected, not a drain failure
    // Runtime id must match the live registration recorded at re-arm: a
    // classify racing a fresh re-registration (new id) must not attach on
    // the retired incarnation. (A BFE pause keeps the id: attaches stay
    // valid while the runtime registration exists.)
    if (calloutId == 0 || (UINT32)gateLayer->calloutId != calloutId) {
        ShRundownRelease(&gateLayer->gate);
        return NULL;
    }

    // Duplicate check first, under the lock, WITHOUT allocating.
    irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
    ctx = skFlowFindLocked(flowId, layerId, calloutId);
    if (ctx) {
        SkFlowAddRef(ctx); // +1 under lock: cannot be freed before return
        ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
        ShRundownRelease(&gateLayer->gate);
        return ctx;
    }
    if (g_SkFlowBucketEntries[skFlowBucketOf(flowId, layerId, calloutId)] >=
        SK_FLOW_BUCKET_LIMIT) {
        ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
        ShRundownRelease(&gateLayer->gate);
        return NULL;
    }
    ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);

    ctx = (SK_FLOW_CTX *)ShOps.AllocPool(sizeof(SK_FLOW_CTX), SK_FLOW_POOL_TAG);
    if (!ctx) {
        ShRundownRelease(&gateLayer->gate);
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
    // Re-check: a duplicate may have been inserted while the lock was
    // dropped for the allocation.
    old = skFlowFindLocked(flowId, layerId, calloutId);
    if (old) {
        SkFlowAddRef(old);
        ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
        ShOps.FreePool(ctx, SK_FLOW_POOL_TAG);
        ShRundownRelease(&gateLayer->gate);
        return old;
    }
    if (g_SkFlowBucketEntries[skFlowBucketOf(flowId, layerId, calloutId)] >=
        SK_FLOW_BUCKET_LIMIT) {
        ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
        ShOps.FreePool(ctx, SK_FLOW_POOL_TAG);
        ShRundownRelease(&gateLayer->gate);
        return NULL;
    }
    // take table ownership BEFORE the association: a concurrent
    // RemoveAll/flowDelete only ever sees a fully-formed owner
    ctx->assocState = SkFlowAssocPending;
    ctx->linked = TRUE;
    InsertTailList(&g_SkFlowBuckets[skFlowBucketOf(flowId, layerId, calloutId)],
                   &ctx->link);
    g_SkFlowEntries++;
    g_SkFlowBucketEntries[skFlowBucketOf(flowId, layerId, calloutId)]++;
    ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);

    // WFP association outside the lock: WFP may synchronously call
    // flowDeleteFn, which takes the same non-recursive spinlock.
    // Failure (any status other than exact STATUS_SUCCESS, incl. positive
    // codes) -> association does not exist.
    st = FwpsFlowAssociateContext0(flowId, skFlowWfpLayerId(layerId), calloutId,
                                   (UINT64)ctx);
    if (st != STATUS_SUCCESS) {
        irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
        if (ctx->linked)
            skFlowUnlinkLocked(ctx);
        ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
        ShRundownRelease(&gateLayer->gate);
        SkFlowRelease(ctx);     // caller ref (returning NULL: nobody holds it)
        return NULL;
    }
    // A natural flow deletion may have already consumed the table reference.
    // The attach actor still keeps ctx alive until the caller ref is returned.
    irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
    if (ctx->linked && ctx->assocState == SkFlowAssocPending) {
        ctx->assocState = SkFlowAssocAssociated;
        ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
        ShRundownRelease(&gateLayer->gate);
        return ctx;
    }
    ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
    ShRundownRelease(&gateLayer->gate);
    SkFlowRelease(ctx); // caller ref (table ref was returned at unlink)
    return NULL;
}

// The callback is the sole owner of a successfully associated table ref.
VOID NTAPI SkFlowDeleteNotify(UINT16 layerId, UINT32 calloutId, UINT64 flowContext) {
    SK_FLOW_CTX *ctx = (SK_FLOW_CTX *)flowContext;
    KIRQL irql;

    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    if (ctx == NULL || !g_SkFlowInited)
        return;
    irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
    if (ctx->linked)
        skFlowUnlinkLocked(ctx);
    ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
}

// PASSIVE_LEVEL, serialized by the manager, after this callout's attach gate
// has drained. Each bucket walk is bounded; the callback may remove table
// membership at any time because a separate removal reference pins ctx.
BOOLEAN SkFlowRemoveAll(UINT32 calloutId) {
    ULONG b;
    BOOLEAN clean = TRUE;
    if (!g_SkFlowInited)
        return TRUE;
    for (b = 0; b < SK_FLOW_BUCKETS; b++) {
        LIST_ENTRY pending;
        LIST_ENTRY *e;
        KIRQL irql;
        InitializeListHead(&pending);
        irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
        for (e = g_SkFlowBuckets[b].Flink; e != &g_SkFlowBuckets[b]; e = e->Flink) {
            SK_FLOW_CTX *ctx = CONTAINING_RECORD(e, SK_FLOW_CTX, link);
            if (ctx->calloutId != calloutId)
                continue;
            if (ctx->assocState != SkFlowAssocAssociated) {
                clean = FALSE;
                continue;
            }
            SkFlowAddRef(ctx);
            ctx->assocState = SkFlowAssocRemoving;
            InsertTailList(&pending, &ctx->removeLink);
        }
        ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
        while (!IsListEmpty(&pending)) {
            SK_FLOW_CTX *ctx;
            NTSTATUS st;
            e = RemoveHeadList(&pending);
            ctx = CONTAINING_RECORD(e, SK_FLOW_CTX, removeLink);
            st = ShOps.FlowRemoveContext(ctx->flowId,
                                         skFlowWfpLayerId(ctx->layerId), calloutId);
            irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
            if (ctx->linked) {
                clean = FALSE;
                // PENDING promises a callback. UNSUCCESSFUL can race a
                // natural flow deletion: only that callback releases the
                // association ref, never a not-found observation alone.
                if (st != STATUS_PENDING && st != STATUS_UNSUCCESSFUL)
                    ctx->assocState = SkFlowAssocAssociated; // retry unconfirmed removal
            }
            ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
            SkFlowRelease(ctx); // remove actor only; never the callback's ref
        }
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
    ULONG b;
    KIRQL irql;
    if (!g_SkFlowInited)
        return 0;
    for (b = 0; b < SK_FLOW_BUCKETS; b++) {
        irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
        for (e = g_SkFlowBuckets[b].Flink; e != &g_SkFlowBuckets[b]; e = e->Flink) {
            SK_FLOW_CTX *c = CONTAINING_RECORD(e, SK_FLOW_CTX, link);
            if (c->calloutId == calloutId)
                n++;
        }
        ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
    }
    return n;
}

// Re-arm a layer's attach gate for a fresh callout runtime registration
// (fresh FwpsCalloutRegister1 only — a BFE pause/resume cycle never
// re-arms: the runtime registration and the recorded id stay valid).
// Precondition: the previous incarnation of this layer's registration was
// drained (SkFlowGateStopAndDrain) or never existed. Defense: in-flight
// attaches still holding the gate => a re-init would corrupt the rundown
// count; refuse (the old gate state stays authoritative) and diagnose.
VOID SkFlowGateRearm(UINT32 layerId, UINT32 calloutId) {
    SK_FLOW_LAYER *g;
    if (!g_SkFlowInited || layerId >= SK_LAYER_COUNT || calloutId == 0)
        return;
    g = &g_SkFlowLayers[layerId];
    if (ShRundownActiveCount(&g->gate) > 0) {
        ShOps.Diag("SkFlowGateRearm: attach gate still held; re-arm refused");
        return;
    }
    // Publish the id BEFORE the gate can accept attaches: every successful
    // Acquire after the re-init observes the new id.
    g->calloutId = (LONG)calloutId;
    ShRundownInit(&g->gate, "flowAttachGate"); // stopped+drained -> re-opened
}

// WFP teardown helper: close the layer's attach gate and wait (bounded) for
// in-flight attaches. Must run BEFORE FwpsCalloutUnregisterById0 so no
// associate can start or remain in flight while the callout is unregistered.
// The gate stays closed until a fresh registration re-arms it
// (SkFlowGateRearm); a BFE pause (session close without unregister) never
// closes it. FALSE = an attach failed to drain within the bound (recorded
// here as ShinkenBlockFlowContextDrain); the caller must not unregister the
// callout and must keep the image resident.
BOOLEAN SkFlowGateStopAndDrain(UINT32 layerId, ULONG retries, ULONG delayMs) {
    if (!g_SkFlowInited || layerId >= SK_LAYER_COUNT)
        return TRUE; // no gate for this layer: no attach of it can be in flight
    ShRundownBeginStop(&g_SkFlowLayers[layerId].gate);
    if (ShRundownDrain(&g_SkFlowLayers[layerId].gate, retries, delayMs) != STATUS_SUCCESS) {
        ShRuntimeRecordBlock(ShinkenBlockFlowContextDrain); // in-flight attach stuck: residency
        return FALSE;
    }
    return TRUE;
}

// Destroy after quiescent: all callouts unregistered (no more flowDelete)
// and all associations drained. TRUE = table empty: quiescence proven, the
// init state is cleared. FALSE = residual entries: the drain invariant was
// broken — the reason is recorded and every entry stays linked and resident
// with the image; NOTHING is force-freed, because a context WFP may still
// reference must never be freed on unproven quiescence (the caller must
// block unload). Caller (runtime gate) guarantees no concurrent access here.
BOOLEAN SkFlowDestroy(void) {
    KIRQL irql;
    ULONG residual;
    if (!g_SkFlowInited)
        return TRUE;
    irql = ShOps.LockAcquireExclusive(&g_SkFlowLock);
    residual = g_SkFlowEntries;
    if (residual == 0)
        g_SkFlowInited = 0; // quiescent: no callback or attach can arrive anymore
    ShOps.LockReleaseExclusive(&g_SkFlowLock, irql);
    if (residual != 0) {
        ShOps.Diag("SkFlowDestroy: residual flow contexts; entries kept resident");
        ShRuntimeRecordBlock(ShinkenBlockFlowContextDrain);
        return FALSE;
    }
    return TRUE;
}
