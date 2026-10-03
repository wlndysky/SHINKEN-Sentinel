// ============================================================================
// wfp/wfp_manager.c — WFP manager (contract and ordering in wfp_manager.h)
//
// Install: installMutex (PASSIVE mutex) -> FwpmEngineOpen0 (DYNAMIC
// session) -> engine transaction Begin -> provider add -> sublayer add ->
// per-layer register/add/filter add -> Commit. Any failure: Abort
// (return value checked: an unconfirmed abort is itself recorded) +
// reverse-phase rollback. Rollback deletes every REGISTERED/ACTIVE
// object and, for callouts, every runtime registration still on the
// books (calloutRuntimeId != 0 — a failed FwpmCalloutAdd0 does NOT erase
// the FwpsCalloutRegister1 fact); flow contexts are stripped with the
// same busyCleanup as normal teardown (a FALSE strip parks the object as
// LEAKED instead of retrying a BUSY that must fail). Unknown rollback
// error => object LEAKED + block reason recorded; failure is returned
// and the caller parks.
//
// Teardown (idempotent): per callout: attach gate Stop+Drain (no new
// FwpsFlowAssociateContext0, in-flight attaches settled) -> strip and
// settle flow contexts BEFORE the unregister safe point (the unregister
// contract forfeits flowDeleteFn; PENDING removals are awaited bounded,
// unknown errors retried; a layer that will not settle keeps its callout
// registered and parks with ShinkenBlockFlowContextDrain) -> per-layer
// unregister (busyCleanup still strips between BUSY retries) -> delete
// filter/callout -> delete sublayer/provider -> close engine. Any
// LEAKED/failure => ShRuntimeRecordBlock + FALSE (caller parks).
// ============================================================================
#include <ntddk.h>
#include "wfp_manager.h"
#include "wfp_guids.h" // g_SkProviderKey/g_SkSubLayerKey single definition (test GUIDs)
#include "../runtime/sk_atomic.h" // SkAtOr32 (one-time mutex init flag)
#include "../packet/flow_context.h"

#define SK_WFP_BUSY_RETRIES    8  // bounded BUSY retry limit for callout unregister
#define SK_WFP_RETRY_DELAY_MS  10
#ifndef FWPM_SESSION_FLAG_DYNAMIC
#define FWPM_SESSION_FLAG_DYNAMIC 0x00000001u // session objects reclaimed on handle close
#endif

SK_WFP_MANAGER g_WfpManager;

// IRQL contract: all WFP calls and BUSY-retry sleeps in this file
// require PASSIVE_LEVEL; a spin lock would raise IRQL to DISPATCH_LEVEL
// and break FwpmEngineOpen0, so the install-path mutex must be a KMUTEX.
static LONG g_WfpMutexReady; // BSS 0: not yet initialized
VOID SkWfpManagerInitMutex(void) {
    if (SkAtOr32(&g_WfpMutexReady, 1) == 0)
        KeInitializeMutex(&g_WfpManager.installMutex, 0);
}
static VOID skWfpLock(void) {
    (VOID)KeWaitForSingleObject(&g_WfpManager.installMutex, Executive,
                                KernelMode, FALSE, NULL);
}
static VOID skWfpUnlock(void) {
    (VOID)KeReleaseMutex(&g_WfpManager.installMutex, FALSE);
}

// Pre-unregister flow strip for one layer (teardown and rollback). Runs
// AFTER the attach gate drain, BEFORE FwpsCalloutUnregisterById0: the
// unregister contract forfeits flowDeleteFn, so every context of this
// callout must be confirmed removed now — SUCCESS/UNSUCCESSFUL return
// their ref immediately, PENDING keeps it only until the promised async
// flowDelete (waited for here, bounded), unknown errors are retried by
// re-stripping. FALSE = contexts remain (PENDING not settled / strip
// untrusted): the caller must NOT unregister the callout (it stays
// registered so the promised callbacks can still fire) and must park.
static BOOLEAN skWfpStripCalloutFlows(UINT32 layerId) {
    UINT32 rtId = g_WfpManager.callouts[layerId].calloutRuntimeId;
    ULONG attempt;

    if (rtId == 0)
        return TRUE; // never registered: no flows possible
    (VOID)SkFlowRemoveAll(rtId);
    for (attempt = 0;; attempt++) {
        if (SkFlowCountFor(rtId) == 0)
            return TRUE;
        if (attempt >= SK_WFP_BUSY_RETRIES) {
            ShRuntimeRecordBlock(ShinkenBlockFlowContextDrain);
            return FALSE;
        }
        ShOps.SleepMs(SK_WFP_RETRY_DELAY_MS);
        (VOID)SkFlowRemoveAll(rtId); // retry unknown-error strips
    }
}

// Between BUSY retries: strip all flow contexts of this callout (BUSY
// root-cause handling). ctx = internal layer id (passed by teardown).
// TRUE only when the strip is confirmed complete AND the table is empty;
// FALSE keeps the caller in the BUSY loop / parks it as LEAKED, and a
// residual flow count additionally records ShinkenBlockFlowContextDrain
// (unload must stay blocked while any context remains associated).
static BOOLEAN skWfpBusyCleanup(PVOID ctx) {
    UINT32 layerId = (UINT32)(UINT64)ctx;
    BOOLEAN clean;
    if (layerId >= SK_LAYER_COUNT)
        return TRUE; // nothing addressable: no strip evidence needed
    clean = SkFlowRemoveAll(g_WfpManager.callouts[layerId].calloutRuntimeId);
    if (SkFlowCount() != 0) {
        ShRuntimeRecordBlock(ShinkenBlockFlowContextDrain);
        return FALSE; // residual contexts: drain unconfirmed
    }
    return clean;
}

// Delete a by-key engine object (sublayer/provider) and classify the
// error: SUCCESS / documented NOT_FOUND => DELETED; anything else =>
// LEAKED. Returns whether removal was confirmed.
static BOOLEAN skWfpDeleteByKey(SK_WFP_OBJECT *o, HANDLE engine, BOOLEAN isSubLayer) {
    NTSTATUS st;
    NTSTATUS notFound = isSubLayer ? FWP_E_SUBLAYER_NOT_FOUND : FWP_E_PROVIDER_NOT_FOUND;

    if (o->state != SkWfpStateRegistered && o->state != SkWfpStateActive)
        return TRUE; // not installed: nothing to do
    if (isSubLayer)
        st = ShOps.SubLayerDeleteByKey(engine, &g_SkSubLayerKey);
    else
        st = ShOps.ProviderDeleteByKey(engine, &g_SkProviderKey);
    o->lastStatus = st;
    if (st == STATUS_SUCCESS || st == notFound) {
        o->state = SkWfpStateDeleted;
        return TRUE;
    }
    o->state = SkWfpStateLeaked; // unknown error: removal state untrusted
    return FALSE;
}

// Reverse-order rollback (install failure path): delete every object that
// is still on the books — per layer filter -> callout (runtime unregister
// + mgmt delete) -> sublayer -> provider -> close engine. Rollback is
// judged by the id facts, not by state alone: a failed FwpmCalloutAdd0
// leaves the runtime registration (calloutRuntimeId != 0) held, and it
// must be unregistered exactly once. Flow stripping uses the same
// busyCleanup as normal teardown: an unconfirmed strip parks the callout
// as LEAKED instead of retrying a BUSY that must fail.
// Returns TRUE = all confirmed removed; FALSE = some LEAKED (caller parks).
static BOOLEAN skWfpRollbackLocked(void) {
    BOOLEAN clean = TRUE;
    UINT32 i;

    for (i = SK_LAYER_COUNT; i-- > 0;) {
        SK_WFP_OBJECT *co = &g_WfpManager.callouts[i];
        SK_WFP_OBJECT *fi = &g_WfpManager.filters[i];

        if (fi->state == SkWfpStateRegistered || fi->state == SkWfpStateActive) {
            SkWfpObjectDelete(fi, g_WfpManager.engine);
            if (fi->state == SkWfpStateLeaked)
                clean = FALSE;
        }
        // unregister whenever a runtime registration exists, regardless of
        // state: AddCallout/AddFilter failure after a successful register
        // keeps calloutRuntimeId set with state REGISTERED (never Failed-only).
        // Same protocol as teardown: attach gate first, then strip + settle
        // flow contexts, then the unregister safe point. A gate that fails
        // to drain or a strip that will not settle keeps the callout
        // REGISTERED and parks (clean = FALSE) rather than unregistering
        // under a live callback surface.
        if (co->state == SkWfpStateRegistered || co->state == SkWfpStateActive ||
            co->calloutRuntimeId != 0) {
            BOOLEAN mayUnregister = TRUE;
            if (co->calloutRuntimeId != 0 &&
                !SkFlowGateStopAndDrain(co->calloutRuntimeId, SK_WFP_BUSY_RETRIES,
                                        SK_WFP_RETRY_DELAY_MS)) {
                ShRuntimeRecordBlock(ShinkenBlockFlowContextDrain);
                mayUnregister = FALSE;
                clean = FALSE;
            }
            if (mayUnregister && !skWfpStripCalloutFlows(i)) {
                mayUnregister = FALSE;
                clean = FALSE;
            }
            if (mayUnregister) {
                // kernel-side registration is outside the engine transaction; explicit unregister required
                SkWfpObjectUnregister(co, (PVOID)(UINT64)i, skWfpBusyCleanup,
                                      SK_WFP_BUSY_RETRIES, SK_WFP_RETRY_DELAY_MS);
            }
            if (co->state == SkWfpStateLeaked) {
                clean = FALSE;
            } else if (mayUnregister && co->calloutId != 0) {
                SkWfpObjectDelete(co, g_WfpManager.engine);
                if (co->state == SkWfpStateLeaked)
                    clean = FALSE;
            }
        }
    }
    if (!skWfpDeleteByKey(&g_WfpManager.sublayer, g_WfpManager.engine, TRUE))
        clean = FALSE;
    if (!skWfpDeleteByKey(&g_WfpManager.provider, g_WfpManager.engine, FALSE))
        clean = FALSE;
    if (g_WfpManager.engine != NULL) {
        NTSTATUS st = ShOps.EngineClose(g_WfpManager.engine);
        g_WfpManager.engineObj.lastStatus = st;
        if (st == STATUS_SUCCESS) {
            // FwpmEngineClose0 has no documented "not-found" form: only SUCCESS confirms close
            g_WfpManager.engineObj.state = SkWfpStateDeleted;
            g_WfpManager.engine = NULL;
        } else {
            g_WfpManager.engineObj.state = SkWfpStateLeaked;
            clean = FALSE;
        }
    }
    return clean;
}

NTSTATUS SkWfpManagerInstall(PDEVICE_OBJECT device) {
    FWPM_SESSION0 session;
    NTSTATUS st;
    NTSTATUS stFail = STATUS_UNSUCCESSFUL;
    UINT32 i;
    BOOLEAN txnBegun = FALSE;
    BOOLEAN clean = FALSE; // abort-unconfirmed flag (OR-ed into the rollback verdict)

    skWfpLock();
    if (g_WfpManager.installed) {
        skWfpUnlock();
        return STATUS_SUCCESS; // idempotent
    }
    // LEAKED guard (a BFE callback may re-run Install): a LEAKED object's
    // engine-side identity is still registered but untrusted; Reset would
    // orphan it (double registration/leak), so refuse reinstall and keep
    // tracking. The caller keeps its deferred retry.
    if (g_WfpManager.engineObj.state == SkWfpStateLeaked ||
        g_WfpManager.provider.state == SkWfpStateLeaked ||
        g_WfpManager.sublayer.state == SkWfpStateLeaked) {
        skWfpUnlock();
        return STATUS_DEVICE_BUSY;
    }
    for (i = 0; i < SK_LAYER_COUNT; i++) {
        if (g_WfpManager.callouts[i].state == SkWfpStateLeaked ||
            g_WfpManager.filters[i].state == SkWfpStateLeaked) {
            skWfpUnlock();
            return STATUS_DEVICE_BUSY;
        }
    }


    SkWfpObjectReset(&g_WfpManager.engineObj, "wfpEngine");
    SkWfpObjectReset(&g_WfpManager.provider, "wfpProvider");
    SkWfpObjectReset(&g_WfpManager.sublayer, "wfpSublayer");
    for (i = 0; i < SK_LAYER_COUNT; i++) {
        SkWfpObjectReset(&g_WfpManager.callouts[i], g_SkCalloutDefs[i].name);
        SkWfpObjectReset(&g_WfpManager.filters[i], g_SkCalloutDefs[i].name);
        g_WfpManager.callouts[i].key = *g_SkCalloutDefs[i].calloutKey;
    }
    g_WfpManager.engine = NULL;

    // Engine (DYNAMIC session: objects are reclaimed on handle close, but
    // teardown still deletes explicitly — only explicit deletion gives
    // confirmed-removal evidence).
    RtlZeroMemory(&session, sizeof(session));
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    g_WfpManager.engineObj.phase = SkWfpPhaseEngineOpen;
    st = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_WfpManager.engine);
    g_WfpManager.engineObj.lastStatus = st;
    if (!NT_SUCCESS(st)) {
        g_WfpManager.engineObj.state = SkWfpStateFailed;
        g_WfpManager.engine = NULL;
        stFail = st;
        goto out;
    }
    g_WfpManager.engineObj.state = SkWfpStateRegistered;

    st = FwpmTransactionBegin0(g_WfpManager.engine, 0);
    if (!NT_SUCCESS(st)) {
        stFail = st;
        goto rollback;
    }
    txnBegun = TRUE;

    // provider
    {
        FWPM_PROVIDER0 prov;
        RtlZeroMemory(&prov, sizeof(prov));
        // BFE requires displayData.name to be non-empty
        // (STATUS_FWP_NULL_DISPLAY_NAME otherwise).
        prov.displayData.name = SK_WFP_PROVIDER_NAME_W;
        prov.providerKey = g_SkProviderKey;
        g_WfpManager.provider.phase = SkWfpPhaseProviderAdd;
        g_WfpManager.provider.key = g_SkProviderKey;
        st = FwpmProviderAdd0(g_WfpManager.engine, &prov, NULL);
        g_WfpManager.provider.lastStatus = st;
        if (!NT_SUCCESS(st)) {
            g_WfpManager.provider.state = SkWfpStateFailed;
            stFail = st;
            goto rollback;
        }
        g_WfpManager.provider.state = SkWfpStateRegistered;
    }
    // sublayer (own sublayer weighted above the UNIVERSAL default)
    {
        FWPM_SUBLAYER0 sub;
        RtlZeroMemory(&sub, sizeof(sub));
        sub.displayData.name = SK_WFP_SUBLAYER_NAME_W;
        sub.subLayerKey = g_SkSubLayerKey;
        sub.providerKey = (GUID *)&g_SkProviderKey;
        sub.weight = 0x100;
        g_WfpManager.sublayer.phase = SkWfpPhaseSubLayerAdd;
        g_WfpManager.sublayer.key = g_SkSubLayerKey;
        st = FwpmSubLayerAdd0(g_WfpManager.engine, &sub, NULL);
        g_WfpManager.sublayer.lastStatus = st;
        if (!NT_SUCCESS(st)) {
            g_WfpManager.sublayer.state = SkWfpStateFailed;
            stFail = st;
            goto rollback;
        }
        g_WfpManager.sublayer.state = SkWfpStateRegistered;
    }
    // per layer: register (kernel-side, outside txn) -> add (engine) -> filter (activate)
    for (i = 0; i < SK_LAYER_COUNT; i++) {
        const SK_CALLOUT_DEF *def = &g_SkCalloutDefs[i];
        SK_WFP_OBJECT *co = &g_WfpManager.callouts[i];
        SK_WFP_OBJECT *fi = &g_WfpManager.filters[i];
        FWPS_CALLOUT1 c1;

        RtlZeroMemory(&c1, sizeof(c1));
        c1.calloutKey = *def->calloutKey;
        // Typed end to end (SK_CALLOUT_DEF fields already carry the exact
        // fwpsk.h signatures): no casts on the registration path.
        c1.classifyFn = def->classifyFn;
        c1.notifyFn = def->notifyFn;
        c1.flowDeleteFn = def->flowDeleteFn;

        st = SkWfpObjectRegisterCallout(co, device, &c1);
        if (!NT_SUCCESS(st)) {
            stFail = st;
            goto rollback;
        }
        // the runtime id is fresh (or recycled): re-arm this callout's
        // flow-attach gate so SkFlowAttach accepts new associations
        SkFlowGateRearm(co->calloutRuntimeId);
        st = SkWfpObjectAddCallout(co, g_WfpManager.engine);
        if (!NT_SUCCESS(st)) {
            stFail = st;
            goto rollback;
        }
        st = SkWfpObjectAddFilter(fi, g_WfpManager.engine, def->layerKey, def->layerId);
        if (!NT_SUCCESS(st)) {
            stFail = st;
            goto rollback;
        }
        co->state = SkWfpStateActive; // filter attached: callout now producing callbacks
    }

    st = FwpmTransactionCommit0(g_WfpManager.engine);
    if (!NT_SUCCESS(st)) {
        stFail = st;
        goto rollback;
    }
    g_WfpManager.installed = TRUE;
    skWfpUnlock();
    return STATUS_SUCCESS;

rollback:
    if (txnBegun) {
        // Abort's return value is checked: an unconfirmed abort leaves the
        // transaction state untrusted, which is itself a rollback failure
        // (objects may or may not exist). The id-based delete paths treat
        // documented NOT_FOUND as confirmed-removed, so rollback still
        // proceeds; only the overall clean verdict is affected.
        NTSTATUS stAbort = FwpmTransactionAbort0(g_WfpManager.engine);
        if (stAbort != STATUS_SUCCESS) {
            ShRuntimeRecordBlock(ShinkenBlockEngineClose);
            g_WfpManager.engineObj.lastStatus = stAbort;
            clean = FALSE; // skWfpRollbackLocked's own verdict is OR-ed below
        }
    }
    if (!skWfpRollbackLocked() || !clean) {
        // Rollback itself failed (LEAKED): record the reason; the caller
        // (runtime/lifecycle.c) parks instead of allowing unload.
        ShRuntimeRecordBlock(ShinkenBlockEngineClose);
    }
out:
    skWfpUnlock();
    return stFail;
}

BOOLEAN SkWfpManagerTeardown(void) {
    UINT32 i;
    BOOLEAN ok = TRUE;

    skWfpLock();
    if (!g_WfpManager.installed && g_WfpManager.engine == NULL) {
        skWfpUnlock();
        return TRUE; // idempotent: not installed or already torn down
    }

    // 1) per-callout attach gate first: close the gate (no new
    // FwpsFlowAssociateContext0 can start) and drain in-flight attaches
    // BEFORE the unregister safe point. An undrained attach means the
    // callout must NOT be unregistered (a late associate would race the
    // disappearing callout): record the block, mark the teardown failed
    // (engine handle retained) and skip that layer's unregister.
    {
        BOOLEAN gateOk[SK_LAYER_COUNT];
        for (i = 0; i < SK_LAYER_COUNT; i++) {
            UINT32 rtId = g_WfpManager.callouts[i].calloutRuntimeId;
            gateOk[i] = TRUE;
            if (rtId != 0 &&
                !SkFlowGateStopAndDrain(rtId, SK_WFP_BUSY_RETRIES, SK_WFP_RETRY_DELAY_MS)) {
                ShRuntimeRecordBlock(ShinkenBlockFlowContextDrain);
                gateOk[i] = FALSE;
                ok = FALSE;
            }
        }
        // 2) per-layer: strip + settle flow contexts BEFORE the unregister
        // safe point (the unregister contract forfeits flowDeleteFn), then
        // unregister (documented safe point; busyCleanup still strips
        // between BUSY retries as a backstop)
        for (i = 0; i < SK_LAYER_COUNT; i++) {
            SK_WFP_OBJECT *co = &g_WfpManager.callouts[i];
            if (!gateOk[i])
                continue; // attach gate undrained: unregister unsafe for this layer
            if (co->state == SkWfpStateActive || co->state == SkWfpStateRegistered) {
                if (!skWfpStripCalloutFlows(i)) {
                    ok = FALSE; // flows remain: callout kept registered (park)
                    continue;
                }
                SkWfpObjectUnregister(co, (PVOID)(UINT64)i, skWfpBusyCleanup,
                                      SK_WFP_BUSY_RETRIES, SK_WFP_RETRY_DELAY_MS);
                if (co->state == SkWfpStateLeaked) {
                    ShRuntimeRecordBlock(ShinkenBlockSensorCalloutBusy);
                    ok = FALSE;
                }
            }
        }
    }
    // Residual flow contexts (unknown RemoveContext errors kept resident by
    // SkFlowRemoveAll, or an unconfirmed strip) must block unload: WFP may
    // still hold flowContext pointers into this image.
    if (SkFlowCount() != 0) {
        ShRuntimeRecordBlock(ShinkenBlockFlowContextDrain);
        ok = FALSE;
    }
    // 3) delete filter / engine-side callout (only parts actually installed)
    for (i = 0; i < SK_LAYER_COUNT; i++) {
        SK_WFP_OBJECT *fi = &g_WfpManager.filters[i];
        SK_WFP_OBJECT *co = &g_WfpManager.callouts[i];
        if (fi->filterId != 0) {
            SkWfpObjectDelete(fi, g_WfpManager.engine);
            if (fi->state == SkWfpStateLeaked) {
                ShRuntimeRecordBlock(ShinkenBlockEngineClose);
                ok = FALSE;
            }
        }
        if (co->calloutId != 0 && co->state != SkWfpStateLeaked) {
            SkWfpObjectDelete(co, g_WfpManager.engine);
            if (co->state == SkWfpStateLeaked) {
                ShRuntimeRecordBlock(ShinkenBlockEngineClose);
                ok = FALSE;
            }
        }
    }
    // 4) sublayer / provider
    if (!skWfpDeleteByKey(&g_WfpManager.sublayer, g_WfpManager.engine, TRUE)) {
        ShRuntimeRecordBlock(ShinkenBlockEngineClose);
        ok = FALSE;
    }
    if (!skWfpDeleteByKey(&g_WfpManager.provider, g_WfpManager.engine, FALSE)) {
        ShRuntimeRecordBlock(ShinkenBlockEngineClose);
        ok = FALSE;
    }
    // 5) close engine (handle retained while LEAKED objects remain — part of the park condition)
    if (g_WfpManager.engine != NULL && ok) {
        NTSTATUS st = ShOps.EngineClose(g_WfpManager.engine);
        g_WfpManager.engineObj.lastStatus = st;
        if (st == STATUS_SUCCESS) {
            g_WfpManager.engineObj.state = SkWfpStateDeleted;
            g_WfpManager.engine = NULL;
        } else {
            g_WfpManager.engineObj.state = SkWfpStateLeaked;
            ShRuntimeRecordBlock(ShinkenBlockEngineClose);
            ok = FALSE;
        }
    }
    if (ok)
        g_WfpManager.installed = FALSE;
    skWfpUnlock();
    return ok;
}
