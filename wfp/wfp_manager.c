// ============================================================================
// wfp/wfp_manager.c — WFP manager (contract and ordering in wfp_manager.h)
//
// Install: installMutex (PASSIVE mutex) -> FwpmEngineOpen0 (DYNAMIC
// session) -> engine transaction Begin -> provider add -> sublayer add ->
// per-layer register/add/filter add -> Commit. Any failure: Abort +
// reverse-phase rollback (deletes only REGISTERED/ACTIVE objects; unknown
// rollback error => object LEAKED + block reason recorded; failure is
// returned and the caller parks).
//
// Teardown (idempotent): per-layer unregister (between BUSY retries,
// SkFlowRemoveAll strips that callout's flow contexts) -> delete
// filter/callout -> delete sublayer/provider -> close engine. Any
// LEAKED/failure => ShRuntimeRecordBlock + FALSE (caller parks; see
// runtime/lifecycle.c and docs/UNLOAD_SAFETY.md §7a).
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

// Between BUSY retries: strip all flow contexts of this callout (BUSY
// root-cause handling). ctx = internal layer id (passed by teardown).
static VOID skWfpBusyCleanup(PVOID ctx) {
    UINT32 layerId = (UINT32)(UINT64)ctx;
    if (layerId < SK_LAYER_COUNT)
        SkFlowRemoveAll(g_WfpManager.callouts[layerId].calloutRuntimeId);
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

// Reverse-order rollback (install failure path): delete only
// REGISTERED/ACTIVE objects — per layer filter -> callout (unregister
// + mgmt delete) -> sublayer -> provider -> close engine.
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
        if (co->state == SkWfpStateRegistered || co->state == SkWfpStateActive) {
            // kernel-side registration is outside the engine transaction; explicit unregister required
            SkWfpObjectUnregister(co, NULL, NULL, SK_WFP_BUSY_RETRIES,
                                  SK_WFP_RETRY_DELAY_MS);
            if (co->state == SkWfpStateLeaked) {
                clean = FALSE;
            } else if (co->calloutId != 0) {
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
    if (txnBegun)
        FwpmTransactionAbort0(g_WfpManager.engine); // Abort's return value carries no new information
    if (!skWfpRollbackLocked()) {
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

    // 1) per-layer unregister (documented safe point that stops new classify references; flow contexts stripped between BUSY retries)
    for (i = 0; i < SK_LAYER_COUNT; i++) {
        SK_WFP_OBJECT *co = &g_WfpManager.callouts[i];
        if (co->state == SkWfpStateActive || co->state == SkWfpStateRegistered) {
            SkWfpObjectUnregister(co, (PVOID)(UINT64)i, skWfpBusyCleanup,
                                  SK_WFP_BUSY_RETRIES, SK_WFP_RETRY_DELAY_MS);
            if (co->state == SkWfpStateLeaked) {
                ShRuntimeRecordBlock(ShinkenBlockSensorCalloutBusy);
                ok = FALSE;
            }
        }
    }
    // 2) delete filter / engine-side callout (only parts actually installed)
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
    // 3) sublayer / provider
    if (!skWfpDeleteByKey(&g_WfpManager.sublayer, g_WfpManager.engine, TRUE)) {
        ShRuntimeRecordBlock(ShinkenBlockEngineClose);
        ok = FALSE;
    }
    if (!skWfpDeleteByKey(&g_WfpManager.provider, g_WfpManager.engine, FALSE)) {
        ShRuntimeRecordBlock(ShinkenBlockEngineClose);
        ok = FALSE;
    }
    // 4) close engine (handle retained while LEAKED objects remain — part of the park condition)
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
