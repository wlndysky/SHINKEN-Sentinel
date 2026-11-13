// Dynamic sessions own all engine objects. Runtime callouts are separate
// registrations and survive BFE restarts. A successful session close removes
// every terminating filter before any runtime registration is withdrawn.
// Failure retains the handle/IDs and forbids unsafe cleanup or reset.
#include <ntddk.h>
#include "wfp_manager.h"
#include "wfp_guids.h" // g_SkProviderKey/g_SkSubLayerKey single definition (test GUIDs)
#include "../packet/flow_context.h"

#define SK_WFP_BUSY_RETRIES 100
#define SK_WFP_RETRY_DELAY_MS 10
#ifndef FWPM_SESSION_FLAG_DYNAMIC
#define FWPM_SESSION_FLAG_DYNAMIC 0x00000001u // session objects reclaimed on handle close
#endif

SK_WFP_MANAGER g_WfpManager;

// IRQL contract: all WFP calls and BUSY-retry sleeps in this file
// require PASSIVE_LEVEL; a spin lock would raise IRQL to DISPATCH_LEVEL
// and break FwpmEngineOpen0, so the install-path mutex must be a KMUTEX.
static BOOLEAN g_WfpMutexReady;
VOID SkWfpManagerInitMutex(void) {
    UINT32 i;
    // DriverEntry is the sole initializer, before callback publication.
    if (g_WfpMutexReady)
        return;
    KeInitializeMutex(&g_WfpManager.installMutex, 0);
    SkWfpObjectReset(&g_WfpManager.engineObj, "wfpEngine");
    SkWfpObjectReset(&g_WfpManager.provider, "wfpProvider");
    SkWfpObjectReset(&g_WfpManager.sublayer, "wfpSublayer");
    for (i = 0; i < SK_LAYER_COUNT; i++) {
        SkWfpObjectReset(&g_WfpManager.callouts[i], g_SkCalloutDefs[i].name);
        SkWfpObjectReset(&g_WfpManager.filters[i], g_SkCalloutDefs[i].name);
        g_WfpManager.callouts[i].key = *g_SkCalloutDefs[i].calloutKey;
    }
    g_WfpMutexReady = TRUE;
}
static VOID skWfpLock(void) {
    (VOID)KeWaitForSingleObject(&g_WfpManager.installMutex, Executive,
                                KernelMode, FALSE, NULL);
}
static VOID skWfpUnlock(void) {
    (VOID)KeReleaseMutex(&g_WfpManager.installMutex, FALSE);
}

// Close/drain the attach gate before stripping flows. Contexts remain linked
// until flowDeleteFn returns the table reference; strip holds only an actor
// reference. Wait globally for callbacks, retrying unknown removal failures.
// A surviving context forbids unregister so its callback remains reachable.
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

// The only authority that discards engine-side identities is confirmed
// closure of their owning dynamic session. Runtime IDs are never cleared here.
static BOOLEAN skWfpCloseSessionLocked(void) {
    UINT32 i;
    NTSTATUS st;
    if (g_WfpManager.engine == NULL)
        return TRUE;
    st = ShOps.EngineClose(g_WfpManager.engine);
    g_WfpManager.engineObj.lastStatus = st;
    if (st != STATUS_SUCCESS) {
        g_WfpManager.engineObj.state = SkWfpStateLeaked;
        ShRuntimeRecordBlock(ShinkenBlockEngineClose);
        return FALSE;
    }
    g_WfpManager.engine = NULL;
    g_WfpManager.installed = FALSE;
    g_WfpManager.engineObj.state = SkWfpStateDeleted;
    g_WfpManager.provider.state = SkWfpStateDeleted;
    g_WfpManager.sublayer.state = SkWfpStateDeleted;
    for (i = 0; i < SK_LAYER_COUNT; i++) {
        SK_WFP_OBJECT *co = &g_WfpManager.callouts[i];
        g_WfpManager.filters[i].filterId = 0;
        g_WfpManager.filters[i].state = SkWfpStateDeleted;
        co->calloutId = 0;
        if (co->state != SkWfpStateLeaked)
            co->state = co->calloutRuntimeId != 0 ?
                SkWfpStateRegistered : SkWfpStateDeleted;
    }
    return TRUE;
}

static BOOLEAN skWfpBusyCleanup(PVOID ctx) {
    return skWfpStripCalloutFlows((UINT32)(UINT64)ctx);
}

static BOOLEAN skWfpTeardownLocked(void) {
    BOOLEAN clean = TRUE;
    UINT32 i;

    // If close fails, filters may still invoke their callouts: retain both.
    if (!skWfpCloseSessionLocked())
        return FALSE;
    for (i = 0; i < SK_LAYER_COUNT; i++) {
        SK_WFP_OBJECT *co = &g_WfpManager.callouts[i];
        if (co->calloutRuntimeId == 0)
            continue;
        if (!SkFlowGateStopAndDrain(i, SK_WFP_BUSY_RETRIES,
                                    SK_WFP_RETRY_DELAY_MS) ||
            !skWfpStripCalloutFlows(i)) {
            ShRuntimeRecordBlock(ShinkenBlockFlowContextDrain);
            clean = FALSE;
            continue;
        }
        (VOID)SkWfpObjectUnregister(co, (PVOID)(UINT64)i, skWfpBusyCleanup,
                                    SK_WFP_BUSY_RETRIES, SK_WFP_RETRY_DELAY_MS);
        if (co->calloutRuntimeId != 0) {
            ShRuntimeRecordBlock(ShinkenBlockSensorCalloutBusy);
            clean = FALSE;
        }
    }
    if (SkFlowCount() != 0) {
        ShRuntimeRecordBlock(ShinkenBlockFlowContextDrain);
        clean = FALSE;
    }
    return clean;
}

static NTSTATUS skWfpInstallLocked(PDEVICE_OBJECT device) {
    FWPM_SESSION0 session;
    NTSTATUS st;
    NTSTATUS stFail = STATUS_UNSUCCESSFUL;
    UINT32 i;
    BOOLEAN txnBegun = FALSE;

    if (g_WfpManager.installed)
        return STATUS_SUCCESS;
    // Never overwrite an unclosed session or an unconfirmed registration.
    if (g_WfpManager.engine != NULL)
        return STATUS_DEVICE_BUSY;
    for (i = 0; i < SK_LAYER_COUNT; i++) {
        if (g_WfpManager.callouts[i].state == SkWfpStateLeaked)
            return STATUS_DEVICE_BUSY;
    }

    // The session is the ownership boundary for all management objects.
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
    // Reuse runtime registrations across BFE restarts; only engine objects
    // belong to this transaction and need to be recreated.
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

        if (co->calloutRuntimeId == 0) {
            st = SkWfpObjectRegisterCallout(co, device, &c1);
            if (!NT_SUCCESS(st)) {
                stFail = st;
                goto rollback;
            }
            SkFlowGateRearm(i, co->calloutRuntimeId);
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
    return STATUS_SUCCESS;

rollback:
    if (txnBegun) {
        NTSTATUS stAbort = FwpmTransactionAbort0(g_WfpManager.engine);
        // Even if abort fails, a successful close below ends the entire
        // dynamic session and supplies definitive management cleanup proof.
        g_WfpManager.engineObj.lastStatus = stAbort;
    }
    if (!skWfpTeardownLocked())
        ShRuntimeEnterUnloadBlocked(ShRuntimeBlockReason());
out:
    return stFail;
}

NTSTATUS SkWfpManagerInstall(PDEVICE_OBJECT device) {
    NTSTATUS st = STATUS_SUCCESS;
    skWfpLock();
    if (ShRuntimeState() == ShinkenUnloadBlocked) {
        skWfpUnlock();
        return STATUS_DEVICE_BUSY;
    }
    if (FwpmBfeStateGet0() == FWPM_SERVICE_RUNNING)
        st = skWfpInstallLocked(device);
    skWfpUnlock();
    return st;
}

NTSTATUS SkWfpManagerBfeStateChange(PDEVICE_OBJECT device, FWPM_SERVICE_STATE state) {
    NTSTATUS st = STATUS_SUCCESS;
    skWfpLock();
    if (ShRuntimeState() == ShinkenUnloadBlocked) {
        skWfpUnlock();
        return STATUS_DEVICE_BUSY;
    }
    if (state == FWPM_SERVICE_STOP_PENDING || state == FWPM_SERVICE_STOPPED) {
        // STOP_PENDING is delivered while the service can still close the
        // session. Leave runtime registrations and existing flow contexts
        // intact; their callbacks remain valid until final driver teardown.
        g_WfpManager.installed = FALSE;
        if (!skWfpCloseSessionLocked())
            st = g_WfpManager.engineObj.lastStatus;
    } else if (state == FWPM_SERVICE_RUNNING &&
               FwpmBfeStateGet0() == FWPM_SERVICE_RUNNING) {
        // A previous close failure must be resolved before a new handle is
        // opened. No reset, fake NOT_FOUND, or orphaned session is allowed.
        if (!g_WfpManager.installed && !skWfpCloseSessionLocked())
            st = g_WfpManager.engineObj.lastStatus;
        else
            st = skWfpInstallLocked(device);
    }
    skWfpUnlock();
    return st;
}

BOOLEAN SkWfpManagerTeardown(void) {
    BOOLEAN clean;
    skWfpLock();
    clean = skWfpTeardownLocked();
    skWfpUnlock();
    return clean;
}
