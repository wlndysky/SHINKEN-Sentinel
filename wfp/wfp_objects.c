// ============================================================================
// wfp/wfp_objects.c — SK_WFP_OBJECT state-machine operations (contract
// in wfp_objects.h)
//
// Error classification discipline (same as runtime-layer ShWfp*):
//   * create phase (register/add) failure => FAILED (object not on the
//     books; may be rebuilt directly);
//   * teardown (unregister/delete): only STATUS_SUCCESS or a documented
//     FWP_E_*_NOT_FOUND => DELETED; STATUS_DEVICE_BUSY => bounded retry
//     (each unregister round first runs busyCleanup to strip flow
//     contexts); anything else => LEAKED (terminal: removal state
//     untrusted; id/key/lastStatus kept; the upper layer records the
//     block reason and parks).
// ============================================================================
#include <ntddk.h>
#include "wfp_objects.h"
#include "wfp_callouts.h"
#include "wfp_guids.h" // g_SkProviderKey/g_SkSubLayerKey/SK_FILTER_* single definition

// explicit filter weight (see SkWfpObjectAddFilter; FWP_EMPTY auto-weight loses arbitration)
static UINT64 g_SkFilterWeight = 0x0000FFFFFFFFFFFFULL;
static const char *const g_SkWfpStateNames[] = {
    "UNINITIALIZED", "PREPARED", "REGISTERED", "ACTIVE",
    "QUIESCING",     "DELETED",  "FAILED",     "LEAKED"
};

const char *SkWfpObjectStateName(SK_WFP_OBJECT_STATE st) {
    if ((UINT32)st >= (UINT32)(sizeof(g_SkWfpStateNames) / sizeof(g_SkWfpStateNames[0])))
        return "?";
    return g_SkWfpStateNames[st];
}

VOID SkWfpObjectReset(SK_WFP_OBJECT *o, const char *name) {
    RtlZeroMemory(o, sizeof(*o));
    o->name = name;
    o->state = SkWfpStateUninitialized;
    o->phase = SkWfpPhaseNone;
}

// find the layer-table definition by callout key (AddCallout/AddFilter need layerKey etc.)
static const SK_CALLOUT_DEF *skWfpDefByCalloutKey(const GUID *key) {
    UINT32 i;
    for (i = 0; i < SK_LAYER_COUNT; i++) {
        if (memcmp(g_SkCalloutDefs[i].calloutKey, key, sizeof(GUID)) == 0)
            return &g_SkCalloutDefs[i];
    }
    return NULL;
}

// FwpsCalloutRegister1: kernel-side registration, typed table
// (const FWPS_CALLOUT1*, matching the fwpsk.h prototype — no void*,
// no casts on the registration path). Success => calloutRuntimeId set
// + REGISTERED; failure => FAILED.
NTSTATUS SkWfpObjectRegisterCallout(SK_WFP_OBJECT *o, PDEVICE_OBJECT device,
                                    const FWPS_CALLOUT1 *callout) {
    NTSTATUS st;

    o->phase = SkWfpPhaseCalloutRegister;
    st = FwpsCalloutRegister1(device, callout, &o->calloutRuntimeId);
    o->lastStatus = st;
    if (NT_SUCCESS(st)) {
        o->state = SkWfpStateRegistered;
    } else {
        o->calloutRuntimeId = 0;
        o->state = SkWfpStateFailed;
    }
    return st;
}

// FwpmCalloutAdd0: engine-side management object. Success => calloutId
// set (state stays REGISTERED; the manager sets ACTIVE once a filter is
// attached). Failure => FAILED.
NTSTATUS SkWfpObjectAddCallout(SK_WFP_OBJECT *o, HANDLE engine) {
    FWPM_CALLOUT0 mc;
    const SK_CALLOUT_DEF *def;
    NTSTATUS st;

    def = skWfpDefByCalloutKey(&o->key);
    if (def == NULL) { // key not in the layer table: internal consistency error
        o->lastStatus = STATUS_INVALID_PARAMETER;
        o->state = SkWfpStateFailed;
        return o->lastStatus;
    }
    RtlZeroMemory(&mc, sizeof(mc));
    // BFE requires displayData.name to be non-empty
    // (STATUS_FWP_NULL_DISPLAY_NAME otherwise).
    mc.displayData.name = SK_WFP_CALLOUT_NAME_W;
    mc.calloutKey = o->key;
    mc.providerKey = (GUID *)&g_SkProviderKey;
    mc.applicableLayer = *def->layerKey;
    o->phase = SkWfpPhaseCalloutAdd;
    st = FwpmCalloutAdd0(engine, &mc, NULL, &o->calloutId);
    o->lastStatus = st;
    if (!NT_SUCCESS(st)) {
        o->calloutId = 0;
        o->state = SkWfpStateFailed;
    }
    return st;
}

// FwpmFilterAdd0: unconditional match-all filter, action
// CALLOUT_TERMINATING pointing at this layer's callout. Success =>
// filterId set + REGISTERED (arbitration callbacks active); failure =>
// FAILED.
NTSTATUS SkWfpObjectAddFilter(SK_WFP_OBJECT *o, HANDLE engine,
                              const GUID *layerKey, UINT32 layerId) {
    FWPM_FILTER0 f;
    const SK_CALLOUT_DEF *def;
    NTSTATUS st;

    def = SkCalloutDefById(layerId);
    if (def == NULL || layerKey == NULL) {
        o->lastStatus = STATUS_INVALID_PARAMETER;
        o->state = SkWfpStateFailed;
        return o->lastStatus;
    }
    RtlZeroMemory(&f, sizeof(f));
    f.displayData.name = SK_WFP_FILTER_NAME_W; // BFE requires non-empty (as above)
    f.filterKey = *def->filterKey;  // explicit key (wfp_guids.h): diagnosable / verifiable by key
    f.layerKey = *layerKey;
    // Explicit high weight: FWP_EMPTY auto-weight is too low and a
    // higher-weight terminating filter would win arbitration (BLOCK
    // computed but not enforced). Weight = 2^48.
    f.weight.type = FWP_UINT64;
    f.weight.uint64 = (UINT64 *)&g_SkFilterWeight;
    f.numFilterConditions = 0;      // no conditions: match all
    f.filterCondition = NULL;
    f.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    f.action.calloutKey = *def->calloutKey;
    o->phase = SkWfpPhaseFilterAdd;
    st = FwpmFilterAdd0(engine, &f, NULL, &o->filterId);
    o->lastStatus = st;
    if (NT_SUCCESS(st)) {
        o->state = SkWfpStateRegistered;
    } else {
        o->filterId = 0;
        o->state = SkWfpStateFailed;
    }
    return st;
}

// FwpsCalloutUnregisterById0 with bounded BUSY retries (same discipline
// as ShWfpUnregisterCalloutById): after a successful return, WFP
// guarantees classifyFn/notifyFn/flowDeleteFn are no longer called
// (documented safe point). Each BUSY round first runs
// busyCleanup(busyCtx) to strip flow contexts (root cause). Unknown
// error / exhausted => LEAKED (terminal).
NTSTATUS SkWfpObjectUnregister(SK_WFP_OBJECT *o, PVOID busyCtx,
                               VOID (*busyCleanup)(PVOID), ULONG maxBusyRetries,
                               ULONG delayMs) {
    NTSTATUS st;
    ULONG attempt;

    if (o->state == SkWfpStateDeleted || o->state == SkWfpStateUninitialized)
        return STATUS_SUCCESS; // idempotent: no longer registered
    if (o->state == SkWfpStateLeaked)
        return STATUS_DEVICE_BUSY; // terminal state: never touch again
    o->state = SkWfpStateQuiescing;
    for (attempt = 0;; attempt++) {
        st = ShOps.UnregisterCalloutById(o->calloutRuntimeId);
        o->lastStatus = st;
        if (st == STATUS_SUCCESS || st == FWP_E_CALLOUT_NOT_FOUND) {
            // NOT_FOUND = documented "not registered", equivalent to success: confirmed removed
            o->state = SkWfpStateDeleted;
            o->busyRetries = attempt;
            return st;
        }
        if (st != STATUS_DEVICE_BUSY) {
            o->busyRetries = attempt;
            o->state = SkWfpStateLeaked; // unknown error: removal state untrusted => park
            return st;
        }
        if (attempt >= maxBusyRetries) {
            o->busyRetries = attempt + 1;
            o->state = SkWfpStateLeaked; // BUSY retries exhausted => park
            return st;
        }
        if (busyCleanup)
            busyCleanup(busyCtx); // strip flow contexts first each round (BUSY root cause)
        ShOps.SleepMs(delayMs);
    }
}

// Delete engine objects by installed part (filter before callout; only
// parts actually installed). Same error classification as unregister:
// SUCCESS / FWP_E_*_NOT_FOUND => DELETED; anything else => LEAKED.
// Note: state DELETED is not an early-out — a callout object carries
// both a runtime registration (unregister sets DELETED) and an
// engine-side mgmt callout (calloutId may still be set). Idempotence
// is judged by whether the id fields are zeroed, not by state.
NTSTATUS SkWfpObjectDelete(SK_WFP_OBJECT *o, HANDLE engine) {
    NTSTATUS st;

    if (o->state == SkWfpStateLeaked)
        return STATUS_DEVICE_BUSY;
    if (o->filterId != 0) {
        st = ShOps.FilterDeleteById(engine, o->filterId);
        o->lastStatus = st;
        if (st == STATUS_SUCCESS || st == FWP_E_FILTER_NOT_FOUND) {
            o->filterId = 0;
            o->state = SkWfpStateDeleted;
            return st;
        }
        o->state = SkWfpStateLeaked;
        return st;
    }
    if (o->calloutId != 0) {
        st = ShOps.CalloutDeleteById(engine, o->calloutId);
        o->lastStatus = st;
        if (st == STATUS_SUCCESS || st == FWP_E_CALLOUT_NOT_FOUND) {
            o->calloutId = 0;
            o->state = SkWfpStateDeleted;
            return st;
        }
        o->state = SkWfpStateLeaked;
        return st;
    }
    return STATUS_SUCCESS; // no parts installed: nothing to do
}
