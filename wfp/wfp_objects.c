// ============================================================================
// wfp/wfp_objects.c — SK_WFP_OBJECT state-machine operations (contract
// in wfp_objects.h)
//
// Error classification discipline (same as runtime-layer ShWfp*):
//   * create phase (register/add) failure => FAILED (object not on the
//     books; may be rebuilt directly);
//   * teardown (unregister/delete): only STATUS_SUCCESS or a documented
//     STATUS_FWP_*_NOT_FOUND => DELETED; STATUS_DEVICE_BUSY => bounded retry
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
// attached). Failure => calloutId cleared; the engine-side object does
// not exist, but a successful FwpsCalloutRegister1 (calloutRuntimeId !=
// 0) is a separate fact on a separate surface — it is kept and the state
// stays REGISTERED so rollback/teardown still run
// FwpsCalloutUnregisterById0 exactly once. state=Failed only when nothing
// at all is on the books.
NTSTATUS SkWfpObjectAddCallout(SK_WFP_OBJECT *o, HANDLE engine) {
    FWPM_CALLOUT0 mc;
    const SK_CALLOUT_DEF *def;
    NTSTATUS st;

    def = skWfpDefByCalloutKey(&o->key);
    if (def == NULL) { // key not in the layer table: internal consistency error
        o->lastStatus = STATUS_INVALID_PARAMETER;
        if (o->calloutRuntimeId == 0)
            o->state = SkWfpStateFailed; // runtime registration also absent: nothing on the books
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
        o->calloutId = 0; // engine-side add failed: no mgmt callout exists
        if (o->calloutRuntimeId == 0)
            o->state = SkWfpStateFailed; // and no runtime registration: full create failure
        // else: runtime registration (calloutRuntimeId) still held — the
        // unregister is owed later; FAILED here would orphan it.
    }
    return st;
}

// FwpmFilterAdd0: unconditional match-all filter, action
// CALLOUT_TERMINATING pointing at this layer's callout. Success =>
// filterId set + REGISTERED (arbitration callbacks active); failure =>
// FAILED.
//
// A permit is deliberately soft: other providers (including Windows
// Firewall) must retain the ability to block at their own sublayers.
// Our explicit BLOCK consumes the right in the classify callback.
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
    f.flags = 0;
    f.filterKey = *def->filterKey;  // explicit key (wfp_guids.h): diagnosable / verifiable by key
    f.layerKey = *layerKey;
    f.subLayerKey = g_SkSubLayerKey;
    f.providerKey = (GUID *)&g_SkProviderKey;
    // Explicit intra-sublayer weight: 2^48 - 1. Cross-sublayer arbitration
    // still applies; a numeric weight is not an enforcement guarantee.
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

// Runtime unregister is independent of the engine session. A nonzero
// runtime ID always carries an unregister obligation, even after the
// corresponding management object or dynamic session has disappeared.
//
// Runtime-registration fact vs object state: the unregister obligation is
// judged by calloutRuntimeId, not by state — a create-phase failure of a
// LATER step (FwpmCalloutAdd0) leaves the runtime registration on the
// books while the state says REGISTERED/FAILED variants; only a
// confirmed removal (or a never-registered id of 0) ends the obligation.
// Exactly-once: confirmed removal zeroes calloutRuntimeId, and only the
// nonzero->confirmed transition performs the unregister.
//
// BUSY handling: each retry round first runs busyCleanup(busyCtx) to
// strip flow contexts (root cause). busyCleanup returns TRUE only when
// the strip is CONFIRMED complete; FALSE (or NULL) means the BUSY root
// cause could not be removed — there is nothing left to retry for, so
// the object parks as LEAKED instead of burning retries that must fail.
// Unknown error / exhausted => LEAKED (terminal).
NTSTATUS SkWfpObjectUnregister(SK_WFP_OBJECT *o, PVOID busyCtx,
                               BOOLEAN (*busyCleanup)(PVOID), ULONG maxBusyRetries,
                               ULONG delayMs) {
    NTSTATUS st;
    ULONG attempt;

    if (o->calloutRuntimeId == 0)
        return STATUS_SUCCESS;
    if (o->state == SkWfpStateLeaked)
        return STATUS_DEVICE_BUSY; // terminal state: never touch again
    o->state = SkWfpStateQuiescing;
    for (attempt = 0;; attempt++) {
        st = ShOps.UnregisterCalloutById(o->calloutRuntimeId);
        o->lastStatus = st;
        if (st == STATUS_SUCCESS || st == STATUS_FWP_CALLOUT_NOT_FOUND) {
            // NOT_FOUND = documented "not registered", equivalent to success: confirmed removed
            o->calloutRuntimeId = 0; // confirmed: the unregister obligation is spent
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
        if (busyCleanup == NULL || !busyCleanup(busyCtx)) {
            // Strip unconfirmed (or impossible): flow contexts may still
            // reference the callout, so every further retry must fail.
            o->busyRetries = attempt + 1;
            o->state = SkWfpStateLeaked;
            return STATUS_DEVICE_BUSY;
        }
        ShOps.SleepMs(delayMs);
    }
}

