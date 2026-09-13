// ============================================================================
// wfp/wfp_objects.h — WFP object lifecycle state machine (per object,
// independent of array indices)
//
// Each object (callout/filter/provider/sublayer/engine/session) holds:
// key (GUID, optional) / id (runtime callout id, engine mgmt callout
// id, filter id) / name / state / last status / BUSY retry count /
// creation phase (SK_WFP_PHASE_*). State machine (direct transitions):
//
//   UNINITIALIZED ──register/add ok──> REGISTERED ──filter attached──> ACTIVE
//        |create-phase failure          | unregister/delete enters
//        v                              v
//      FAILED (not on the books;    QUIESCING (transient: teardown/
//       may be rebuilt directly)     unregister retry loop running)
//                                        | success / documented NOT_FOUND
//                                        v
//                                     DELETED (confirmed removed; no
//                                       further callbacks possible)
//                                        removal untrusted (unknown
//                                        error / BUSY exhausted)
//                                        => LEAKED (terminal)
//
// Reserved values: PREPARED and SkWfpPhaseTeardown currently have no
// transition path (register/add failure goes straight to FAILED,
// success straight to REGISTERED; teardown is orchestrated by the
// manager with no dedicated phase) — enum slots kept for future
// two-phase-commit semantics. QUIESCING has a transition path (set
// only by SkWfpObjectUnregister).
// Concurrency: object state transitions only under the manager's
// install/teardown lock (wfp_manager.c, PASSIVE install/teardown
// path); diagnostic fields may be read from any context (single-word
// reads).
// ============================================================================
#pragma once
#include <ntddk.h>
#include "../runtime/runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _SK_WFP_OBJECT_STATE {
    SkWfpStateUninitialized = 0, // never initialized
    SkWfpStatePrepared,          // reserved (no transition path today: goes straight to REGISTERED)
    SkWfpStateRegistered,        // registered with WFP (runtime callout or engine object)
    SkWfpStateActive,            // producing callbacks (after filter attach)
    SkWfpStateQuiescing,         // teardown in progress
    SkWfpStateDeleted,           // confirmed deleted/unregistered (no further callbacks)
    SkWfpStateFailed,            // create/register failed (never registered; may be rebuilt)
    SkWfpStateLeaked             // removal state untrusted (terminal; resource kept + caller parks)
} SK_WFP_OBJECT_STATE;

typedef enum _SK_WFP_PHASE {
    SkWfpPhaseNone = 0,
    SkWfpPhaseEngineOpen,
    SkWfpPhaseProviderAdd,
    SkWfpPhaseSubLayerAdd,
    SkWfpPhaseCalloutRegister, // FwpsCalloutRegister*
    SkWfpPhaseCalloutAdd,      // FwpmCalloutAdd*
    SkWfpPhaseFilterAdd,
    SkWfpPhaseTeardown           // reserved (teardown orchestrated by the manager; no dedicated phase)
} SK_WFP_PHASE;

typedef struct _SK_WFP_OBJECT {
    const char *name;        // static diagnostic name
    GUID key;                // by-key identity (optional; all-zero if none)
    UINT32 calloutRuntimeId; // product of FwpsCalloutRegister*
    UINT32 calloutId;        // product of FwpmCalloutAdd*
    UINT64 filterId;         // product of FwpmFilterAdd*
    SK_WFP_OBJECT_STATE state;
    SK_WFP_PHASE phase;      // latest creation phase (rollback deletes only REGISTERED/ACTIVE)
    NTSTATUS lastStatus;     // last API return value
    ULONG busyRetries;       // BUSY retry count (diagnostic)
} SK_WFP_OBJECT;

const char *SkWfpObjectStateName(SK_WFP_OBJECT_STATE st);
VOID SkWfpObjectReset(SK_WFP_OBJECT *o, const char *name);
// Registration-surface operations (all check return values and advance
// state; same discipline as runtime-layer ShWfp*: unknown error =>
// Leaked). See wfp/wfp_objects.c.
NTSTATUS SkWfpObjectRegisterCallout(SK_WFP_OBJECT *o, PDEVICE_OBJECT device,
                                    const FWPS_CALLOUT1 *callout); // FwpsCalloutRegister1
NTSTATUS SkWfpObjectAddCallout(SK_WFP_OBJECT *o, HANDLE engine);   // FwpmCalloutAdd0
NTSTATUS SkWfpObjectAddFilter(SK_WFP_OBJECT *o, HANDLE engine,
                              const GUID *layerKey, UINT32 layerId);
NTSTATUS SkWfpObjectUnregister(SK_WFP_OBJECT *o, PVOID busyCtx,
                               VOID (*busyCleanup)(PVOID), ULONG maxBusyRetries,
                               ULONG delayMs);
NTSTATUS SkWfpObjectDelete(SK_WFP_OBJECT *o, HANDLE engine); // delete by installed part

#ifdef __cplusplus
}
#endif
