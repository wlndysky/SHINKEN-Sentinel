// ============================================================================
// packet/flow_context.h — flow contexts (flowDelete/strip; BUSY-retry
// root-cause handling)
//
// A flow context is a refcounted non-paged record: classify
// (FLOW_ESTABLISHED) attaches, flowDelete releases; when callout
// unregister returns BUSY, SkFlowRemoveAll strips all associations of
// that callout (removes the BUSY root cause).
//
// Ownership/association protocol (single g_SkFlowLock; explicit fields,
// never LIST_ENTRY link-pointer arithmetic, as membership test):
//   linked     : global-table membership; the lock is the only unlink
//                authority (skFlowUnlinkLocked). Set only while the
//                table reference is held.
//   assocState : SkFlowAssocFree -> Pending -> Associated -> Removing.
//                Drives the FwpsFlowRemoveContext0 result handling:
//                SUCCESS = removal confirmed (sync flowDelete, if any,
//                already ran); PENDING = an async flowDelete still owns
//                the table reference; UNSUCCESSFUL = no association (no
//                callback will ever come); unknown error = removal state
//                untrusted, the entry is kept and unload is blocked.
//   table ref  : held from InsertTailList until exactly one unlink event
//                (flowDelete / confirmed strip / attach rollback).
// Attach runs under a per-callout attach gate (SHINKEN_RUNDOWN): WFP
// teardown closes the gate (SkFlowGateStopAndDrain) BEFORE unregistering
// the callout, so no FwpsFlowAssociateContext0 can start once teardown
// is underway, and in-flight attaches always complete first.
// ============================================================================
#pragma once
#include <ntddk.h>
#include "../runtime/runtime.h"
#include "../runtime/rundown.h"

#ifdef __cplusplus
extern "C" {
#endif

// WFP flow-context association state (transitions under g_SkFlowLock only;
// read at <= DISPATCH, written with the lock held)
typedef enum _SK_FLOW_ASSOC_STATE {
    SkFlowAssocFree = 0,   // never associated, or association fully rolled back
    SkFlowAssocPending,    // FwpsFlowAssociateContext0 in flight; table ref held
    SkFlowAssocAssociated, // WFP holds flowContext; a flowDeleteFn will arrive
    SkFlowAssocRemoving    // FwpsFlowRemoveContext0 issued; awaiting its verdict
} SK_FLOW_ASSOC_STATE;

typedef struct _SK_FLOW_CTX {
    volatile LONG ref;      // refcount (atomic)
    UINT64 flowId;
    UINT32 layerId;
    UINT32 calloutId;
    UINT64 packetsSeen;     // statistics
    BOOLEAN linked;         // global-table membership (protected by g_SkFlowLock)
    SK_FLOW_ASSOC_STATE assocState; // association state (protected by g_SkFlowLock)
    LIST_ENTRY link;        // global flow table (valid only while linked)
} SK_FLOW_CTX;

NTSTATUS SkFlowInit(void);              // initialize the flow table + attach gates
VOID SkFlowDestroy(void);               // destroy after quiesce (all contexts released)
SK_FLOW_CTX *SkFlowAttach(UINT64 flowId, UINT32 layerId, UINT32 calloutId);
VOID SkFlowAddRef(SK_FLOW_CTX *ctx);
VOID SkFlowRelease(SK_FLOW_CTX *ctx);   // free at zero (non-paged)
// Strip all associations of one callout (between BUSY retries / at
// teardown). TRUE = every entry this call detached is confirmed removed
// and no Associated entry of the callout remains; FALSE = at least one
// detached entry came back PENDING or with an unknown error. Entries
// owned by an in-flight attach (Pending) or by a promised async
// flowDelete (Removing) are NOT detached; callers that need "table empty"
// must consult SkFlowCountFor (a FALSE from an earlier round is expected
// while async removals settle). At final teardown a nonzero residual
// count blocks unload (ShinkenBlockFlowContextDrain) and unknown-error
// entries stay resident with the image; no dangling association is left.
BOOLEAN SkFlowRemoveAll(UINT32 calloutId);
ULONG SkFlowCount(void);                // diagnostic
ULONG SkFlowCountFor(UINT32 calloutId); // diagnostic: entries of one callout
// Re-arm a gate for a freshly registered callout runtime id (install /
// reinstall). Precondition: the previous incarnation of this id was
// drained (teardown gate stop+drain) or never used; re-arming while an
// old attach still holds the gate would corrupt the rundown count.
VOID SkFlowGateRearm(UINT32 calloutId);
// Per-callout attach gate: close the gate (new SkFlowAttach abandons)
// and wait for in-flight attaches (bounded). Call BEFORE
// FwpsCalloutUnregisterById0. FALSE = an attach did not drain within the
// bound: the caller must record ShinkenBlockFlowContextDrain and keep the
// image resident (the callout is NOT unregistered on this path).
BOOLEAN SkFlowGateStopAndDrain(UINT32 calloutId, ULONG retries, ULONG delayMs);

#ifdef __cplusplus
}
#endif
