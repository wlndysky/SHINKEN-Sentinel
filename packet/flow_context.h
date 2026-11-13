// Nonpaged flow tracking. Fixed hash buckets use the full
// (flowId, layerId, calloutId) key; each bucket has a bounded capacity.
// Admission failure skips optional tracking, never changes network policy.
// A successful WFP association owns one table reference until flowDeleteFn.
// Attach and removal actors hold separate references across WFP calls.
// Removal never hides membership from the callback or frees its reference.
// Gates are indexed by our internal layer IDs, not WFP-assigned runtime IDs.
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
    SkFlowAssocFree = 0,   // never associated, or association fully settled/rolled back
    SkFlowAssocPending,    // FwpsFlowAssociateContext0 in flight; table ref held
    SkFlowAssocAssociated, // WFP holds flowContext; a flowDeleteFn will arrive
    SkFlowAssocRemoving    // FwpsFlowRemoveContext0 issued; awaiting verdict/callback
} SK_FLOW_ASSOC_STATE;

typedef struct _SK_FLOW_CTX {
    volatile LONG ref;      // refcount (atomic)
    UINT64 flowId;          // hash key: flowId + layerId + calloutId
    UINT32 layerId;
    UINT32 calloutId;
    UINT64 packetsSeen;     // statistics
    BOOLEAN linked;         // bucket membership (protected by g_SkFlowLock)
    SK_FLOW_ASSOC_STATE assocState; // association state (protected by g_SkFlowLock)
    LIST_ENTRY link;        // hash bucket linkage (valid only while linked)
    LIST_ENTRY removeLink;  // private removal batch; actor reference pins ctx
} SK_FLOW_CTX;

NTSTATUS SkFlowInit(void);              // initialize the flow table + per-layer attach gates
// Destroy after quiesce (all callouts unregistered, all associations
// drained). TRUE = table empty: quiescence proven, init state cleared.
// FALSE = residual entries: the drain invariant was broken — the reason is
// recorded (ShinkenBlockFlowContextDrain) and the entries stay linked and
// resident with the image; NOTHING is force-freed, because WFP may still
// hold flowContext pointers into entries whose quiescence is unproven.
// FALSE must block image unload (caller keeps the driver resident).
BOOLEAN SkFlowDestroy(void);
SK_FLOW_CTX *SkFlowAttach(UINT64 flowId, UINT32 layerId, UINT32 calloutId);
VOID SkFlowAddRef(SK_FLOW_CTX *ctx);
VOID SkFlowRelease(SK_FLOW_CTX *ctx);   // free at zero (non-paged)
// Serialized PASSIVE teardown after the attach gate drains. Marks associated
// entries Removing and invokes WFP outside the lock. The manager waits for
// callbacks globally; there is no per-flow sleep. Unknown failures remain
// retryable; pending/natural deletion retains the table ref until callback.
// FALSE means unconfirmed work remains; callers also check SkFlowCountFor.
BOOLEAN SkFlowRemoveAll(UINT32 calloutId);
ULONG SkFlowCount(void);                // diagnostic
ULONG SkFlowCountFor(UINT32 calloutId); // diagnostic: entries of one callout
// Re-arm a layer's attach gate for a freshly registered callout runtime id
// (fresh FwpsCalloutRegister1 only — a BFE pause/resume cycle never
// re-arms: the runtime registration and the recorded id stay valid).
// Precondition: the previous incarnation of this layer's registration was
// drained (SkFlowGateStopAndDrain) or never existed; re-arming while an
// old attach still holds the gate would corrupt the rundown count
// (refused defensively, old gate state stays authoritative).
VOID SkFlowGateRearm(UINT32 layerId, UINT32 calloutId);
// Per-layer attach gate: close the gate (new SkFlowAttach of this layer
// abandons) and wait for in-flight attaches (bounded). Call BEFORE
// FwpsCalloutUnregisterById0. The gate stays closed until a fresh
// registration re-arms it; a BFE pause (session close without unregister)
// never closes it. FALSE = an attach did not drain within the bound: the
// caller must record ShinkenBlockFlowContextDrain and keep the image
// resident (the callout is NOT unregistered on this path).
BOOLEAN SkFlowGateStopAndDrain(UINT32 layerId, ULONG retries, ULONG delayMs);

#ifdef __cplusplus
}
#endif
