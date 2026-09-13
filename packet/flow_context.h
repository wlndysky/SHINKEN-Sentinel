// ============================================================================
// packet/flow_context.h — flow contexts (flowDelete/strip; BUSY-retry
// root-cause handling)
//
// A flow context is a refcounted non-paged record: classify
// (FLOW_ESTABLISHED) attaches, flowDelete releases; when callout
// unregister returns BUSY, SkFlowRemoveAll strips all associations of
// that callout (removes the BUSY root cause).
// ============================================================================
#pragma once
#include <ntddk.h>
#include "../runtime/runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _SK_FLOW_CTX {
    volatile LONG ref;      // refcount (atomic)
    UINT64 flowId;
    UINT32 layerId;
    UINT32 calloutId;
    UINT64 packetsSeen;     // statistics
    LIST_ENTRY link;        // global flow table
} SK_FLOW_CTX;

NTSTATUS SkFlowInit(void);              // initialize the flow table
VOID SkFlowDestroy(void);               // destroy after quiesce (all contexts released)
SK_FLOW_CTX *SkFlowAttach(UINT64 flowId, UINT32 layerId, UINT32 calloutId);
VOID SkFlowAddRef(SK_FLOW_CTX *ctx);
VOID SkFlowRelease(SK_FLOW_CTX *ctx);   // free at zero (non-paged)
VOID SkFlowRemoveAll(UINT32 calloutId); // strip all associations of a callout (between BUSY retries)
ULONG SkFlowCount(void);                // diagnostic

#ifdef __cplusplus
}
#endif
