// ============================================================================
// wfp/wfp_callouts.h — callout layer selection and classification
// table (one card per callout)
//
// Layers chosen by real function (connection verdict + flow tracking):
//
// | layer (internal id) | trigger             | metadata access     | IRQL    | rule eval | action        | flow ctx    | teardown |
// |---------------------|---------------------|---------------------|---------|-----------|---------------|-------------|----------|
// | ALE_AUTH_CONNECT_V4 | outbound TCP conn / | pid, path, remote/  | DISPATCH| snapshot  | BLOCK/PERMIT  | registered  | manager  |
// |                     | UDP first packet    | local addr+port,    |         |           |               | (stats)     |          |
// |                     |                     | protocol            |         |           |               |             |          |
// | ALE_AUTH_CONNECT_V6 | same (v6)           | same                | same    | same      | same          | same        | same     |
// | ALE_RECV_ACCEPT_V4  | inbound TCP accept /| same                | same    | same      | same          | same        | same     |
// |                     | UDP first packet    |                     |         |           |               |             |          |
// | ALE_RECV_ACCEPT_V6  | same (v6)           | same                | same    | same      | same          | same        | same     |
// | FLOW_ESTABLISHED_V4 | flow setup/teardown | flowId (ctx attach) | DISPATCH| none      | always PERMIT | attach/free | manager  |
// | FLOW_ESTABLISHED_V6 | same (v6)           | same                | same    | none      | always PERMIT | same        | same     |
//
// Constraints: ALE_AUTH_* allow hard BLOCK (FWPS_RIGHT_ACTION_WRITE);
// classify never allocates paged memory, never blocks, never touches
// user pointers; rule evaluation reads an immutable snapshot only.
// ============================================================================
#pragma once
#include <ntddk.h>
#include "../rules/rule_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// internal layer ids (rule.layerId values)
typedef enum _SK_LAYER_ID {
    SkLayerAleAuthConnectV4 = 0,
    SkLayerAleAuthConnectV6,
    SkLayerAleRecvAcceptV4,
    SkLayerAleRecvAcceptV6,
    SkLayerFlowEstablishedV4,
    SkLayerFlowEstablishedV6,
    SK_LAYER_COUNT
} SK_LAYER_ID;

// Per-layer description (definitions in wfp_callouts.c): layer GUID,
// callout GUID, filter GUID, classify/notify/flowDelete, display name.
// Filters are unconditional (match all) with explicit weight and
// explicit filterKey (see wfp_guids.h, wfp_objects.c).
typedef struct _SK_CALLOUT_DEF {
    UINT32 layerId;          // SK_LAYER_ID
    const GUID *layerKey;    // FWPM_LAYER_*
    const GUID *calloutKey;  // driver GUID (single definition in wfp_guids.h)
    const GUID *filterKey;   // driver GUID (single definition in wfp_guids.h)
    const char *name;
    // Typed WDK callback signatures (fwpsk.h; identical ABI-compatible
    // typedefs in shim/wdk_shim.h for the host build) — no void* and no
    // casts anywhere on the FWPS_CALLOUT1 registration path.
    FWPS_CALLOUT_CLASSIFY_FN1 classifyFn;
    FWPS_CALLOUT_NOTIFY_FN1 notifyFn;
    FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0 flowDeleteFn; // may be NULL
    UINT32 hardBlockAllowed; // layer permits a hard FWP_ACTION_BLOCK verdict
} SK_CALLOUT_DEF;

extern const SK_CALLOUT_DEF g_SkCalloutDefs[SK_LAYER_COUNT];
const SK_CALLOUT_DEF *SkCalloutDefById(UINT32 layerId);

#ifdef __cplusplus
}
#endif
