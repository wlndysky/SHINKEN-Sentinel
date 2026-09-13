// ============================================================================
// wfp/wfp_callouts.c — six-layer callout definition table (contract
// and layer semantics in wfp_callouts.h)
//
// Layers chosen by real function (connection verdict + flow tracking).
// All callout/filter/provider/sublayer GUIDs are defined once in
// wfp_guids.h (test GUIDs; inventory in wdk/guid_registry.json).
// ============================================================================
#include <ntddk.h>
#include "wfp_callouts.h"
#include "wfp_guids.h" // SK_CALLOUT_*/SK_FILTER_* single definition
#ifdef SHINKEN_HOST_SHIM
#include <wfp_layers.h> // FWPM_LAYER_* needed only by the shim (real WDK gets them from fwpmk.h)
#endif
#include "../packet/classify.h" // the six classifyFn prototypes

// flowDeleteFn lives in packet/flow_context.c (flow_context.h does not
// declare this callback prototype; extern'ed here in
// FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0 form).
extern VOID NTAPI SkFlowDeleteNotify(UINT16 layerId, UINT32 calloutId,
                                     UINT64 flowContext);


// notifyFn: FwpsCalloutRegister1 requires non-NULL; this driver never
// adds/removes objects other than its own filters, so notifications
// are always accepted (no state kept).
static NTSTATUS NTAPI SkCalloutNotifyStub(FWPS_CALLOUT_NOTIFY_TYPE notifyType,
                                          const GUID *filterKey, FWPS_FILTER1 *filter) {
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

const SK_CALLOUT_DEF g_SkCalloutDefs[SK_LAYER_COUNT] = {
    // ALE_AUTH_CONNECT: outbound connection verdict (hard BLOCK allowed)
    { SkLayerAleAuthConnectV4, &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
      &SK_CALLOUT_ALE_AUTH_CONNECT_V4, &SK_FILTER_ALE_AUTH_CONNECT_V4,
      "SkAleAuthConnectV4",
      SkClassifyAleAuthConnectV4, SkCalloutNotifyStub, NULL, 1 },
    { SkLayerAleAuthConnectV6, &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
      &SK_CALLOUT_ALE_AUTH_CONNECT_V6, &SK_FILTER_ALE_AUTH_CONNECT_V6,
      "SkAleAuthConnectV6",
      SkClassifyAleAuthConnectV6, SkCalloutNotifyStub, NULL, 1 },
    // ALE_RECV_ACCEPT: inbound accept verdict (hard BLOCK allowed)
    { SkLayerAleRecvAcceptV4, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
      &SK_CALLOUT_ALE_RECV_ACCEPT_V4, &SK_FILTER_ALE_RECV_ACCEPT_V4,
      "SkAleRecvAcceptV4",
      SkClassifyAleRecvAcceptV4, SkCalloutNotifyStub, NULL, 1 },
    { SkLayerAleRecvAcceptV6, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
      &SK_CALLOUT_ALE_RECV_ACCEPT_V6, &SK_FILTER_ALE_RECV_ACCEPT_V6,
      "SkAleRecvAcceptV6",
      SkClassifyAleRecvAcceptV6, SkCalloutNotifyStub, NULL, 1 },
    // FLOW_ESTABLISHED: flow context attach/release (always PERMIT; hard BLOCK not allowed)
    { SkLayerFlowEstablishedV4, &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
      &SK_CALLOUT_FLOW_ESTABLISHED_V4, &SK_FILTER_FLOW_ESTABLISHED_V4,
      "SkFlowEstablishedV4",
      SkClassifyFlowEstablishedV4, SkCalloutNotifyStub,
      SkFlowDeleteNotify, 0 },
    { SkLayerFlowEstablishedV6, &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
      &SK_CALLOUT_FLOW_ESTABLISHED_V6, &SK_FILTER_FLOW_ESTABLISHED_V6,
      "SkFlowEstablishedV6",
      SkClassifyFlowEstablishedV6, SkCalloutNotifyStub,
      SkFlowDeleteNotify, 0 },
};

const SK_CALLOUT_DEF *SkCalloutDefById(UINT32 layerId) {
    if (layerId >= SK_LAYER_COUNT)
        return NULL;
    return &g_SkCalloutDefs[layerId];
}
