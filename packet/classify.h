// ============================================================================
// packet/classify.h — WFP classify path (ALE verdict + flow tracking)
//
// Constraints (all classify callbacks at <= DISPATCH_LEVEL): no paged
// allocation; no blocking; no user-pointer access; no inFixedValues
// overrun. Verdict rights (FWPS_CLASSIFY_OUT0.rights, fwpstypes.h):
// actionType is written only while FWPS_RIGHT_ACTION_WRITE is held;
// the callout never grants itself that right. With the bit clear on
// entry a higher-priority component already decided — actionType/rights
// are untouched, but rule evaluation and audit telemetry still run
// (audit records must not depend on arbitration state; only the
// classifyOut write is gated on the right). Finality contract: BLOCK
// always clears the WRITE bit (a veto consumes the right). PERMIT clears
// the WRITE bit ONLY when the matched filter carries
// FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT. Our filters leave this flag unset,
// so other providers may still block a permitted connection. The
// verdict computed here is an internal decision, not a guarantee that
// Windows enforces it. BLOCK only on ALE_AUTH_* (hardBlockAllowed=1);
// FLOW_ESTABLISHED always PERMITs (never forced BLOCK; flow context
// attach only); with missing metadata (pid=0/appId=0), rules with
// pid/appId conditions do not match; telemetry delivery failure never
// affects the verdict.
// ============================================================================
#pragma once
#include <ntddk.h>
#include "../rules/rule_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

// classify entry points (WFP callback prototypes per fwpsk; compat prototypes under shim)
VOID NTAPI SkClassifyAleAuthConnectV4(const FWPS_INCOMING_VALUES0 *inFixed,
                                      const FWPS_INCOMING_METADATA_VALUES0 *meta,
                                      VOID *layerData, const VOID *classifyContext,
                                      const FWPS_FILTER1 *filter, UINT64 flowContext,
                                      FWPS_CLASSIFY_OUT0 *classifyOut);
VOID NTAPI SkClassifyAleAuthConnectV6(const FWPS_INCOMING_VALUES0 *a,
                                      const FWPS_INCOMING_METADATA_VALUES0 *b, VOID *c,
                                      const void *d, const FWPS_FILTER1 *e, UINT64 f,
                                      FWPS_CLASSIFY_OUT0 *g);
VOID NTAPI SkClassifyAleRecvAcceptV4(const FWPS_INCOMING_VALUES0 *a,
                                     const FWPS_INCOMING_METADATA_VALUES0 *b, VOID *c,
                                     const void *d, const FWPS_FILTER1 *e, UINT64 f,
                                     FWPS_CLASSIFY_OUT0 *g);
VOID NTAPI SkClassifyAleRecvAcceptV6(const FWPS_INCOMING_VALUES0 *a,
                                     const FWPS_INCOMING_METADATA_VALUES0 *b, VOID *c,
                                     const void *d, const FWPS_FILTER1 *e, UINT64 f,
                                     FWPS_CLASSIFY_OUT0 *g);
VOID NTAPI SkClassifyFlowEstablishedV4(const FWPS_INCOMING_VALUES0 *a,
                                       const FWPS_INCOMING_METADATA_VALUES0 *b, VOID *c,
                                       const void *d, const FWPS_FILTER1 *e, UINT64 f,
                                       FWPS_CLASSIFY_OUT0 *g);
VOID NTAPI SkClassifyFlowEstablishedV6(const FWPS_INCOMING_VALUES0 *a,
                                       const FWPS_INCOMING_METADATA_VALUES0 *b, VOID *c,
                                       const void *d, const FWPS_FILTER1 *e, UINT64 f,
                                       FWPS_CLASSIFY_OUT0 *g);

// build the evaluation tuple from WFP inputs (internal; tests call directly)
VOID SkClassifyBuildTuple(UINT32 layerId, const FWPS_INCOMING_VALUES0 *inFixed,
                          const FWPS_INCOMING_METADATA_VALUES0 *meta, SK_CLASSIFY_TUPLE *out);
// tuple => verdict => classifyOut (internal; tests call directly).
// filter = the matched FWPS_FILTER1 (its FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT
// decides whether a written PERMIT is final); may be NULL.
VOID SkClassifyApplyVerdict(UINT32 layerId, const SK_CLASSIFY_TUPLE *tuple,
                            const FWPS_FILTER1 *filter, FWPS_CLASSIFY_OUT0 *classifyOut);

#ifdef __cplusplus
}
#endif
