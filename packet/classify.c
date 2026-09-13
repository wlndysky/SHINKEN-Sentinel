// ============================================================================
// packet/classify.c — WFP classify path (ALE verdict + flow tracking;
// contract in classify.h)
//
// Per-layer constraints (layer table in wfp/wfp_callouts.h;
// implementation-side constraints here):
//   * IRQL: all classify callbacks run at <= DISPATCH_LEVEL — no paged
//     allocation (non-paged/stack only), no blocking (no sleep/event
//     wait), no user-pointer access; the snapshot reader path is
//     lock-free (rundown Acquire/Release are __sync atomics).
//   * inFixedValues: check valueCount before indexing, never overrun;
//     with missing metadata (pid=0/appId=0/userId=NULL), rules carrying
//     pid/appId/SID conditions do not match (fail-closed, rule-side
//     semantics, see rule_match.c).
//   * action (verdict-rights contract, FWPS_CLASSIFY_OUT0 in
//     fwpstypes.h, authoritative comment in fwpstypes.idl): a callout
//     may write actionType only while it holds FWPS_RIGHT_ACTION_WRITE
//     ("FWPS_RIGHT_ACTION_WRITE must be held to update the actionType
//     unless executing a veto"; this driver never vetoes), and must
//     NEVER grant itself that right (no rights |=
//     FWPS_RIGHT_ACTION_WRITE anywhere). With the bit clear on entry a
//     higher-priority component already decided: actionType/rights
//     stay untouched (fail-open, no re-arbitration from here) — but
//     rule evaluation and audit telemetry still run, because AUDIT's
//     contract is "record, never change the action": audit visibility
//     must not depend on arbitration state (SkClassifyApplyVerdict
//     gates ONLY the classifyOut write on the right). When this
//     callout owns the verdict it writes actionType and CLEARS the
//     WRITE bit — final within WFP arbitration (kernel execution of
//     the written action is the platform's responsibility; a hardened
//     VM may ignore third-party callout verdicts, see
//     docs/REAL_KERNEL_VALIDATION_20260913.md). BLOCK only on
//     ALE_AUTH_* (hardBlockAllowed=1); layers with
//     hardBlockAllowed==0 (FLOW_ESTABLISHED_*) only PERMIT even when
//     the computed verdict is BLOCK (never forced BLOCK).
//   * FLOW_ESTABLISHED_*: always PERMIT, no rule evaluation; only
//     attach/reuse the flow context (release is flowDelete/RemoveAll's
//     job; attach failure does not affect the permit).
//   * self-injection: packets whose flowContext low 32 bits equal
//     SK_INJECT_TAG (injected by this driver) are permitted directly,
//     skipping rule evaluation (no re-classification/infinite loop;
//     see injection.h).
//   * telemetry delivery failure never affects the verdict.
// ============================================================================
#include <ntddk.h>
#include "../runtime/sk_atomic.h"
#include "classify.h"
#include "flow_context.h"
#include "injection.h"
#include "../telemetry/event_queue.h"
#include "../control/protocol.h" // SK_EVENT_RECORD (audit telemetry record wire format)
#include "../wfp/wfp_callouts.h" // SK_LAYER_ID + hardBlockAllowed
#include "../wfp/wfp_manager.h"  // g_WfpManager (FLOW attach needs the runtime callout id)

// Field-index layout, two variants:
//   shim/host: SK_FIELD_* (wdk_shim.h abstract layout, incl. DIRECTION);
//   real WDK: the four ALE layers of fwpsk.h (AUTH_CONNECT_V4/V6,
//     RECV_ACCEPT_V4/V6) share one relative layout (first 8 items of
//     FWPS_FIELDS_*): 2=IP_LOCAL_ADDRESS, 4=IP_LOCAL_PORT, 5=IP_PROTOCOL,
//     6=IP_REMOTE_ADDRESS, 7=IP_REMOTE_PORT; ALE layers have no
//     DIRECTION field — direction is implied by the layer (connect=out,
//     recv-accept=in).
#ifdef SHINKEN_HOST_SHIM
#define SK_F_PROTOCOL    SK_FIELD_PROTOCOL
#define SK_F_LOCAL_ADDR  SK_FIELD_LOCAL_ADDR
#define SK_F_REMOTE_ADDR SK_FIELD_REMOTE_ADDR
#define SK_F_LOCAL_PORT  SK_FIELD_LOCAL_PORT
#define SK_F_REMOTE_PORT SK_FIELD_REMOTE_PORT
#define SK_F_DIRECTION   SK_FIELD_DIRECTION
#else
#define SK_F_PROTOCOL    5u
#define SK_F_LOCAL_ADDR  2u
#define SK_F_REMOTE_ADDR 6u
#define SK_F_LOCAL_PORT  4u
#define SK_F_REMOTE_PORT 7u
#endif

// telemetry event types (match SK_EVENT_RECORD.type in control/protocol.h)
#define SK_EVT_VERDICT_AUDIT 1
#define SK_EVT_RATE_LIMITED  3

// ---------------------------------------------------------------------------
// Self-injection guard: packets injected by this driver (context low
// 32 bits == SK_INJECT_TAG) are permitted directly — no
// re-classification / infinite loop (injection.h contract).
// ---------------------------------------------------------------------------
static BOOLEAN skClassifySelfInjected(UINT64 flowContext) {
    return SkInjectIsSelf(flowContext);
}

// ---------------------------------------------------------------------------
// inFixedValues field reads (check valueCount first to prevent
// overrun; types per the known ALE layer layout, indices per
// wdk_shim.h SK_FIELD_*)
// ---------------------------------------------------------------------------
static UINT8 skFieldU8(const FWPS_INCOMING_VALUES0 *in, UINT32 idx) {
    if (in->valueCount > idx)
        return in->incomingValue[idx].value.uint8;
    return 0;
}
static UINT16 skFieldU16(const FWPS_INCOMING_VALUES0 *in, UINT32 idx) {
    if (in->valueCount > idx)
        return in->incomingValue[idx].value.uint16;
    return 0;
}

static VOID skFieldAddr(const FWPS_INCOMING_VALUES0 *in, UINT32 idx, UINT32 family,
                        UINT8 out[16]) {
    if (in->valueCount <= idx)
        return; // missing: keep 0 (wildcard semantics decided by the rule-side mask)
    if (family == AF_INET) {
        UINT32 v = in->incomingValue[idx].value.uint32; // network-order uint32
        out[0] = (UINT8)(v >> 24);                      // store big-endian
        out[1] = (UINT8)(v >> 16);
        out[2] = (UINT8)(v >> 8);
        out[3] = (UINT8)v;
    } else {
        FWP_BYTE_ARRAY16 *a = in->incomingValue[idx].value.byteArray16;
        if (a)
            RtlCopyMemory(out, a->byteArray16, 16);
    }
}

// layer => family (internal layer id, see wfp_callouts.h)
static UINT32 skLayerFamily(UINT32 layerId) {
    switch (layerId) {
    case SkLayerAleAuthConnectV4:
    case SkLayerAleRecvAcceptV4:
    case SkLayerFlowEstablishedV4:
        return AF_INET;
    default:
        return AF_INET6;
    }
}

// build the evaluation tuple from WFP inputs (all kernel-owned data; missing fields stay 0/NULL)
VOID SkClassifyBuildTuple(UINT32 layerId, const FWPS_INCOMING_VALUES0 *inFixed,
                          const FWPS_INCOMING_METADATA_VALUES0 *meta,
                          SK_CLASSIFY_TUPLE *out) {
    LARGE_INTEGER now;

    RtlZeroMemory(out, sizeof(*out));
    out->layerId = layerId;
    out->family = skLayerFamily(layerId);
    // layer default direction (connect=out, recv_accept=in)
    if (layerId == SkLayerAleAuthConnectV4 || layerId == SkLayerAleAuthConnectV6)
        out->direction = SK_RULE_DIR_OUT;
    else if (layerId == SkLayerAleRecvAcceptV4 || layerId == SkLayerAleRecvAcceptV6)
        out->direction = SK_RULE_DIR_IN;

    if (inFixed && inFixed->incomingValue) {
        out->protocol = skFieldU8(inFixed, SK_F_PROTOCOL);
        skFieldAddr(inFixed, SK_F_LOCAL_ADDR, out->family, out->localAddr);
        skFieldAddr(inFixed, SK_F_REMOTE_ADDR, out->family, out->remoteAddr);
        out->localPort = skFieldU16(inFixed, SK_F_LOCAL_PORT);
        out->remotePort = skFieldU16(inFixed, SK_F_REMOTE_PORT);
#ifdef SHINKEN_HOST_SHIM
        // shim layout has a DIRECTION field; overrides the layer default when present
        {
            UINT8 dir = skFieldU8(inFixed, SK_F_DIRECTION);
            if (inFixed->valueCount > SK_F_DIRECTION)
                out->direction = (dir == 0) ? SK_RULE_DIR_OUT : SK_RULE_DIR_IN;
        }
#endif
        // real WDK: ALE layers have no DIRECTION field; keep the layer default (above)
    }

    if (meta) {
#ifdef SHINKEN_HOST_SHIM
        if (meta->flags & SK_META_PROCESS_ID)
            out->processId = (UINT32)meta->processId;
        // processPath: FWP_BYTE_BLOB* (lowercased UTF-16; same hash as the control side)
        if ((meta->flags & SK_META_PROCESS_PATH) && meta->processPath_x) {
            FWP_BYTE_BLOB *blob = (FWP_BYTE_BLOB *)meta->processPath_x;
            if (blob->data && blob->size >= sizeof(WCHAR))
                out->appId = SkRuleHashAppPath((PCWSTR)blob->data,
                                               blob->size / sizeof(WCHAR));
        }
#else
        // real WDK: gated by the currentMetadataValues bitmask (fwpsk.h)
        if ((meta->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) &&
            meta->processId)
            out->processId = (UINT32)meta->processId;
        if ((meta->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_PATH) &&
            meta->processPath && meta->processPath->data &&
            meta->processPath->size >= sizeof(WCHAR))
            out->appId = SkRuleHashAppPath((PCWSTR)meta->processPath->data,
                                           meta->processPath->size / sizeof(WCHAR));
#endif
        // userId: the metadata SID does not participate in matching
        // today (same semantics on both builds; rules with SID
        // conditions do not match per documented semantics;
        // rule_types.h §SID)
    }
    KeQuerySystemTime(&now); // safe at any IRQL
    out->nowUtc100ns = (UINT64)now.QuadPart;
}

// ---------------------------------------------------------------------------
// telemetry (never blocks or affects the verdict; failure ignored)
// ---------------------------------------------------------------------------
static VOID skClassifyPostEvent(UINT32 type, UINT64 ruleId,
                                const SK_CLASSIFY_TUPLE *tuple) {
    SK_EVENT_RECORD rec;
    RtlZeroMemory(&rec, sizeof(rec));
    rec.timestampUtc100ns = tuple->nowUtc100ns;
    rec.ruleId = ruleId;
    rec.type = type;
    rec.family = tuple->family;
    rec.protocol = tuple->protocol;
    rec.direction = tuple->direction;
    rec.processId = tuple->processId;
    rec.localPort = tuple->localPort;
    rec.remotePort = tuple->remotePort;
    RtlCopyMemory(rec.localAddr, tuple->localAddr, 16);
    RtlCopyMemory(rec.remoteAddr, tuple->remoteAddr, 16);
    (VOID)SkTelemetryPostRecord(type, &rec, sizeof(rec)); // failure ignored
}

// tuple => verdict => classifyOut (verdict-rights contract in the file
// header; audit-split contract: evaluate + telemetry ALWAYS, gate only
// the actionType/rights write on FWPS_RIGHT_ACTION_WRITE)
VOID SkClassifyApplyVerdict(UINT32 layerId, const SK_CLASSIFY_TUPLE *tuple,
                            FWPS_CLASSIFY_OUT0 *classifyOut) {
    const SK_RULE_SNAPSHOT *snap;
    SK_VERDICT verdict;
    const SK_CALLOUT_DEF *def;

    // A tuple is required by both matching and telemetry; reject malformed
    // direct callers before either path can dereference it.
    if (tuple == NULL)
        return;

    // Audit split (design decision): rule evaluation and telemetry
    // ALWAYS run; only the classifyOut write is gated on the write
    // right. AUDIT's contract is "record, never change the action", so
    // audit visibility must not depend on arbitration state — skipping
    // evaluation when another component already decided would lose
    // audit records exactly in the interesting case. ALE layers
    // classify per connection, not per packet, so the snapshot scan
    // cost is bounded. Snapshot reader protocol: Acquire (success =
    // stable reference) -> evaluate -> Release; strict pairing, no
    // early-out between them. Acquire NULL (store closed) => default
    // PERMIT (reason=SnapshotUnavailable), Release(NULL) is a no-op.
    snap = SkRuleStoreAcquire();
    SkRuleEvaluate(snap, tuple, &verdict);
    SkRuleStoreRelease(snap);

    // Telemetry (never blocks, never affects the verdict; failure ignored)
    if (verdict.rateLimited)
        skClassifyPostEvent(SK_EVT_RATE_LIMITED, verdict.ruleId, tuple);
    else if (verdict.action == SkVerdictAudit)
        skClassifyPostEvent(SK_EVT_VERDICT_AUDIT, verdict.ruleId, tuple);

    // Verdict-rights gate (FWPS_CLASSIFY_OUT0.rights, fwpstypes.h):
    // without FWPS_RIGHT_ACTION_WRITE — or without classifyOut at all —
    // a higher-priority component already decided: actionType and
    // rights stay untouched. This callout never re-arbitrates a lost
    // decision and never grants itself the write right.
    if (classifyOut == NULL ||
        (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
        return;

    def = SkCalloutDefById(layerId);
    if (verdict.action == SkVerdictBlock && def && def->hardBlockAllowed) {
        // Hard verdict only on ALE_AUTH_* layers. Clearing the WRITE
        // right (never setting it) makes this callout's action final
        // within WFP arbitration: lower-weight sublayers can no longer
        // overwrite it. (Computed verdict != kernel execution; see the
        // file header.)
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }
    // PERMIT (default policy / ALLOW / AUDIT / fail-open on layers
    // that disallow hard BLOCK): once written, this callout's action
    // is final as well, so the WRITE right is cleared here too — the
    // fwpstypes.h contract (FWPS_CLASSIFY_OUT0 / FWPS_RIGHT_ACTION_WRITE)
    // never requires PERMIT to keep the bit.
    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

// ---------------------------------------------------------------------------
// six classify entry points (WFP callbacks; <= DISPATCH)
// ---------------------------------------------------------------------------

// ALE verdict common body
static VOID skClassifyAleCommon(UINT32 layerId,
                                const FWPS_INCOMING_VALUES0 *inFixed,
                                const FWPS_INCOMING_METADATA_VALUES0 *meta,
                                UINT64 flowContext,
                                FWPS_CLASSIFY_OUT0 *classifyOut) {
    SK_CLASSIFY_TUPLE tuple;

    if (classifyOut == NULL)
        return;
    if (skClassifySelfInjected(flowContext)) {
        // self-injected packet: permit directly (verdict-rights contract:
        // write only while holding the WRITE right; action final)
        if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) {
            classifyOut->actionType = FWP_ACTION_PERMIT;
            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        }
        return;
    }
    SkClassifyBuildTuple(layerId, inFixed, meta, &tuple);
    SkClassifyApplyVerdict(layerId, &tuple, classifyOut);
}

// FLOW_ESTABLISHED common body: always PERMIT + attach the flow
// context (flowDelete/RemoveAll own release; attach failure does not
// affect the permit).
static VOID skClassifyFlowCommon(UINT32 layerId,
                                 const FWPS_INCOMING_METADATA_VALUES0 *meta,
                                 UINT64 flowContext,
                                 FWPS_CLASSIFY_OUT0 *classifyOut) {
    UINT32 runtimeId;

    if (classifyOut == NULL)
        return;
    // FLOW_ESTABLISHED: always PERMIT, never BLOCK — written only under
    // the verdict-rights contract (final once written). Without the
    // WRITE right a higher-priority component already decided; the
    // flow-context attach below is bookkeeping and still runs.
    if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
    if (skClassifySelfInjected(flowContext))
        return;
#ifdef SHINKEN_HOST_SHIM
    if (meta == NULL || meta->flowHandle == 0)
        return;
#else
    // real WDK: flowHandle is gated by the currentMetadataValues bitmask
    if (meta == NULL ||
        !(meta->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) ||
        meta->flowHandle == 0)
        return;
#endif
    runtimeId = g_WfpManager.callouts[layerId].calloutRuntimeId;
    if (runtimeId != 0) {
        SK_FLOW_CTX *ctx = SkFlowAttach(meta->flowHandle, layerId, runtimeId);
        if (ctx) {
            SkAtAdd64((volatile LONG64 *)&ctx->packetsSeen, 1); // statistics
            SkFlowRelease(ctx); // attach reference belongs to the flow table; this call keeps none
        }
    }
}

VOID NTAPI SkClassifyAleAuthConnectV4(const FWPS_INCOMING_VALUES0 *inFixed,
                                      const FWPS_INCOMING_METADATA_VALUES0 *meta,
                                      VOID *layerData, const VOID *classifyContext,
                                      const FWPS_FILTER1 *filter, UINT64 flowContext,
                                      FWPS_CLASSIFY_OUT0 *classifyOut) {
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    skClassifyAleCommon(SkLayerAleAuthConnectV4, inFixed, meta, flowContext,
                        classifyOut);
}

VOID NTAPI SkClassifyAleAuthConnectV6(const FWPS_INCOMING_VALUES0 *a,
                                      const FWPS_INCOMING_METADATA_VALUES0 *b, VOID *c,
                                      const void *d, const FWPS_FILTER1 *e, UINT64 f,
                                      FWPS_CLASSIFY_OUT0 *g) {
    UNREFERENCED_PARAMETER(c);
    UNREFERENCED_PARAMETER(d);
    UNREFERENCED_PARAMETER(e);
    skClassifyAleCommon(SkLayerAleAuthConnectV6, a, b, f, g);
}

VOID NTAPI SkClassifyAleRecvAcceptV4(const FWPS_INCOMING_VALUES0 *a,
                                     const FWPS_INCOMING_METADATA_VALUES0 *b, VOID *c,
                                     const void *d, const FWPS_FILTER1 *e, UINT64 f,
                                     FWPS_CLASSIFY_OUT0 *g) {
    UNREFERENCED_PARAMETER(c);
    UNREFERENCED_PARAMETER(d);
    UNREFERENCED_PARAMETER(e);
    skClassifyAleCommon(SkLayerAleRecvAcceptV4, a, b, f, g);
}

VOID NTAPI SkClassifyAleRecvAcceptV6(const FWPS_INCOMING_VALUES0 *a,
                                     const FWPS_INCOMING_METADATA_VALUES0 *b, VOID *c,
                                     const void *d, const FWPS_FILTER1 *e, UINT64 f,
                                     FWPS_CLASSIFY_OUT0 *g) {
    UNREFERENCED_PARAMETER(c);
    UNREFERENCED_PARAMETER(d);
    UNREFERENCED_PARAMETER(e);
    skClassifyAleCommon(SkLayerAleRecvAcceptV6, a, b, f, g);
}

VOID NTAPI SkClassifyFlowEstablishedV4(const FWPS_INCOMING_VALUES0 *a,
                                       const FWPS_INCOMING_METADATA_VALUES0 *b, VOID *c,
                                       const void *d, const FWPS_FILTER1 *e, UINT64 f,
                                       FWPS_CLASSIFY_OUT0 *g) {
    UNREFERENCED_PARAMETER(a);
    UNREFERENCED_PARAMETER(c);
    UNREFERENCED_PARAMETER(d);
    UNREFERENCED_PARAMETER(e);
    skClassifyFlowCommon(SkLayerFlowEstablishedV4, b, f, g);
}

VOID NTAPI SkClassifyFlowEstablishedV6(const FWPS_INCOMING_VALUES0 *a,
                                       const FWPS_INCOMING_METADATA_VALUES0 *b, VOID *c,
                                       const void *d, const FWPS_FILTER1 *e, UINT64 f,
                                       FWPS_CLASSIFY_OUT0 *g) {
    UNREFERENCED_PARAMETER(a);
    UNREFERENCED_PARAMETER(c);
    UNREFERENCED_PARAMETER(d);
    UNREFERENCED_PARAMETER(e);
    skClassifyFlowCommon(SkLayerFlowEstablishedV6, b, f, g);
}
