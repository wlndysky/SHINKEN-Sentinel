// ============================================================================
// control/ioctl.c — control-plane IOCTL dispatch and lifecycle
// (wire protocol: control/protocol.h)
//
// Contracts:
//   * All METHOD_BUFFERED: the I/O manager copies/probes user buffers; this
//     file never dereferences user pointers; protocol structs hold no pointers.
//   * Request gate: g_ControlGateOpen (this module, closed by Quiesce) &&
//     ShRuntimeIsActive(); new IOCTLs during unload fail DEVICE_NOT_READY.
//   * Handle count: ShHandleOpen in EvtFileCreate, paired ShHandleClose in
//     EvtFileDestroy by `counted`; SkControlQuiesce bounded-waits for zero.
//   * Privilege: SkIoctlQueryCallerPrivileged() once at create, stored in the
//     per-handle SK_IOCTL_CONTEXT; query commands open, modify needs privilege.
//   * Validation order (locked, test-anchored): inlen >= sizeof(header) ->
//     Size == actual inlen -> Version -> Flags==0 -> Command < SkCmdMax ->
//     IOCTL function == Command -> privilege for modify -> per-command payload.
//   * Idempotency: RequestId is echoed only, never deduped; idempotency comes
//     from command semantics. REPLACE parses fully to a temp array, then
//     publishes atomically; parse failure never touches the store.
//   * Completion: always WdfRequestSetInformation + WdfRequestComplete.
// ============================================================================
#include <ntddk.h>
#include "../runtime/sk_atomic.h"
#include <wdf.h>
// CTL_CODE/METHOD_BUFFERED/FILE_ANY_ACCESS come from shim/wdk_shim.h
#include "ioctl.h"
#include "../rules/rule_store.h"   // SkRuleStore* (snapshot store, writers PASSIVE)
#include "../rules/rule_engine.h"  // g_SkRuleStats (GET_STATS)
#include "../driver/driver.h"      // SkDeviceCreate (driver/device.c)
#include "../telemetry/event_queue.h" // SkTelemetryStats / SkTelemetryFlush

#ifndef STATUS_REVISION_MISMATCH
#define STATUS_REVISION_MISMATCH ((NTSTATUS)0xC0000059L)
#endif

#define SK_IOCTL_POOL_TAG 0x6F636B53 /* 'Skco' */

#ifdef SHINKEN_HOST_SHIM
// ---- WDF APIs the shim does not declare (real WDK provides SAL-annotated
//      prototypes via wdfrequest.h; redeclaring there breaks C28251) ----
VOID WdfRequestGetParameters(WDFREQUEST request, WDF_REQUEST_PARAMETERS *params);
VOID WdfRequestSetInformation(WDFREQUEST request, ULONG_PTR information);
WDFFILEOBJECT WdfRequestGetFileObject(WDFREQUEST request);
#endif

// ---- exports from driver/device.c used by this module ----
// Device/SDDL/queue/FileObjectConfig creation all lives in device.c.
VOID SkDeviceDelete(void); // WdfObjectDelete(g_SkControlWdfDevice) + clear, idempotent

#ifdef SHINKEN_HOST_SHIM
// ---------------------------------------------------------------------------
// per-handle context type token: shim equivalent of
// WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(SK_IOCTL_CONTEXT) — a unique address is
// the type. device.c passes &SkIoctlContextTypeToken as
// WDF_OBJECT_ATTRIBUTES.ContextTypeInfo; create/destroy/dispatch fetch the
// context with the same token. (Real WDK uses the ioctl.h declaration macro.)
// ---------------------------------------------------------------------------
#endif

// ---------------------------------------------------------------------------
// Privilege decision (at create, in the caller's process context, PASSIVE)
// ---------------------------------------------------------------------------
#ifdef SHINKEN_HOST_TEST
// host tests: defined by tests/ (single-TU include; no default here)
BOOLEAN SkIoctlQueryCallerPrivileged(void);
#else
// Defense in depth on top of the device SDDL (GA only for SY/BA): privileged
// iff System process (PID 4, covers LocalSystem services) or the process
// primary token is Administrators; token lookup failure -> default deny.
PVOID PsReferencePrimaryToken(PEPROCESS process);
VOID PsDereferencePrimaryToken(PVOID token);
BOOLEAN SeTokenIsAdmin(PVOID token);
BOOLEAN SkIoctlQueryCallerPrivileged(void) {
    PVOID token;
    BOOLEAN admin = FALSE;
    if ((HANDLE)(uintptr_t)PsGetCurrentProcessId() == (HANDLE)4)
        return TRUE; // System process / LocalSystem
    token = PsReferencePrimaryToken(IoGetCurrentProcess());
    if (token) {
        admin = SeTokenIsAdmin(token);
        PsDereferencePrimaryToken(token);
    }
    return admin;
}
#endif

// ---------------------------------------------------------------------------
// Request gate / lifecycle state
// ---------------------------------------------------------------------------
static volatile LONG g_ControlGateOpen = 0; // 1=accept IOCTL (runtime Active also required)
static BOOLEAN g_ControlReady = FALSE;      // control device created

#define SK_CONTROL_DRAIN_RETRIES 200 /* 200 * 10ms = 2s bounded handle-drain wait */
#define SK_CONTROL_DRAIN_MS 10

// ---- manual-queue consumer ----
// Dispatch model: the queue is WdfIoQueueDispatchManual; this module runs a
// dedicated consumer thread that pulls requests via WdfIoQueueRetrieveNextRequest.
//
// Ownership:
//   queue owns a request until RetrieveNextRequest returns STATUS_SUCCESS;
//   after retrieval the consumer thread owns it and MUST complete it (dispatch
//   or, once stopping, DEVICE_NOT_READY). Requests still queued after the
//   consumer exits are completed by SkControlQuiesce's WdfIoQueuePurge.
// Wakeup (no busy-spin, no lost wakeup):
//   g_SkDequeueDoorbell is set by SkIoctlEvtQueueReady (WDF ReadyNotify:
//   queue empty->non-empty, registered once in SkControlInit; callback IRQL
//   <= DISPATCH, KeSetEvent only). g_SkDequeueStopEvent is set by Quiesce
//   after the stop flag. Both are auto-reset (ShOps.EventInit); the consumer
//   drains the queue to empty before every wait, so a set arriving between
//   drain and wait keeps the event signaled and the wait returns at once.
//   Event set/wait pairs provide the release/acquire ordering for the stop
//   flag and queue state; no lockless-volatile-only handoff.
// Creators/destroy order: events + ReadyNotify in SkControlInit (events first,
//   ReadyNotify may fire immediately); Quiesce sets stop -> signals stop event
//   -> joins the thread -> only then purges the queue; SkControlDestroy
//   (runtime-gated) deletes the device, which deletes the queue.
extern WDFQUEUE g_SkControlWdfQueue; // filled by device.c at queue creation
static PVOID g_SkDequeueThread = NULL;
static volatile LONG g_SkDequeueStop = 0;
static SHINKEN_EVENT g_SkDequeueDoorbell; // queue became non-empty (ReadyNotify)
static SHINKEN_EVENT g_SkDequeueStopEvent; // stop requested by SkControlQuiesce

#define SK_DEQUEUE_WAIT_MS 0xFFFFFFFFu /* ~infinite: wake on doorbell/stop only */

// EvtIoQueueState (WDF ReadyNotify), IRQL <= DISPATCH_LEVEL: event set only.
static VOID skIoctlEvtQueueReady(WDFQUEUE queue, WDFCONTEXT context) {
    UNREFERENCED_PARAMETER(queue);
    UNREFERENCED_PARAMETER(context);
    ShOps.EventSet(&g_SkDequeueDoorbell);
}


// ---------------------------------------------------------------------------
// Completion helper: every completion path is SetInformation + Complete
// ---------------------------------------------------------------------------
static VOID skComplete(WDFREQUEST request, NTSTATUS status, ULONG_PTR information) {
    WdfRequestSetInformation(request, information);
    WdfRequestComplete(request, status);
}

// ---------------------------------------------------------------------------
// Command dispatch argument pack
// ---------------------------------------------------------------------------
typedef struct _SK_IOCTL_CALL {
    const SHINKEN_IOCTL_HEADER *hdr; // validated input header
    const UINT8 *payload;            // after the header (payloadLen bytes, kernel buffer)
    UINT32 payloadLen;
    UINT8 *out;                      // output buffer (NULL = caller gave none)
    UINT32 outLen;
    ULONG_PTR information;           // out: completion byte count
} SK_IOCTL_CALL;

static BOOLEAN skIsModifyCommand(UINT32 cmd) {
    switch (cmd) {
    case SkCmdAddRule:
    case SkCmdUpdateRule:
    case SkCmdDeleteRule:
    case SkCmdReplaceRuleset:
    case SkCmdClearRules:
    case SkCmdSetDefaultPolicy:
        return TRUE;
    default:
        return FALSE;
    }
}

// Echo output header (RequestId echo; Size = total output bytes)
static VOID skEchoHeader(SK_IOCTL_CALL *c, UINT32 totalBytes) {
    SHINKEN_IOCTL_HEADER *o = (SHINKEN_IOCTL_HEADER *)c->out;
    o->Size = totalBytes;
    o->Version = SK_IOCTL_VERSION;
    o->Command = c->hdr->Command;
    o->Flags = 0;
    o->RequestId = c->hdr->RequestId;
}

// Commands without an output payload: echo the header if there is room
static ULONG_PTR skEchoIfRoom(SK_IOCTL_CALL *c) {
    if (c->out && c->outLen >= sizeof(SHINKEN_IOCTL_HEADER)) {
        skEchoHeader(c, sizeof(SHINKEN_IOCTL_HEADER));
        return sizeof(SHINKEN_IOCTL_HEADER);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// SK_RULE_WIRE wire-format validation/conversion (ADD/UPDATE single rule,
// shared with the REPLACE walk)
//
// pathOffset is relative to this wire; pathChars==0 means no path condition
// (pathOffset must then be 0 and the payload exactly one wire — the caller
// checks the total length).
// ---------------------------------------------------------------------------
static NTSTATUS skValidateWire(const UINT8 *cur, UINT32 remaining, UINT32 *wireBytesOut) {
    const SK_RULE_WIRE *w;
    UINT64 need;
    if (remaining < sizeof(SK_RULE_WIRE))
        return STATUS_INVALID_PARAMETER;
    w = (const SK_RULE_WIRE *)cur;
    if (w->pathChars > SK_RULE_PATH_MAX_CHARS)
        return STATUS_INVALID_PARAMETER;
    if (w->pathChars == 0) {
        if (w->pathOffset != 0)
            return STATUS_INVALID_PARAMETER;
        *wireBytesOut = sizeof(SK_RULE_WIRE);
        return STATUS_SUCCESS;
    }
    if (w->pathOffset < sizeof(SK_RULE_WIRE))
        return STATUS_INVALID_PARAMETER;
    if (w->pathOffset % sizeof(WCHAR))
        return STATUS_INVALID_PARAMETER; // WCHAR alignment
    need = (UINT64)w->pathOffset + (UINT64)w->pathChars * sizeof(WCHAR);
    if (need > remaining)
        return STATUS_INVALID_PARAMETER; // out of range (64-bit sum, no overflow)
    *wireBytesOut = (UINT32)need;
    return STATUS_SUCCESS;
}

// Precondition: skValidateWire passed. appId is computed by the driver
// (FNV-1a64 of lowercase UTF-16, see rule_types.h); without a path condition
// the APPID mask bit and appId are cleared (callers cannot set appId directly).
static VOID skConvertWire(const UINT8 *cur, SK_RULE *out) {
    const SK_RULE_WIRE *w = (const SK_RULE_WIRE *)cur;
    *out = w->rule;
    if (w->pathChars == 0) {
        out->appId = 0;
        out->mask &= ~SK_RULE_M_APPID;
    } else {
        out->appId = SkRuleHashAppPath((PCWSTR)(cur + w->pathOffset), w->pathChars);
        out->mask |= SK_RULE_M_APPID;
    }
}

// ---------------------------------------------------------------------------
// Per-command handlers (statically separated; input is fully parsed to locals
// before any output write — buffered output shares the system buffer with
// input, writing first would destroy the input)
// ---------------------------------------------------------------------------
static NTSTATUS skCmdQueryCapabilities(SK_IOCTL_CALL *c) {
    UINT32 total = sizeof(SHINKEN_IOCTL_HEADER) + sizeof(SK_CAPABILITIES);
    SK_CAPABILITIES *caps;
    if (!c->out || c->outLen < total) {
        c->information = total;
        return STATUS_BUFFER_TOO_SMALL;
    }
    skEchoHeader(c, total);
    caps = (SK_CAPABILITIES *)(c->out + sizeof(SHINKEN_IOCTL_HEADER));
    caps->maxRules = SK_RULE_MAX;
    caps->maxReplaceBytes = SK_REPLACE_MAX_BYTES;
    // Condition support is implicit in the rule contract, not advertised here:
    // ifIndex/SID rule conditions are reserved/unsupported (never implemented
    // in the classify data plane) — SkRuleValidate rejects SK_RULE_M_IFINDEX /
    // SK_RULE_M_SID, so no capability bit claims them.
    caps->supportsActions = 0xF; // bit0 ALLOW bit1 BLOCK bit2 AUDIT bit3 RATE_LIMIT
    caps->protocolVersion = SK_IOCTL_VERSION;
    c->information = total;
    return STATUS_SUCCESS;
}

static BOOLEAN skEnumCountCb(const SK_RULE *rule, PVOID ctx) {
    UNREFERENCED_PARAMETER(rule);
    (*(UINT32 *)ctx)++;
    return TRUE;
}

static NTSTATUS skCmdGetRuleVersion(SK_IOCTL_CALL *c) {
    UINT32 total = sizeof(SHINKEN_IOCTL_HEADER) + sizeof(SK_RULE_VERSION);
    SK_RULE_VERSION *v;
    UINT32 count = 0;
    NTSTATUS status;
    if (!c->out || c->outLen < total) {
        c->information = total;
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = SkRuleStoreEnum(skEnumCountCb, &count); // counted under storeLock
    if (!NT_SUCCESS(status))
        return status;
    skEchoHeader(c, total);
    v = (SK_RULE_VERSION *)(c->out + sizeof(SHINKEN_IOCTL_HEADER));
    v->version = SkRuleStoreVersion();
    v->ruleCount = count;
    v->defaultPolicy = SkRuleStoreDefaultPolicy();
    c->information = total;
    return STATUS_SUCCESS;
}

static NTSTATUS skCmdAddOrUpdateRule(SK_IOCTL_CALL *c, BOOLEAN isUpdate) {
    UINT32 wireBytes;
    NTSTATUS status;
    SK_RULE rule;
    status = skValidateWire(c->payload, c->payloadLen, &wireBytes);
    if (!NT_SUCCESS(status))
        return status;
    if (wireBytes != c->payloadLen)
        return STATUS_INVALID_PARAMETER; // exact length: no trailing bytes
    skConvertWire(c->payload, &rule);
    // semantic field validation lives in the store (SkRuleValidate); id
    // conflict/not-found statuses pass through unchanged
    return isUpdate ? SkRuleStoreUpdate(&rule) : SkRuleStoreAdd(&rule);
}

static NTSTATUS skCmdDeleteRule(SK_IOCTL_CALL *c) {
    const SK_RULE_ID *id;
    if (c->payloadLen != sizeof(SK_RULE_ID))
        return STATUS_INVALID_PARAMETER;
    id = (const SK_RULE_ID *)c->payload;
    return SkRuleStoreDelete(id->ruleId);
}

typedef struct _SK_ENUM_FILL {
    UINT8 *cursor;
    UINT32 remaining;
    UINT32 count;
    BOOLEAN overflow; // rules grew between the two enum passes (no shared lock)
} SK_ENUM_FILL;

static BOOLEAN skEnumFillCb(const SK_RULE *rule, PVOID ctx) {
    SK_ENUM_FILL *f = (SK_ENUM_FILL *)ctx;
    SK_RULE_WIRE *w;
    if (f->remaining < sizeof(SK_RULE_WIRE)) {
        f->overflow = TRUE;
        return FALSE; // stop enumeration
    }
    w = (SK_RULE_WIRE *)f->cursor;
    w->rule = *rule;
    w->pathChars = 0; // only the appId hash is stored; enumeration never replays paths
    w->pathOffset = 0;
    f->cursor += sizeof(SK_RULE_WIRE);
    f->remaining -= sizeof(SK_RULE_WIRE);
    f->count++;
    return TRUE;
}

static NTSTATUS skCmdEnumRules(SK_IOCTL_CALL *c) {
    UINT32 count = 0;
    UINT32 total;
    NTSTATUS status;
    SK_ENUM_FILL fill;
    SK_ENUM_HEADER *eh;
    // first pass: count (output capacity check)
    status = SkRuleStoreEnum(skEnumCountCb, &count);
    if (!NT_SUCCESS(status))
        return status;
    total = sizeof(SHINKEN_IOCTL_HEADER) + sizeof(SK_ENUM_HEADER) +
            count * sizeof(SK_RULE_WIRE);
    if (!c->out || c->outLen < total) {
        c->information = total; // report required byte count
        return STATUS_BUFFER_TOO_SMALL;
    }
    // second pass: fill
    fill.cursor = c->out + sizeof(SHINKEN_IOCTL_HEADER) + sizeof(SK_ENUM_HEADER);
    fill.remaining = c->outLen - sizeof(SHINKEN_IOCTL_HEADER) - sizeof(SK_ENUM_HEADER);
    fill.count = 0;
    fill.overflow = FALSE;
    status = SkRuleStoreEnum(skEnumFillCb, &fill);
    if (!NT_SUCCESS(status))
        return status;
    if (fill.overflow) {
        c->information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }
    total = sizeof(SHINKEN_IOCTL_HEADER) + sizeof(SK_ENUM_HEADER) +
            fill.count * sizeof(SK_RULE_WIRE);
    skEchoHeader(c, total);
    eh = (SK_ENUM_HEADER *)(c->out + sizeof(SHINKEN_IOCTL_HEADER));
    eh->count = fill.count;
    eh->version = SkRuleStoreVersion();
    c->information = total;
    return STATUS_SUCCESS;
}

static NTSTATUS skCmdReplaceRuleset(SK_IOCTL_CALL *c) {
    const SK_REPLACE_HEADER *rh;
    const UINT8 *cur;
    UINT32 remaining, i, wireBytes;
    SK_RULE *rules = NULL;
    NTSTATUS status;
    if (c->payloadLen < sizeof(SK_REPLACE_HEADER))
        return STATUS_INVALID_PARAMETER;
    rh = (const SK_REPLACE_HEADER *)c->payload;
    if (rh->count > SK_RULE_MAX)
        return STATUS_INVALID_PARAMETER;
    if (rh->rulesBytes > SK_REPLACE_MAX_BYTES)
        return STATUS_INVALID_PARAMETER;
    if ((UINT64)sizeof(SK_REPLACE_HEADER) + rh->rulesBytes != c->payloadLen)
        return STATUS_INVALID_PARAMETER; // rulesBytes must match the payload exactly
    cur = c->payload + sizeof(SK_REPLACE_HEADER);
    remaining = rh->rulesBytes;
    if (rh->count != 0) {
        if ((UINT64)rh->count * sizeof(SK_RULE_WIRE) > remaining)
            return STATUS_INVALID_PARAMETER; // cannot hold even count wire headers
        rules = (SK_RULE *)ShOps.AllocPool(rh->count * sizeof(SK_RULE), SK_IOCTL_POOL_TAG);
        if (!rules)
            return STATUS_INSUFFICIENT_RESOURCES;
    }
    // parse fully into a temp array first: any bad wire -> store untouched
    for (i = 0; i < rh->count; i++) {
        status = skValidateWire(cur, remaining, &wireBytes);
        if (!NT_SUCCESS(status))
            goto done;
        skConvertWire(cur, &rules[i]);
        cur += wireBytes;
        remaining -= wireBytes;
    }
    if (remaining != 0) {
        status = STATUS_INVALID_PARAMETER; // the walk must consume the rule area exactly
        goto done;
    }
    // atomic publish: expectedVersion (0=unconditional; nonzero optimistic
    // concurrency, mismatch -> STATUS_RETRY) and rollback semantics are the
    // store's contract (rule_store.h)
    status = SkRuleStoreReplace(rules, rh->count, rh->expectedVersion);
done:
    if (rules)
        ShOps.FreePool(rules, SK_IOCTL_POOL_TAG);
    return status;
}

static NTSTATUS skCmdSetDefaultPolicy(SK_IOCTL_CALL *c) {
    const SK_DEFAULT_POLICY *p;
    if (c->payloadLen != sizeof(SK_DEFAULT_POLICY))
        return STATUS_INVALID_PARAMETER;
    p = (const SK_DEFAULT_POLICY *)c->payload;
    if (p->policy != SkVerdictPermit && p->policy != SkVerdictBlock)
        return STATUS_INVALID_PARAMETER; // only 0/1 (protocol note)
    return SkRuleStoreSetDefaultPolicy(p->policy);
}

static NTSTATUS skCmdGetStats(SK_IOCTL_CALL *c) {
    UINT32 total = sizeof(SHINKEN_IOCTL_HEADER) + sizeof(SK_STATS_OUT);
    SK_STATS_OUT *s;
    if (!c->out || c->outLen < total) {
        c->information = total;
        return STATUS_BUFFER_TOO_SMALL;
    }
    skEchoHeader(c, total);
    s = (SK_STATS_OUT *)(c->out + sizeof(SHINKEN_IOCTL_HEADER));
    s->rules = g_SkRuleStats; // classify updates concurrently; diagnostic read (64-bit, no tearing)
    SkTelemetryStats(&s->eventsPosted, &s->eventsConsumed, &s->eventsDropped,
                     &s->eventsOverflowDropped);
    c->information = total;
    return STATUS_SUCCESS;
}

static NTSTATUS skCmdFlushEvents(SK_IOCTL_CALL *c) {
    UINT32 fixedBytes = sizeof(SHINKEN_IOCTL_HEADER) + sizeof(SK_FLUSH_HEADER);
    UINT32 cap, count;
    SK_FLUSH_HEADER *fh;
    if (!c->out || c->outLen < fixedBytes) {
        c->information = fixedBytes;
        return STATUS_BUFFER_TOO_SMALL;
    }
    cap = (c->outLen - fixedBytes) / SK_EVENT_RECORD_SIZE;
    if (cap > SK_FLUSH_MAX_EVENTS)
        cap = SK_FLUSH_MAX_EVENTS;
    // SkTelemetryFlush (telemetry/event_queue.c): copies the consumed-record
    // ring into fixed-size records (SK_EVENT_RECORD, kernel-owned, no pointers)
    count = SkTelemetryFlush(c->out + fixedBytes, cap, SK_EVENT_RECORD_SIZE);
    skEchoHeader(c, fixedBytes + count * SK_EVENT_RECORD_SIZE);
    fh = (SK_FLUSH_HEADER *)(c->out + sizeof(SHINKEN_IOCTL_HEADER));
    fh->count = count;
    fh->recordSize = SK_EVENT_RECORD_SIZE;
    c->information = fixedBytes + count * SK_EVENT_RECORD_SIZE;
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// KMDF queue callback: the control plane's single entry (wired by device.c)
// ---------------------------------------------------------------------------
VOID SkIoctlEvtDeviceControl(WDFQUEUE queue, WDFREQUEST request, size_t outLen,
                             size_t inLen, ULONG ioControlCode) {
    WDF_REQUEST_PARAMETERS params;
    SHINKEN_IOCTL_HEADER *hdr = NULL;
    size_t realInLen = 0, realOutLen = 0;
    UINT8 *out = NULL;
    NTSTATUS status;
    WDFFILEOBJECT file;
    SK_IOCTL_CONTEXT *ctx = NULL;
    SK_IOCTL_CALL call;
    UINT32 func;
    UNREFERENCED_PARAMETER(queue);
    (void)inLen; // actual lengths come from Retrieve*Buffer (KMDF is the source of truth)

    // request gate: during unload (Quiesce closed it / runtime not Active)
    // fail fast without touching any subsystem
    if (!g_ControlGateOpen || !ShRuntimeIsActive()) {
        skComplete(request, STATUS_DEVICE_NOT_READY, 0);
        return;
    }

    // per-handle context (privilege decided at create; queries tolerate no ctx)
    file = WdfRequestGetFileObject(request);
    if (file) {
#ifdef SHINKEN_HOST_SHIM
        ctx = (SK_IOCTL_CONTEXT *)WdfObjectGetTypedContextWorker(
            file, (PVOID)&SkIoctlContextTypeToken);
#else
        ctx = SkIoctlGetContext(file); // WDF typed accessor (ioctl.h)
#endif
    }

    // Request-parameter self-consistency: IRP IOCTL code must match the
    // callback argument. params.Size is required input for WDF.
    RtlZeroMemory(&params, sizeof(params));
    params.Size = sizeof(params);
    WdfRequestGetParameters(request, &params);
    if (params.Parameters.DeviceIoControl.IoControlCode != ioControlCode) {
        skComplete(request, STATUS_INVALID_DEVICE_REQUEST, 0);
        return;
    }

    // 1) input length >= sizeof(header) (METHOD_BUFFERED: the I/O manager
    //    already copied/probed the user buffer; never touch user pointers here)
    status = WdfRequestRetrieveInputBuffer(request, sizeof(SHINKEN_IOCTL_HEADER),
                                           (PVOID *)&hdr, &realInLen);
    if (!NT_SUCCESS(status)) {
        skComplete(request, status, 0);
        return;
    }
    if (realInLen < sizeof(SHINKEN_IOCTL_HEADER) || realInLen > 0xFFFFFFFFu) {
        skComplete(request, STATUS_BUFFER_TOO_SMALL, 0);
        return;
    }
    // 2) Size field == actual input length (buffer consistency)
    if ((UINT64)hdr->Size != (UINT64)realInLen) {
        skComplete(request, STATUS_INVALID_PARAMETER, 0);
        return;
    }
    // 3) Version
    if (hdr->Version != SK_IOCTL_VERSION) {
        skComplete(request, STATUS_REVISION_MISMATCH, 0);
        return;
    }
    // 4) Flags must be 0
    if (hdr->Flags != 0) {
        skComplete(request, STATUS_INVALID_PARAMETER, 0);
        return;
    }
    // 5) Command range
    if (hdr->Command >= SkCmdMax) {
        skComplete(request, STATUS_INVALID_DEVICE_REQUEST, 0);
        return;
    }
    // 5b) IOCTL function number must equal Command (protocol: same numbering)
    func = (ioControlCode >> 2) & 0xFFFu;
    if (func != (UINT32)(SK_IOCTL_FUNCTION_BASE + hdr->Command)) {
        skComplete(request, STATUS_INVALID_DEVICE_REQUEST, 0);
        return;
    }
    // 6) modify commands require privilege (per-handle, decided at create)
    if (skIsModifyCommand(hdr->Command) && (!ctx || !ctx->privileged)) {
        skComplete(request, STATUS_ACCESS_DENIED, 0);
        return;
    }

    // output buffer (buffered: shares the system buffer with input; parse first)
    if (outLen > 0) {
        status = WdfRequestRetrieveOutputBuffer(request, 0, (PVOID *)&out, &realOutLen);
        if (!NT_SUCCESS(status) || !out) {
            skComplete(request, NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status, 0);
            return;
        }
        if (realOutLen > 0xFFFFFFFFu)
            realOutLen = 0xFFFFFFFFu;
    }

    RtlZeroMemory(&call, sizeof(call));
    call.hdr = hdr;
    call.payload = (const UINT8 *)hdr + sizeof(SHINKEN_IOCTL_HEADER);
    call.payloadLen = (UINT32)realInLen - sizeof(SHINKEN_IOCTL_HEADER);
    call.out = out;
    call.outLen = (UINT32)realOutLen;
    call.information = 0;

    switch (hdr->Command) {
    case SkCmdQueryCapabilities:
        status = skCmdQueryCapabilities(&call);
        break;
    case SkCmdGetRuleVersion:
        status = skCmdGetRuleVersion(&call);
        break;
    case SkCmdAddRule:
        status = skCmdAddOrUpdateRule(&call, FALSE);
        break;
    case SkCmdUpdateRule:
        status = skCmdAddOrUpdateRule(&call, TRUE);
        break;
    case SkCmdDeleteRule:
        status = skCmdDeleteRule(&call);
        break;
    case SkCmdEnumRules:
        status = skCmdEnumRules(&call);
        break;
    case SkCmdReplaceRuleset:
        status = skCmdReplaceRuleset(&call);
        break;
    case SkCmdClearRules:
        status = SkRuleStoreClear();
        break;
    case SkCmdSetDefaultPolicy:
        status = skCmdSetDefaultPolicy(&call);
        break;
    case SkCmdGetStats:
        status = skCmdGetStats(&call);
        break;
    case SkCmdFlushEvents:
        status = skCmdFlushEvents(&call);
        break;
    default: // unreachable after check 5); defensive
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    // successful no-payload commands: echo the header if there is room
    // (RequestId echo only; no dedup — idempotency is by command semantics)
    if (NT_SUCCESS(status) && call.information == 0)
        call.information = skEchoIfRoom(&call);

    skComplete(request, status, call.information);
}

// ---------------------------------------------------------------------------
// File object callbacks (wired by device.c WDF_FILEOBJECT_CONFIG / EvtDestroyCallback)
// ---------------------------------------------------------------------------
VOID SkIoctlEvtFileCreate(WDFDEVICE device, WDFREQUEST request, WDFFILEOBJECT fileObject) {
    SK_IOCTL_CONTEXT *ctx;
    UNREFERENCED_PARAMETER(device);
#ifdef SHINKEN_HOST_SHIM
    ctx = (SK_IOCTL_CONTEXT *)WdfObjectGetTypedContextWorker(
        fileObject, (PVOID)&SkIoctlContextTypeToken);
#else
    ctx = SkIoctlGetContext(fileObject);
#endif
    if (ctx) {
        ctx->privileged = SkIoctlQueryCallerPrivileged(); // decided once at create
        ctx->counted = TRUE;
        ShHandleOpen(); // unload-gate drain object; Destroy pairs by `counted`
    }
    WdfRequestComplete(request, STATUS_SUCCESS);
}

VOID SkIoctlEvtFileCleanup(WDFFILEOBJECT fileObject) {
    // no cleanup-time state: the handle count pairs at Destroy (it stays
    // counted while the file object lives = user handle open blocks unload)
    UNREFERENCED_PARAMETER(fileObject);
}

VOID SkIoctlEvtFileClose(WDFFILEOBJECT fileObject) {
    UNREFERENCED_PARAMETER(fileObject);
}

VOID SkIoctlEvtFileDestroy(WDFOBJECT fileObject) {
    SK_IOCTL_CONTEXT *ctx;
#ifdef SHINKEN_HOST_SHIM
    ctx = (SK_IOCTL_CONTEXT *)WdfObjectGetTypedContextWorker(
        fileObject, (PVOID)&SkIoctlContextTypeToken);
#else
    ctx = SkIoctlGetContext(fileObject);
#endif
    if (ctx && ctx->counted) {
        ctx->counted = FALSE;
        ShHandleClose();
    }
}
// ---------------------------------------------------------------------------
// Manual-queue consumer thread: blocks on doorbell/stop events, then drains
// the queue and dispatches synchronously (dispatch body SkIoctlEvtDeviceControl,
// every path completes synchronously, nothing pended).
//
// Request lifecycle (concurrency state sketch):
//   queued:    owned by the WDF queue (producer = framework/IRP).
//   retrieved: RetrieveNextRequest == STATUS_SUCCESS -> owned by THIS thread;
//              must reach completed exactly once (never dropped on stop).
//   executing: inside SkIoctlEvtDeviceControl; finishes before the thread may
//              exit (Quiesce joins the thread, so no dispatch outlives it).
//   completed: skComplete (dispatched result or DEVICE_NOT_READY when stop is
//              set) or, for requests never retrieved, Quiesce's IoQueuePurge.
//   stop race: stop flag is checked only to choose the completion status of a
//              retrieved request, never to abandon it; loop exit happens only
//              after a drain that returned queue-empty.
// ---------------------------------------------------------------------------
static VOID skDequeueThreadBody(PVOID ctx) {
    WDF_REQUEST_PARAMETERS params;
    WDFREQUEST req;
    NTSTATUS st;
    UNREFERENCED_PARAMETER(ctx);
    for (;;) {
        for (;;) {
            st = WdfIoQueueRetrieveNextRequest(g_SkControlWdfQueue, &req);
            if (!NT_SUCCESS(st))
                break; // queue empty: queue still owns anything it holds
            if (g_SkDequeueStop != 0) {
                skComplete(req, STATUS_DEVICE_NOT_READY, 0); // stop race: retrieved requests still complete
                continue;
            }
            RtlZeroMemory(&params, sizeof(params));
            params.Size = sizeof(params);
            WdfRequestGetParameters(req, &params);
            SkIoctlEvtDeviceControl(g_SkControlWdfQueue, req,
                                    params.Parameters.DeviceIoControl.OutputBufferLength,
                                    params.Parameters.DeviceIoControl.InputBufferLength,
                                    params.Parameters.DeviceIoControl.IoControlCode);
        }
        if (g_SkDequeueStop != 0)
            return; // drained to empty; post-exit arrivals are purged by Quiesce
        // Drain-first, then wait: an arrival after the drain keeps the
        // auto-reset doorbell signaled, so this wait returns at once.
        (VOID)ShOps.EventWaitAny(&g_SkDequeueDoorbell, &g_SkDequeueStopEvent,
                                 SK_DEQUEUE_WAIT_MS);
    }
}


// ---------------------------------------------------------------------------
// Control-plane lifecycle
// ---------------------------------------------------------------------------
NTSTATUS SkControlInit(PDRIVER_OBJECT driverObject) {
    NTSTATUS st;
    UNREFERENCED_PARAMETER(driverObject);
    if (g_ControlReady)
        return STATUS_SUCCESS; // idempotent
    // Control device is created exactly once by DriverEntry (device.c).
    g_ControlReady = TRUE;
    // Events BEFORE ReadyNotify: the callback may fire during registration.
    ShOps.EventInit(&g_SkDequeueDoorbell);
    ShOps.EventInit(&g_SkDequeueStopEvent);
    g_SkDequeueStop = 0;
    st = WdfIoQueueReadyNotify(g_SkControlWdfQueue, skIoctlEvtQueueReady, NULL);
    if (st != STATUS_SUCCESS) {
        g_ControlReady = FALSE;
        return st;
    }
    // Consumer thread; without it the control plane is unusable -> init fails.
    g_SkDequeueThread = NULL;
    st = ShOps.ThreadCreate(skDequeueThreadBody, NULL, &g_SkDequeueThread);
    if (st != STATUS_SUCCESS) {
        g_SkDequeueThread = NULL;
        g_ControlReady = FALSE;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // Open the request gate only after the consumer exists (fenced create:
    // success means the startup decision is made; failure left no consumer).
    SkAtFence();
    g_ControlGateOpen = 1;
    return STATUS_SUCCESS;
}

BOOLEAN SkControlQuiesce(void) {
    ULONG i;
    NTSTATUS jst;
    g_ControlGateOpen = 0; // close request gate: new IOCTLs -> DEVICE_NOT_READY
    SkAtFence();
    // Stop the consumer first: stop flag, then signal its event (the set/wait
    // pair orders the flag; the thread always wakes, even mid-drain).
    SkAtOr32(&g_SkDequeueStop, 1);
    ShOps.EventSet(&g_SkDequeueStopEvent);
    if (g_SkDequeueThread != NULL) {
        jst = ShOps.ThreadJoin(g_SkDequeueThread);
        if (jst != STATUS_SUCCESS) {
            // join failed: thread may still run -> block unload; keep the
            // thread handle, the device, and everything the thread touches.
            ShRuntimeRecordBlock(ShinkenBlockWorkerThreadDrain);
            return FALSE;
        }
        g_SkDequeueThread = NULL; // only after a confirmed exit
    }
    // Consumer exited: re-take queue ownership of never-retrieved requests and
    // let WDF complete them (unload semantics: user side sees failure).
    if (g_SkControlWdfQueue != NULL)
        WdfIoQueuePurge(g_SkControlWdfQueue, NULL, NULL);
    // Bounded wait for per-handle count to reach zero (Destroy pairs decrement)
    for (i = 0; i < SK_CONTROL_DRAIN_RETRIES; i++) {
        if (ShHandlesOpen() == 0)
            return TRUE;
        ShOps.SleepMs(SK_CONTROL_DRAIN_MS);
    }
    if (ShHandlesOpen() == 0)
        return TRUE;
    ShRuntimeRecordBlock(ShinkenBlockHandleContextsOpen); // handles open -> block unload
    return FALSE;
}

VOID SkControlDestroy(void) {
    // Only reached after SkControlQuiesce returned TRUE (runtime gate).
    g_ControlGateOpen = 0;
    if (g_ControlReady) {
        g_ControlReady = FALSE;
        SkDeviceDelete(); // device.c: WdfObjectDelete(control device), idempotent
    }
}
