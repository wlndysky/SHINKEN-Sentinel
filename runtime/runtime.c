// ============================================================================
// runtime/runtime.c — unified runtime state machine / rundown / WFP object
// tracking (full proof in docs/UNLOAD_SAFETY.md).
//
// Unload policy:
//   a) All drains complete within bounded retries => QUIESCENT => destroy
//      allowed, normal return.
//   b) Any drain failure => UNLOAD_BLOCKED (RESIDENT_FAILURE): EvtDriverUnload
//      parks in ShRuntimeBlockUnloadForever(), KMDF cannot finish the unload,
//      the driver image stays resident, WFP callback code stays valid.
// ============================================================================
#include <ntddk.h>
#include "sk_atomic.h"
#include "runtime.h"

// ---------------------------------------------------------------------------
static SHINKEN_RUNTIME_STATE g_State = ShinkenUninitialized;
static SHINKEN_BLOCK_REASON g_BlockReason = ShinkenBlockNone; // first cause (kept, idempotent)
// Full block-reason history (including later causes): residency is never an
// unexplained hang — a debugger can inspect g_BlockHistory/g_BlockHistoryCount;
// each record also triggers one Diag.
#define SHINKEN_BLOCK_HISTORY_CAP 16
static SHINKEN_BLOCK_REASON g_BlockHistory[SHINKEN_BLOCK_HISTORY_CAP];
static volatile LONG g_BlockHistoryCount;
static SHINKEN_RUNDOWN g_InjectionRundown; // in-flight injection gate (see .h proof)
static volatile LONG64 g_HandlesOpen = 0;  // per-handle context count

SHINKEN_RUNDOWN ShRundownBfe;
SHINKEN_RUNDOWN ShRundownWorkItem;
SHINKEN_TEST_HOOK *ShTestHook;

static const char *const g_StateNames[] = {"Uninitialized", "Active", "Teardown", "Quiescent",
                                           "UNLOAD_BLOCKED"};
static const char *const g_ReasonNames[] = {
    "None",
    "SensorCalloutBusy",
    "DivertCalloutBusy",
    "FlowContextDrain",
    "InjectionDrain",
    "WorkItemDrain",
    "EventThreadDrain",
    "HandleContextsOpen",
    "BfeCallbackActive",
    "BfeUnsubscribe",
    "EngineClose",
    "RundownStuck",
    "RundownUnderflow",
    "WorkerThreadDrain",
};

// ---------------------------------------------------------------------------
// Kernel default ops table (IR build; host-test build provides and overrides
// the whole ShOps in tests/)
#ifndef SHINKEN_HOST_TEST
static NTSTATUS shkUnregById(UINT32 id) { return FwpsCalloutUnregisterById0(id); }
static NTSTATUS shkUnregByKey(const GUID *key) { return FwpsCalloutUnregisterByKey0(key); }
static NTSTATUS shkFilterDelById(HANDLE engine, UINT64 filterId) {
    return FwpmFilterDeleteById0(engine, filterId);
}
static NTSTATUS shkFilterDelByKey(HANDLE engine, const GUID *key) {
    return FwpmFilterDeleteByKey0(engine, key);
}
static NTSTATUS shkCalloutDelById(HANDLE engine, UINT32 id) {
    return FwpmCalloutDeleteById0(engine, id);
}
static NTSTATUS shkCalloutDelByKey(HANDLE engine, const GUID *key) {
    return FwpmCalloutDeleteByKey0(engine, key);
}
static NTSTATUS shkProviderDelByKey(HANDLE engine, const GUID *key) {
    return FwpmProviderDeleteByKey0(engine, key);
}
static NTSTATUS shkSubLayerDelByKey(HANDLE engine, const GUID *key) {
    return FwpmSubLayerDeleteByKey0(engine, key);
}
static NTSTATUS shkEngineClose(HANDLE engine) { return FwpmEngineClose0(engine); }
static NTSTATUS shkInjectionDestroy(HANDLE h) { return FwpsInjectionHandleDestroy0(h); }
static NTSTATUS shkFlowRemoveContext(UINT64 flowId, UINT16 layerId, UINT32 calloutId) {
    return FwpsFlowRemoveContext0(flowId, layerId, calloutId);
}
static NTSTATUS shkBfeUnsubscribe(HANDLE h) { return FwpmBfeStateUnsubscribeChanges0(h); }
static NTSTATUS shkWorkItemFlush(PVOID item) {
    WdfWorkItemFlush(item); // synchronous: waits for the work item routine to return
    return STATUS_SUCCESS;
}
static PVOID shkAllocPool(ULONG size, ULONG tag) {
#ifndef SHINKEN_HOST_SHIM
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, tag); // WDK-recommended form
#else
    return ExAllocatePoolWithTag(NonPagedPoolNx, size, tag); // shim lacks ExAllocatePool2
#endif
}
static VOID shkFreePool(PVOID block, ULONG tag) { ExFreePoolWithTag(block, tag); }

// --- thread/event default implementations ---
static NTSTATUS shkThreadCreate(SHINKEN_THREAD_FN body, PVOID ctx, PVOID *outThreadObject) {
    return ShThreadCreateFenced(body, ctx, outThreadObject); // startup fence (below)
}
static NTSTATUS shkThreadJoin(PVOID threadObject) {
    NTSTATUS st = KeWaitForSingleObject(threadObject, Executive, KernelMode, FALSE, NULL);
    ObfDereferenceObject(threadObject);
    return st;
}
static VOID shkEventInit(SHINKEN_EVENT *ev) {
    KeInitializeEvent((PKEVENT)ev, SynchronizationEvent, FALSE);
}
static VOID shkEventSet(SHINKEN_EVENT *ev) { KeSetEvent((PKEVENT)ev, 0, FALSE); }
static BOOLEAN shkEventWait(SHINKEN_EVENT *ev, ULONG timeoutMs) {
    LARGE_INTEGER to;
    to.QuadPart = -(LONGLONG)timeoutMs * 10000; // relative timeout (negative)
    return KeWaitForSingleObject((PKEVENT)ev, Executive, KernelMode, FALSE, &to) == STATUS_SUCCESS;
}
static BOOLEAN shkEventWaitAny(SHINKEN_EVENT *a, SHINKEN_EVENT *b, ULONG timeoutMs) {
    PVOID objs[2];
    LARGE_INTEGER to;
    objs[0] = (PKEVENT)a;
    objs[1] = (PKEVENT)b;
    to.QuadPart = -(LONGLONG)timeoutMs * 10000; // relative timeout (negative)
    return KeWaitForMultipleObjects(2, objs, WaitAny, Executive, KernelMode, FALSE, &to,
                                    NULL) != STATUS_TIMEOUT;
}
#ifndef SHINKEN_HOST_SHIM
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
#endif
static KIRQL shkLockAcquire(PEX_SPIN_LOCK lock) { return ExAcquireSpinLockExclusive(lock); }
#ifndef SHINKEN_HOST_SHIM
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(DISPATCH_LEVEL)
#endif
static VOID shkLockRelease(PEX_SPIN_LOCK lock, KIRQL oldIrql) {
    ExReleaseSpinLockExclusive(lock, oldIrql);
}
static VOID shkSleepMs(ULONG ms) {
    LARGE_INTEGER to;
    to.QuadPart = -(LONGLONG)ms * 10000;
    KeDelayExecutionThread(KernelMode, FALSE, &to);
}
static VOID shkDiag(const char *msg) { DbgPrint(msg); }

SHINKEN_OPS ShOps = {
    shkUnregById,        shkUnregByKey,        shkFilterDelById,     shkFilterDelByKey,
    shkCalloutDelById,   shkCalloutDelByKey,   shkProviderDelByKey,  shkSubLayerDelByKey,
    shkEngineClose,      shkInjectionDestroy,  shkFlowRemoveContext, shkBfeUnsubscribe,
    shkWorkItemFlush,    shkAllocPool,         shkFreePool,          shkThreadCreate,
    shkThreadJoin,       shkEventInit,         shkEventSet,          shkEventWait,
    shkEventWaitAny,
    shkLockAcquire,      shkLockRelease,       shkSleepMs,           shkDiag,
};
#endif // !SHINKEN_HOST_TEST

// ---------------------------------------------------------------------------
// Thread startup fence (kernel build; host fence-test TUs opt in via
// SHINKEN_HOST_FENCE_TEST and supply the kernel-API stubs).
//
// Contract (IRQL: PASSIVE_LEVEL only):
//   success => *outThreadObject holds a referenced thread object the caller
//              owns; released only via ThreadJoin (wait + deref exactly once).
//   failure => no running untracked thread exists: the spawned wrapper was
//              abort-gated before the body ran and reaped via the original handle.
// The startup context is consumed and freed by the wrapper on every path
// after the gate opens; the creator frees it only if the thread never spawned.
// ---------------------------------------------------------------------------
#if !defined(SHINKEN_HOST_TEST) || defined(SHINKEN_HOST_FENCE_TEST)
#define SHINKEN_THREAD_STARTUP_TAG 'fThS' // 'ShTf' startup context pool tag

typedef struct _SHINKEN_THREAD_STARTUP {
    SHINKEN_THREAD_FN body;
    PVOID ctx;
    KEVENT startup; // creator -> thread: object published, run the body
    KEVENT abort;   // creator -> thread: reference failed, exit without the body
} SHINKEN_THREAD_STARTUP;

#ifndef SHINKEN_HOST_SHIM
// ntddk.h declares ZwClose but not ZwWaitForSingleObject (it lives in
// ntifs.h/zwapi.h); declare it locally instead of pulling ntifs.h in.
NTSYSAPI NTSTATUS NTAPI ZwWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable,
                                              PLARGE_INTEGER Timeout);
#endif

static PVOID shkFenceAllocStartup(ULONG size) {
#ifndef SHINKEN_HOST_SHIM
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, SHINKEN_THREAD_STARTUP_TAG);
#else
    return ExAllocatePoolWithTag(NonPagedPoolNx, size, SHINKEN_THREAD_STARTUP_TAG);
#endif
}

static VOID shkThreadFenceWrapper(PVOID ctx) {
    SHINKEN_THREAD_STARTUP *sc = (SHINKEN_THREAD_STARTUP *)ctx;
    PVOID gate[2];
    NTSTATUS wait;
    SHINKEN_THREAD_FN body;
    PVOID bodyCtx;

    // Gate first: the body and its context are touched only after the
    // creator's startup/abort decision arrives.
    gate[0] = &sc->startup;
    gate[1] = &sc->abort;
    wait = KeWaitForMultipleObjects(2, gate, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);
    body = sc->body;
    bodyCtx = sc->ctx;
    ExFreePoolWithTag(sc, SHINKEN_THREAD_STARTUP_TAG); // thread-side free, every path
    if (wait == STATUS_WAIT_0) // startup index only; abort or wait error exits silently
        body(bodyCtx);
}

NTSTATUS ShThreadCreateFenced(SHINKEN_THREAD_FN body, PVOID ctx, PVOID *outThreadObject) {
    NTSTATUS st;
    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES oa;
    HANDLE handle = NULL;
    SHINKEN_THREAD_STARTUP *sc;

    *outThreadObject = NULL;
    sc = (SHINKEN_THREAD_STARTUP *)shkFenceAllocStartup(sizeof(SHINKEN_THREAD_STARTUP));
    if (!sc)
        return STATUS_INSUFFICIENT_RESOURCES;
    sc->body = body;
    sc->ctx = ctx;
    KeInitializeEvent(&sc->startup, NotificationEvent, FALSE);
    KeInitializeEvent(&sc->abort, NotificationEvent, FALSE);
    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.RootDirectory = NULL;
    oa.ObjectName = NULL;
    oa.Attributes = OBJ_KERNEL_HANDLE;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;
    st = PsCreateSystemThread(&handle, THREAD_ALL_ACCESS, &oa, NULL, &clientId,
                              shkThreadFenceWrapper, sc);
    if (st < 0) {
        ExFreePoolWithTag(sc, SHINKEN_THREAD_STARTUP_TAG); // never spawned: creator still owns it
        return st;
    }
    st = ObReferenceObjectByHandle(handle, THREAD_ALL_ACCESS, NULL, KernelMode,
                                   outThreadObject, NULL);
    if (st >= 0) {
        KeSetEvent(&sc->startup, 0, FALSE); // open the gate: the body may run now
        ZwClose(handle);                    // the object reference outlives the handle
        return STATUS_SUCCESS;
    }
    // Reference failed but the thread is spawned: abort-gate it, then reap it
    // via the original handle (never closed before this wait). The wrapper
    // exits without running the body; no untracked thread survives.
    KeSetEvent(&sc->abort, 0, FALSE);
    ZwWaitForSingleObject(handle, FALSE, NULL);
    ZwClose(handle);
    *outThreadObject = NULL;
    return st;
}
#endif // !SHINKEN_HOST_TEST || SHINKEN_HOST_FENCE_TEST

// ---------------------------------------------------------------------------
// state machine
// ---------------------------------------------------------------------------
VOID ShRuntimeInit(void) {
    if (g_State == ShinkenUninitialized) {
        g_BlockReason = ShinkenBlockNone;
        g_BlockHistoryCount = 0;
        ShRundownInit(&ShRundownBfe, "BfeCallback");
        ShRundownInit(&ShRundownWorkItem, "IoWorkItem");
        ShRundownInit(&g_InjectionRundown, "Injection");
    }
}

VOID ShRuntimeActivate(void) {
    ShRuntimeInit();
    if (g_State == ShinkenUninitialized)
        g_State = ShinkenActive;
    // Re-activating after Teardown/terminal is a programming error: keep state (diagnostically visible)
}

SHINKEN_RUNTIME_STATE ShRuntimeState(void) { return g_State; }
SHINKEN_BLOCK_REASON ShRuntimeBlockReason(void) { return g_BlockReason; }

const char *ShRuntimeStateName(SHINKEN_RUNTIME_STATE st) {
    return g_StateNames[(unsigned)st % 5];
}
const char *ShRuntimeBlockReasonName(SHINKEN_BLOCK_REASON why) {
    return g_ReasonNames[(unsigned)why % 14];
}

BOOLEAN ShRuntimeIsActive(void) { return g_State == ShinkenActive; }

BOOLEAN ShRuntimeDestroyAllowed(void) {
    return g_State == ShinkenQuiescent || g_State == ShinkenUninitialized;
}

BOOLEAN ShRuntimeBeginTeardown(void) {
    if (g_State == ShinkenTeardown)
        return TRUE; // idempotent
    if (g_State != ShinkenActive)
        return g_State == ShinkenUninitialized; // never activated: nothing to drain
    g_State = ShinkenTeardown;
    return TRUE;
}

VOID ShRuntimeRecordBlock(SHINKEN_BLOCK_REASON why) {
    LONG idx = SkAtAdd32(&g_BlockHistoryCount, 1);
    if (idx < SHINKEN_BLOCK_HISTORY_CAP)
        g_BlockHistory[idx] = why; // later causes also kept in order (beyond capacity: counted only)
    if (g_BlockReason == ShinkenBlockNone)
        g_BlockReason = why; // keep first cause
    ShOps.Diag("SHINKEN: unload block reason recorded (see ShRuntimeBlockHistory*)");
}

ULONG ShRuntimeBlockHistoryCount(void) { return (ULONG)g_BlockHistoryCount; }

SHINKEN_BLOCK_REASON ShRuntimeBlockHistoryAt(ULONG index) {
    if (index >= SHINKEN_BLOCK_HISTORY_CAP || (LONG)index >= g_BlockHistoryCount)
        return ShinkenBlockNone;
    return g_BlockHistory[index];
}

VOID ShRuntimeEnterQuiescent(void) {
    if (g_State == ShinkenTeardown)
        g_State = ShinkenQuiescent;
}

VOID ShRuntimeEnterUnloadBlocked(SHINKEN_BLOCK_REASON why) {
    ShRuntimeRecordBlock(why);
    if (g_State != ShinkenUnloadBlocked) {
        g_State = ShinkenUnloadBlocked;
        ShOps.Diag("SHINKEN: runtime enter UNLOAD_BLOCKED (resident failure)");
    }
}

VOID ShRuntimeBlockUnloadForever(void) {
    ULONG iter = 0;
    ShOps.Diag("SHINKEN: unload blocked; driver image stays resident; EvtDriverUnload parks");
    for (;;) {
        if (ShTestHook && ShTestHook->AbortBlockedWait && ShTestHook->AbortBlockedWait(iter))
            return; // tests only: ShTestHook is always NULL in kernel builds
        ShOps.SleepMs(1000);
        iter++;
    }
}

BOOLEAN ShRuntimeRunUnload(BOOLEAN (*sensorQuiesce)(VOID), BOOLEAN (*divertQuiesce)(VOID),
                           VOID (*sensorCleanup)(VOID), VOID (*divertCleanup)(VOID)) {
    BOOLEAN sensorOk = TRUE, divertOk = TRUE;

    ShRuntimeBeginTeardown(); // Active -> Teardown (rejects new async refs)

    if (sensorQuiesce)
        sensorOk = sensorQuiesce(); // on failure it already called ShRuntimeRecordBlock
    if (divertQuiesce)
        divertOk = divertQuiesce();

    if (!sensorOk || !divertOk || g_State == ShinkenUnloadBlocked) {
        // Policy b: any subsystem not quiescent => no destroy, driver stays resident
        if (g_BlockReason == ShinkenBlockNone)
            ShRuntimeRecordBlock(ShinkenBlockRundownStuck);
        ShRuntimeEnterUnloadBlocked(g_BlockReason);
        ShRuntimeBlockUnloadForever();
        return FALSE;
    }
    ShRuntimeEnterQuiescent();
    // destroy phase: ShRuntimeDestroyAllowed() is TRUE; each cleanup still validates item by item
    if (sensorCleanup)
        sensorCleanup();
    if (divertCleanup)
        divertCleanup();
    // Post-cleanup re-check: cleanup may have newly discovered a drain failure
    // (e.g. rule snapshot readers stuck, SkRuleStoreShutdown returns FALSE)
    // and called EnterUnloadBlocked — once blocked, must stay resident, never
    // return TRUE (returning lets KMDF unload the image while callbacks/
    // readers may still reference its code). No unloadable "Quiescent with
    // half-finished cleanup" state exists.
    if (g_State == ShinkenUnloadBlocked) {
        ShRuntimeBlockUnloadForever();
        return FALSE;
    }
    return TRUE;
}

// Underflow report point for rundown.c (kept here: needs g_State/RecordBlock)
VOID ShRuntimeReportUnderflow(SHINKEN_RUNDOWN *r) {
    SkAtAdd32(&r->underflows, 1);
    ShRuntimeRecordBlock(ShinkenBlockRundownUnderflow);
    if (g_State == ShinkenTeardown)
        ShRuntimeEnterUnloadBlocked(ShinkenBlockRundownUnderflow);
}


// ---------------------------------------------------------------------------
// WFP object tracking
// ---------------------------------------------------------------------------
VOID ShWfpObjectInit(SHINKEN_WFP_OBJECT *o, const char *name, UINT32 calloutId, UINT64 filterId,
                     const GUID *key) {
    o->name = name;
    o->id = calloutId;
    o->filterId = filterId;
    o->key = key;
    o->state = ShWfpUnregistered;
    o->busyRetries = 0;
    o->lastStatus = STATUS_SUCCESS;
}

VOID ShWfpObjectMark(SHINKEN_WFP_OBJECT *o, SHINKEN_WFP_OBJECT_STATE st) { o->state = st; }

// ---------------------------------------------------------------------------
// Unregister/delete error classification (teardown discipline):
//   * STATUS_SUCCESS or the API's documented "object not found" status
//     (FWP_E_*_NOT_FOUND, values in runtime.h) => Deleted: confirmed clear,
//     no more callbacks possible;
//   * STATUS_DEVICE_BUSY => transient: bounded retries (unregister strips
//     flow contexts between rounds);
//   * Any other status => **unknown error**: clear state untrustworthy,
//     never mark Deleted; enter ShWfpLeaked terminal state — id/key/
//     lastStatus/busyRetries all retained, caller records the block reason
//     and stays resident; while an unconfirmed object exists, do not close
//     the engine, free pools, or let DriverUnload return.
// ---------------------------------------------------------------------------
NTSTATUS ShWfpUnregisterCalloutById(SHINKEN_WFP_OBJECT *o, PVOID busyCtx,
                                    VOID (*busyCleanup)(PVOID), ULONG maxBusyRetries,
                                    ULONG delayMs) {
    NTSTATUS st;
    ULONG attempt;

    if (o->state == ShWfpDeleted || o->state == ShWfpUnregistered)
        return STATUS_SUCCESS; // idempotent: not on the books
    if (o->state == ShWfpLeaked)
        return STATUS_DEVICE_BUSY; // terminal: never touch again, caller stays resident
    for (attempt = 0;; attempt++) {
        st = ShOps.UnregisterCalloutById(o->id);
        o->lastStatus = st;
        if (st == STATUS_SUCCESS || st == FWP_E_CALLOUT_NOT_FOUND) {
            // Success = code-level safety point: after FwpsCalloutUnregisterById0
            // succeeds, WFP guarantees classifyFn/notifyFn/flowDeleteFn are no
            // longer called (UNLOAD_SAFETY.md §2); NOT_FOUND = documented "not registered".
            o->state = ShWfpDeleted;
            o->busyRetries = attempt;
            return st;
        }
        if (st != STATUS_DEVICE_BUSY) {
            o->busyRetries = attempt;
            o->state = ShWfpLeaked; // unknown error: clear state untrustworthy => residency
            return st;
        }
        if (attempt >= maxBusyRetries) {
            // BUSY root cause is usually an associated flow context; retries exhausted => LEAKED + residency
            o->busyRetries = attempt + 1;
            o->state = ShWfpLeaked;
            return st;
        }
        if (busyCleanup)
            busyCleanup(busyCtx); // strip flow contexts between rounds (see SkRemoveFlowContexts)
        ShOps.SleepMs(delayMs);
    }
}

NTSTATUS ShWfpUnregisterCalloutByKey(SHINKEN_WFP_OBJECT *o, ULONG maxBusyRetries, ULONG delayMs) {
    NTSTATUS st;
    ULONG attempt;

    if (o->state == ShWfpDeleted || o->state == ShWfpUnregistered)
        return STATUS_SUCCESS;
    if (o->state == ShWfpLeaked)
        return STATUS_DEVICE_BUSY;
    for (attempt = 0;; attempt++) {
        st = ShOps.UnregisterCalloutByKey(o->key);
        o->lastStatus = st;
        if (st == STATUS_SUCCESS || st == FWP_E_CALLOUT_NOT_FOUND) {
            o->state = ShWfpDeleted;
            o->busyRetries = attempt;
            return st;
        }
        if (st != STATUS_DEVICE_BUSY) {
            o->busyRetries = attempt;
            o->state = ShWfpLeaked; // unknown error => residency
            return st;
        }
        if (attempt >= maxBusyRetries) {
            o->busyRetries = attempt + 1;
            o->state = ShWfpLeaked;
            return st;
        }
        ShOps.SleepMs(delayMs);
    }
}
NTSTATUS ShWfpDeleteFilterById(SHINKEN_WFP_OBJECT *o, HANDLE engine) {
    if (o->state == ShWfpLeaked)
        return STATUS_DEVICE_BUSY;
    if (o->filterId == 0 || o->state == ShWfpDeleted)
        return STATUS_SUCCESS;
    o->state = ShWfpDeletePending;
    o->lastStatus = ShOps.FilterDeleteById(engine, o->filterId);
    if (o->lastStatus == STATUS_SUCCESS || o->lastStatus == FWP_E_FILTER_NOT_FOUND) {
        o->state = ShWfpDeleted; // success or documented "not found": confirmed clear
        o->filterId = 0;
        return o->lastStatus;
    }
    o->state = ShWfpLeaked; // unknown error: not confirmed clear (engine object remains)
    return o->lastStatus;
}

NTSTATUS ShWfpDeleteFilterByKey(SHINKEN_WFP_OBJECT *o, HANDLE engine) {
    if (o->state == ShWfpLeaked)
        return STATUS_DEVICE_BUSY;
    if (o->key == NULL || o->state == ShWfpDeleted)
        return STATUS_SUCCESS;
    o->state = ShWfpDeletePending;
    o->lastStatus = ShOps.FilterDeleteByKey(engine, o->key);
    if (o->lastStatus == STATUS_SUCCESS || o->lastStatus == FWP_E_FILTER_NOT_FOUND) {
        o->state = ShWfpDeleted;
        return o->lastStatus;
    }
    o->state = ShWfpLeaked;
    return o->lastStatus;
}

NTSTATUS ShWfpDeleteCalloutById(SHINKEN_WFP_OBJECT *o, HANDLE engine) {
    if (o->state == ShWfpLeaked)
        return STATUS_DEVICE_BUSY;
    if (o->id == 0 || o->state == ShWfpDeleted)
        return STATUS_SUCCESS;
    o->state = ShWfpDeletePending;
    o->lastStatus = ShOps.CalloutDeleteById(engine, o->id);
    if (o->lastStatus == STATUS_SUCCESS || o->lastStatus == FWP_E_CALLOUT_NOT_FOUND) {
        o->state = ShWfpDeleted;
        o->id = 0;
        return o->lastStatus;
    }
    o->state = ShWfpLeaked;
    return o->lastStatus;
}

NTSTATUS ShWfpDeleteCalloutByKey(SHINKEN_WFP_OBJECT *o, HANDLE engine) {
    if (o->state == ShWfpLeaked)
        return STATUS_DEVICE_BUSY;
    if (o->key == NULL || o->state == ShWfpDeleted)
        return STATUS_SUCCESS;
    o->state = ShWfpDeletePending;
    o->lastStatus = ShOps.CalloutDeleteByKey(engine, o->key);
    if (o->lastStatus == STATUS_SUCCESS || o->lastStatus == FWP_E_CALLOUT_NOT_FOUND) {
        o->state = ShWfpDeleted;
        return o->lastStatus;
    }
    o->state = ShWfpLeaked;
    return o->lastStatus;
}

NTSTATUS ShWfpDeleteProviderByKey(SHINKEN_WFP_OBJECT *o, HANDLE engine) {
    if (o->state == ShWfpLeaked)
        return STATUS_DEVICE_BUSY;
    if (o->key == NULL || o->state == ShWfpDeleted)
        return STATUS_SUCCESS;
    o->state = ShWfpDeletePending;
    o->lastStatus = ShOps.ProviderDeleteByKey(engine, o->key);
    if (o->lastStatus == STATUS_SUCCESS || o->lastStatus == FWP_E_PROVIDER_NOT_FOUND) {
        o->state = ShWfpDeleted;
        return o->lastStatus;
    }
    o->state = ShWfpLeaked;
    return o->lastStatus;
}

NTSTATUS ShWfpDeleteSubLayerByKey(SHINKEN_WFP_OBJECT *o, HANDLE engine) {
    if (o->state == ShWfpLeaked)
        return STATUS_DEVICE_BUSY;
    if (o->key == NULL || o->state == ShWfpDeleted)
        return STATUS_SUCCESS;
    o->state = ShWfpDeletePending;
    o->lastStatus = ShOps.SubLayerDeleteByKey(engine, o->key);
    if (o->lastStatus == STATUS_SUCCESS || o->lastStatus == FWP_E_SUBLAYER_NOT_FOUND) {
        o->state = ShWfpDeleted;
        return o->lastStatus;
    }
    o->state = ShWfpLeaked;
    return o->lastStatus;
}

NTSTATUS ShWfpEngineClose(SHINKEN_WFP_OBJECT *o, HANDLE engine) {
    if (o->state == ShWfpLeaked)
        return STATUS_DEVICE_BUSY; // engine handle retained (part of the residency condition)
    o->lastStatus = ShOps.EngineClose(engine);
    if (o->lastStatus == STATUS_SUCCESS) {
        // FwpmEngineClose0 has no documented "not found" form: only SUCCESS confirms closure
        o->state = ShWfpDeleted;
        return STATUS_SUCCESS;
    }
    o->state = ShWfpLeaked;
    return o->lastStatus;
}

// ---------------------------------------------------------------------------
// in-flight injection (dedicated rundown implementation, proof in runtime.h)
//
// Why not a bare counter: a raw fetch_add has no "stop" semantics — between
// quiesce drain observing zero and the injection handle destroy, a concurrent
// classify could Begin again and FwpsInject*Async0 on the destroyed handle
// (UAF). The rundown stop bit gives a single linearization point: Begin after
// GateStop must fail; Begin before GateStop is always awaited by drain.
// ---------------------------------------------------------------------------
BOOLEAN ShInjectionBegin(void) { return ShRundownAcquire(&g_InjectionRundown); }

VOID ShInjectionEnd(void) { ShRundownRelease(&g_InjectionRundown); }

LONG ShInjectionInFlight(void) {
    LONG c = ShRundownActiveCount(&g_InjectionRundown);
    return c < 0 ? 0 : c; // -1 (stopped and drained) is equivalent to 0 for callers
}

VOID ShInjectionGateStop(void) { ShRundownBeginStop(&g_InjectionRundown); }

NTSTATUS ShInjectionDrain(ULONG retries, ULONG delayMs) {
    ULONG i;
    // Correct protocol: caller does ShInjectionGateStop() first (quiesce).
    // Compatibility semantics: without GateStop this degrades to a bare count
    // observation (diagnostics/tests); success then proves nothing about
    // handle-destroy safety.
    for (i = 0;; i++) {
        LONG c = g_InjectionRundown.count;
        if (c == SHINKEN_RUNDOWN_STOP_BIT || c == 0)
            // stopped and drained, or not stopped but currently no in-flight (compat path)
            return STATUS_SUCCESS;
        if (i >= retries)
            return SHINKEN_STATUS_TIMEOUT;
        ShOps.SleepMs(delayMs);
    }
}

NTSTATUS ShInjectionDestroyTracked(SHINKEN_WFP_OBJECT *o, HANDLE handle, ULONG maxBusyRetries,
                                   ULONG delayMs) {
    NTSTATUS st;
    ULONG attempt;

    if (handle == NULL || o->state == ShWfpDeleted)
        return STATUS_SUCCESS;
    if (o->state == ShWfpLeaked)
        return STATUS_DEVICE_BUSY;
    for (attempt = 0;; attempt++) {
        st = ShOps.InjectionHandleDestroy(handle);
        o->lastStatus = st;
        if (st == STATUS_SUCCESS) {
            // Success = safety point: after destroy succeeds WFP no longer calls
            // completionFn on this handle. FwpsInjectionHandleDestroy0 has no
            // documented "not found" form — every other non-BUSY error (and
            // BUSY exhaustion below) means destroy state untrustworthy:
            // Leaked, completionFn code must stay resident.
            o->state = ShWfpDeleted;
            o->busyRetries = attempt;
            return st;
        }
        if (st != STATUS_DEVICE_BUSY) {
            o->busyRetries = attempt;
            o->state = ShWfpLeaked; // unknown error => residency
            return st;
        }
        if (attempt >= maxBusyRetries) {
            o->busyRetries = attempt + 1;
            o->state = ShWfpLeaked; // completionFn may still execute: residency
            return st;
        }
        ShOps.SleepMs(delayMs);
    }
}

// ---------------------------------------------------------------------------
// per-handle context
// ---------------------------------------------------------------------------
VOID ShHandleOpen(void) { SkAtAdd64(&g_HandlesOpen, 1); }

VOID ShHandleClose(void) { SkAtSub64(&g_HandlesOpen, 1); }

LONG64 ShHandlesOpen(void) { return g_HandlesOpen; }

// ---------------------------------------------------------------------------
// Host-test only: reset runtime globals (not compiled in kernel builds)
// ---------------------------------------------------------------------------
#ifdef SHINKEN_HOST_TEST
VOID ShTestReset(VOID) {
    g_State = ShinkenUninitialized;
    g_BlockReason = ShinkenBlockNone;
    g_BlockHistoryCount = 0;
    g_HandlesOpen = 0;
    ShRuntimeInit();
}
#endif
