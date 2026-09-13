// ============================================================================
// runtime/runtime.h — unified runtime state machine / rundown / WFP object
// tracking (see docs/UNLOAD_SAFETY.md).
//
// Architecture:
//   * One runtime state machine for the whole merged driver (sensor + divert).
//   * EvtDriverUnload may enter the destroy phase only after every async
//     reference (classify/flowDelete unregister, BFE callbacks, work items,
//     per-handle contexts, injection completions, event thread) is quiescent.
//   * Any drain failure => terminal UNLOAD_BLOCKED (RESIDENT_FAILURE): the
//     driver stays resident and EvtDriverUnload never returns (KMDF has no
//     "refuse unload" return; the only safe failure policy is not returning).
//
// Builds: kernel build (ShOps default table binds WDK APIs directly);
// host-test build (SHINKEN_HOST_TEST): tests/ provide ShOps mocks + fault
// injection.
// ============================================================================
#pragma once
#include <ntddk.h>
#include "rundown.h" // SHINKEN_RUNDOWN + ShRundown* (proof in that header)

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Sync primitive abstraction (kernel: KEVENT/thread object; host: Win32 event/thread, same storage)
// ---------------------------------------------------------------------------
typedef struct _SHINKEN_EVENT {
    long x[8]; // kernel: first 0x18 bytes are a KEVENT; host: first field holds HANDLE
} SHINKEN_EVENT;

typedef VOID (*SHINKEN_THREAD_FN)(PVOID ctx);

// Startup-fenced thread create (implementation in runtime.c; host fence-test
// TUs opt in via SHINKEN_HOST_FENCE_TEST). IRQL: PASSIVE_LEVEL only.
//   success => caller owns a referenced thread object usable by ThreadJoin.
//   failure => no running untracked thread exists: the spawned wrapper was
//              abort-gated before the body ran and reaped via its handle.
#if !defined(SHINKEN_HOST_TEST) || defined(SHINKEN_HOST_FENCE_TEST)
NTSTATUS ShThreadCreateFenced(SHINKEN_THREAD_FN body, PVOID ctx, PVOID *outThreadObject);
#endif

// ---------------------------------------------------------------------------
// runtime terminal state machine
// ---------------------------------------------------------------------------
typedef enum _SHINKEN_RUNTIME_STATE {
    ShinkenUninitialized = 0, // not yet initialized (destroy not refused)
    ShinkenActive,            // normal: accepts new async work
    ShinkenTeardown,          // unload started: rejects new async refs, draining
    ShinkenQuiescent,         // all async refs drained: destroy phase allowed
    ShinkenUnloadBlocked      // terminal (RESIDENT_FAILURE): resident, all destroy forbidden
} SHINKEN_RUNTIME_STATE;

typedef enum _SHINKEN_BLOCK_REASON {
    ShinkenBlockNone = 0,
    ShinkenBlockSensorCalloutBusy,  // sensor FwpsCalloutUnregisterById0 BUSY retries exhausted
    ShinkenBlockDivertCalloutBusy,  // divert FwpsCalloutUnregisterByKey0 BUSY retries exhausted
    ShinkenBlockFlowContextDrain,   // flow contexts still associated
    ShinkenBlockInjectionDrain,     // injection not complete / FwpsInjectionHandleDestroy0 BUSY
    ShinkenBlockWorkItemDrain,      // work item still running after flush
    ShinkenBlockEventThreadDrain,   // event thread cannot join / queue cannot drain
    ShinkenBlockHandleContextsOpen, // user handles (per-handle contexts) still open at unload
    ShinkenBlockBfeCallbackActive,  // BFE state callback still in flight
    ShinkenBlockBfeUnsubscribe,     // BFE unsubscribe failed
    ShinkenBlockEngineClose,        // engine-side filter/callout/sublayer/provider delete failed
    ShinkenBlockRundownStuck,       // rundown never drains (holder permanently stuck)
    ShinkenBlockRundownUnderflow,   // double Release detected (count corrupt, drain untrustworthy)
    ShinkenBlockWorkerThreadDrain   // worker thread join failed (thread may still run)
} SHINKEN_BLOCK_REASON;

// Registration-face state of each callout/filter/provider/sublayer
typedef enum _SHINKEN_WFP_OBJECT_STATE {
    ShWfpUnregistered = 0, // never successfully registered
    ShWfpRegistered,       // on the books (runtime callout or engine object)
    ShWfpDeletePending,    // engine-side delete issued but unconfirmed
    ShWfpDeleted,          // confirmed deleted/unregistered: no more callbacks possible
    ShWfpLeaked            // terminal: cannot delete/unregister => keep resources, stay resident
} SHINKEN_WFP_OBJECT_STATE;

typedef struct _SHINKEN_WFP_OBJECT {
    const char *name;             // diagnostic name (static string)
    UINT32 id;                    // by-id path: calloutRuntimeId / calloutId
    UINT64 filterId;              // by-id path: for FwpmFilterDeleteById0
    const GUID *key;              // by-key path
    SHINKEN_WFP_OBJECT_STATE state;
    ULONG busyRetries;            // diagnostics: BUSY retry count
    NTSTATUS lastStatus;          // diagnostics: last API return value
} SHINKEN_WFP_OBJECT;


// ---------------------------------------------------------------------------
// Injectable ops table (kernel defaults in runtime.c; tests/ override them)
// ---------------------------------------------------------------------------
typedef struct _SHINKEN_OPS {
    // --- WFP unregister/delete (all return values must be checked) ---
    NTSTATUS (*UnregisterCalloutById)(UINT32 id);
    NTSTATUS (*UnregisterCalloutByKey)(const GUID *key);
    NTSTATUS (*FilterDeleteById)(HANDLE engine, UINT64 filterId);
    NTSTATUS (*FilterDeleteByKey)(HANDLE engine, const GUID *key);
    NTSTATUS (*CalloutDeleteById)(HANDLE engine, UINT32 id);
    NTSTATUS (*CalloutDeleteByKey)(HANDLE engine, const GUID *key);
    NTSTATUS (*ProviderDeleteByKey)(HANDLE engine, const GUID *key);
    NTSTATUS (*SubLayerDeleteByKey)(HANDLE engine, const GUID *key);
    NTSTATUS (*EngineClose)(HANDLE engine);
    NTSTATUS (*InjectionHandleDestroy)(HANDLE handle);
    NTSTATUS (*FlowRemoveContext)(UINT64 flowId, UINT16 layerId, UINT32 calloutId);
    NTSTATUS (*BfeUnsubscribe)(HANDLE changeHandle);
    // --- work item ---
    NTSTATUS (*WorkItemFlush)(PVOID workItem);
    // --- memory (event nodes) ---
    PVOID (*AllocPool)(ULONG size, ULONG tag);
    VOID (*FreePool)(PVOID block, ULONG tag);
    // --- sync/threads ---
    // ThreadCreate: PASSIVE only. Success => caller owns a thread object usable
    // by ThreadJoin; failure => no running untracked thread exists.
    NTSTATUS (*ThreadCreate)(SHINKEN_THREAD_FN body, PVOID ctx, PVOID *outThreadObject);
    // ThreadJoin: PASSIVE only. Success => thread exited, object dereferenced
    // exactly once; failure => caller must NOT destroy anything the thread may touch.
    NTSTATUS (*ThreadJoin)(PVOID threadObject);
    VOID (*EventInit)(SHINKEN_EVENT *ev);
    VOID (*EventSet)(SHINKEN_EVENT *ev);
    BOOLEAN (*EventWait)(SHINKEN_EVENT *ev, ULONG timeoutMs); // TRUE=signaled, FALSE=timeout
    BOOLEAN (*EventWaitAny)(SHINKEN_EVENT *a, SHINKEN_EVENT *b, ULONG timeoutMs); // TRUE=either signaled
    KIRQL (*LockAcquireExclusive)(PEX_SPIN_LOCK lock);
    VOID (*LockReleaseExclusive)(PEX_SPIN_LOCK lock, KIRQL oldIrql);
    VOID (*SleepMs)(ULONG ms);
    VOID (*Diag)(const char *msg);
} SHINKEN_OPS;

extern SHINKEN_OPS ShOps;

// Test hook (always NULL in kernel builds; see ShRuntimeBlockUnloadForever)
typedef struct _SHINKEN_TEST_HOOK {
    int (*AbortBlockedWait)(ULONG iteration); // nonzero => break out of resident wait (tests only)
} SHINKEN_TEST_HOOK;
extern SHINKEN_TEST_HOOK *ShTestHook;
#ifndef SHINKEN_STATUS_TIMEOUT
#define SHINKEN_STATUS_TIMEOUT ((NTSTATUS)0x00000102L) // STATUS_TIMEOUT
#endif

// WFP documented "object not found" statuses (winerror.h); only these plus
// STATUS_SUCCESS may mark an object Deleted — every other error means the
// clear state is untrustworthy:
#ifndef FWP_E_CALLOUT_NOT_FOUND
#define FWP_E_CALLOUT_NOT_FOUND  ((NTSTATUS)0x80320001L) // callout not found
#define FWP_E_FILTER_NOT_FOUND   ((NTSTATUS)0x80320003L) // filter not found
#define FWP_E_PROVIDER_NOT_FOUND ((NTSTATUS)0x80320005L) // provider not found
#define FWP_E_SUBLAYER_NOT_FOUND ((NTSTATUS)0x80320007L) // sublayer not found
#endif

// ---------------------------------------------------------------------------
// runtime state machine API
// ---------------------------------------------------------------------------
VOID ShRuntimeInit(void);
VOID ShRuntimeActivate(void);                        // Uninitialized -> Active
SHINKEN_RUNTIME_STATE ShRuntimeState(void);
SHINKEN_BLOCK_REASON ShRuntimeBlockReason(void);
const char *ShRuntimeStateName(SHINKEN_RUNTIME_STATE st);
const char *ShRuntimeBlockReasonName(SHINKEN_BLOCK_REASON why);
BOOLEAN ShRuntimeIsActive(void);                     // state == Active
BOOLEAN ShRuntimeDestroyAllowed(void);               // TRUE only when Quiescent (or never activated)
BOOLEAN ShRuntimeBeginTeardown(void);                // Active -> Teardown; idempotent
VOID ShRuntimeRecordBlock(SHINKEN_BLOCK_REASON why); // record failure reason (first cause + history)
// Block-reason record: first cause stays in ShRuntimeBlockReason(); all
// reasons (including later ones) enter an ordered history (capacity 16,
// count unbounded), each triggering one Diag — residency is never an
// unexplained hang; the full failure chain is observable.
ULONG ShRuntimeBlockHistoryCount(void);                    // total recorded reasons
SHINKEN_BLOCK_REASON ShRuntimeBlockHistoryAt(ULONG index); // out of range => ShinkenBlockNone
VOID ShRuntimeEnterQuiescent(void);                  // Teardown -> Quiescent
VOID ShRuntimeEnterUnloadBlocked(SHINKEN_BLOCK_REASON why); // -> terminal (idempotent, keeps first cause)
VOID ShRuntimeBlockUnloadForever(void);              // resident wait (test hook may break out)
// Unified unload gate: all quiesce pass => cleanup; else UNLOAD_BLOCKED +
// residency. After cleanup returns, state is re-checked: a drain failure
// discovered inside cleanup (e.g. rule snapshot readers stuck) enters
// UNLOAD_BLOCKED — once blocked, never return TRUE (returning lets KMDF
// unload the image).
// Returns TRUE if cleanup completed and runtime is still Quiescent (normal
// unload); FALSE means residency (test hook broke out).
BOOLEAN ShRuntimeRunUnload(BOOLEAN (*sensorQuiesce)(VOID), BOOLEAN (*divertQuiesce)(VOID),
                           VOID (*sensorCleanup)(VOID), VOID (*divertCleanup)(VOID));


// ---------------------------------------------------------------------------
// WFP object tracking API (all check return values and advance obj->state)
// ---------------------------------------------------------------------------
VOID ShWfpObjectInit(SHINKEN_WFP_OBJECT *o, const char *name, UINT32 calloutId, UINT64 filterId,
                     const GUID *key);
VOID ShWfpObjectMark(SHINKEN_WFP_OBJECT *o, SHINKEN_WFP_OBJECT_STATE st);
// Bounded BUSY-retry unregister; busyCleanup (strip flow contexts) runs between BUSY retries; exhausted => Leaked.
NTSTATUS ShWfpUnregisterCalloutById(SHINKEN_WFP_OBJECT *o, PVOID busyCtx,
                                    VOID (*busyCleanup)(PVOID), ULONG maxBusyRetries,
                                    ULONG delayMs);
NTSTATUS ShWfpUnregisterCalloutByKey(SHINKEN_WFP_OBJECT *o, ULONG maxBusyRetries, ULONG delayMs);
NTSTATUS ShWfpDeleteFilterById(SHINKEN_WFP_OBJECT *o, HANDLE engine);
NTSTATUS ShWfpDeleteFilterByKey(SHINKEN_WFP_OBJECT *o, HANDLE engine);
NTSTATUS ShWfpDeleteCalloutById(SHINKEN_WFP_OBJECT *o, HANDLE engine);
NTSTATUS ShWfpDeleteCalloutByKey(SHINKEN_WFP_OBJECT *o, HANDLE engine);
NTSTATUS ShWfpDeleteProviderByKey(SHINKEN_WFP_OBJECT *o, HANDLE engine);
NTSTATUS ShWfpDeleteSubLayerByKey(SHINKEN_WFP_OBJECT *o, HANDLE engine);
NTSTATUS ShWfpEngineClose(SHINKEN_WFP_OBJECT *o, HANDLE engine);

// ---------------------------------------------------------------------------
// in-flight injection tracking — implemented on a dedicated rundown
// (g_InjectionRundown):
//   Begin = rundown Acquire: FALSE means GateStop is in effect (unload/
//           rollback started); caller must abandon the injection and free
//           the packet itself (no completion will arrive; must not End).
//   End   = rundown Release (pairs a successful Begin; completion or
//           submit-failure path).
//   Gate semantics close the UAF window "drain sees zero -> destroy handle
//   -> classify Begins again and injects on the destroyed handle"
//   (docs/UNLOAD_SAFETY.md §2).
BOOLEAN ShInjectionBegin(void); // FALSE = GateStop in effect, injection forbidden
VOID ShInjectionEnd(void);
LONG ShInjectionInFlight(void);
VOID ShInjectionGateStop(void); // close the injection gate (quiesce calls before drain)
NTSTATUS ShInjectionDrain(ULONG retries, ULONG delayMs);
// Bounded BUSY-retry injection handle destroy; in-flight nonzero / BUSY exhausted => Leaked.
NTSTATUS ShInjectionDestroyTracked(SHINKEN_WFP_OBJECT *o, HANDLE handle, ULONG maxBusyRetries,
                                   ULONG delayMs);
// per-handle context tracking (divert user handles)
// ---------------------------------------------------------------------------
VOID ShHandleOpen(void);
VOID ShHandleClose(void);
LONG64 ShHandlesOpen(void);

// In-flight tracking for BFE state callbacks (shared by sensor + divert)
extern SHINKEN_RUNDOWN ShRundownBfe;
extern SHINKEN_RUNDOWN ShRundownWorkItem; // Io* work item(SHINKEN fw-event worker)

#ifdef __cplusplus
}
#endif
