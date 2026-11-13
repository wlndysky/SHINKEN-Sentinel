// ============================================================================
// runtime/runtime.h — unified runtime state machine / rundown / WFP object
// tracking (proof inline in lifecycle/runtime headers).
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
// host-test build (SHINKEN_HOST_TEST): ShOps mocks + fault injection are
// provided externally.
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
typedef KEVENT SHINKEN_EVENT;

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
// Injectable ops table (kernel defaults in runtime.c; host-test build overrides them)
// ---------------------------------------------------------------------------
typedef struct _SHINKEN_OPS {
    // --- WFP unregister/delete (all return values must be checked) ---
    NTSTATUS (*UnregisterCalloutById)(UINT32 id);
    NTSTATUS (*EngineClose)(HANDLE engine);
    NTSTATUS (*InjectionHandleDestroy)(HANDLE handle);
    NTSTATUS (*FlowRemoveContext)(UINT64 flowId, UINT16 layerId, UINT32 calloutId);
    NTSTATUS (*BfeUnsubscribe)(HANDLE changeHandle);
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

#ifndef SHINKEN_STATUS_TIMEOUT
#define SHINKEN_STATUS_TIMEOUT ((NTSTATUS)0x00000102L) // STATUS_TIMEOUT
#endif

// Kernel WFP APIs return NTSTATUS (0xC022xxxx), not the user-mode
// FWP_E_* HRESULT values (0x8032xxxx). The shim needs these definitions.
#ifndef STATUS_FWP_CALLOUT_NOT_FOUND
#define STATUS_FWP_CALLOUT_NOT_FOUND  ((NTSTATUS)0xC0220001L)
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
VOID ShRuntimeBlockUnloadForever(void);              // resident wait; never returns
// Unified unload gate: all quiesce pass => cleanup; else UNLOAD_BLOCKED +
// residency. After cleanup returns, state is re-checked: a drain failure
// discovered inside cleanup (e.g. rule snapshot readers stuck) enters
// UNLOAD_BLOCKED — once blocked, never return TRUE (returning lets KMDF
// unload the image).
// Returns TRUE only after confirmed cleanup; failure parks indefinitely.
BOOLEAN ShRuntimeRunUnload(BOOLEAN (*sensorQuiesce)(VOID), BOOLEAN (*divertQuiesce)(VOID),
                           VOID (*sensorCleanup)(VOID), VOID (*divertCleanup)(VOID));


// ---------------------------------------------------------------------------
// WFP object tracking API (all check return values and advance obj->state)
// ---------------------------------------------------------------------------
VOID ShWfpObjectInit(SHINKEN_WFP_OBJECT *o, const char *name, UINT32 calloutId, UINT64 filterId,
                     const GUID *key);

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
//   (unload safety invariant).
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

#ifdef __cplusplus
}
#endif
