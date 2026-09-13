// ============================================================================
// runtime/lifecycle.c — subsystem lifecycle orchestration (contract in
// lifecycle.h; ordering proof in docs/UNLOAD_SAFETY.md §7).
//
// Start order (SkLifecycleStart; any step failure rolls back completed steps
// in reverse):
//   0. SkDeviceCreate             control device + queue + symlink (DriverEntry,
//                                 BEFORE this function; tracked as SK_STEP_DEVICE —
//                                 the device is an owned resource of the rollback
//                                 graph even when no later step ever ran)
//   1. SkRuleStoreInit            rule store (empty snapshot version 0)
//   2. telemetry queue init (static storage) + event thread start
//   3. SkControlInit              control-plane thread/gate (means thread/gate
//                                 ready, NOT device created — the device is step 0)
//   4. SkInjectInit               injection handle + NBL/NB pools
//
// Quiesce order (SkLifecycleQuiesce; failure => FALSE, runtime stays resident):
//   1. close IOCTL new-request gate (SkControlQuiesce: latch + wait handles==0)
//   2. rule write gate: IsActive==FALSE after ShRuntimeBeginTeardown closes it
//      (rechecked via SkRuleStoreWritable; snapshot reader drain is guaranteed
//      by the rule_store rundown)
//   3. telemetry stop (ShEventThreadStop: close producer gate + join + drain)
//   4. injection gate (SkInjectQuiesce: GateStop + drain + destroy handle)
//   5. BFE unsubscribe + ShRundownBfe BeginStop/Drain (bounded wait)
//   6. WFP teardown (SkWfpManagerTeardown: callout unregister is the documented
//      safety point, flow contexts stripped between BUSY retries, then engine
//      objects deleted + engine closed)
//   7. drain ShRundownWorkItem
//   8. event-thread final re-check (idempotent)
// Destroy order (SkLifecycleDestroy, only after ShRuntimeDestroyAllowed):
//   SkInjectDestroy (pools) -> SkFlowDestroy -> SkRuleStoreShutdown (snapshot
//   free; drain failure => UNLOAD_BLOCKED and the destroy chain stops
//   immediately) -> SkControlDestroy (delete device). Engine close already
//   done at teardown (step 6).
//
// UNLOAD_BLOCKED policy (demo-only; full argument in docs/UNLOAD_SAFETY.md):
// any quiesce/rollback failure => runtime enters UNLOAD_BLOCKED and
// EvtDriverUnload never returns — the image can never be unloaded while any
// drain failed, so code referenced by WFP/BFE/work-item callbacks stays
// valid. Cost: sc stop sits in STOP_PENDING until SCM times out. The resident
// loop holds no locks/resources and can be interrupted at shutdown.
// Diagnosability: ShRuntimeBlockReason (first cause) + g_BlockHistory (all
// causes) + per-object state/lastStatus/busyRetries.
//
// Idempotent: repeated quiesce/destroy safe; partial-init rollback reuses the
// same function pair. BFE callback: on engine recovery (FWPM_SERVICE_RUNNING)
// re-runs SkWfpManagerInstall; the callback body is wrapped in ShRundownBfe
// Acquire/Release (the drain target of unload step 5).
// ============================================================================
#include <ntddk.h>
#include "runtime.h"
#include "rundown.h"
#include "lifecycle.h"
#include "../telemetry/event_queue.h"
#include "../rules/rule_store.h"
#include "../control/ioctl.h"
#include "../packet/injection.h"
#include "../packet/flow_context.h" // flow context table (orchestration point here)
#include "../wfp/wfp_manager.h" // SkWfpManagerInstall/Teardown
#include "../driver/driver.h" // SkDeviceDelete (device-step rollback)

// Drain bounded-retry parameters (all PASSIVE paths; timeout => residency, never assume "callbacks are short")
#define SK_LIFECYCLE_DRAIN_RETRIES  100
#define SK_LIFECYCLE_DRAIN_DELAY_MS 10

// Start-step bitmap (rollback only unwinds completed steps; quiesce/destroy idempotent)
#define SK_STEP_RULES   0x01
#define SK_STEP_EVENTQ  0x02
#define SK_STEP_CONTROL 0x04 // SkControlInit succeeded: consumer thread + request gate ready
#define SK_STEP_INJECT  0x08
#define SK_STEP_BFE     0x10
#define SK_STEP_WFP     0x20
#define SK_STEP_FLOW    0x40
#define SK_STEP_DEVICE  0x80 // SkDeviceCreate succeeded (DriverEntry): named device + symlink exist

static ULONG g_SkSteps;                  // completed start steps
static PDEVICE_OBJECT g_SkDevice;        // control device WDM object (for callout registration)
static BOOLEAN g_SkWfpDeferred;          // BFE not running: install deferred to BFE callback
HANDLE g_SkBfeChangeHandle;              // BFE subscription handle (global: diagnostics/tests)

// Telemetry queue: driver-level singleton in telemetry/event_queue.c
// (g_SkTelemetryQueue, image-level storage, never freed — same discipline as
// rundown invariant 9); lifecycle only orchestrates Init/Start/Stop.

// Keep the first cause if a subsystem already recorded one; otherwise record this step's fallback cause.
static VOID skRecordIfNone(SHINKEN_BLOCK_REASON why) {
    if (ShRuntimeBlockReason() == ShinkenBlockNone)
        ShRuntimeRecordBlock(why);
}

// ---------------------------------------------------------------------------
// BFE state-change callback (may arrive on a BFE service thread, PASSIVE):
// engine recovered (FWPM_SERVICE_RUNNING) => (re)install WFP objects.
// Rundown-wrapped: after unload step 5 BeginStop, Acquire must fail so the
// callback never touches the manager; in-flight callbacks before BeginStop
// are always awaited by Drain (proof in rundown.h).
// ---------------------------------------------------------------------------
static VOID NTAPI SkBfeStateChangeCallback(PVOID context, FWPM_SERVICE_STATE state) {
    UNREFERENCED_PARAMETER(context);
    if (!ShRundownAcquire(&ShRundownBfe))
        return; // unload/rollback in progress: callback covered by unsubscribe+drain
    if (state == FWPM_SERVICE_RUNNING && ShRuntimeIsActive() && g_SkDevice != NULL) {
        // Install is idempotent (manager.installed gate); on failure stay deferred, retried on next state transition
        if (SkWfpManagerInstall(g_SkDevice) >= 0)
            g_SkWfpDeferred = FALSE;
        else
            g_SkWfpDeferred = TRUE;
    }
    ShRundownRelease(&ShRundownBfe);
}

// ---------------------------------------------------------------------------
// BFE quiesce (shared by start rollback and unload): unsubscribe (failure is a
// residency-level error) -> BeginStop -> bounded drain of in-flight callbacks.
// ---------------------------------------------------------------------------
static BOOLEAN skBfeQuiesce(void) {
    if (g_SkBfeChangeHandle != NULL) {
        NTSTATUS st = ShOps.BfeUnsubscribe(g_SkBfeChangeHandle);
        if (st != STATUS_SUCCESS) {
            // unsubscribe not confirmed: callbacks may still arrive; keep the
            // handle (diagnostics) and do not proceed to destroy
            skRecordIfNone(ShinkenBlockBfeUnsubscribe);
            return FALSE;
        }
        g_SkBfeChangeHandle = NULL; // documented success: no new callbacks
    }
    ShRundownBeginStop(&ShRundownBfe);
    if (ShRundownDrain(&ShRundownBfe, SK_LIFECYCLE_DRAIN_RETRIES,
                      SK_LIFECYCLE_DRAIN_DELAY_MS) != STATUS_SUCCESS) {
        skRecordIfNone(ShinkenBlockBfeCallbackActive); // in-flight callback won't leave: residency
        return FALSE;
    }
    return TRUE;
}

// ---------------------------------------------------------------------------
// Telemetry quiesce (shared by start rollback and unload): stop the event
// thread (close producer gate + join + fallback drain); failure (producers
// stuck / join failed / queue non-empty) => residency-level error.
// ---------------------------------------------------------------------------
static BOOLEAN skEventQuiesce(void) {
    // exact compare: ShEventThreadStop returns SHINKEN_STATUS_TIMEOUT (0x102,
    // positive) when producers/thread refuse to drain; NT_SUCCESS/`< 0` would
    // misread it as stopped and let destroy run under a live event thread.
    if (ShEventThreadStop(&g_SkTelemetryQueue) != STATUS_SUCCESS) {
        skRecordIfNone(ShinkenBlockEventThreadDrain);
        return FALSE;
    }
    return TRUE;
}

// ---------------------------------------------------------------------------
// Quiesce all subsystems (order in file header). Precondition:
// ShRuntimeBeginTeardown already done by runtime (ShRuntimeRunUnload). Failing
// steps record their own reason; unrecorded ones get a fallback here;
// returning FALSE puts the runtime into residency.
// ---------------------------------------------------------------------------
BOOLEAN SkLifecycleQuiesce(void) {
    BOOLEAN ok = TRUE;

    // 1) IOCTL new-request gate + wait for user handles to reach zero (control/ioctl.c records its own reason)
    if (!SkControlQuiesce()) {
        skRecordIfNone(ShinkenBlockHandleContextsOpen);
        ok = FALSE;
    }
    // 2) Rule write gate: after BeginTeardown IsActive==FALSE => writes rejected;
    //    recheck Writable()==FALSE (still writable = gate broken = protocol violation)
    if (SkRuleStoreWritable()) {
        skRecordIfNone(ShinkenBlockRundownStuck);
        ok = FALSE;
    }
    // 3) telemetry stop (event thread stop/join/fallback drain)
    if (!skEventQuiesce())
        ok = FALSE;
    // 4) injection gate: GateStop + drain in-flight + destroy injection handle (packet/injection.c)
    if (!SkInjectQuiesce()) {
        skRecordIfNone(ShinkenBlockInjectionDrain);
        ok = FALSE;
    }
    // 5) BFE unsubscribe + drain callback rundown (must precede WFP teardown:
    //    callbacks may trigger reinstall; cut the callback source first)
    if (!skBfeQuiesce())
        ok = FALSE;
    // 6) WFP teardown: unregister all callouts (safety point) + delete engine
    //    objects + close engine; records precise reasons internally
    if (!SkWfpManagerTeardown()) {
        skRecordIfNone(ShinkenBlockEngineClose);
        ok = FALSE;
    }
    // 7) drain work item rundown (Io* work item in flight => bounded wait)
    ShRundownBeginStop(&ShRundownWorkItem);
    if (ShRundownDrain(&ShRundownWorkItem, SK_LIFECYCLE_DRAIN_RETRIES,
                      SK_LIFECYCLE_DRAIN_DELAY_MS) != STATUS_SUCCESS) {
        skRecordIfNone(ShinkenBlockWorkItemDrain);
        ok = FALSE;
    }
    // 8) event-thread final re-check (idempotent; must be FALSE after step 3 succeeded)
    if (ShEventThreadRunning(&g_SkTelemetryQueue)) {
        skRecordIfNone(ShinkenBlockEventThreadDrain);
        ok = FALSE;
    }
    return ok;
}

// ---------------------------------------------------------------------------
// Subsystem destroy (step-level idempotency per module). Runs only when
// ShRuntimeDestroyAllowed()==TRUE (Quiescent or never activated).
// ---------------------------------------------------------------------------
VOID SkLifecycleDestroy(void) {
    if (!ShRuntimeDestroyAllowed())
        return; // resident terminal state: all destroy forbidden (defense in depth; runtime gate is first)
    SkInjectDestroy();      // destroy injection pools (handle already destroyed at quiesce)
    SkFlowDestroy();        // flow context table (WFP teardown at quiesce stripped all associations)
    // Free rule snapshots: any snapshot still has readers => shutdown already
    // called EnterUnloadBlocked; the destroy chain must stop immediately — do
    // not run SkControlDestroy or any later destroy, do not clear
    // g_SkSteps/g_SkDevice (preserve the failure scene; deleting the device
    // would strip residency protection from the IOCTL dispatch code while
    // in-flight snapshot readers still reference the image).
    if (!SkRuleStoreShutdown()) {
        ShRuntimeEnterUnloadBlocked(ShinkenBlockRundownStuck); // idempotent, keeps first cause
        return;
    }
    SkControlDestroy();     // delete control device (SkDeviceDelete, idempotent)
    SkDeviceDelete();       // device step backstop: idempotent no-op when
                            // SkControlDestroy already deleted the device
    g_SkSteps = 0;
    g_SkDevice = NULL;
}

// ---------------------------------------------------------------------------
// Start-failure rollback: quiesce completed steps in reverse order (same
// function pair as unload); destroy only if all succeed; any quiesce failure
// => FALSE (caller does EnterUnloadBlocked + residency).
// ---------------------------------------------------------------------------
static BOOLEAN skLifecycleRollback(void) {
    BOOLEAN ok = TRUE;

    ShRuntimeBeginTeardown(); // never activated: gate with nothing to drain (idempotent)
    // Reverse order: WFP -> BFE -> injection -> control -> telemetry (quiesce part)
    // If WFP install failed, the manager already rolled back internally;
    // teardown is idempotent and also catches the "internal rollback itself
    // LEAKED" form (returns FALSE)
    if (!SkWfpManagerTeardown()) {
        skRecordIfNone(ShinkenBlockEngineClose);
        ok = FALSE;
    }
    if ((g_SkSteps & SK_STEP_BFE) && !skBfeQuiesce())
        ok = FALSE;
    if ((g_SkSteps & SK_STEP_INJECT) && !SkInjectQuiesce()) {
        skRecordIfNone(ShinkenBlockInjectionDrain);
        ok = FALSE;
    }
    if ((g_SkSteps & SK_STEP_CONTROL) && !SkControlQuiesce()) {
        skRecordIfNone(ShinkenBlockHandleContextsOpen);
        ok = FALSE;
    }
    if ((g_SkSteps & SK_STEP_EVENTQ) && !skEventQuiesce())
        ok = FALSE;
    if (!ok)
        return FALSE; // quiesce not all passed: destroy fully forbidden (objects kept, residency)
    // destroy part (state Uninitialized => ShRuntimeDestroyAllowed is TRUE)
    if (g_SkSteps & SK_STEP_INJECT)
        SkInjectDestroy();
    if (g_SkSteps & SK_STEP_FLOW)
        SkFlowDestroy();
    if (g_SkSteps & SK_STEP_RULES) {
        // Snapshot drain failure => already UNLOAD_BLOCKED internally: destroy
        // chain stops, g_SkSteps kept (failure scene), rollback fails (residency)
        if (!SkRuleStoreShutdown())
            return FALSE;
    }
    if (g_SkSteps & SK_STEP_CONTROL)
        SkControlDestroy();
    if (g_SkSteps & SK_STEP_DEVICE) {
        // The device predates every lifecycle step (created by DriverEntry),
        // so it must be deleted even when SK_STEP_CONTROL is clear
        // (SkControlInit failed or was never reached). SkControlDestroy's own
        // device deletion is gated on g_ControlReady — TRUE only after a fully
        // successful SkControlInit — so the device-only case needs this
        // explicit delete (idempotent with the CONTROL branch above).
        // WdfObjectDelete precondition holds by construction: with control
        // init unsuccessful the consumer thread was never created, the
        // request gate never opened, and no handle context was ever counted
        // (SkControlInit's failure paths restore all three); with CONTROL set,
        // SkControlQuiesce already proved thread/requests/handles stopped.
        SkDeviceDelete();
    }
    g_SkSteps = 0;
    g_SkDevice = NULL;
    return TRUE;
}

// ---------------------------------------------------------------------------
// SkLifecycleStart: order in file header. Full success => STATUS_SUCCESS
// (ShRuntimeActivate is done by DriverEntry afterwards — before activation
// the runtime rejects new async refs and all subsystem gates stay closed, so
// no "callback references a not-yet-ready subsystem" window during install).
// Any step failure: internal rollback; rollback failure => UNLOAD_BLOCKED +
// STATUS_DEVICE_BUSY (DriverEntry detects the resident terminal state and
// BlockUnloadForever instead of returning a failure code).
// ---------------------------------------------------------------------------
NTSTATUS SkLifecycleStart(PDRIVER_OBJECT driverObject, PDEVICE_OBJECT wdmDevice) {
    NTSTATUS status;
    FWPM_SERVICE_STATE bfeState;

    // SK_STEP_DEVICE first: DriverEntry's SkDeviceCreate succeeded immediately
    // before this call (wdmDevice is its product), so the named device +
    // symlink enter the rollback graph before any step that can fail.
    g_SkSteps = SK_STEP_DEVICE;
    g_SkDevice = wdmDevice;
    g_SkWfpDeferred = FALSE;
    SkWfpManagerInitMutex(); // KMUTEX one-time init (idempotent via BSS flag; must
                             // precede any install/teardown/BFE callback reachability)


    // 1) rule store
    status = SkRuleStoreInit();
    if (status < 0)
        goto rollback;
    g_SkSteps |= SK_STEP_RULES;

    // 2) telemetry singleton init (static storage, inside event_queue.c) + event thread
    SkTelemetryInit();
    status = SkTelemetryStart();
    if (status < 0)
        goto rollback;
    g_SkSteps |= SK_STEP_EVENTQ;

    // 3) control plane (request gate / handle stats; device already created by DriverEntry via SkDeviceCreate)
    status = SkControlInit(driverObject);
    if (status < 0)
        goto rollback;
    g_SkSteps |= SK_STEP_CONTROL;

    // 4) injection subsystem (handle + NBL/NB pools)
    status = SkInjectInit();
    if (status < 0)
        goto rollback;
    g_SkSteps |= SK_STEP_INJECT;

    // 4b) flow context table (WFP teardown's BUSY root-cause handling
    //     SkFlowRemoveAll depends on it; must exist before callouts can attach contexts)
    status = SkFlowInit();
    if (status < 0)
        goto rollback;
    g_SkSteps |= SK_STEP_FLOW;

    // 5) BFE state subscription (must precede WFP install: install depends on
    //    the engine-availability signal; failure => init-failure rollback)
    status = FwpmBfeStateSubscribeChanges0(wdmDevice, SkBfeStateChangeCallback, NULL,
                                           &g_SkBfeChangeHandle);
    if (status < 0) {
        g_SkBfeChangeHandle = NULL;
        goto rollback;
    }
    g_SkSteps |= SK_STEP_BFE;

    // 6) WFP install: BFE running => install now; not running => subscribe
    //    only, defer to the BFE callback
    bfeState = FwpmBfeStateGet0();
    if (bfeState == FWPM_SERVICE_RUNNING) {
        status = SkWfpManagerInstall(wdmDevice);
        if (status < 0)
            goto rollback; // internally rolled back; rollback LEAKED is caught by skLifecycleRollback
        g_SkSteps |= SK_STEP_WFP;
    } else {
        g_SkWfpDeferred = TRUE;
    }

    return STATUS_SUCCESS;

rollback:
    if (!skLifecycleRollback()) {
        // Rollback itself failed: object clear state untrustworthy => resident
        // terminal state (STATUS_DEVICE_BUSY reachable only via the test hook)
        ShRuntimeEnterUnloadBlocked(ShRuntimeBlockReason());
        return STATUS_DEVICE_BUSY;
    }
    return status;
}
