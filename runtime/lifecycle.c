// Initialize all callback-visible state before subscribing to BFE; publish
// the control device only after startup succeeds (DriverEntry).
// Shutdown cuts the BFE callback source before touching the WFP manager.
// A confirmed dynamic-session close removes filters before runtime callout
// unregister. No subsystem destroy runs while any owner remains unconfirmed.
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
#define SK_STEP_FLOW    0x40
#define SK_STEP_DEVICE  0x80 // SkDeviceCreate succeeded (DriverEntry): named device + symlink exist

static ULONG g_SkSteps;                  // completed start steps
static PDEVICE_OBJECT g_SkDevice;        // control device WDM object (for callout registration)
HANDLE g_SkBfeChangeHandle;              // BFE subscription handle (global: diagnostics/tests)

// Telemetry uses image-static bounded storage; lifecycle owns its thread.

// Keep the first cause if a subsystem already recorded one; otherwise record this step's fallback cause.
static VOID skRecordIfNone(SHINKEN_BLOCK_REASON why) {
    if (ShRuntimeBlockReason() == ShinkenBlockNone)
        ShRuntimeRecordBlock(why);
}

// BFE callbacks may arrive during initialization, before runtime activation.
// All resources they need are initialized before subscription. Rollback must
// unsubscribe and drain this rundown before it tears the manager down.
static VOID NTAPI SkBfeStateChangeCallback(PVOID context, FWPM_SERVICE_STATE state) {
    NTSTATUS st;
    UNREFERENCED_PARAMETER(context);
    if (!ShRundownAcquire(&ShRundownBfe))
        return;
    if (ShRuntimeState() != ShinkenTeardown &&
        ShRuntimeState() != ShinkenUnloadBlocked && g_SkDevice != NULL) {
        st = SkWfpManagerBfeStateChange(g_SkDevice, state);
        if (!NT_SUCCESS(st))
            ShOps.Diag("SHINKEN: BFE synchronization failed; manager retains ownership");
    }
    ShRundownRelease(&ShRundownBfe);
}

// ---------------------------------------------------------------------------
// BFE quiesce (shared by start rollback and unload): unsubscribe (failure is a
// residency-level error) -> BeginStop -> bounded drain of in-flight callbacks.
// ---------------------------------------------------------------------------
static BOOLEAN skBfeQuiesce(void) {
    ShRundownBeginStop(&ShRundownBfe);
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
    if (ShRundownDrain(&ShRundownBfe, SK_LIFECYCLE_DRAIN_RETRIES,
                      SK_LIFECYCLE_DRAIN_DELAY_MS) != STATUS_SUCCESS) {
        skRecordIfNone(ShinkenBlockBfeCallbackActive); // in-flight callback won't leave: residency
        return FALSE;
    }
    return TRUE;
}

// ---------------------------------------------------------------------------
// Telemetry closes producer admission under its queue lock, drains queued
// records on the consumer, and joins before reporting success.
// ---------------------------------------------------------------------------
static BOOLEAN skEventQuiesce(void) {
    if (SkTelemetryStop() != STATUS_SUCCESS) {
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
    // Prevent reinstall before closing the session and unregistering callouts.
    // A failed unsubscribe/drain means the manager must remain untouched.
    if (!skBfeQuiesce()) {
        ok = FALSE;
    } else if (!SkWfpManagerTeardown()) {
        skRecordIfNone(ShinkenBlockEngineClose);
        ok = FALSE;
    }
    if (SkTelemetryRunning()) {
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
    if (!SkFlowDestroy()) {
        ShRuntimeEnterUnloadBlocked(ShinkenBlockFlowContextDrain);
        return;
    }
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

    ShRuntimeBeginTeardown();
    // The subscription exists before the first install. Stop callbacks first
    // even during failed startup; otherwise they can reinstall behind rollback.
    if ((g_SkSteps & SK_STEP_BFE) && !skBfeQuiesce()) {
        ok = FALSE;
    } else if (!SkWfpManagerTeardown()) {
        skRecordIfNone(ShinkenBlockEngineClose);
        ok = FALSE;
    }
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
    if (!ok || ShRuntimeState() == ShinkenUnloadBlocked)
        return FALSE;
    // Destroy only after every owner and runtime failure state is clear.
    if (g_SkSteps & SK_STEP_INJECT)
        SkInjectDestroy();
    if ((g_SkSteps & SK_STEP_FLOW) && !SkFlowDestroy())
        return FALSE;
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

// Startup is private until DriverEntry publishes the control device.
// Callback resources are ready before BFE subscription; the initial query
// and later notifications serialize inside the manager.
NTSTATUS SkLifecycleStart(PDRIVER_OBJECT driverObject, PDEVICE_OBJECT wdmDevice) {
    NTSTATUS status;

    // SK_STEP_DEVICE first: DriverEntry's SkDeviceCreate succeeded immediately
    // before this call (wdmDevice is its product), so the named device +
    // symlink enter the rollback graph before any step that can fail.
    g_SkSteps = SK_STEP_DEVICE;
    g_SkDevice = wdmDevice;
    SkWfpManagerInitMutex(); // before installation or callback publication


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
    //     SkFlowRemoveAll and the per-callout attach gates depend on it;
    //     must exist before callouts can attach contexts)
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

    // The manager checks the live BFE state under its installation lock.
    // Notifications are accepted even before ShRuntimeActivate, closing the
    // query/activation window that could otherwise lose the RUNNING event.
    status = SkWfpManagerInstall(wdmDevice);
    if (!NT_SUCCESS(status) || ShRuntimeState() == ShinkenUnloadBlocked) {
        if (NT_SUCCESS(status))
            status = STATUS_DEVICE_BUSY;
        goto rollback;
    }

    return STATUS_SUCCESS;

rollback:
    if (!skLifecycleRollback()) {
        // Rollback failed: preserve owners and enter resident terminal state.
        ShRuntimeEnterUnloadBlocked(ShRuntimeBlockReason());
        return STATUS_DEVICE_BUSY;
    }
    return status;
}
