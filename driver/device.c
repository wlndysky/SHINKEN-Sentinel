// ============================================================================
// driver/device.c — KMDF control device creation
//
// Boundary with control/ioctl.c:
//   * This file only builds the device-object layer: WdfControlDeviceInitAllocate
//     (SDDL) → WdfDeviceInit* config → WdfDeviceCreate → default IOCTL queue →
//     symbolic link; it merely wires callbacks into WDF_FILEOBJECT_CONFIG /
//     WDF_OBJECT_ATTRIBUTES.EvtDestroyCallback / WDF_IO_QUEUE_CONFIG.
//   * All file-object callbacks (create/cleanup/close/destroy) and the IOCTL
//     dispatch body live in control/ioctl.c.
//
// SDDL: D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;WD)
//   — SYSTEM/Administrators full control (GA), others generic read (GR);
//   write commands are re-authorized (privileged check) by ioctl.c at create.
// ============================================================================
#include <ntddk.h>
#include <wdf.h>

#include "../runtime/runtime.h"
#include "../control/ioctl.h" // SK_IOCTL_DEVICE_TYPE / SkIoctlEvtDeviceControl / context layout
#include "driver.h"          // SkDeviceCreate contract
extern WDFDRIVER g_SkWdfDriver; // KMDF driver object from driver.c

// Exported beyond driver.h (extern-referenced by control/ioctl.c):
VOID SkDeviceDelete(void); // delete control device (idempotent), called by SkControlDestroy
// File-object callback bodies and the context type token are defined by
// control/ioctl.c and declared via control/ioctl.h (not re-declared here).

// Control device WDF object (deleted via SkDeviceDelete by ioctl.c's SkControlDestroy)
WDFDEVICE g_SkControlWdfDevice;

// Control device default queue (pulled by ioctl.c's dequeue thread)
WDFQUEUE g_SkControlWdfQueue;
// Device name / symbolic link (user mode opens \\.\ShinkenWfp)
static const WCHAR kSkDeviceName[] = L"\\Device\\ShinkenWfp";
static const WCHAR kSkDosDeviceName[] = L"\\??\\ShinkenWfp";
// SDDL: SYSTEM/Admin full control, others generic read (see file header)
static const WCHAR kSkSddl[] = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;WD)";

static VOID skInitUnicode(PUNICODE_STRING us, const WCHAR *s, ULONG bytes) {
    us->Length = (USHORT)(bytes - sizeof(WCHAR));
    us->MaximumLength = (USHORT)bytes;
    us->Buffer = (PWSTR)s;
}

// ---------------------------------------------------------------------------
// SkDeviceCreate: build the control device and return its WDM device object
// (lifecycle needs the WDM object for FwpsCalloutRegister1).
// Failure contract: this function cleans up after itself; the caller does
// nothing on failure. Pre-create failures (allocate / assign-name /
// WdfDeviceCreate) free the caller-owned deviceInit with WdfDeviceInitFree;
// post-create failures (WdfIoQueueCreate / WdfDeviceCreateSymbolicLink) call
// SkDeviceDelete() here, deleting the half-built device (and its queue child,
// with the queue global cleared) exactly once — no named device/symlink
// survives a failed call. Only on SUCCESS does ownership pass to the caller's
// rollback graph (SK_STEP_DEVICE → SkControlDestroy/SkDeviceDelete).
// ---------------------------------------------------------------------------
// skTraceFail: DbgPrint the failing call name — WDF status codes do not
// identify which call was rejected.
static VOID skTraceFail(const char *what, NTSTATUS st) {
    if (st < 0)
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "SHINKEN: SkDeviceCreate step=%s status=0x%08X\n", what,
                   (unsigned int)st);
}

NTSTATUS SkDeviceCreate(PDRIVER_OBJECT driverObject, PDEVICE_OBJECT *wdmDeviceOut) {
    NTSTATUS status;
    PWDFDEVICE_INIT deviceInit;
    UNICODE_STRING sddl;
    UNICODE_STRING deviceName;
    UNICODE_STRING dosName;
    WDF_FILEOBJECT_CONFIG fileConfig;
    WDF_OBJECT_ATTRIBUTES fileAttrs;
    WDF_OBJECT_ATTRIBUTES devAttrs;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_OBJECT_ATTRIBUTES queueAttrs;
    WDFQUEUE queue;

    UNREFERENCED_PARAMETER(driverObject);
    *wdmDeviceOut = NULL;
    queue = NULL;

    skInitUnicode(&sddl, kSkSddl, sizeof(kSkSddl));
    skInitUnicode(&deviceName, kSkDeviceName, sizeof(kSkDeviceName));
    skInitUnicode(&dosName, kSkDosDeviceName, sizeof(kSkDosDeviceName));

    deviceInit = WdfControlDeviceInitAllocate(g_SkWdfDriver, &sddl);
    if (!deviceInit)
        return STATUS_INSUFFICIENT_RESOURCES;

    WdfDeviceInitSetDeviceType(deviceInit, SK_IOCTL_DEVICE_TYPE); // matches the IOCTL code family
    WdfDeviceInitSetIoType(deviceInit, WdfDeviceIoBuffered); // all METHOD_BUFFERED
    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    skTraceFail("WdfDeviceInitAssignName", status);
    if (status < 0) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    // File-object config: create/cleanup/close callbacks + destroy callback +
    // context type (callback bodies/per-handle semantics in control/ioctl.c; wiring only here)
    RtlZeroMemory(&fileConfig, sizeof(fileConfig));
    fileConfig.Size = sizeof(fileConfig);
    fileConfig.EvtDeviceFileCreate = SkIoctlEvtFileCreate;
    fileConfig.EvtFileClose = SkIoctlEvtFileClose;
    fileConfig.EvtFileCleanup = SkIoctlEvtFileCleanup;
    // Callbacks consume cleanup/close themselves; do not auto-forward.
    fileConfig.AutoForwardCleanupClose = WdfFalse;
    fileConfig.FileObjectClass = WdfFileObjectWdfCannotUseFsContexts;
    RtlZeroMemory(&fileAttrs, sizeof(fileAttrs));
    // Size is required: zero makes WDF silently ignore the file-object
    // config and CreateFile hangs forever.
    fileAttrs.Size = sizeof(fileAttrs);
    fileAttrs.EvtDestroyCallback = SkIoctlEvtFileDestroy; // counted pair of ShHandleClose
    // ExecutionLevel split: file-object attributes stay Passive (create-path
    // callbacks are inherently PASSIVE); device/queue attributes below are
    // Dispatch so IRPs dispatch inline on the arrival thread. The dispatch
    // path uses only spinlocks/nonpaged pool/KeSetEvent — safe at DISPATCH_LEVEL.
    fileAttrs.ExecutionLevel = WdfExecutionLevelPassive;
    fileAttrs.SynchronizationScope = WdfSynchronizationScopeNone;
#ifndef SHINKEN_HOST_SHIM
    WDF_OBJECT_ATTRIBUTES_SET_CONTEXT_TYPE(&fileAttrs, SK_IOCTL_CONTEXT);
#else
    fileAttrs.ContextTypeInfo = (PVOID)&SkIoctlContextTypeToken;
#endif
    WdfDeviceInitSetFileObjectConfig(deviceInit, &fileConfig, &fileAttrs);
    // Device attributes: explicit WdfExecutionLevelDispatch — IRPs invoke
    // EvtIoDeviceControl inline on the arrival thread (safe: see above).
    RtlZeroMemory(&devAttrs, sizeof(devAttrs));
    devAttrs.Size = sizeof(devAttrs);
    devAttrs.ExecutionLevel = WdfExecutionLevelDispatch;
    devAttrs.SynchronizationScope = WdfSynchronizationScopeNone;
    status = WdfDeviceCreate(&deviceInit, &devAttrs, &g_SkControlWdfDevice);
    skTraceFail("WdfDeviceCreate", status);
    if (status < 0) {
        WdfDeviceInitFree(deviceInit); // on failure the init is still caller-owned
        return status;
    }
    // After WdfDeviceCreate succeeds, WDF owns deviceInit — do not free

    // Default queue (DeviceControl only; request-gate/serialization semantics in ioctl.c).
    //
    // Manual dispatch: ioctl.c's dequeue thread pulls requests via
    // WdfIoQueueRetrieveNextRequest (reads the queue directly); presentation-based
    // parallel dispatch is not used.
    RtlZeroMemory(&queueConfig, sizeof(queueConfig));
    queueConfig.Size = sizeof(queueConfig);
    queueConfig.DispatchType = WdfIoQueueDispatchManual;
    queueConfig.PowerManaged = WdfFalse; // control device is not power-managed
    queueConfig.DefaultQueue = 1;
    RtlZeroMemory(&queueAttrs, sizeof(queueAttrs));
    queueAttrs.Size = sizeof(queueAttrs);
    // ExecutionLevel Dispatch (see devAttrs comment above).
    queueAttrs.ExecutionLevel = WdfExecutionLevelDispatch;
    queueAttrs.SynchronizationScope = WdfSynchronizationScopeNone;
    status = WdfIoQueueCreate(g_SkControlWdfDevice, &queueConfig, &queueAttrs, &g_SkControlWdfQueue);
    skTraceFail("WdfIoQueueCreate", status);
    if (status < 0)
        goto fail_delete_device;

    status = WdfDeviceCreateSymbolicLink(g_SkControlWdfDevice, &dosName);
    skTraceFail("WdfDeviceCreateSymbolicLink", status);
    if (status < 0)
        goto fail_delete_device;
    // Non-PnP control device has no PDO, so device interfaces are
    // unavailable; the only user-mode open path is \\.\ShinkenWfp.

    WdfControlFinishInitializing(g_SkControlWdfDevice);
    *wdmDeviceOut = WdfDeviceWdmGetDeviceObject(g_SkControlWdfDevice);
    return STATUS_SUCCESS;

fail_delete_device:
    SkDeviceDelete();
    return status;
}

// ---------------------------------------------------------------------------
// SkDeviceDelete: delete the control device (idempotent). Called by
// control/ioctl.c's SkControlDestroy — reachable only after the runtime gate
// (ShRuntimeDestroyAllowed) allows destroy. WdfObjectDelete takes the queue
// with it (the queue is a child of the device), so the queue global is
// cleared in the same step: a stale WDFQUEUE handle must never survive the
// device it belongs to (a later purge/quiesce on it would touch a freed
// object).
// ---------------------------------------------------------------------------
VOID SkDeviceDelete(void) {
    if (g_SkControlWdfDevice != NULL) {
        g_SkControlWdfQueue = NULL; // cleared before the delete: no window
                                    // where the queue global outlives validity
        WdfObjectDelete(g_SkControlWdfDevice);
        g_SkControlWdfDevice = NULL;
    }
}
