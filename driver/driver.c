// ============================================================================
// driver/driver.c — single DriverEntry / single EvtDriverUnload
//
// Lifecycle orchestration:
//   DriverEntry
//     └─ ShRuntimeInit → WdfDriverCreate(EvtDriverUnload=SkEvtDriverUnload)
//        → SkDeviceCreate(control device + IOCTL queue + SDDL, driver/device.c;
//          UNPUBLISHED: KMDF itself fails every create/IOCTL until publication,
//          so no driver callback can run mid-initialization; tracked as
//          SK_STEP_DEVICE by SkLifecycleStart, so a failure in ANY later step
//          rolls the device back too — no named device/symlink is ever left
//          behind by a failed DriverEntry)
//        → SkLifecycleStart(rules → telemetry → control → inject → BFE subscribe
//          → WFP install; any failure rolls back in reverse order incl. the
//          device step; rollback failure => UNLOAD_BLOCKED => stay resident,
//          never return failure)
//        → ShRuntimeActivate → SkDevicePublish (WdfControlFinishInitializing):
//          only now can the first Create/IOCTL arrive, and every gate it
//          touches (create rundown / request gate / consumer thread) is ready
//
//   SkEvtDriverUnload(sole KMDF unload callback)
//     └─ ShRuntimeRunUnload(...) — destroy runs only after full quiesce;
//        otherwise UNLOAD_BLOCKED + resident, no return (KMDF EvtDriverUnload
//        has no "refuse unload" result).
// ============================================================================
#include <ntddk.h>
#include <wdf.h>

#include "../runtime/runtime.h"
#include "../runtime/lifecycle.h"
#include "driver.h"

WDFDRIVER g_SkWdfDriver; // KMDF driver object (WdfDriverCreate product; extern-referenced by device.c)

// ---------------------------------------------------------------------------
// SkEvtDriverUnload: sole unload path. Returning lets KMDF unload the image,
// so return only after ShRuntimeRunUnload reports fully quiescent (destroy
// done); any drain failure => ShRuntimeBlockUnloadForever keeps the image
// resident (in-flight WFP/BFE/work-item callback code stays valid forever).
// ---------------------------------------------------------------------------
static VOID SkEvtDriverUnload(WDFDRIVER Driver) {
    UNREFERENCED_PARAMETER(Driver);
    (VOID)ShRuntimeRunUnload(SkLifecycleQuiesce, NULL, SkLifecycleDestroy, NULL);
}

// ---------------------------------------------------------------------------
// DriverEntry (KMDF non-PnP mode)
// ---------------------------------------------------------------------------
NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    WDF_DRIVER_CONFIG driverConfig;
    PDEVICE_OBJECT wdmDevice = NULL;

    ShRuntimeInit(); // idempotent: runtime state machine/rundown globally ready

    RtlZeroMemory(&driverConfig, sizeof(driverConfig));
    driverConfig.Size = sizeof(driverConfig);
    driverConfig.EvtDriverDeviceAdd = NULL;                 // non-PnP: no AddDevice
    driverConfig.EvtDriverUnload = SkEvtDriverUnload;
    driverConfig.DriverInitFlags = WdfDriverInitNonPnpDriver;
    driverConfig.DriverPoolTag = 0;
    status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &driverConfig,
                             &g_SkWdfDriver);
    if (status < 0)
        return status; // driver object not created: no subsystem state yet, fail directly

    // Control device + IOCTL queue + SDDL (all callbacks exported by
    // control/ioctl.c). UNPUBLISHED until SkDevicePublish below: during
    // SkLifecycleStart KMDF itself completes any create/IOCTL, so no
    // file-object callback can observe half-initialized subsystems.
    status = SkDeviceCreate(DriverObject, &wdmDevice);
    if (status < 0)
        return status; // device init released internally on failure (WdfDeviceInitFree/WdfObjectDelete)

    // Subsystem orchestrated start (order/rollback: see runtime/lifecycle.c header)
    status = SkLifecycleStart(DriverObject, wdmDevice);
    if (status < 0) {
        // Internally rolled back, or rollback failed into UNLOAD_BLOCKED.
        // Returning failure while resident would unload the image even though
        // callbacks may still reference it, so that branch never returns.
        if (ShRuntimeState() == ShinkenUnloadBlocked)
            ShRuntimeBlockUnloadForever();
        return status; // device (unpublished) was rolled back or kept resident
    }

    // Activate is a CAS Uninitialized -> Active: a late BFE-callback rollback
    // failure during startup may already have won the race into the terminal
    // UnloadBlocked state, in which case Activate refuses and the image must
    // stay resident — park forever BEFORE publishing (a published device
    // would accept creates while all destroy is forbidden), never return a
    // failure code that could unload the image under live callbacks.
    ShRuntimeActivate();  // all subsystems ready: open the gate for async work
    if (ShRuntimeState() == ShinkenUnloadBlocked)
        ShRuntimeBlockUnloadForever(); // resident wait; never returns
    SkDevicePublish();   // publish the control device: only now can the first
                         // Create/IOCTL arrive, against fully started subsystems
    return STATUS_SUCCESS;
}

// LLVM IR anchor: keep entry/unload callback alive under O2
void *const __llvm_keep_shinken_driver[] = {
    (void *)DriverEntry,
    (void *)SkEvtDriverUnload,
};
