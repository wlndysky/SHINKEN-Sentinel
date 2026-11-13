// ============================================================================
// driver/driver.h — driver entry public declarations (single DriverEntry / single EvtDriverUnload)
// ============================================================================
#pragma once
#include <ntddk.h>
#include <wdf.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SHINKEN_HOST_SHIM
DRIVER_INITIALIZE DriverEntry; // real WDK: marks the entry role for code analysis (C28101)
#else
NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
#endif

// Device creation (driver/device.c): control device + IOCTL queue + SDDL ACL.
// Returns an UNPUBLISHED device: until SkDevicePublish, KMDF itself completes
// every create/IOCTL aimed at the device, so no file-object callback can run
// while subsystem initialization is still in flight.
NTSTATUS SkDeviceCreate(PDRIVER_OBJECT driverObject, PDEVICE_OBJECT *wdmDeviceOut);
// Device publication (driver/device.c): WdfControlFinishInitializing. DriverEntry
// calls it only after SkLifecycleStart succeeded AND ShRuntimeActivate opened the
// runtime gate — the first create that can ever reach EvtFileCreate therefore
// observes every subsystem (incl. SkControlInit's create-rundown/request gate and
// consumer thread) ready. VOID by WDK contract (WdfControlFinishInitializing has
// no failure path); no-op when no device exists (SkDeviceDelete already ran).
VOID SkDevicePublish(void);
// Device deletion (driver/device.c): idempotent WdfObjectDelete of the control
// device (published or not). Called by SkControlDestroy (control/ioctl.c) on the
// normal path and by the lifecycle rollback for the device step (SK_STEP_DEVICE)
// when control init failed or was never reached.
VOID SkDeviceDelete(void);

#ifdef __cplusplus
}
#endif
