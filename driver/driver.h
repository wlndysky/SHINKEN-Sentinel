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

// Device creation (driver/device.c): control device + IOCTL queue + SDDL ACL
NTSTATUS SkDeviceCreate(PDRIVER_OBJECT driverObject, PDEVICE_OBJECT *wdmDeviceOut);
// Device deletion (driver/device.c): idempotent WdfObjectDelete of the control
// device. Called by SkControlDestroy (control/ioctl.c) on the normal path and
// by the lifecycle rollback for the device step (SK_STEP_DEVICE) when control
// init failed or was never reached.
VOID SkDeviceDelete(void);

#ifdef __cplusplus
}
#endif
