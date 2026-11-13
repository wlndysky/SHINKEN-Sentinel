// ============================================================================
// control/ioctl.h — IOCTL dispatch and per-handle context (protocol: protocol.h)
// ============================================================================
#pragma once
#include <ntddk.h>
#include "protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

// Per-handle context (KMDF file-object attachment): privilege flag + counted pairing.
// `counted` is set ONLY after the handle-create gate (ShRundown, see ioctl.c)
// accepted the create; EvtFileDestroy pairs ShHandleClose exactly when counted.
typedef struct _SK_IOCTL_CONTEXT {
    BOOLEAN privileged;   // handle-scoped capability: enabled BUILTIN\Administrators
                          // group of the creator's EFFECTIVE token (impersonation- and
                          // UAC deny-only aware; see ioctl.c), decided once at create
    BOOLEAN counted;      // ShHandleOpen paired (destroy decrements on this)
} SK_IOCTL_CONTEXT;

// Control-plane lifecycle
NTSTATUS SkControlInit(PDRIVER_OBJECT driverObject);  // start control-plane consumers: ReadyNotify +
                                                      // dequeue thread + create-rundown reset + request
                                                      // gate (device/queue/ACL live in driver/device.c)
BOOLEAN SkControlQuiesce(void);                       // close request + handle-create gates (ShRundown),
                                                      // drain in-flight creates, join consumer,
                                                      // bounded-wait handles==0; TRUE => destroy allowed
VOID SkControlDestroy(void);                          // delete device (after the gate allows destroy)

// KMDF callback (wired up by driver/device.c)
VOID SkIoctlEvtDeviceControl(WDFQUEUE queue, WDFREQUEST request, size_t outLen,
                             size_t inLen, ULONG ioControlCode);

// File-object callbacks (implemented in ioctl.c; wired by driver/device.c's
// WDF_FILEOBJECT_CONFIG / EvtDestroyCallback): create determines privilege and
// pairs ShHandleOpen, destroy pairs ShHandleClose per `counted`; cleanup/close
// are empty hooks (counting semantics: see ioctl.c comments).
#ifndef SHINKEN_HOST_SHIM
// Real WDK: KMDF typed context (WDF_DECLARE_TYPE_AND_GLOBALS generates a
// selectany global, safe for multi-TU inclusion); use generated SkIoctlGetContext.
#include <wdf.h>
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(SK_IOCTL_CONTEXT, SkIoctlGetContext)
#else
extern const char SkIoctlContextTypeToken; // shim: SK_IOCTL_CONTEXT type token
#endif
VOID SkIoctlEvtFileCreate(WDFDEVICE device, WDFREQUEST request, WDFFILEOBJECT fileObject);
VOID SkIoctlEvtFileCleanup(WDFFILEOBJECT fileObject);
VOID SkIoctlEvtFileClose(WDFFILEOBJECT fileObject);
VOID SkIoctlEvtFileDestroy(WDFOBJECT fileObject);

#ifdef __cplusplus
}
#endif
