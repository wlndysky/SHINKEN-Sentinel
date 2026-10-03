// ============================================================================
// wfp/wfp_manager.h — WFP manager: unified install, transaction,
// rollback and teardown of engine session / provider / sublayer /
// callout / filter
//
// Install order: engine open (DYNAMIC session) -> provider -> sublayer ->
// per layer: callout register (flow-attach gate re-armed) -> callout add
// -> filter add (txn commit).
// Rollback: delete everything still on the books in reverse phase order —
// per layer filter -> callout (attach gate stop+drain, flow strip+settle,
// runtime unregister + mgmt delete; a failed FwpmCalloutAdd0 does NOT
// erase the runtime registration) -> sublayer -> provider -> close
// engine. Abort's return value is checked. Unknown error => Leaked =>
// caller parks (no image-unloading failure).
// Teardown: per callout close + drain the flow-attach gate, then strip
// and settle flow contexts BEFORE the callout-unregister safe point
// (busyCleanup still strips between BUSY retries), then delete
// filter/callout/sublayer/provider and close the engine. Idempotent.
// FALSE on failure (LEAKED / BUSY exhausted / flows not settled):
// caller parks.
// ============================================================================
#pragma once
#include <ntddk.h>
#include "wfp_objects.h"
#include "wfp_callouts.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _SK_WFP_MANAGER {
    HANDLE engine;              // FWPM engine handle (DYNAMIC session)
    SK_WFP_OBJECT engineObj;    // engine handle close tracking
    SK_WFP_OBJECT provider;
    SK_WFP_OBJECT sublayer;
    SK_WFP_OBJECT callouts[SK_LAYER_COUNT];   // per-layer runtime+mgmt callout
    SK_WFP_OBJECT filters[SK_LAYER_COUNT];    // per-layer filter
    KMUTEX installMutex;        // install/teardown mutex (PASSIVE path;
                                // KMUTEX required: WFP calls fail at
                                // DISPATCH_LEVEL, see wfp_manager.c)

    BOOLEAN installed;          // install-complete flag
} SK_WFP_MANAGER;

extern SK_WFP_MANAGER g_WfpManager;

// Install all WFP objects (device = control device WDM object). Rolls
// back internally on failure; if rollback itself fails (LEAKED), the
// caller (runtime/lifecycle.c) parks.
NTSTATUS SkWfpManagerInstall(PDEVICE_OBJECT device);
// Teardown: stop classify references + delete all objects + close the
// engine. Idempotent. FALSE on failure (LEAKED / BUSY exhausted):
// caller parks.
BOOLEAN SkWfpManagerTeardown(void);
// Initialize installMutex (one-time KeInitializeMutex; call at the top
// of SkLifecycleStart, before any install/teardown can arrive; the
// BSS-zero flag makes it idempotent).
VOID SkWfpManagerInitMutex(void);

#ifdef __cplusplus
}
#endif
