// ============================================================================
// wfp/wfp_manager.h — WFP manager: unified install, transaction,
// rollback and teardown of engine session / provider / sublayer /
// callout / filter (see docs/WFP_LIFETIME.md)
//
// Install order: engine open (DYNAMIC session) -> provider -> sublayer ->
// per layer: callout register -> callout add -> filter add (txn commit).
// Rollback: delete only REGISTERED/ACTIVE objects in reverse phase
// order; unknown error => Leaked => caller parks (no image-unloading
// failure). Teardown: stop new classify references first (callout
// unregister is the documented safe point), strip flow contexts between
// BUSY retries, then delete filter/callout/sublayer/provider and close
// the engine. Idempotent.
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
