// WFP ownership has two lifetimes: a dynamic engine session owns all
// management objects; runtime callouts survive BFE service restarts.
// Close the session (with confirmed success) BEFORE unregistering any
// runtime callout. This removes its terminating filters without leaving
// a registered filter that WFP would turn into an unconditional BLOCK.
// All operations below require PASSIVE_LEVEL and serialize on installMutex.
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
    KMUTEX installMutex;
    BOOLEAN installed;          // all management objects committed in this session
} SK_WFP_MANAGER;

extern SK_WFP_MANAGER g_WfpManager;

// Initialize once, before subscribing to BFE notifications.
VOID SkWfpManagerInitMutex(void);
// Synchronize with the current BFE state. A stopped service defers
// installation; runtime registrations remain independently tracked.
NTSTATUS SkWfpManagerInstall(PDEVICE_OBJECT device);
NTSTATUS SkWfpManagerBfeStateChange(PDEVICE_OBJECT device, FWPM_SERVICE_STATE state);
// Close the dynamic session, drain flows, then unregister every nonzero
// runtime ID, including IDs left by failed installation or rollback.
// FALSE retains ownership and forbids driver unload.
BOOLEAN SkWfpManagerTeardown(void);

#ifdef __cplusplus
}
#endif
