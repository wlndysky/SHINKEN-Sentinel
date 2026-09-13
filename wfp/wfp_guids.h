// ============================================================================
// wfp/wfp_guids.h — single definition point for all WFP/device GUIDs
// of this driver
//
// Rules:
//   * each provider/sublayer/callout/filter/device-interface GUID gets
//     exactly one DEFINE_GUID here; every other unit references this
//     header and must never redefine one;
//   * real WDK build: this header expands to extern declarations in
//     normal TUs; the single instantiation is emitted by
//     wfp/wfp_guids.c (which includes this header after <initguid.h>);
//   * shim/host build: shim/guiddef.h's DEFINE_GUID expands to static
//     const, so each TU holds a private copy with the same value (code
//     compares/copies GUIDs by value only — no pointer-identity
//     dependency, see skWfpDefByCalloutKey in wfp_objects.c);
//   * current values are test GUIDs (not production GUIDs); inventory
//     and sync surface in wdk/guid_registry.json;
//   * zero GUIDs forbidden; never mix test/production GUIDs (a change
//     updates this file + inventory + INF in one commit).
// ============================================================================
#pragma once
#include <guiddef.h>

// ---- provider / sublayer (engine objects, deleted by key; referenced by wfp_manager.c) ----
DEFINE_GUID(g_SkProviderKey, 0x471b9041, 0x60c8, 0x4000,
            0x89, 0xab, 0x0f, 0x99, 0xb7, 0x04, 0x95, 0xbe);
DEFINE_GUID(g_SkSubLayerKey, 0xa0ee102a, 0x514e, 0x48ca,
            0xa4, 0x35, 0x22, 0x5a, 0x4d, 0x30, 0x3c, 0xb0);

// ---- BFE displayData.name (BFE requires non-empty, else
//      STATUS_FWP_NULL_DISPLAY_NAME; uniform test labels) ----
#define SK_WFP_PROVIDER_NAME_W L"SHINKEN WFP Demo Provider (test)"
#define SK_WFP_SUBLAYER_NAME_W L"SHINKEN WFP Demo SubLayer (test)"
#define SK_WFP_CALLOUT_NAME_W  L"SHINKEN WFP Demo Callout (test)"
#define SK_WFP_FILTER_NAME_W   L"SHINKEN WFP Demo Filter (test)"

// ---- callout (runtime registration + engine-side mgmt object; referenced by wfp_callouts.c layer cards) ----
DEFINE_GUID(SK_CALLOUT_ALE_AUTH_CONNECT_V4, 0x9087874c, 0x8fa9, 0x4f56,
            0xb4, 0x26, 0x45, 0x74, 0xe1, 0x17, 0xbd, 0x1f);
DEFINE_GUID(SK_CALLOUT_ALE_AUTH_CONNECT_V6, 0x9679cb37, 0xab39, 0x4ad6,
            0xb8, 0x12, 0xb8, 0x63, 0xc4, 0x3b, 0xa8, 0xa0);
DEFINE_GUID(SK_CALLOUT_ALE_RECV_ACCEPT_V4, 0x1b8647f8, 0x9e64, 0x45ec,
            0x89, 0xf6, 0xf2, 0x4b, 0x71, 0x70, 0x7b, 0x51);
DEFINE_GUID(SK_CALLOUT_ALE_RECV_ACCEPT_V6, 0x1db4282c, 0xa9ab, 0x4e2b,
            0xb2, 0xcd, 0x35, 0x36, 0x39, 0xc1, 0x43, 0xbd);
DEFINE_GUID(SK_CALLOUT_FLOW_ESTABLISHED_V4, 0xe5fb640f, 0x6ffc, 0x42df,
            0xa0, 0xa3, 0xe0, 0xa9, 0x53, 0x5c, 0x10, 0xf8);
DEFINE_GUID(SK_CALLOUT_FLOW_ESTABLISHED_V6, 0x350e9656, 0xb326, 0x43e4,
            0x8b, 0x6e, 0x59, 0x03, 0x91, 0x92, 0xd4, 0x00);

// ---- filter (explicit key: diagnosable / verifiable by key; referenced by wfp_objects.c AddFilter) ----
DEFINE_GUID(SK_FILTER_ALE_AUTH_CONNECT_V4, 0x947cc9ea, 0x2435, 0x45e9,
            0xbd, 0x6b, 0x41, 0xec, 0x15, 0xd8, 0x23, 0x55);
DEFINE_GUID(SK_FILTER_ALE_AUTH_CONNECT_V6, 0xaa02a16f, 0xffdb, 0x4154,
            0xb8, 0x60, 0x03, 0x99, 0x9d, 0x03, 0x2c, 0xa5);
DEFINE_GUID(SK_FILTER_ALE_RECV_ACCEPT_V4, 0x27fcf1b3, 0xcf86, 0x4532,
            0xaa, 0xe6, 0x87, 0xe9, 0x88, 0x42, 0xe4, 0x00);
DEFINE_GUID(SK_FILTER_ALE_RECV_ACCEPT_V6, 0xd622f799, 0x5d79, 0x411f,
            0x93, 0x31, 0xfd, 0x3c, 0xf4, 0x5f, 0xcd, 0xf0);
DEFINE_GUID(SK_FILTER_FLOW_ESTABLISHED_V4, 0x474719f0, 0x8148, 0x43ec,
            0x91, 0x11, 0x2b, 0x7b, 0xe6, 0xba, 0x67, 0x9e);
DEFINE_GUID(SK_FILTER_FLOW_ESTABLISHED_V6, 0xb5667965, 0xa574, 0x436f,
            0x93, 0x58, 0x22, 0xcd, 0x55, 0x11, 0x72, 0x19);

