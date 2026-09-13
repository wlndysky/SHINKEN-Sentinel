// ============================================================================
// wfp/wfp_guids.c — single GUID instantiation unit (real WDK build)
//
// Real WDK: <initguid.h> makes the DEFINE_GUIDs below expand to
// definitions:
//   * engine GUIDs from fwpsk.h/fwpmk.h (FWPM_LAYER_*/
//     FWPM_CONDITION_*; no kernel lib provides definitions, so exactly
//     one TU must instantiate them);
//   * this driver's GUIDs from wfp_guids.h.
// This TU has a per-item vcxproj override and does not force-include
// fwpsk/fwpmk — otherwise the include guards would defeat INITGUID
// (all other TUs get extern declarations only).
// Shim/host build: shim/guiddef.h's DEFINE_GUID is always static const
// and initguid.h is an empty header, so this unit emits no extra link
// symbols; fwpsk/fwpmk arrive via -include and are not included here.
// ============================================================================
#ifdef SHINKEN_HOST_SHIM
#include "wfp_guids.h"
#else
#include <initguid.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include "wfp_guids.h"
#endif
