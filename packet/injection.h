// ============================================================================
// packet/injection.h — injection lifecycle (gate + drain + handle/pool
// owner)
//
// Protocol (runtime-layer injection gate; proof in runtime/rundown.h):
// acquire an injection reference (ShInjectionBegin) -> validate
// handle/pool -> build NBL -> submit async injection -> completion
// owns the NBL and returns the reference exactly once
// (ShInjectionEnd).
// teardown: GateStop -> Drain -> destroy handles -> destroy pools.
// Packet injection state must be obtained from WFP's injection-state API;
// the ALE flow-context pointer must never be treated as an injection tag.
// ============================================================================
#pragma once
#include <ntddk.h>
#include "../runtime/runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

// injection subsystem lifecycle
// SkInjectInit publishes readiness only after both handles and pools exist.
// Failed partial initialization runs tracked teardown; unconfirmed destruction
// keeps ownership and blocks unload. Re-init after quiesce is refused.
NTSTATUS SkInjectInit(void);        // create injection handles + NBL/NB pools
BOOLEAN SkInjectQuiesce(void);      // GateStop + drain in-flight + destroy handles;
                                    // on full success clears the init state bit
                                    // (re-init is then refused)
VOID SkInjectDestroy(void);         // destroy pools (after handle destroy)


#ifdef __cplusplus
}
#endif
