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
// Self-injection guard: SkInjectIsSelf recognizes packets injected by
// this driver (tagged injection context); classify/reinject paths
// permit them directly — no re-classification / infinite loop.
// ============================================================================
#pragma once
#include <ntddk.h>
#include "../runtime/runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

// injection subsystem lifecycle
NTSTATUS SkInjectInit(void);        // create injection handles + NBL/NB pools
BOOLEAN SkInjectQuiesce(void);      // GateStop + drain in-flight + destroy handles
VOID SkInjectDestroy(void);         // destroy pools (after handle destroy)

// self-injection check (SK_INJECT_TAG written into the injection context at submit; compared in classify)
#define SK_INJECT_TAG 0x534B4A54u // 'SKJT'
BOOLEAN SkInjectIsSelf(UINT64 injectionContext);

#ifdef __cplusplus
}
#endif
