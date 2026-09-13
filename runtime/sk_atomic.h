// ============================================================================
// runtime/sk_atomic.h — atomic operation abstraction (dual implementation,
// shared by production and host builds).
//
// Semantics (identical on both sides): Add/Sub/Or/Cas/Xchg return the OLD
// value; Or32FetchNew returns the NEW value; Fence is a full barrier
// (seq_cst).
//   * real kernel (MSVC): Interlocked* (x64 locked instructions, RMWs carry a
//     full barrier), Fence = MemoryBarrier();
//   * shim/host (clang): __sync_* builtins.
// Production code must use this header — never raw __sync_* (absent in MSVC)
// or raw Interlocked* (absent in shim/host).
// ============================================================================
#pragma once
#include <ntddk.h>

#if defined(_MSC_VER) && !defined(__clang__)

#include <intrin.h>

static __forceinline LONG SkAtAdd32(volatile LONG *p, LONG v) { return InterlockedExchangeAdd(p, v); }
static __forceinline LONG SkAtSub32(volatile LONG *p, LONG v) { return InterlockedExchangeAdd(p, -v); }
static __forceinline LONG64 SkAtAdd64(volatile LONG64 *p, LONG64 v) { return InterlockedExchangeAdd64(p, v); }
static __forceinline LONG64 SkAtSub64(volatile LONG64 *p, LONG64 v) { return InterlockedExchangeAdd64(p, -v); }
static __forceinline LONG SkAtOr32(volatile LONG *p, LONG v) { return InterlockedOr(p, v); }
static __forceinline LONG SkAtOr32FetchNew(volatile LONG *p, LONG v) { return InterlockedOr(p, v) | v; }
static __forceinline LONG SkAtCas32(volatile LONG *p, LONG newVal, LONG cmp) {
    return InterlockedCompareExchange(p, newVal, cmp);
}
static __forceinline LONG64 SkAtCas64(volatile LONG64 *p, LONG64 newVal, LONG64 cmp) {
    return InterlockedCompareExchange64(p, newVal, cmp);
}
static __forceinline LONG SkAtXchg32(volatile LONG *p, LONG v) { return InterlockedExchange(p, v); }
static __forceinline LONG64 SkAtXchg64(volatile LONG64 *p, LONG64 v) { return InterlockedExchange64(p, v); }
static __forceinline VOID SkAtFence(void) { MemoryBarrier(); }

#else // shim/host: clang __sync builtins

static __inline LONG SkAtAdd32(volatile LONG *p, LONG v) { return __sync_fetch_and_add(p, v); }
static __inline LONG SkAtSub32(volatile LONG *p, LONG v) { return __sync_fetch_and_sub(p, v); }
static __inline LONG64 SkAtAdd64(volatile LONG64 *p, LONG64 v) { return __sync_fetch_and_add(p, v); }
static __inline LONG64 SkAtSub64(volatile LONG64 *p, LONG64 v) { return __sync_fetch_and_sub(p, v); }
static __inline LONG SkAtOr32(volatile LONG *p, LONG v) { return __sync_fetch_and_or(p, v); }
static __inline LONG SkAtOr32FetchNew(volatile LONG *p, LONG v) { return __sync_or_and_fetch(p, v); }
static __inline LONG SkAtCas32(volatile LONG *p, LONG newVal, LONG cmp) {
    return __sync_val_compare_and_swap(p, cmp, newVal);
}
static __inline LONG64 SkAtCas64(volatile LONG64 *p, LONG64 newVal, LONG64 cmp) {
    return __sync_val_compare_and_swap(p, cmp, newVal);
}
static __inline LONG SkAtXchg32(volatile LONG *p, LONG v) { return __sync_lock_test_and_set(p, v); }
static __inline LONG64 SkAtXchg64(volatile LONG64 *p, LONG64 v) { return __sync_lock_test_and_set(p, v); }
static __inline VOID SkAtFence(void) { __sync_synchronize(); }

#endif
