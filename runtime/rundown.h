// ============================================================================
// runtime/rundown.h — custom rundown (stop-bit scheme, isomorphic to
// EX_RUNDOWN_REF). All atomics via sk_atomic.h (full barriers), so every
// linearization point below is also a memory-ordering point.
//
// State encoding: single volatile LONG count; top bit (0x80000000) = stop bit.
//   count >= 0 : not stopped; value = active holder count
//   count <  0 : BeginStop in effect; low 31 bits = holder count
//
// Invariants:
// 1) Acquire linearizes at successful CAS(count: c>=0 -> c+1). A negative
//    read (stop bit set) fails immediately; CAS failure always implies a
//    competitor made progress (no livelock).
// 2) BeginStop linearizes at atomic OR of STOP_BIT. Once set, every
//    concurrent/later Acquire must fail; Acquires already past their CAS
//    are unaffected (RMWs serialize, count conserved).
// 3) Release never underflows: every Release pairs a successful Acquire, so
//    pre-decrement is >= 1 (running) or STOP_BIT+1 (stopped). Pre-decrement
//    == 0 or == STOP_BIT = double Release: count is rolled back, underflow
//    recorded (ShinkenBlockRundownUnderflow); during Teardown goes straight
//    to UNLOAD_BLOCKED.
// 4) Last Release "wakes" Drain without an event: Drain polls. Last holder
//    decrements to exactly STOP_BIT; next poll observes success. No event,
//    no lost-wakeup window.
// 5) WaitDrained cannot miss a wakeup: count == STOP_BIT is a persistent
//    fact (stop bit irreversible, holders only decrease).
// 6) Memory order: full barriers keep object accesses after Acquire and
//    before Release; Drain observes drained, then destroy is safe
//    (happens-before with holders' last access).
// 7) Misuse semantics: repeat BeginStop = idempotent; Drain without
//    BeginStop = bounded retry then TIMEOUT (caller's responsibility);
//    repeat Release = underflow terminal state (see 3).
// 8) Permanently stuck holder: bounded Drain timeout => caller records
//    ShinkenBlockRundownStuck => UNLOAD_BLOCKED residency (never relies on
//    "callbacks are short").
// 9) Lifetime: SHINKEN_RUNDOWN lives only in image-level static storage,
//    never freed or reused. Exception: rule snapshot readers rundown is
//    freed with the snapshot, strictly after BeginStop+drain, and readers
//    take the reference under g_PublishLock (pointer read and Acquire
//    atomic under one lock; see rules/rule_store.c header).
// ============================================================================
#pragma once
#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHINKEN_RUNDOWN_STOP_BIT 0x80000000L

typedef struct _SHINKEN_RUNDOWN {
    volatile LONG count;
    const char *name;
    volatile LONG underflows; // diagnostics: detected double-Release count
} SHINKEN_RUNDOWN;

VOID ShRundownInit(SHINKEN_RUNDOWN *r, const char *name);
BOOLEAN ShRundownAcquire(SHINKEN_RUNDOWN *r);
VOID ShRundownBeginStop(SHINKEN_RUNDOWN *r);
VOID ShRundownRelease(SHINKEN_RUNDOWN *r);
LONG ShRundownActiveCount(SHINKEN_RUNDOWN *r); // >=0 active holders; -1 stopped and drained
NTSTATUS ShRundownDrain(SHINKEN_RUNDOWN *r, ULONG retries, ULONG delayMs);

#ifdef __cplusplus
}
#endif
