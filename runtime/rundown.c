// ============================================================================
// runtime/rundown.c — custom rundown implementation (proof in rundown.h).
// Underflow consequences (record reason / enter residency) are delegated to
// runtime.c via ShRuntimeReportUnderflow; rundown never touches runtime state.
// ============================================================================
#include <ntddk.h>
#include "sk_atomic.h"
#include "rundown.h"
#include "runtime.h"

// Provided by runtime.c: records the underflow reason and decides residency.
VOID ShRuntimeReportUnderflow(SHINKEN_RUNDOWN *r);

VOID ShRundownInit(SHINKEN_RUNDOWN *r, const char *name) {
    r->count = 0;
    r->name = name;
    r->underflows = 0;
}

BOOLEAN ShRundownAcquire(SHINKEN_RUNDOWN *r) {
    LONG c;
    for (;;) {
        c = r->count; // negative read => BeginStop already in effect
        if (c < 0)
            return FALSE;
        if (c >= 0x40000000L)
            return FALSE; // defensive: near count ceiling, treat as stopped
        // CAS failure only from concurrent BeginStop or Acquire/Release;
        // re-read and retry. BeginStop linearizing first => Acquire must fail.
        if (SkAtCas32(&r->count, c + 1, c) == c)
            return TRUE;
    }
}

VOID ShRundownBeginStop(SHINKEN_RUNDOWN *r) {
    // Linearization point: once the stop bit is set, no non-negative read can
    // match an Acquire CAS again. Existing holder count (low 31 bits) unaffected.
    SkAtOr32FetchNew(&r->count, SHINKEN_RUNDOWN_STOP_BIT);
}

VOID ShRundownRelease(SHINKEN_RUNDOWN *r) {
    LONG before = SkAtSub32(&r->count, 1);
    // Underflow detection, two forms:
    //   before == STOP_BIT : Release while stopped with no holders (double Release);
    //   before == 0        : Release while running with no holders (unpaired) —
    //     without rollback count becomes -1, misread as "stopped, 1 holder":
    //    all later Acquires fail and Drain never succeeds.
    if (before == SHINKEN_RUNDOWN_STOP_BIT || before == 0) {
        // Roll back and report the terminal failure; during Teardown the
        // corrupted count cannot prove drained => residency.
        SkAtAdd32(&r->count, 1);
        ShRuntimeReportUnderflow(r);
    }
}

LONG ShRundownActiveCount(SHINKEN_RUNDOWN *r) {
    LONG c = r->count;
    if (c == SHINKEN_RUNDOWN_STOP_BIT)
        return -1; // stopped and drained
    if (c < 0)
        return c & ~SHINKEN_RUNDOWN_STOP_BIT; // stopped, holders remain
    return c;
}

NTSTATUS ShRundownDrain(SHINKEN_RUNDOWN *r, ULONG retries, ULONG delayMs) {
    ULONG i;
    // Precondition: caller already did BeginStop. Bounded retries; drained not
    // observed => SHINKEN_STATUS_TIMEOUT, caller enters residency.
    for (i = 0;; i++) {
        if (r->count == SHINKEN_RUNDOWN_STOP_BIT)
            return STATUS_SUCCESS;
        if (i >= retries)
            return SHINKEN_STATUS_TIMEOUT;
        ShOps.SleepMs(delayMs);
    }
}
