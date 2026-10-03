// ============================================================================
// telemetry/event_queue.c — telemetry event queue thread (the real consumer).
// This file is the sole owner of the queue: the produce/consume/stop/drain
// protocol is described below.
//
// Node layout (kernel-owned memory, fully copied before enqueue, no user
// pointers retained):
//   +0x00 UINT32 type            event type
//   +0x04 UINT32 payloadSize     payload valid bytes (0 = no inline record)
//   +0x08 UINT64 ctx             referenced object (producer already +1 ref)
//   +0x10 volatile LONG* counter optional counter (producer already +1)
//   +0x18 LIST_ENTRY link        list node (popped via CONTAINING_RECORD)
//
// Lock order: the queue lock protects only the list and the producers gate;
// onEvent/freeNode are always called outside the queue lock (onEvent takes
// flow-table locks / refcount ops and must not nest under it).
//
// Stop protocol (single-stopper state machine + producer gate + join):
//   Post:  producer-gate Enter (under queue lock: check stopping, on success
//          producers+1) -> allocate node -> recheck stopping under queue lock
//          -> enqueue / abandon -> Leave
//   Stop:  CAS stopping 0->1 elects exactly ONE stop executor; every other
//          concurrent Stop caller waits on q->stopDone until state 2 is
//          published and then returns the SAME recorded stopResult — losers
//          never drain, free, join, or touch threadObject themselves. The
//          executor: take threadObject under startLock (ownership stays with
//          the queue until a join confirms exit) -> wait producers==0 (any
//          producer that entered before the CAS is covered; any later Post
//          observes stopping!=0 under the queue lock and drops) -> wake ->
//          join; ONLY on exact STATUS_SUCCESS clear threadObject (under
//          startLock) -> fallback drain -> publish stopResult, stopping=2,
//          EventSet(stopDone).
//   No-TOCTOU argument: "stopping!=0" and Post's in-lock stopping check are
//   both atomic observations of the same word, and a producer holding a
//   producers reference is awaited (producers==0) before join/drain — a post
//   either enqueued before the CAS (covered by join/drain) or reads the new
//   state and drops; it cannot enqueue after the drain.
//   Any failure: threadObject and ownership info are RETAINED (the thread may
//   still run), stopResult carries the failure, the caller records
//   ShinkenBlockEventThreadDrain and stays resident.
// Capacity policy: when capacity>0 and the queue is full (in-lock
// pending>=capacity), drop-newest and count overflowDropped — telemetry must
// never block the classify/verdict path. All send failures (stopped / full /
// alloc failure) balance references in place, never affecting the network path.
#define SH_EVENT_PRODUCER_WAIT_RETRIES 100 // bounded wait for producers to reach zero
#define SH_EVENT_PRODUCER_WAIT_DELAY_MS 10
#include <ntddk.h>
#include "../runtime/sk_atomic.h"
#include "event_queue.h"

// CONTAINING_RECORD: real WDK provides it via wdm.h; the shim does not (same
// fallback pattern as packet/flow_context.c).
#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(addr, type, field) \
    ((type *)((char *)(addr) - (size_t)&((type *)0)->field))
#endif

static VOID shEventNodeConsume(SHINKEN_EVENT_QUEUE *q, SHINKEN_EVENT_NODE *n) {
    // Called outside the queue lock: counter decrement + ctx release + node accounting
    if (n->counter)
        SkAtSub32(n->counter, 1);
    if (q->onEvent)
        q->onEvent(n); // semantics: release the reference held by n->ctx (SkFlowCtxRelease family)
    SkAtAdd64(&q->consumed, 1);
}

static VOID shEventDropInPlace(SHINKEN_EVENT_QUEUE *q, UINT32 type, UINT64 ctx,
                               volatile LONG *counter) {
    // Stop/alloc-failure path: not enqueued, references released in place (no leak)
    SHINKEN_EVENT_NODE drop;
    drop.type = type;
    drop.ctx = ctx;
    drop.counter = NULL;
    drop.payloadSize = 0;
    if (counter)
        SkAtSub32(counter, 1);
    if (q->onEvent)
        q->onEvent(&drop);
    SkAtAdd64(&q->dropped, 1);
}

static SHINKEN_EVENT_NODE *shEventPopLocked(SHINKEN_EVENT_QUEUE *q) {
    // Pop the head node (caller holds the queue lock; lock-side work is list-only); NULL if empty
    LIST_ENTRY *ent;
    ent = q->head->Flink;
    if (ent == q->head)
        return NULL;
    q->head->Flink = ent->Flink; // RemoveHeadList
    ent->Flink->Blink = q->head;
    SkAtSub32((volatile LONG *)q->pending, 1);
    return CONTAINING_RECORD(ent, SHINKEN_EVENT_NODE, link);
}

// ---------------------------------------------------------------------------
// Sync primitives (all via ShOps/sk_atomic; stopping is never read/written as plain volatile)
// ---------------------------------------------------------------------------
static LONG shEventStoppingRead(SHINKEN_EVENT_QUEUE *q) {
    return SkAtOr32(&q->stopping, 0); // atomic read
}

// Producer gate: check stopping and register producers under the queue lock.
// The gate closes at Stop's CAS(0->1) linearization point; Enter's in-lock
// check plus the producers refcount jointly close the enqueue window (see the
// file-header stop protocol).
static BOOLEAN shEventProducerEnter(SHINKEN_EVENT_QUEUE *q) {
    KIRQL irql = ShOps.LockAcquireExclusive(q->lock);
    if (shEventStoppingRead(q) != 0) {
        ShOps.LockReleaseExclusive(q->lock, irql);
        return FALSE;
    }
    SkAtAdd32(&q->producers, 1);
    ShOps.LockReleaseExclusive(q->lock, irql);
    return TRUE;
}

static VOID shEventProducerLeave(SHINKEN_EVENT_QUEUE *q) {
    SkAtSub32(&q->producers, 1);
}

#ifdef SHINKEN_HOST_TEST
// Host-test barrier hook (test builds only): invoked after acquiring the
// producer reference and before node allocation, to force the "passed the
// stopping check then paused" TOCTOU interleaving. Used by the external
// forced-interleaving host harness (repo-external: E:/test/verify/control-telemetry/).
VOID (*ShEventTestBarrier)(SHINKEN_EVENT_QUEUE *q);
#endif

VOID ShEventQueueInit(SHINKEN_EVENT_QUEUE *q, EX_SPIN_LOCK *lock, LIST_ENTRY *head,
                      volatile LONG *pending, SHINKEN_EVENT_SINK onEvent) {
    q->lock = lock;
    q->head = head;
    q->pending = pending;
    q->onEvent = onEvent;
    q->threadObject = NULL;
    q->stopping = 0;
    q->stopResult = STATUS_SUCCESS;
    q->producers = 0;
    q->startLock = 0;
    q->posted = q->consumed = q->dropped = 0;
    *lock = 0;
    InitializeListHead(head);
    *pending = 0;
    q->capacity = 0;
    q->overflowDropped = 0;
    ShOps.EventInit(&q->doorbell);
    ShOps.EventInit(&q->stopDone); // signaled once when the stop executor publishes state 2
}

BOOLEAN ShEventPost(SHINKEN_EVENT_QUEUE *q, UINT32 type, UINT64 ctx, volatile LONG *counter) {
    SHINKEN_EVENT_NODE *n;
    KIRQL irql;

    if (!q || !q->head) { // queue uninitialized (init-failure rollback window): do not post, balance refs in place
        if (counter)
            SkAtSub32(counter, 1);
        return FALSE;
    }
    // 1) Producer gate: in-lock stopping check + producers registration
    //    (gate closes at Stop's CAS(0->1) linearization point)
    if (!shEventProducerEnter(q)) {
        shEventDropInPlace(q, type, ctx, counter); // stopping: drop (balanced in place)
        return FALSE;
    }
#ifdef SHINKEN_HOST_TEST
    if (ShEventTestBarrier)
        ShEventTestBarrier(q); // barrier: pause holding the producers reference (forced interleaving)
#endif
    n = (SHINKEN_EVENT_NODE *)ShOps.AllocPool(sizeof(SHINKEN_EVENT_NODE), SHINKEN_EVENT_TAG);
    if (!n) {
        shEventProducerLeave(q);
        shEventDropInPlace(q, type, ctx, counter);
        return FALSE;
    }
    n->type = type;
    n->payloadSize = 0;
    n->ctx = ctx;
    n->counter = counter;
    irql = ShOps.LockAcquireExclusive(q->lock);
    // 2) In-lock recheck: between Enter and here Stop may have advanced
    //    stopping (atomic CAS); on failure abandon the enqueue; node/counter/ctx all balanced in place
    if (shEventStoppingRead(q) != 0) {
        ShOps.LockReleaseExclusive(q->lock, irql);
        shEventProducerLeave(q);
        ShOps.FreePool(n, SHINKEN_EVENT_TAG);
        shEventDropInPlace(q, type, ctx, counter);
        return FALSE;
    }
    // Queue full: drop-newest (drop the current new event), never block the
    // producer (telemetry must not stall classify); node/refs balanced in place
    if (q->capacity > 0 && SkAtAdd32((volatile LONG *)q->pending, 0) >= q->capacity) {
        ShOps.LockReleaseExclusive(q->lock, irql);
        shEventProducerLeave(q);
        ShOps.FreePool(n, SHINKEN_EVENT_TAG);
        shEventDropInPlace(q, type, ctx, counter);
        SkAtAdd64(&q->overflowDropped, 1);
        return FALSE;
    }
    InsertTailList(q->head, &n->link);
    SkAtAdd32((volatile LONG *)q->pending, 1);
    ShOps.LockReleaseExclusive(q->lock, irql);
    shEventProducerLeave(q); // 3) leave the critical section (node enqueued, owned by consumer/drain)
    SkAtAdd64(&q->posted, 1);
    ShOps.EventSet(&q->doorbell); // wake the consumer (else an event may linger
                                  // for one 100ms stop-probe period)
    return TRUE;
}

VOID ShEventThreadBody(PVOID ctx) {
    SHINKEN_EVENT_QUEUE *q = (SHINKEN_EVENT_QUEUE *)ctx;
    for (;;) {
        // doorbell is a SynchronizationEvent: sleep when empty; the 100ms timeout
        // only probes for stop; the inner loop really dequeues, consumes, and releases refs
        BOOLEAN signaled;
        SHINKEN_EVENT_NODE *n;
        KIRQL irql;
        signaled = ShOps.EventWait(&q->doorbell, 100);
        if (!signaled && shEventStoppingRead(q) != 0 &&
            SkAtAdd32((volatile LONG *)q->pending, 0) == 0)
            return; // stopped and queue empty: exit (producer gate closed and drained, no new nodes)
        for (;;) {
            irql = ShOps.LockAcquireExclusive(q->lock);
            n = shEventPopLocked(q);
            ShOps.LockReleaseExclusive(q->lock, irql);
            if (!n)
                break;
            shEventNodeConsume(q, n);                       // outside lock: counter--/ctx release
            ShOps.FreePool(n, SHINKEN_EVENT_TAG);           // outside lock: node free
        }
    }
}

// Start/Stop mutual exclusion: the startLock critical section covers "check
// stopping + create thread + publish threadObject" (Start) and "take/clear
// threadObject" (Stop). Outcome is definite: Start first => Stop joins the
// new thread; Stop first => Start is refused (stopping 1 or 2 — the gate is
// closing or closed; state 2 is terminal, never restart).
// (All call sites are PASSIVE: ThreadCreate itself requires PASSIVE; CAS spin is legal.)
NTSTATUS ShEventThreadStart(SHINKEN_EVENT_QUEUE *q) {
    NTSTATUS st;
    PVOID thr = NULL;

    if (!q || !q->head)
        return STATUS_INVALID_DEVICE_STATE; // queue uninitialized: do not start a thread
    while (SkAtCas32(&q->startLock, 1, 0) != 0)
        ShOps.SleepMs(0); // yield (Start/Stop critical section is very short)
    if (shEventStoppingRead(q) != 0) {
        q->startLock = 0;
        return STATUS_INVALID_DEVICE_STATE; // stopping/stopped: never restart (terminal semantics)
    }
    if (q->threadObject) {
        q->startLock = 0;
        return STATUS_SUCCESS; // already running (BFE callback repeated-start scenario)
    }
    st = ShOps.ThreadCreate(ShEventThreadBody, q, &thr);
    if (st >= 0)
        q->threadObject = thr; // published inside startLock: Stop either cannot see it
                               // (not created) or takes it and joins — join is never missed
    q->startLock = 0;
    return st;
}

VOID ShEventDrain(SHINKEN_EVENT_QUEUE *q) {
    if (!q || !q->head)
        return;
    for (;;) {
        SHINKEN_EVENT_NODE *n;
        KIRQL irql = ShOps.LockAcquireExclusive(q->lock);
        n = shEventPopLocked(q);
        ShOps.LockReleaseExclusive(q->lock, irql);
        if (!n)
            return;
        shEventNodeConsume(q, n);
        ShOps.FreePool(n, SHINKEN_EVENT_TAG);
    }
}

NTSTATUS ShEventThreadStop(SHINKEN_EVENT_QUEUE *q) {
    NTSTATUS result = STATUS_SUCCESS;
    PVOID thr = NULL;
    ULONG i;

    if (!q || !q->head)
        return STATUS_SUCCESS; // queue uninitialized: nothing to stop or drain

    // 0) Elect exactly ONE stop executor: CAS 0->1. Any other concurrent Stop
    //    caller (or a later idempotent Stop) takes the waiter path: it blocks
    //    until state 2 is published and returns the SAME stopResult. Waiters
    //    never touch threadObject, never join, never drain, never free — so a
    //    failed stop cannot be "completed" early by a second caller.
    if (SkAtCas32(&q->stopping, 1, 0) != 0) {
        while (shEventStoppingRead(q) != 2)
            ShOps.EventWait(&q->stopDone, 100); // bounded probe; state 2 is persistent (no lost wakeup)
        return q->stopResult; // full-barrier publish (atomic Xchg) before state 2 was set
    }

    // --- single executor from here on; stopping == 1 (stop-in-progress) ---
    // 1) Take threadObject under startLock (mutual exclusion with Start).
    //    Ownership stays with the queue until a join CONFIRMS exit: on any
    //    failure below threadObject is retained so a later Stop (or the
    //    residency path) still knows the live thread.
    while (SkAtCas32(&q->startLock, 1, 0) != 0)
        ShOps.SleepMs(0);
    thr = q->threadObject;
    q->startLock = 0;
    // 2) Wait for all entered producers to leave (any later Post observes
    //    stopping!=0 under the queue lock and drops; no new node possible —
    //    precondition for join/drain)
    for (i = 0;; i++) {
        if (SkAtAdd32(&q->producers, 0) == 0)
            break;
        if (i >= SH_EVENT_PRODUCER_WAIT_RETRIES) {
            result = SHINKEN_STATUS_TIMEOUT; // producers stuck: threadObject kept, caller stays resident
            goto done;
        }
        ShOps.SleepMs(SH_EVENT_PRODUCER_WAIT_DELAY_MS);
    }
    ShOps.EventSet(&q->doorbell); // 3) wake the consumer so it observes the stop

    if (thr) {
        result = ShOps.ThreadJoin(thr); // 4) join (the consumer empties the queue before exiting)
        if (result != STATUS_SUCCESS)
            goto done; // join failed (incl. positive): thread may still run => keep threadObject + ownership
        // 5) confirmed exit: NOW — and only now — clear threadObject (under
        //    startLock, the same critical section that publishes it).
        while (SkAtCas32(&q->startLock, 1, 0) != 0)
            ShOps.SleepMs(0);
        if (q->threadObject == thr)
            q->threadObject = NULL;
        q->startLock = 0;
    }
    ShEventDrain(q); // 6) fallback drain (guarantees release even if the thread never started)
    if (SkAtAdd32((volatile LONG *)q->pending, 0) != 0) {
        result = SHINKEN_STATUS_TIMEOUT; // queue cannot drain: ownership info kept
        goto done;
    }
    result = STATUS_SUCCESS;
done:
    // Publish the outcome: result first, then the terminal state, then the
    // wake. sk_atomic/SkOps ops are full barriers, so waiters that observe
    // state 2 also observe stopResult.
    q->stopResult = result;
    SkAtXchg32(&q->stopping, 2); // stopped (terminal; idempotent repeat Stops return stopResult)
    ShOps.EventSet(&q->stopDone);
    return result;
}

LONG ShEventPending(SHINKEN_EVENT_QUEUE *q) {
    return SkAtAdd32((volatile LONG *)q->pending, 0); // unified atomic load (sk_atomic.h)
}

BOOLEAN ShEventThreadRunning(SHINKEN_EVENT_QUEUE *q) {
    // TRUE only while a created thread is owned and not yet joined: after a
    // successful Stop threadObject is NULL (cleared at step 5); after a FAILED
    // Stop it stays non-NULL, truthfully reporting the still-live thread.
    return SkAtAdd64((volatile LONG64 *)&q->threadObject, 0) != 0;
}
// ---------------------------------------------------------------------------
// Inline record posting (ctx=0/counter=NULL; capacity/stop/alloc failure =>
// dropped and counted; telemetry never blocks the verdict path)
// ---------------------------------------------------------------------------
BOOLEAN ShEventPostRecord(SHINKEN_EVENT_QUEUE *q, UINT32 type, const void *record,
                          UINT32 size) {
    SHINKEN_EVENT_NODE *n;
    KIRQL irql;

    if (!q || !q->head || !record || size > SK_EVENT_PAYLOAD_SIZE)
        return FALSE;
    if (!shEventProducerEnter(q)) {
        SkAtAdd64(&q->dropped, 1); // stopping: count the drop (consistent with ShEventPost)
        return FALSE;
    }
    n = (SHINKEN_EVENT_NODE *)ShOps.AllocPool(sizeof(SHINKEN_EVENT_NODE), SHINKEN_EVENT_TAG);
    if (!n) {
        shEventProducerLeave(q);
        SkAtAdd64(&q->dropped, 1);
        return FALSE;
    }
    n->type = type;
    n->payloadSize = size;
    n->ctx = 0;
    n->counter = NULL;
    RtlCopyMemory(n->payload, record, size); // copy into kernel-owned memory before enqueue
    irql = ShOps.LockAcquireExclusive(q->lock);
    if (shEventStoppingRead(q) != 0 ||
        (q->capacity > 0 && SkAtAdd32((volatile LONG *)q->pending, 0) >= q->capacity)) {
        ShOps.LockReleaseExclusive(q->lock, irql);
        shEventProducerLeave(q);
        ShOps.FreePool(n, SHINKEN_EVENT_TAG);
        SkAtAdd64(&q->dropped, 1);
        if (shEventStoppingRead(q) == 0)
            SkAtAdd64(&q->overflowDropped, 1);
        return FALSE;
    }
    InsertTailList(q->head, &n->link);
    SkAtAdd32((volatile LONG *)q->pending, 1);
    ShOps.LockReleaseExclusive(q->lock, irql);
    shEventProducerLeave(q);
    SkAtAdd64(&q->posted, 1);
    ShOps.EventSet(&q->doorbell);
    return TRUE;
}

// ---------------------------------------------------------------------------
// Driver-level telemetry singleton: queue + consumed-record ring (for flush, overwrites oldest)
// ---------------------------------------------------------------------------
#define SK_TELEMETRY_CAPACITY   4096 // queue cap (drop-newest when full)
#define SK_TELEMETRY_RING       1024 // consumed-record ring (overwrites oldest)

static EX_SPIN_LOCK g_SkTelemetryLock;
static LIST_ENTRY g_SkTelemetryHead;
static volatile LONG g_SkTelemetryPending;
SHINKEN_EVENT_QUEUE g_SkTelemetryQueue;

static EX_SPIN_LOCK g_SkRingLock;
static UINT8 g_SkRing[SK_TELEMETRY_RING][SK_EVENT_PAYLOAD_SIZE];
static UINT32 g_SkRingSize[SK_TELEMETRY_RING];
static UINT32 g_SkRingHead;  // next write position
static UINT64 g_SkRingTotal; // total writes ever (= upper-bound reference for flush)

static VOID shTelemetrySink(SHINKEN_EVENT_NODE *n) {
    // Consumer: copy the record into the consumed ring (overwrites oldest); no reference to release (ctx=0)
    KIRQL irql;
    if (n->payloadSize == 0 || n->payloadSize > SK_EVENT_PAYLOAD_SIZE)
        return;
    irql = ShOps.LockAcquireExclusive(&g_SkRingLock);
    RtlCopyMemory(g_SkRing[g_SkRingHead], n->payload, n->payloadSize);
    g_SkRingSize[g_SkRingHead] = n->payloadSize;
    g_SkRingHead = (g_SkRingHead + 1) % SK_TELEMETRY_RING;
    SkAtAdd64((volatile LONG64 *)&g_SkRingTotal, 1);
    ShOps.LockReleaseExclusive(&g_SkRingLock, irql);
}

VOID SkTelemetryInit(void) {
    ShEventQueueInit(&g_SkTelemetryQueue, &g_SkTelemetryLock, &g_SkTelemetryHead,
                     &g_SkTelemetryPending, shTelemetrySink);
    g_SkTelemetryQueue.capacity = SK_TELEMETRY_CAPACITY;
}

NTSTATUS SkTelemetryStart(void) { return ShEventThreadStart(&g_SkTelemetryQueue); }

NTSTATUS SkTelemetryStop(void) { return ShEventThreadStop(&g_SkTelemetryQueue); }

BOOLEAN SkTelemetryPost(UINT32 type, UINT64 ctx, volatile LONG *counter) {
    return ShEventPost(&g_SkTelemetryQueue, type, ctx, counter);
}

BOOLEAN SkTelemetryPostRecord(UINT32 type, const void *record, UINT32 size) {
    return ShEventPostRecord(&g_SkTelemetryQueue, type, record, size);
}

VOID SkTelemetryStats(UINT64 *posted, UINT64 *consumed, UINT64 *dropped,
                      UINT64 *overflowDropped) {
    // Unified atomic loads (sk_atomic.h): the consumer updates these on
    // another thread; diagnostic reads must not tear or cache.
    if (posted)
        *posted = (UINT64)SkAtAdd64((volatile LONG64 *)&g_SkTelemetryQueue.posted, 0);
    if (consumed)
        *consumed = (UINT64)SkAtAdd64((volatile LONG64 *)&g_SkTelemetryQueue.consumed, 0);
    if (dropped)
        *dropped = (UINT64)SkAtAdd64((volatile LONG64 *)&g_SkTelemetryQueue.dropped, 0);
    if (overflowDropped)
        *overflowDropped = (UINT64)SkAtAdd64((volatile LONG64 *)&g_SkTelemetryQueue.overflowDropped, 0);
}

UINT32 SkTelemetryFlush(void *out, UINT32 maxRecords, UINT32 recordSize) {
    // Copy the ring's current contents in write order into out (kernel buffer);
    // return the count. Copy only under the ring lock; an inconsistent snapshot
    // is acceptable (telemetry semantics).
    // Per-record contract: exactly g_SkRingSize[idx] payload bytes are
    // meaningful; the rest of the fixed-size record is ZEROED, so a short
    // record never leaks stale bytes from a previously longer record that
    // occupied the same ring slot or output buffer.
    KIRQL irql;
    UINT32 avail, start, i, n;
    UINT64 total;
    if (!out || recordSize > SK_EVENT_PAYLOAD_SIZE || recordSize == 0)
        return 0;
    irql = ShOps.LockAcquireExclusive(&g_SkRingLock);
    total = (UINT64)SkAtAdd64((volatile LONG64 *)&g_SkRingTotal, 0);
    avail = total < SK_TELEMETRY_RING ? (UINT32)total : SK_TELEMETRY_RING;
    n = avail < maxRecords ? avail : maxRecords;
    start = (g_SkRingHead + SK_TELEMETRY_RING - n) % SK_TELEMETRY_RING;
    for (i = 0; i < n; i++) {
        UINT32 idx = (start + i) % SK_TELEMETRY_RING;
        UINT32 bytes = g_SkRingSize[idx];
        UINT8 *dst = (UINT8 *)out + (UINT64)i * recordSize;
        if (bytes > recordSize)
            bytes = recordSize; // defensive: recordSize <= PAYLOAD_SIZE is checked above
        RtlZeroMemory(dst, recordSize);
        RtlCopyMemory(dst, g_SkRing[idx], bytes);
    }
    ShOps.LockReleaseExclusive(&g_SkRingLock, irql);
    return n;
}
