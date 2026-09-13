// ============================================================================
// telemetry/event_queue.c — telemetry event queue thread (the real consumer).
// This file is the sole owner of the queue: the produce/consume/stop/drain
// protocol is described below and in docs/UNLOAD_SAFETY.md §5.
//
// Node layout (kernel-owned memory, fully copied before enqueue, no user
// pointers retained):
//   +0x00 UINT32 type            event type
//   +0x08 UINT64 ctx             referenced object (producer already +1 ref)
//   +0x10 volatile LONG* counter optional counter (producer already +1)
//   +0x18 LIST_ENTRY link        list node
//
// Lock order: the queue lock protects only the list and the stopping/
// producers gate; onEvent/freeNode are always called outside the queue lock
// (onEvent takes flow-table locks / refcount ops and must not nest under it).
//
// Stop protocol (producer gate latch + producer refcount + consumer join +
// fallback drain):
//   Post:  producer-gate Enter (under queue lock: check stopping, on success
//          producers+1) -> allocate node -> recheck stopping under queue lock
//          -> enqueue / abandon -> Leave
//   Stop:  inside startLock set stopping=1 (closes the production entrance;
//          forms a single linearization point with Enter's in-lock check) ->
//          wait producers==0 (all entered producers have left; any later Post
//          must take the drop path, no new node possible) -> wake -> join ->
//          drain
//   Any failure: caller records ShinkenBlockEventThreadDrain and stays
//   resident.
// Key invariant: "stopping set" and "Post's stopping check" both happen under
// the same queue lock, so there is no TOCTOU of the form "post passes the
// check, stop completes drain, post then enqueues" — a post either enqueues
// before the set (covered by drain/join) or reads stopping after it and drops.
// Capacity policy: when capacity>0 and the queue is full (in-lock
// pending>=capacity), drop-newest and count overflowDropped — telemetry must
// never block the classify/verdict path. All send failures (stopped / full /
// alloc failure) balance references in place, never affecting the network path.
#define SH_EVENT_PRODUCER_WAIT_RETRIES 100 // bounded wait for producers to reach zero
#define SH_EVENT_PRODUCER_WAIT_DELAY_MS 10
#include <ntddk.h>
#include "../runtime/sk_atomic.h"
#include "event_queue.h"

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
    return (SHINKEN_EVENT_NODE *)((char *)ent - 0x18);
}

// ---------------------------------------------------------------------------
// Sync primitives (all via ShOps/sk_atomic; stopping is never read/written as plain volatile)
// ---------------------------------------------------------------------------
static LONG shEventStoppingRead(SHINKEN_EVENT_QUEUE *q) {
    return SkAtOr32(&q->stopping, 0); // atomic read
}

// Producer gate: check stopping and register producers under the queue lock —
// forms a single linearization point with Stop's in-lock stopping set; holding
// a producers reference permits enqueue.
static BOOLEAN shEventProducerEnter(SHINKEN_EVENT_QUEUE *q) {
    KIRQL irql = ShOps.LockAcquireExclusive(q->lock);
    if (q->stopping) {
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
// stopping check then paused" TOCTOU interleaving (see T16).
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
    q->producers = 0;
    q->startLock = 0;
    q->posted = q->consumed = q->dropped = 0;
    *lock = 0;
    InitializeListHead(head);
    *pending = 0;
    q->capacity = 0;
    q->overflowDropped = 0;
    ShOps.EventInit(&q->doorbell);
}

BOOLEAN ShEventPost(SHINKEN_EVENT_QUEUE *q, UINT32 type, UINT64 ctx, volatile LONG *counter) {
    SHINKEN_EVENT_NODE *n;
    KIRQL irql;

    if (!q || !q->head) { // queue uninitialized (init-failure rollback window): do not post, balance refs in place
        if (counter)
            SkAtSub32(counter, 1);
        return FALSE;
    }
    // 1) Producer gate: in-lock stopping check + producers registration (linearized with Stop's set)
    if (!shEventProducerEnter(q)) {
        shEventDropInPlace(q, type, ctx, counter); // stopping: drop (balanced in place)
        return FALSE;
    }
#ifdef SHINKEN_HOST_TEST
    if (ShEventTestBarrier)
        ShEventTestBarrier(q); // barrier: pause holding the producers reference (T16 forced interleaving)
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
    // 2) In-lock recheck: between Enter and here Stop may have set stopping
    //    (also in-lock) — on failure abandon the enqueue; node/counter/ctx all balanced in place
    if (q->stopping) {
        ShOps.LockReleaseExclusive(q->lock, irql);
        shEventProducerLeave(q);
        ShOps.FreePool(n, SHINKEN_EVENT_TAG);
        shEventDropInPlace(q, type, ctx, counter);
        return FALSE;
    }
    // Queue full: drop-newest (drop the current new event), never block the
    // producer (telemetry must not stall classify); node/refs balanced in place
    if (q->capacity > 0 && *q->pending >= q->capacity) {
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
        if (!signaled && shEventStoppingRead(q) && *q->pending == 0)
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
// stopping + create thread + publish threadObject" (Start) and "set stopping +
// take threadObject" (Stop). Outcome is definite: Start first => Stop joins the
// new thread; Stop first => Start is refused.
// (All call sites are PASSIVE: ThreadCreate itself requires PASSIVE; CAS spin is legal.)
NTSTATUS ShEventThreadStart(SHINKEN_EVENT_QUEUE *q) {
    NTSTATUS st;
    PVOID thr = NULL;

    if (!q || !q->head)
        return STATUS_INVALID_DEVICE_STATE; // queue uninitialized: do not start a thread
    while (SkAtCas32(&q->startLock, 1, 0) != 0)
        ShOps.SleepMs(0); // yield (Stop critical section is very short)
    if (q->stopping) {
        q->startLock = 0;
        return STATUS_INVALID_DEVICE_STATE; // already stopped: never restart (terminal semantics)
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
    NTSTATUS st = STATUS_SUCCESS;
    PVOID thr;
    ULONG i;

    if (!q || !q->head)
        return STATUS_SUCCESS; // queue uninitialized: nothing to stop or drain
    // 1) Close the production entrance (set inside startLock; linearized with
    //    Enter's in-lock check). Idempotent: a repeated Stop sees stopping
    //    already set; the steps below are no-ops/fallbacks.
    while (SkAtCas32(&q->startLock, 1, 0) != 0)
        ShOps.SleepMs(0);
    SkAtXchg32(&q->stopping, 1);
    thr = q->threadObject;
    q->threadObject = NULL;
    q->startLock = 0;
    // 2) Wait for all entered producers to leave (any later Post must take the
    //    drop path; no new node possible — precondition for join/drain)
    for (i = 0;; i++) {
        if (SkAtAdd32(&q->producers, 0) == 0)
            break;
        if (i >= SH_EVENT_PRODUCER_WAIT_RETRIES)
            return SHINKEN_STATUS_TIMEOUT; // producers stuck: caller stays resident
        ShOps.SleepMs(SH_EVENT_PRODUCER_WAIT_DELAY_MS);
    }
    ShOps.EventSet(&q->doorbell); // 3) wake the consumer so it observes the stop

    if (thr) {
        st = ShOps.ThreadJoin(thr); // 4) join (the consumer empties the queue before exiting)
        if (st != STATUS_SUCCESS)
            return st; // join failed (incl. positive): thread may still run => caller stays resident
    }
    ShEventDrain(q); // 5) fallback drain (guarantees release even if the thread never started)
    if (*q->pending != 0)
        return SHINKEN_STATUS_TIMEOUT;
    return st;
}

LONG ShEventPending(SHINKEN_EVENT_QUEUE *q) { return *q->pending; }

BOOLEAN ShEventThreadRunning(SHINKEN_EVENT_QUEUE *q) { return q->threadObject != NULL; }
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
    if (q->stopping || (q->capacity > 0 && *q->pending >= q->capacity)) {
        ShOps.LockReleaseExclusive(q->lock, irql);
        shEventProducerLeave(q);
        ShOps.FreePool(n, SHINKEN_EVENT_TAG);
        SkAtAdd64(&q->dropped, 1);
        if (!q->stopping)
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

VOID SkTelemetryStop(void) { (VOID)ShEventThreadStop(&g_SkTelemetryQueue); }

BOOLEAN SkTelemetryPost(UINT32 type, UINT64 ctx, volatile LONG *counter) {
    return ShEventPost(&g_SkTelemetryQueue, type, ctx, counter);
}

BOOLEAN SkTelemetryPostRecord(UINT32 type, const void *record, UINT32 size) {
    return ShEventPostRecord(&g_SkTelemetryQueue, type, record, size);
}

VOID SkTelemetryStats(UINT64 *posted, UINT64 *consumed, UINT64 *dropped,
                      UINT64 *overflowDropped) {
    if (posted)
        *posted = (UINT64)g_SkTelemetryQueue.posted;
    if (consumed)
        *consumed = (UINT64)g_SkTelemetryQueue.consumed;
    if (dropped)
        *dropped = (UINT64)g_SkTelemetryQueue.dropped;
    if (overflowDropped)
        *overflowDropped = (UINT64)g_SkTelemetryQueue.overflowDropped;
}

UINT32 SkTelemetryFlush(void *out, UINT32 maxRecords, UINT32 recordSize) {
    // Copy the ring's current contents in write order into out (kernel buffer);
    // return the count. Copy only under the ring lock; an inconsistent snapshot
    // is acceptable (telemetry semantics).
    KIRQL irql;
    UINT32 avail, start, i, n;
    if (!out || recordSize > SK_EVENT_PAYLOAD_SIZE || recordSize == 0)
        return 0;
    irql = ShOps.LockAcquireExclusive(&g_SkRingLock);
    avail = g_SkRingTotal < SK_TELEMETRY_RING ? (UINT32)g_SkRingTotal : SK_TELEMETRY_RING;
    n = avail < maxRecords ? avail : maxRecords;
    start = (g_SkRingHead + SK_TELEMETRY_RING - n) % SK_TELEMETRY_RING;
    for (i = 0; i < n; i++) {
        UINT32 idx = (start + i) % SK_TELEMETRY_RING;
        RtlCopyMemory((UINT8 *)out + (UINT64)i * recordSize, g_SkRing[idx], recordSize);
    }
    ShOps.LockReleaseExclusive(&g_SkRingLock, irql);
    return n;
}
