// Bounded nonpaged telemetry. Producers copy one record under a spin lock;
// there is no classify-time allocation, blocking wait, or user-memory access.
// Stop closes the same lock-protected admission gate and joins the consumer.
#include <ntddk.h>
#include "../runtime/sk_atomic.h"
#include "event_queue.h"

#define SK_TELEMETRY_CAPACITY 4096u
#define SK_TELEMETRY_RING 1024u

typedef struct _SK_TELEMETRY_RECORD {
    UINT32 size;
    UINT8 payload[SK_EVENT_PAYLOAD_SIZE];
} SK_TELEMETRY_RECORD;

static EX_SPIN_LOCK g_QueueLock;
static EX_SPIN_LOCK g_RingLock;
static SK_TELEMETRY_RECORD g_Pending[SK_TELEMETRY_CAPACITY];
static UINT32 g_PendingHead;
static UINT32 g_PendingCount;
static SK_TELEMETRY_RECORD g_Consumed[SK_TELEMETRY_RING];
static UINT32 g_ConsumedHead;
static UINT32 g_ConsumedCount;
static SHINKEN_EVENT g_Doorbell;
static SHINKEN_EVENT g_StopDone;
static PVOID g_Thread;
static volatile LONG g_StopState; // 0 accepting, 1 joining, 2 stopped
static NTSTATUS g_StopResult;
static BOOLEAN g_Initialized;
static volatile LONG64 g_Posted;
static volatile LONG64 g_ConsumedTotal;
static volatile LONG64 g_Dropped;
static volatile LONG64 g_OverflowDropped;

// Startup and lifecycle teardown are serialized by DriverEntry/unload.
VOID SkTelemetryInit(void) {
    if (g_Initialized)
        return;
    ShOps.EventInit(&g_Doorbell);
    ShOps.EventInit(&g_StopDone);
    g_Initialized = TRUE;
}

static VOID skTelemetryThread(PVOID context) {
    UNREFERENCED_PARAMETER(context);
    for (;;) {
        KIRQL irql = ShOps.LockAcquireExclusive(&g_QueueLock);
        if (g_PendingCount != 0) {
            SK_TELEMETRY_RECORD record;
            SK_TELEMETRY_RECORD *src = &g_Pending[g_PendingHead];
            SK_TELEMETRY_RECORD *dst;
            record.size = src->size;
            RtlCopyMemory(record.payload, src->payload, src->size);
            g_PendingHead = (g_PendingHead + 1) % SK_TELEMETRY_CAPACITY;
            g_PendingCount--;
            ShOps.LockReleaseExclusive(&g_QueueLock, irql);
            irql = ShOps.LockAcquireExclusive(&g_RingLock);
            dst = &g_Consumed[g_ConsumedHead];
            dst->size = record.size;
            RtlCopyMemory(dst->payload, record.payload, record.size);
            g_ConsumedHead = (g_ConsumedHead + 1) % SK_TELEMETRY_RING;
            if (g_ConsumedCount < SK_TELEMETRY_RING)
                g_ConsumedCount++;
            SkAtAdd64(&g_ConsumedTotal, 1);
            ShOps.LockReleaseExclusive(&g_RingLock, irql);
            continue;
        }
        if (g_StopState != 0) {
            ShOps.LockReleaseExclusive(&g_QueueLock, irql);
            return;
        }
        ShOps.LockReleaseExclusive(&g_QueueLock, irql);
        // SynchronizationEvent retains a wake racing the empty observation.
        (VOID)ShOps.EventWait(&g_Doorbell, 0xFFFFFFFFu);
    }
}

NTSTATUS SkTelemetryStart(void) {
    if (!g_Initialized || SkAtOr32(&g_StopState, 0) != 0)
        return STATUS_INVALID_DEVICE_STATE;
    if (g_Thread != NULL)
        return STATUS_SUCCESS;
    return ShOps.ThreadCreate(skTelemetryThread, NULL, &g_Thread);
}

NTSTATUS SkTelemetryStop(void) {
    KIRQL irql;
    NTSTATUS st = STATUS_SUCCESS;
    if (!g_Initialized)
        return STATUS_SUCCESS;
    irql = ShOps.LockAcquireExclusive(&g_QueueLock);
    if (g_StopState != 0) {
        ShOps.LockReleaseExclusive(&g_QueueLock, irql);
        while (SkAtOr32(&g_StopState, 0) != 2)
            (VOID)ShOps.EventWait(&g_StopDone, 100);
        return g_StopResult;
    }
    SkAtXchg32(&g_StopState, 1);
    ShOps.EventSet(&g_Doorbell);
    ShOps.LockReleaseExclusive(&g_QueueLock, irql);
    if (g_Thread != NULL) {
        st = ShOps.ThreadJoin(g_Thread);
        if (st == STATUS_SUCCESS)
            g_Thread = NULL;
    }
    g_StopResult = st;
    SkAtXchg32(&g_StopState, 2);
    ShOps.EventSet(&g_StopDone);
    return st;
}

BOOLEAN SkTelemetryRunning(void) {
    return SkAtAdd64((volatile LONG64 *)&g_Thread, 0) != 0;
}

BOOLEAN SkTelemetryPostRecord(UINT32 type, const void *record, UINT32 size) {
    KIRQL irql;
    UINT32 tail;
    UNREFERENCED_PARAMETER(type); // type is already part of the wire record
    if (!g_Initialized || record == NULL || size == 0 || size > SK_EVENT_PAYLOAD_SIZE)
        return FALSE;
    irql = ShOps.LockAcquireExclusive(&g_QueueLock);
    if (g_StopState != 0 || g_PendingCount == SK_TELEMETRY_CAPACITY) {
        SkAtAdd64(&g_Dropped, 1);
        if (g_StopState == 0)
            SkAtAdd64(&g_OverflowDropped, 1);
        ShOps.LockReleaseExclusive(&g_QueueLock, irql);
        return FALSE;
    }
    tail = (g_PendingHead + g_PendingCount) % SK_TELEMETRY_CAPACITY;
    g_Pending[tail].size = size;
    RtlCopyMemory(g_Pending[tail].payload, record, size);
    g_PendingCount++;
    SkAtAdd64(&g_Posted, 1);
    ShOps.EventSet(&g_Doorbell); // legal at DISPATCH_LEVEL; no post-stop wake races
    ShOps.LockReleaseExclusive(&g_QueueLock, irql);
    return TRUE;
}

VOID SkTelemetryStats(UINT64 *posted, UINT64 *consumed, UINT64 *dropped,
                      UINT64 *overflowDropped) {
    if (posted)
        *posted = (UINT64)SkAtAdd64(&g_Posted, 0);
    if (consumed)
        *consumed = (UINT64)SkAtAdd64(&g_ConsumedTotal, 0);
    if (dropped)
        *dropped = (UINT64)SkAtAdd64(&g_Dropped, 0);
    if (overflowDropped)
        *overflowDropped = (UINT64)SkAtAdd64(&g_OverflowDropped, 0);
}

UINT32 SkTelemetryFlush(void *out, UINT32 maxRecords, UINT32 recordSize) {
    KIRQL irql;
    UINT32 n, start, i;
    if (out == NULL || recordSize == 0 || recordSize > SK_EVENT_PAYLOAD_SIZE)
        return 0;
    irql = ShOps.LockAcquireExclusive(&g_RingLock);
    n = g_ConsumedCount < maxRecords ? g_ConsumedCount : maxRecords;
    start = (g_ConsumedHead + SK_TELEMETRY_RING - n) % SK_TELEMETRY_RING;
    for (i = 0; i < n; i++) {
        const SK_TELEMETRY_RECORD *src = &g_Consumed[(start + i) % SK_TELEMETRY_RING];
        UINT8 *dst = (UINT8 *)out + (UINT64)i * recordSize;
        UINT32 bytes = src->size < recordSize ? src->size : recordSize;
        RtlZeroMemory(dst, recordSize);
        RtlCopyMemory(dst, src->payload, bytes);
    }
    ShOps.LockReleaseExclusive(&g_RingLock, irql);
    return n;
}
