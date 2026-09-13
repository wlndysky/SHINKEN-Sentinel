// ============================================================================
// telemetry/event_queue.h — telemetry event queue/thread public interface
// (implementation in event_queue.c).
// ============================================================================
#pragma once
#include <ntddk.h>
#include "../runtime/runtime.h"

#define SHINKEN_EVENT_TAG 0x6E667772 /* 'rwfn' */

#define SK_EVENT_PAYLOAD_SIZE 80 // inline capacity of a telemetry record

typedef struct _SHINKEN_EVENT_NODE {
    UINT32 type;             // +0x00 event type
    UINT32 payloadSize;      // +0x04 payload valid bytes (0 = no inline record)
    UINT64 ctx;              // +0x08 referenced object (producer already +1 ref; 0 = none)
    volatile LONG *counter;  // +0x10 optional counter (producer already +1)
    LIST_ENTRY link;         // +0x18
    UINT8 payload[SK_EVENT_PAYLOAD_SIZE]; // kernel-owned data copy (no pointers)
} SHINKEN_EVENT_NODE;
typedef VOID (*SHINKEN_EVENT_SINK)(SHINKEN_EVENT_NODE *node); // releases the ctx reference
typedef struct _SHINKEN_EVENT_QUEUE {
    EX_SPIN_LOCK *lock;         // queue lock (owner: caller-provided image-level storage)
    LIST_ENTRY *head;           // list head (same owner)
    volatile LONG *pending;     // queued node count (same owner)
    volatile LONG capacity;     // queue cap (0 = unbounded); when full: drop-newest
    volatile LONG64 overflowDropped; // stats: dropped because full (telemetry must never block classify)
    SHINKEN_EVENT doorbell;
    PVOID threadObject;         // read/written inside the startLock critical section (see .c start protocol)
    volatile LONG stopping;     // stop flag: set atomically (inside startLock),
                                // always read atomically — never plain volatile
    volatile LONG producers;    // producers inside the "enqueue critical section"
                                // (atomic); while held, the stopping recheck and
                                // enqueue happen under the queue lock; Stop must
                                // wait for it to reach zero before join/drain
    volatile LONG startLock;    // Start/Stop mutual exclusion (CAS spin; all call sites PASSIVE)
    SHINKEN_EVENT_SINK onEvent;
    volatile LONG64 posted;
    volatile LONG64 consumed;
    volatile LONG64 dropped;
} SHINKEN_EVENT_QUEUE;

VOID ShEventQueueInit(SHINKEN_EVENT_QUEUE *q, EX_SPIN_LOCK *lock, LIST_ENTRY *head,
                      volatile LONG *pending, SHINKEN_EVENT_SINK onEvent);
BOOLEAN ShEventPost(SHINKEN_EVENT_QUEUE *q, UINT32 type, UINT64 ctx, volatile LONG *counter);
VOID ShEventThreadBody(PVOID ctx);
NTSTATUS ShEventThreadStart(SHINKEN_EVENT_QUEUE *q);
NTSTATUS ShEventThreadStop(SHINKEN_EVENT_QUEUE *q);
VOID ShEventDrain(SHINKEN_EVENT_QUEUE *q);
LONG ShEventPending(SHINKEN_EVENT_QUEUE *q);
BOOLEAN ShEventThreadRunning(SHINKEN_EVENT_QUEUE *q);
// Post an inline record (ctx=0/counter=NULL form; size<=SK_EVENT_PAYLOAD_SIZE)
BOOLEAN ShEventPostRecord(SHINKEN_EVENT_QUEUE *q, UINT32 type, const void *record,
                          UINT32 size);

// ---------------------------------------------------------------------------
// Driver-level telemetry singleton (owner: this module; lifecycle only calls Start/Stop)
// SkTelemetryPost never blocks: stopped/capacity full/alloc failure => balance
// references in place and return FALSE.
// ---------------------------------------------------------------------------
extern SHINKEN_EVENT_QUEUE g_SkTelemetryQueue;

VOID SkTelemetryInit(void);      // initialize the queue (idempotent)
NTSTATUS SkTelemetryStart(void); // start the consumer thread
VOID SkTelemetryStop(void);      // stop protocol (gate + join + drain)
BOOLEAN SkTelemetryPost(UINT32 type, UINT64 ctx, volatile LONG *counter);
BOOLEAN SkTelemetryPostRecord(UINT32 type, const void *record, UINT32 size);
// Stats and flush (FLUSH_EVENTS): flush copies the consumed-record ring to out (kernel buffer)
VOID SkTelemetryStats(UINT64 *posted, UINT64 *consumed, UINT64 *dropped,
                      UINT64 *overflowDropped);
UINT32 SkTelemetryFlush(void *out, UINT32 maxRecords, UINT32 recordSize);
