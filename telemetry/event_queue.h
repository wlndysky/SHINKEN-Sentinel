// Bounded telemetry records, copied into nonpaged static storage.
#pragma once
#include <ntddk.h>
#include "../runtime/runtime.h"

#define SK_EVENT_PAYLOAD_SIZE 80

// Lifecycle methods require PASSIVE_LEVEL and are serialized by the driver.
VOID SkTelemetryInit(void);
NTSTATUS SkTelemetryStart(void);
NTSTATUS SkTelemetryStop(void);
BOOLEAN SkTelemetryRunning(void);
// <= DISPATCH_LEVEL; never allocates or waits. Overflow drops the newest record.
BOOLEAN SkTelemetryPostRecord(UINT32 type, const void *record, UINT32 size);
VOID SkTelemetryStats(UINT64 *posted, UINT64 *consumed, UINT64 *dropped,
                      UINT64 *overflowDropped);
// Copies the latest consumed records; snapshot semantics, not destructive dequeue.
UINT32 SkTelemetryFlush(void *out, UINT32 maxRecords, UINT32 recordSize);
