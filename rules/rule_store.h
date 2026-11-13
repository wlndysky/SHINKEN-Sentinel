// ============================================================================
// rules/rule_store.h — Rule store: immutable snapshots + atomic publish +
// deferred reclaim.
// Concurrency (read-mostly; classify may run at DISPATCH; full linearization
// proof in rule_store.c):
//   Readers (classify): under one short g_PublishLock section R — read
//     g_Current + closed check + snapshot->readers rundown Acquire (success =
//     stable reference; the snapshot cannot be freed while held) -> release
//     lock -> evaluate -> Release. All non-paged; no paged calls, no blocking,
//     no user pointers.
//   Writers (PASSIVE, serialized by storeLock): build new snapshot -> in one
//     g_PublishLock section W swap g_Current + BeginStop the displaced + queue
//     to retire list -> drain and free the retire list outside the lock at
//     the next publish/teardown (drain must be PASSIVE; readers at DISPATCH
//     hold only a bounded short path).
//   Version: +1 per publish, monotonic; expectedVersion mismatch =>
//     STATUS_RETRY (optimistic concurrency); failed update leaves the old
//     snapshot current (natural rollback).
//   Rollback slot: the displaced snapshot is kept (same reference protocol;
//     content immutable; drained readers then copied and republished) to
//     support ROLLBACK to the previous version.
//   RATE_LIMIT buckets: one reference-counted non-paged SK_RATE_BUCKET per
//   RATE_LIMIT rule, allocated only by the writer while building the next
//   snapshot (the classify path never allocates); allocation failure aborts
//   the publish — the old policy stays in effect, there is no data-plane
//   fail-open. A published snapshot owns one reference per non-NULL
//   buckets[i]; reclaim releases them and frees the object at refcount zero.
//   Equal id/rate/interval/burst shares a bucket for enabled rules. A
//   burst-only change copies and clamps the state into a separate bucket;
//   other parameter changes and disables start full. Copying occurs during
//   snapshot building: overlapping policy versions finish independently.
//   No failed publish changes the current bucket's tokens or refill clock.
// ============================================================================
#pragma once
#include <ntddk.h>
#include "rule_types.h"
#include "../runtime/runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

// Per-RATE_LIMIT-rule token bucket (classify-time refill/consume math and
// locking in rule_engine.c; allocation and refcount ownership in
// rule_store.c). In a snapshot, buckets[i] is non-NULL iff rules[i].action
// == SkRuleActionRateLimit — enabled or not: a disabled rule carries a
// never-consumed full bucket, so a later re-enable cannot inherit stale
// tokens (the documented disable-clears-bucket semantics).
typedef struct _SK_RATE_BUCKET {
    EX_SPIN_LOCK lock;    // protects mutable state; <= DISPATCH_LEVEL
    UINT64 tokens;        // current token count (<= owning rule's burst)
    UINT64 lastRefillMs;  // QPC ms baseline, valid once started
    BOOLEAN started;     // first consumption anchors the refill interval
    LONG refs;            // owning snapshots; writer path only, plain
                          // counter — every transition is storeLock-serialized
} SK_RATE_BUCKET;


typedef struct _SK_RULE_SNAPSHOT {
    SK_RULE *rules;          // non-paged array (count entries, verdict-sorted)
    SK_RATE_BUCKET **buckets; // parallel to rules; [i] != NULL iff rules[i]
                              // is RATE_LIMIT (SK_RATE_BUCKET contract above)
    UINT32 count;
    UINT64 version;          // publish version (monotonic)
    UINT32 defaultPolicy;    // SkVerdictPermit / SkVerdictBlock
    SHINKEN_RUNDOWN readers; // active classify readers
    LONG retired;            // displaced (freed once readers drain to zero)
    LIST_ENTRY retireLink;
} SK_RULE_SNAPSHOT;

// Lifecycle
NTSTATUS SkRuleStoreInit(void);          // builds empty snapshot (version 0)
BOOLEAN SkRuleStoreShutdown(void);       // TRUE = all snapshots drained+freed
                                         //   (reinstall allowed);
                                         // FALSE = readers remain => UNLOAD_BLOCKED
                                         //   terminal state, snapshots kept on the
                                         //   retire list, cleanup must stop
BOOLEAN SkRuleStoreWritable(void);       // write gate closed after teardown

// Reader API (classify path; NULL return = store closed)
const SK_RULE_SNAPSHOT *SkRuleStoreAcquire(void);
VOID SkRuleStoreRelease(const SK_RULE_SNAPSHOT *snap);
UINT64 SkRuleStoreVersion(void);        // scalar read under lock, never bare g_Current
UINT32 SkRuleStoreDefaultPolicy(void);

// Writer API (PASSIVE; all validate-then-publish; on failure the old rule set
// stays in effect)
NTSTATUS SkRuleStoreAdd(const SK_RULE *rule);                 // id conflict => ALREADY_EXISTS
NTSTATUS SkRuleStoreUpdate(const SK_RULE *rule);              // id missing => NOT_FOUND
NTSTATUS SkRuleStoreDelete(UINT64 ruleId);
NTSTATUS SkRuleStoreSetEnabled(UINT64 ruleId, BOOLEAN enabled);
NTSTATUS SkRuleStoreReplace(const SK_RULE *rules, UINT32 count, UINT64 expectedVersion);
NTSTATUS SkRuleStoreClear(void);
NTSTATUS SkRuleStoreRollback(void); // roll back to previous version (none => NOT_FOUND)
NTSTATUS SkRuleStoreSetDefaultPolicy(UINT32 policy);
// Enumeration (caller supplies output callback; storeLock held for the whole
// walk of the current snapshot. The const SK_RULE* passed to the callback
// points inside the snapshot and is valid only during the callback; SK_RULE
// is value-copy semantics — copy it to keep it.)
NTSTATUS SkRuleStoreEnum(BOOLEAN (*onRule)(const SK_RULE *, PVOID), PVOID ctx);
NTSTATUS SkRuleStoreFind(UINT64 ruleId, SK_RULE *out);

// Rule validation (field ranges / intervals / integer overflow / prefix
// bounds; shared by ioctl and store)
NTSTATUS SkRuleValidate(const SK_RULE *rule);

#ifdef __cplusplus
}
#endif
