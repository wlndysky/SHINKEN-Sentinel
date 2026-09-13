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
// ============================================================================
#pragma once
#include <ntddk.h>
#include "rule_types.h"
#include "../runtime/runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _SK_RULE_SNAPSHOT {
    SK_RULE *rules;          // non-paged array (count entries, verdict-sorted)
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
