// ============================================================================
// rules/rule_engine.h — Rule evaluation (classify hot path) and statistics.
// Verdict semantics (precedence pinned in rule_types.h):
//   scan the snapshot (pre-sorted by priority desc + action strength +
//   ruleId); the first fully matching enabled rule is the verdict; RATE_LIMIT
//   consults the rule's per-snapshot bucket object (rule_store.h; shared
//   across publishes for unchanged rules, never allocated here); no match
//   => snapshot defaultPolicy. Timing stats: QPC deltas (exposed via
//   GET_STATS).
// ============================================================================
#pragma once
#include <ntddk.h>
#include "rule_store.h"

#ifdef __cplusplus
extern "C" {
#endif

// Evaluate a tuple against a snapshot. Never fails; snap==NULL => default
// PERMIT (store closed).
VOID SkRuleEvaluate(const SK_RULE_SNAPSHOT *snap, const SK_CLASSIFY_TUPLE *tuple,
                    SK_VERDICT *out);

// Statistics (classify updates; GET_STATS reads)
extern SK_RULE_STATS g_SkRuleStats;
VOID SkRuleStatsReset(void);

#ifdef __cplusplus
}
#endif
