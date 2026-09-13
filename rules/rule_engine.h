// ============================================================================
// rules/rule_engine.h — Rule evaluation (classify hot path) and statistics.
// Verdict semantics (precedence pinned in rule_types.h; docs/RULE_ENGINE.md):
//   scan the snapshot (pre-sorted by priority desc + action strength +
//   ruleId); the first fully matching enabled rule is the verdict; RATE_LIMIT
//   consults the token bucket (mutable state outside the snapshot); no match
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

// RATE_LIMIT state (one entry per rule id; snapshot-independent, lazily
// cleaned when the rule is removed)
VOID SkRuleRateReset(UINT64 ruleId); // call on rule delete/disable

#ifdef __cplusplus
}
#endif
