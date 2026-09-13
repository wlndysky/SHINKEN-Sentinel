// ============================================================================
// rules/rule_types.h — Rule engine public types: kernel snapshot format +
// verdict semantics.
//   * Rules live in an immutable snapshot array (non-paged); classify reads
//     a stable snapshot only.
//   * Match fields are optional (wildcard) via mask bits; addresses are
//     address+prefix (v4 32 / v6 128 bit), ports are closed intervals.
//   * appId = FNV-1a 64 hash of the lowercased UTF-16 image path; no path
//     strings are produced or stored.
//   * Validity window is UTC 100ns (FILETIME ticks); 0/0 = permanent.
//   * RESERVED conditions: SK_RULE_M_IFINDEX / SK_RULE_M_SID are defined for
//     wire-format stability but unsupported — SkRuleValidate rejects any rule
//     carrying them (the classify data plane never fills ifIndex/userId).
// ============================================================================
#pragma once
#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---- Rule actions ----
typedef enum _SK_RULE_ACTION {
    SkRuleActionAllow = 0,  // explicit permit
    SkRuleActionBlock,      // explicit block (strongest action)
    SkRuleActionAudit,      // permit + telemetry event
    SkRuleActionRateLimit   // token bucket: permit within bucket, block over limit
    // REDIRECT/INSPECT: unsupported by the ALE verdict path (documented demo limit)
} SK_RULE_ACTION;

// ---- Match-field presence bits (rule.mask) ----
#define SK_RULE_M_FAMILY     0x0001 // family present
#define SK_RULE_M_DIRECTION  0x0002 // direction present
#define SK_RULE_M_PROTOCOL   0x0004 // protocol present
#define SK_RULE_M_LOCALADDR  0x0008 // localAddr/prefix present
#define SK_RULE_M_REMOTEADDR 0x0010 // remoteAddr/prefix present
#define SK_RULE_M_LOCALPORT  0x0020 // localPortMin/Max present
#define SK_RULE_M_REMOTEPORT 0x0040 // remotePortMin/Max present
#define SK_RULE_M_PID        0x0080 // processId present
#define SK_RULE_M_APPID      0x0100 // appId (path hash) present
#define SK_RULE_M_LAYER      0x0200 // layerId present
#define SK_RULE_M_IFINDEX    0x0400 // RESERVED: unsupported, rejected by SkRuleValidate
#define SK_RULE_M_SID        0x0800 // RESERVED: unsupported, rejected by SkRuleValidate
#define SK_RULE_M_TIME       0x1000 // notBefore/notAfter present

#define SK_RULE_DIR_ANY  0
#define SK_RULE_DIR_OUT  1
#define SK_RULE_DIR_IN   2

#define SK_RULE_PROTO_ANY 0
// protocol holds IPPROTO_* values (TCP=6, UDP=17, ICMP=1, ICMPv6=58)

// Single rule; immutable within a snapshot. 1:1 conversion of the IOCTL wire
// format; contains no user pointers.
typedef struct _SK_RULE {
    UINT64 ruleId;        // unique id (allocator-guaranteed, 0 invalid)
    UINT32 priority;      // higher value evaluates first
    UINT32 mask;          // SK_RULE_M_* bits
    UINT32 action;        // SK_RULE_ACTION
    UINT32 enabled;       // 0/1
    UINT32 family;        // AF_INET(2)/AF_INET6(23)
    UINT32 direction;     // SK_RULE_DIR_*
    UINT32 protocol;      // IPPROTO_* or 0
    UINT32 layerId;       // SK_LAYER_* internal id (see wfp/wfp_callouts.h)
    UINT32 ifIndex;       // interface index, 0=any
    UINT32 processId;     // PID, 0=any
    UINT64 appId;         // path hash, 0=any
    UINT64 notBefore;     // UTC 100ns; requires SK_RULE_M_TIME
    UINT64 notAfter;      // UTC 100ns; requires SK_RULE_M_TIME
    UINT32 localPortMin, localPortMax;   // closed interval
    UINT32 remotePortMin, remotePortMax;
    UINT8  localAddr[16];  // v4 uses first 4 bytes, v6 all 16
    UINT8  remoteAddr[16];
    UINT8  localPrefix;    // prefix length (v4<=32, v6<=128)
    UINT8  remotePrefix;
    UINT8  sid[32];        // optional user SID (first 32 bytes; equality only)
    UINT32 sidLength;      // valid sid bytes (0 or 8..32)
    // RATE_LIMIT: refill rateTokens tokens per rateIntervalMs, bucket cap burst
    UINT32 rateTokens;
    UINT32 rateIntervalMs;
    UINT32 burst;
} SK_RULE;

// ---- Classify input tuple (extracted by packet/classify.c from WFP
//      inFixedValues/metadata; all kernel-owned data) ----
typedef struct _SK_CLASSIFY_TUPLE {
    UINT32 family;
    UINT32 direction;   // SK_RULE_DIR_*
    UINT32 protocol;
    UINT32 layerId;     // SK_LAYER_* internal id
    UINT32 ifIndex;     // never filled by the data plane (condition reserved)
    UINT32 processId;   // 0 = metadata missing
    UINT64 appId;       // 0 = metadata missing
    UINT32 localPort;
    UINT32 remotePort;
    UINT8  localAddr[16];
    UINT8  remoteAddr[16];
    const UINT8 *userId;    // always NULL today: no metadata user id is wired
                            // up (condition reserved); kept for matcher tests
    UINT32 userIdLength;
    UINT64 nowUtc100ns;     // caller supplies KeQuerySystemTime (any-IRQL safe)
} SK_CLASSIFY_TUPLE;

// ---- Verdict result ----
typedef enum _SK_VERDICT_ACTION {
    SkVerdictPermit = 0, // permit (default policy or no match)
    SkVerdictBlock,      // block
    SkVerdictAudit       // permit + telemetry
} SK_VERDICT_ACTION;

typedef struct _SK_VERDICT {
    UINT32 action;       // SK_VERDICT_ACTION
    UINT64 ruleId;       // matched rule (0 = default policy)
    UINT32 rateLimited;  // RATE_LIMIT over limit
    UINT32 hardBlock;    // verdict may be written as hard BLOCK (write gated on
                         // holding FWPS_RIGHT_ACTION_WRITE; the right is
                         // cleared after the write, never set/granted)
    UINT32 reason;       // SK_VERDICT_REASON (diagnostic class)
} SK_VERDICT;

// ---- Verdict reason (diagnostics: field mismatch / snapshot unavailable /
//      default policy) ----
typedef enum _SK_VERDICT_REASON {
    SkVerdictReasonRuleMatch = 0,     // enabled rule matched (incl. RATE_LIMIT over limit)
    SkVerdictReasonNoMatch,           // fields mismatched (incl. disabled/expired rules skipped)
    SkVerdictReasonSnapshotUnavailable // snapshot unavailable (store closed / no reference)
    // Missing metadata is not a separate verdict: rules conditioned on
    // pid/appId/SID simply do not match (fail-closed, never silently matched).
} SK_VERDICT_REASON;

// ---- Verdict precedence (documented in docs/RULE_ENGINE.md; test-pinned) ----
//   1) higher priority wins;
//   2) tie: action strength BLOCK > RATE_LIMIT > AUDIT > ALLOW;
//   3) tie: lower ruleId wins (deterministic);
//   4) no match => default policy (SET_DEFAULT_POLICY, factory PERMIT).
// RATE_LIMIT permits as AUDIT within the bucket, blocks over the limit.

// ---- Statistics (GET_STATS) ----
typedef struct _SK_RULE_STATS {
    UINT64 classifyCalls;
    UINT64 verdictPermit;
    UINT64 verdictBlock;
    UINT64 verdictAudit;
    UINT64 rateLimited;
    UINT64 ruleHits;
    UINT64 defaultHits;
    UINT64 matchNsTotal;   // cumulative match time (QPC delta)
    UINT64 matchNsMax;     // worst single call
    UINT64 matchNsSamples;
} SK_RULE_STATS;

// Path normalization hash (shared by control-side add and classify-side
// evaluation for identical equality semantics).
UINT64 SkRuleHashAppPath(PCWSTR path, UINT32 chars); // FNV-1a64 over lowercased UTF-16

#ifdef __cplusplus
}
#endif
