// ============================================================================
// rules/rule_match.c — Boolean matcher + app path hash (classify hot path,
// read-only).
// Contract (rules/rule_types.h):
//   * mask bits mark field presence; unset fields are wildcards;
//   * ports are closed intervals; addresses are address+prefix compared
//     bitwise at the tuple family width (v4 first 4 bytes / v6 all 16; a
//     family-wildcard rule's address condition is interpreted at each
//     tuple's own family width);
//   * SID conditions compare for equality only when tuple->userId is set and
//     equal-length, else no match;
//   * validity notBefore <= now <= notAfter (UTC 100ns); 0/0 = permanent;
//   * enabled == 0 never matches.
// Entire file is a non-paged read-only path: no allocation, no blocking,
// any-IRQL safe.
// ============================================================================
#include <ntddk.h>
#include "rule_types.h"
#include "../packet/packet_helpers.h" // SkPkAddrMatch (shared with packet; single convention)

// ---- FNV-1a 64 (offset basis / prime are the FNV standard constants) ----
#define SK_FNV1A64_OFFSET 14695981039346656037ULL
#define SK_FNV1A64_PRIME  1099511628211ULL

// Hash of the normalized (lowercased) UTF-16 image path; shared by the
// control-side rule add and the classify-side evaluation for identical
// equality semantics. Empty path => 0 (consistent with appId 0=any; avoids an
// empty-string hash colliding with the wildcard). Case folding is ASCII A-Z
// only; all other characters (incl. separators) are kept (documented demo
// limit).
UINT64 SkRuleHashAppPath(PCWSTR path, UINT32 chars) {
    UINT64 h = SK_FNV1A64_OFFSET;
    UINT32 i;
    if (path == NULL || chars == 0)
        return 0;
    for (i = 0; i < chars; i++) {
        WCHAR c = path[i];
        if (c >= (WCHAR)'A' && c <= (WCHAR)'Z')
            c = (WCHAR)(c + ((WCHAR)'a' - (WCHAR)'A'));
        h ^= (UINT64)c;
        h *= SK_FNV1A64_PRIME;
    }
    return h;
}

// Boolean matcher: TRUE only if every mask-set field of the rule matches.
// Address prefix comparison delegates to SkPkAddrMatch at the tuple family
// width (v4=32 / v6=128 bits); unknown family or over-wide prefix => no match
// (conservative direction; SkRuleValidate already bounds prefix by family).
BOOLEAN SkRuleMatch(const SK_RULE *rule, const SK_CLASSIFY_TUPLE *tuple) {
    UINT32 m;
    if (rule->enabled == 0)
        return FALSE; // disabled rules never match
    m = rule->mask;

    if ((m & SK_RULE_M_FAMILY) && rule->family != tuple->family)
        return FALSE;
    // direction/protocol value 0 (ANY) is a wildcard even when the mask bit
    // is set (consistent with SK_RULE_DIR_ANY / SK_RULE_PROTO_ANY).
    if ((m & SK_RULE_M_DIRECTION) && rule->direction != SK_RULE_DIR_ANY &&
        rule->direction != tuple->direction)
        return FALSE;
    if ((m & SK_RULE_M_PROTOCOL) && rule->protocol != SK_RULE_PROTO_ANY &&
        rule->protocol != tuple->protocol)
        return FALSE;
    if ((m & SK_RULE_M_LAYER) && rule->layerId != tuple->layerId)
        return FALSE;
    // ifIndex/processId/appId: rule-side 0 = any (rule_types.h field
    // comments). Fail-closed: missing metadata => tuple field is 0, so any
    // nonzero rule condition cannot be equal => no match; absence is never
    // silently treated as a match (the rule_types.h SID note applies to
    // pid/appId too; tests pin all three missing forms).
    // Reserved: SkRuleValidate rejects SK_RULE_M_IFINDEX, so no stored rule
    // ever carries it; branch kept for matcher-level tests only.
    if ((m & SK_RULE_M_IFINDEX) && rule->ifIndex != 0 && rule->ifIndex != tuple->ifIndex)
        return FALSE;
    if ((m & SK_RULE_M_PID) && rule->processId != 0 && rule->processId != tuple->processId)
        return FALSE;
    if ((m & SK_RULE_M_APPID) && rule->appId != 0 && rule->appId != tuple->appId)
        return FALSE;

    // port closed intervals
    if (m & SK_RULE_M_LOCALPORT) {
        if (tuple->localPort < rule->localPortMin || tuple->localPort > rule->localPortMax)
            return FALSE;
    }
    if (m & SK_RULE_M_REMOTEPORT) {
        if (tuple->remotePort < rule->remotePortMin || tuple->remotePort > rule->remotePortMax)
            return FALSE;
    }

    // address prefixes (width by tuple family)
    if (m & SK_RULE_M_LOCALADDR) {
        if (!SkPkAddrMatch(tuple->localAddr, rule->localAddr, rule->localPrefix,
                           tuple->family))
            return FALSE;
    }
    if (m & SK_RULE_M_REMOTEADDR) {
        if (!SkPkAddrMatch(tuple->remoteAddr, rule->remoteAddr, rule->remotePrefix,
                           tuple->family))
            return FALSE;
    }

    // SID equality: only when metadata carries an equal-length user id
    // (ALE_AUTH semantics). Reserved: SkRuleValidate rejects SK_RULE_M_SID
    // (tuple->userId is never filled), so no stored rule ever carries it;
    // branch kept for matcher-level tests only.
    if (m & SK_RULE_M_SID) {
        if (tuple->userId == NULL)
            return FALSE;
        if (rule->sidLength == 0 || tuple->userIdLength != rule->sidLength)
            return FALSE;
        if (memcmp(rule->sid, tuple->userId, rule->sidLength) != 0)
            return FALSE;
    }

    // validity window: notBefore <= now <= notAfter; 0/0 = permanent
    if (m & SK_RULE_M_TIME) {
        if (rule->notBefore != 0 || rule->notAfter != 0) {
            if (tuple->nowUtc100ns < rule->notBefore || tuple->nowUtc100ns > rule->notAfter)
                return FALSE;
        }
    }
    return TRUE;
}
