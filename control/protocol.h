// ============================================================================
// control/protocol.h — user-mode control-plane IOCTL protocol (versioned, length-safe)
//
// Transport: all METHOD_BUFFERED — rule/query payloads stay under 1MB, so
// buffered lets the I/O manager copy/probe user buffers; the driver never
// touches user pointers. (IN_DIRECT/OUT_DIRECT pays off for bulk streams,
// which this control plane does not have.)
//
// Authorization: privilege is determined at EvtDeviceFileCreate (process token
// is LocalSystem or Administrators => privileged) and recorded in the
// per-handle context; query commands allow unprivileged callers, write
// commands require privilege, else STATUS_ACCESS_DENIED. The device object
// itself gets SDDL D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;WD) (SYSTEM/
// Administrators full control, others generic read) — see driver/device.c.
// ============================================================================
#pragma once
#include <ntddk.h>
#include "../rules/rule_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SK_IOCTL_DEVICE_TYPE 0x9C40 // custom type in the FILE_DEVICE_UNKNOWN class
#define SK_IOCTL_VERSION     1

#define SK_IOCTL_FUNCTION_BASE 0x800
#define SK_IOCTL_CODE(cmd)                                                                    \
    ((UINT32)CTL_CODE(SK_IOCTL_DEVICE_TYPE, SK_IOCTL_FUNCTION_BASE + (cmd), METHOD_BUFFERED,  \
                      FILE_ANY_ACCESS))

// Command words (Header.Command matches the IOCTL code function number)
typedef enum _SK_IOCTL_COMMAND {
    SkCmdQueryCapabilities = 0,
    SkCmdGetRuleVersion,
    SkCmdAddRule,
    SkCmdUpdateRule,
    SkCmdDeleteRule,
    SkCmdEnumRules,
    SkCmdReplaceRuleset,
    SkCmdClearRules,
    SkCmdSetDefaultPolicy,
    SkCmdGetStats,
    SkCmdFlushEvents,
    SkCmdMax
} SK_IOCTL_COMMAND;

#define IOCTL_SHINKEN_QUERY_CAPABILITIES SK_IOCTL_CODE(SkCmdQueryCapabilities)
#define IOCTL_SHINKEN_GET_RULE_VERSION   SK_IOCTL_CODE(SkCmdGetRuleVersion)
#define IOCTL_SHINKEN_ADD_RULE           SK_IOCTL_CODE(SkCmdAddRule)
#define IOCTL_SHINKEN_UPDATE_RULE        SK_IOCTL_CODE(SkCmdUpdateRule)
#define IOCTL_SHINKEN_DELETE_RULE        SK_IOCTL_CODE(SkCmdDeleteRule)
#define IOCTL_SHINKEN_ENUM_RULES         SK_IOCTL_CODE(SkCmdEnumRules)
#define IOCTL_SHINKEN_REPLACE_RULESET    SK_IOCTL_CODE(SkCmdReplaceRuleset)
#define IOCTL_SHINKEN_CLEAR_RULES        SK_IOCTL_CODE(SkCmdClearRules)
#define IOCTL_SHINKEN_SET_DEFAULT_POLICY SK_IOCTL_CODE(SkCmdSetDefaultPolicy)
#define IOCTL_SHINKEN_GET_STATS          SK_IOCTL_CODE(SkCmdGetStats)
#define IOCTL_SHINKEN_FLUSH_EVENTS       SK_IOCTL_CODE(SkCmdFlushEvents)

// Common header of every request (input and output buffers both start with it)
typedef struct _SHINKEN_IOCTL_HEADER {
    UINT32 Size;       // total bytes of this buffer (including header)
    UINT16 Version;    // SK_IOCTL_VERSION
    UINT16 Command;    // SK_IOCTL_COMMAND
    UINT32 Flags;      // reserved, must be 0
    UINT64 RequestId;  // caller-allocated; echo/log only, duplicates are not errors
                       // (idempotence is guaranteed by command semantics)
} SHINKEN_IOCTL_HEADER;

// ---- Payloads ----
// Capabilities query (QUERY_CAPABILITIES output)
typedef struct _SK_CAPABILITIES {
    UINT32 maxRules;         // SK_RULE_MAX
    UINT32 maxReplaceBytes;  // SK_REPLACE_MAX_BYTES
    UINT32 supportsActions;  // bitmask: bit0 ALLOW, bit1 BLOCK, bit2 AUDIT, bit3 RATE_LIMIT
    UINT32 protocolVersion;  // SK_IOCTL_VERSION
} SK_CAPABILITIES;

// ADD/UPDATE payload: header + SK_RULE; path string appended separately (pathChars/pathOffset)
// REPLACE_RULESET payload: header + SK_REPLACE_HEADER + SK_RULE[count]
#define SK_RULE_MAX           4096
#define SK_REPLACE_MAX_BYTES  (1u * 1024 * 1024)
#define SK_RULE_PATH_MAX_CHARS 260

// rule.mask: SK_RULE_M_IFINDEX / SK_RULE_M_SID are reserved — accepted by the
// wire format for stability but unsupported; the driver rejects rules carrying
// them with STATUS_INVALID_PARAMETER (SkRuleValidate, rules/rule_store.c).
typedef struct _SK_RULE_WIRE {
    SK_RULE rule;          // match/action fields (without path)
    UINT32 pathChars;      // image path length in chars (0 = no path condition); <= SK_RULE_PATH_MAX_CHARS
    UINT32 pathOffset;     // offset of the WCHAR array relative to this SK_RULE_WIRE
    // WCHAR path[pathChars] follows immediately (driver lowercases it and computes appId)
} SK_RULE_WIRE;

typedef struct _SK_REPLACE_HEADER {
    UINT32 count;        // rule count <= SK_RULE_MAX
    UINT32 rulesBytes;   // total bytes of the rule area that follows (= count * sizeof(SK_RULE_WIRE+path))
    UINT64 expectedVersion; // 0 = unconditional; nonzero requires the current version
                            // to match (optimistic concurrency), else STATUS_RETRY —
                            // the caller should GET_RULE_VERSION and retry
} SK_REPLACE_HEADER;

// DELETE_RULE payload
typedef struct _SK_RULE_ID {
    UINT64 ruleId;
} SK_RULE_ID;

// ENUM_RULES output: header + SK_ENUM_HEADER + SK_RULE_WIRE[]
typedef struct _SK_ENUM_HEADER {
    UINT32 count;      // entries returned this time
    UINT64 version;    // snapshot version
} SK_ENUM_HEADER;

// GET_RULE_VERSION output
typedef struct _SK_RULE_VERSION {
    UINT64 version;
    UINT32 ruleCount;
    UINT32 defaultPolicy; // SK_VERDICT_*
} SK_RULE_VERSION;

// SET_DEFAULT_POLICY payload
typedef struct _SK_DEFAULT_POLICY {
    UINT32 policy; // SkVerdictPermit / SkVerdictBlock
} SK_DEFAULT_POLICY;

// GET_STATS output: header + SK_RULE_STATS (rules/rule_types.h) + queue stats
typedef struct _SK_STATS_OUT {
    SK_RULE_STATS rules;
    UINT64 eventsPosted;
    UINT64 eventsConsumed;
    UINT64 eventsDropped;
    UINT64 eventsOverflowDropped;
} SK_STATS_OUT;

// FLUSH_EVENTS output: header + SK_FLUSH_HEADER + event records[]
#define SK_EVENT_RECORD_SIZE 80
#define SK_FLUSH_MAX_EVENTS  1024
typedef struct _SK_FLUSH_HEADER {
    UINT32 count;
    UINT32 recordSize; // SK_EVENT_RECORD_SIZE
} SK_FLUSH_HEADER;

// Event record (fixed-size copy of kernel-owned memory; no pointers)
typedef struct _SK_EVENT_RECORD {
    UINT64 timestampUtc100ns;
    UINT64 ruleId;
    UINT32 type;      // 1=verdict-audit, 2=verdict-block, 3=rate-limited
    UINT32 family;
    UINT32 protocol;
    UINT32 direction;
    UINT32 processId;
    UINT32 localPort;
    UINT32 remotePort;
    UINT32 pad;
    UINT8  localAddr[16];
    UINT8  remoteAddr[16];
} SK_EVENT_RECORD;

#ifdef __cplusplus
}
#endif
