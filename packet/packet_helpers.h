// ============================================================================
// packet/packet_helpers.h — packet/address helpers (shared by packet and rules)
// ============================================================================
#pragma once
#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

// Address prefix match: AF_INET compares the first 4 bytes
// (prefix<=32), AF_INET6 all 16 bytes (prefix<=128); bitwise
// big-endian compare, bits beyond the prefix ignored.
BOOLEAN SkPkAddrMatch(const UINT8 *addr, const UINT8 *ruleAddr, UINT8 prefix,
                      UINT32 family);

// diagnostic formatting (writes "a.b.c.d" or uncompressed v6 into buf; returns the would-be character count; diagnostic path only)
UINT32 SkPkFormatAddr(const UINT8 *addr, UINT32 family, char *buf, UINT32 bufSize);

#ifdef __cplusplus
}
#endif
