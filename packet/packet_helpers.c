// ============================================================================
// packet/packet_helpers.c — address compare / prefix match /
// diagnostic formatting helpers
//
// Addresses are compared bit-by-bit in big-endian (network) order:
// addr[0] is the most significant byte. v4 uses the first 4 bytes
// (prefix <= 32), v6 all 16 bytes (prefix <= 128). Pure computation:
// no allocation, no locks, safe at any IRQL — classify (DISPATCH) and
// rule_match share these primitives (interface in
// packet/packet_helpers.h).
// ============================================================================
#include <ntddk.h>
#include "packet_helpers.h"

// Prefix match: are the first `prefix` bits of addr and ruleAddr equal
// (big-endian)? family only selects the address width (AF_INET = 4
// bytes / AF_INET6 = 16 bytes); unknown family or prefix beyond the
// width => no match (conservative direction).
BOOLEAN SkPkAddrMatch(const UINT8 *addr, const UINT8 *ruleAddr, UINT8 prefix,
                      UINT32 family) {
    UINT32 width;   // address width in bytes
    UINT32 full;    // whole-byte count
    UINT32 remBits; // remaining bits (0..7)
    UINT8 mask;
    UINT32 i;

    if (family == AF_INET)
        width = 4;
    else if (family == AF_INET6)
        width = 16;
    else
        return FALSE;
    if (prefix > width * 8)
        return FALSE;
    if (prefix == 0)
        return TRUE; // empty prefix = wildcard

    full = prefix / 8;
    remBits = prefix % 8;
    for (i = 0; i < full; i++) {
        if (addr[i] != ruleAddr[i])
            return FALSE;
    }
    if (remBits == 0)
        return TRUE;
    // remaining bits: compare the high remBits of both bytes (big-endian => high bits first)
    mask = (UINT8)(0xFFu << (8 - remBits));
    return (BOOLEAN)((addr[full] & mask) == (ruleAddr[full] & mask));
}

// ---- diagnostic formatting (hand-rolled decimal/hex, no Rtlsprintf; diagnostic path only) ----

static UINT32 skPkDecimalDigits(UINT32 v) {
    UINT32 n = 1;
    while (v >= 10) {
        v /= 10;
        n++;
    }
    return n;
}

static VOID skPkPutDec(char **p, char *end, UINT32 v) {
    char tmp[10];
    UINT32 n = 0;
    while (v != 0) {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    }
    if (n == 0)
        tmp[n++] = '0';
    while (n != 0 && *p < end)
        **p = tmp[--n], (*p)++;
}

static VOID skPkPutHex4(char **p, char *end, UINT32 v) {
    static const char hex[] = "0123456789abcdef";
    int shift;
    for (shift = 12; shift >= 0 && *p < end; shift -= 4)
        **p = hex[(v >> shift) & 0xF], (*p)++;
}

// Diagnostic address formatting: v4 => "a.b.c.d", v6 => 8 hex groups
// (uncompressed). Returns the would-be character count (excluding
// NUL; may exceed the actual write — truncation is visible to the
// caller). Output is NUL-terminated when bufSize > 0.
UINT32 SkPkFormatAddr(const UINT8 *addr, UINT32 family, char *buf, UINT32 bufSize) {
    char *p = buf;
    char *end; // last writable byte (NUL slot)
    UINT32 i;
    UINT32 need = 0;

    if (bufSize == 0)
        return 0;
    end = buf + bufSize - 1;
    if (family == AF_INET) {
        for (i = 0; i < 4; i++) {
            if (i != 0) {
                if (p < end)
                    *p++ = '.';
                need++;
            }
            skPkPutDec(&p, end, addr[i]);
            need += skPkDecimalDigits(addr[i]);
        }
    } else if (family == AF_INET6) {
        for (i = 0; i < 16; i += 2) {
            if (i != 0) {
                if (p < end)
                    *p++ = ':';
                need++;
            }
            skPkPutHex4(&p, end, ((UINT32)addr[i] << 8) | addr[i + 1]);
            need += 4;
        }
    } else {
        if (p < end)
            *p++ = '?';
        need = 1;
    }
    *p = '\0';
    return need;
}
