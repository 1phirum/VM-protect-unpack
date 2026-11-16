/* checksum.c - FNV-1a 32-bit and CRC-32/ISO-HDLC for control-plane records
 *
 * Producers hash a bounded preview (a page, a code window) and publish the
 * digest together with the algorithm tag from checksum.h. Both routines are
 * pure: no globals, no lazy table, so they are safe to call from the VEH and
 * from several publishing threads at once.
 */
#include "unpack/deobf/dynamic/control/checksum.h"

/* One lane of the reflected CRC-32 table. The table is built per call on the
 * stack: 1 KiB, deterministic, and free of the init race a shared lazy table
 * would need. The producers hash at most one page per call, so the 2048 table
 * ops are noise next to the byte loop. */
static uint32_t crc32_lane(uint32_t index) {
    uint32_t c = index;
    for (int k = 0; k < 8; k++)
        c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
    return c;
}

uint32_t checksum_fnv1a32(const void* data, size_t len) {
    if (!data && len) return 0;
    if (len > VMPX_CHECKSUM_MAX_LEN) return 0;

    const uint8_t* p = (const uint8_t*)data;
    uint32_t h = 2166136261u;   /* FNV-1a 32-bit offset basis */
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 16777619u;         /* FNV-1a 32-bit prime */
    }
    return h;
}

uint32_t checksum_crc32(const void* data, size_t len) {
    if (!data && len) return 0;
    if (len > VMPX_CHECKSUM_MAX_LEN) return 0;

    uint32_t table[256];
    for (uint32_t i = 0; i < 256; i++) table[i] = crc32_lane(i);

    const uint8_t* p = (const uint8_t*)data;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        crc = table[(crc ^ p[i]) & 0xFFu] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

uint32_t checksum_apply(uint32_t algo, const void* data, size_t len) {
    switch (algo) {
    case VMPX_HASH_FNV1A32: return checksum_fnv1a32(data, len);
    case VMPX_HASH_CRC32:   return checksum_crc32(data, len);
    case VMPX_HASH_NONE:    return 0;
    default:                return 0;   /* unknown tag: fail closed */
    }
}

int checksum_supported(uint32_t algo) {
    switch (algo) {
    case VMPX_HASH_NONE:
    case VMPX_HASH_FNV1A32:
    case VMPX_HASH_CRC32:
        return 1;
    default:
        return 0;
    }
}

const char* checksum_name(uint32_t algo) {
    switch (algo) {
    case VMPX_HASH_NONE:    return "none";
    case VMPX_HASH_FNV1A32: return "fnv1a32";
    case VMPX_HASH_CRC32:   return "crc32";
    default:                return "unknown";
    }
}
