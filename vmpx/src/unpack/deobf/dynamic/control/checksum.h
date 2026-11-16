/* checksum.h - per-record digest algorithms for the dynamic control plane
 *
 * A control-plane record carries one 32-bit digest (`crc32`) and one
 * algorithm tag (`hash_algo`). The tag names the algorithm that produced the
 * digest; a consumer must not assume CRC-32 because the field is named so.
 * The tag travels inside the shared mapping, so the numeric values below are
 * wire values and must never be renumbered. Zero means "no digest".
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

/* Algorithm tags. Fixed wire values, stored in vmpx_dyn_event_t::hash_algo. */
typedef enum {
    VMPX_HASH_NONE    = 0,   /* no digest; the digest field is zero          */
    VMPX_HASH_FNV1A32 = 1,   /* FNV-1a 32-bit, offset basis 2166136261       */
    VMPX_HASH_CRC32   = 2    /* CRC-32/ISO-HDLC, reflected, poly 0xEDB88320  */
} vmpx_hash_algo_t;

/* Largest buffer a single call will read. A longer length is refused and the
 * call returns zero instead of looping over a corrupted length. */
#define VMPX_CHECKSUM_MAX_LEN (1u << 20)

/* The algorithm every producer uses when it hashes a preview buffer. Both the
 * tag and the value come from this one constant, so they cannot disagree. */
#define VMPX_HASH_DEFAULT VMPX_HASH_FNV1A32

/* Stage-B A07: the wire values are part of the mapping format. Fail the build
 * rather than let a renumbering become a silent protocol change. */
typedef char vmpx_hash_wire_none[(VMPX_HASH_NONE == 0) ? 1 : -1];
typedef char vmpx_hash_wire_fnv1a32[(VMPX_HASH_FNV1A32 == 1) ? 1 : -1];
typedef char vmpx_hash_wire_crc32[(VMPX_HASH_CRC32 == 2) ? 1 : -1];

const char* checksum_name(uint32_t algo);
int checksum_supported(uint32_t algo);

uint32_t checksum_fnv1a32(const void* data, size_t len);
uint32_t checksum_crc32(const void* data, size_t len);

/* Dispatch on a wire algorithm tag. Unknown tags and VMPX_HASH_NONE return
 * zero; a length above VMPX_CHECKSUM_MAX_LEN is refused, also zero. */
uint32_t checksum_apply(uint32_t algo, const void* data, size_t len);
