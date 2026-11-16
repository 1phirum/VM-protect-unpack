/* codec.h - explicit little-endian wire codec for the dynamic control plane
 *
 * The mapped region is a shared struct, but the wire contract is the field
 * order in control.h, not the compiler's idea of it. This codec reads and
 * writes each field at an explicit offset with explicit widths so a packing
 * change, a struct reorder, or a differing endianness is a typed rejection
 * instead of a silent misread. No struct memcpy is the contract.
 *
 * The decoded output keeps the field order of vmpx_dyn_event_t, so a decoded
 * record is byte-compatible with the current producer. The compile-time
 * assertions below fail the build if that order moves.
 */
#pragma once

#include "control.h"

/* Wire size of one event slot and the validated header prefix. */
#define VMPX_CODEC_EVENT_SIZE 296u
#define VMPX_CODEC_HDR_MIN    40u   /* through shard_events */

/* Explicit field offsets. These are the wire layout, not the C layout; the
 * typedefs at the bottom of this file hold them equal to offsetof() on the
 * current struct. */
#define VMPX_CODEC_EV_OFF_READY      0u
#define VMPX_CODEC_EV_OFF_EPOCH      4u
#define VMPX_CODEC_EV_OFF_PRODUCER   8u
#define VMPX_CODEC_EV_OFF_TID        12u
#define VMPX_CODEC_EV_OFF_TICK       16u
#define VMPX_CODEC_EV_OFF_SEQ        24u
#define VMPX_CODEC_EV_OFF_TYPE       32u
#define VMPX_CODEC_EV_OFF_FLAGS      36u
#define VMPX_CODEC_EV_OFF_LEN        40u
#define VMPX_CODEC_EV_OFF_CRC32      44u
#define VMPX_CODEC_EV_OFF_HASH_ALGO  48u
#define VMPX_CODEC_EV_OFF_AUX        52u
#define VMPX_CODEC_EV_OFF_AUX2       56u
#define VMPX_CODEC_EV_OFF_ADDR       64u
#define VMPX_CODEC_EV_OFF_SIZE       72u
#define VMPX_CODEC_EV_OFF_EIP        80u
#define VMPX_CODEC_EV_OFF_ESP        88u
#define VMPX_CODEC_EV_OFF_DATA       96u
#define VMPX_CODEC_EV_OFF_RESERVED   288u
#define VMPX_CODEC_EV_OFF_PAGE_EPOCH 292u

/* Distinct outcomes. A caller can tell a layout mismatch from a corrupt slot
 * without parsing a string, and every rejection is a value, never a crash. */
typedef enum {
    CODEC_OK = 0,
    CODEC_ERR_NULL,              /* required pointer was null            */
    CODEC_ERR_SHORT,             /* buffer smaller than the wire object   */
    CODEC_ERR_MAGIC,             /* header magic wrong                    */
    CODEC_ERR_VERSION,           /* header protocol version wrong         */
    CODEC_ERR_HEADER_SIZE,       /* header_size != mapped control size    */
    CODEC_ERR_RECORD_SIZE,       /* record_size != 296                    */
    CODEC_ERR_POINTER_WIDTH,     /* pointer_width != sizeof(void*)        */
    CODEC_ERR_ENDIANNESS,        /* endianness != VMPX_DYN_ENDIAN         */
    CODEC_ERR_SHARD_COUNT,       /* shard_count != VMPX_DYN_MAX_PRODUCERS */
    CODEC_ERR_SHARD_EVENTS,      /* shard_events != VMPX_DYN_SHARD_EVENTS */
    CODEC_ERR_LEN_RANGE,         /* len > VMPX_DYN_DATA                   */
    CODEC_ERR_PREVIEW_TRUNCATED  /* len runs past the supplied slot       */
} codec_status_t;

/* Decoded control header. Validation fields are always filled; the derived
 * fields are filled only when the caller supplies enough bytes for them. */
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t pid;
    uint32_t header_size;
    uint32_t record_size;
    uint32_t pointer_width;
    uint32_t endianness;
    uint32_t shard_count;
    uint32_t shard_events;

    uint32_t epoch;
    uint32_t total;
    uint32_t flags;
    uint32_t range_count;
    uint64_t image_base;
    uint32_t image_size;
    uint32_t page_size;
    uint64_t range_base[VMPX_DYN_MAX_RANGES];
    uint64_t range_size[VMPX_DYN_MAX_RANGES];
    uint32_t range_flags[VMPX_DYN_MAX_RANGES];
} vmpx_dyn_hdr_t;

/* One event slot in, one vmpx_dyn_event_t out. slot_size is the number of
 * readable bytes at `slot`; it must be at least VMPX_CODEC_EVENT_SIZE. */
codec_status_t codec_decode_event(const uint8_t* slot, uint32_t slot_size,
                                  vmpx_dyn_event_t* out);

/* The inverse. Writes VMPX_CODEC_EVENT_SIZE bytes at `slot`. */
codec_status_t codec_encode_event(const vmpx_dyn_event_t* in, uint8_t* slot,
                                  uint32_t slot_size);

/* Decode and validate the control header from `base`, `size` bytes. All six
 * layout fields are checked against the compiled constants of this module. */
codec_status_t codec_decode_header(const uint8_t* base, uint32_t size,
                                   vmpx_dyn_hdr_t* out);

/* The inverse. `base` must hold at least sizeof(vmpx_dyn_ctl_t) bytes. */
codec_status_t codec_encode_header(const vmpx_dyn_hdr_t* in, uint8_t* base,
                                   uint32_t size);

/* Fill a header view with this build's canonical layout fields. */
void codec_header_default(vmpx_dyn_hdr_t* out);

const char* codec_status_name(codec_status_t st);

/* Wire order is the contract: these fail the compile if the struct moves. */
typedef char vmpx_codec_assert_size
    [(sizeof(vmpx_dyn_event_t) == VMPX_CODEC_EVENT_SIZE) ? 1 : -1];
typedef char vmpx_codec_assert_ready
    [(offsetof(vmpx_dyn_event_t, ready) == VMPX_CODEC_EV_OFF_READY) ? 1 : -1];
typedef char vmpx_codec_assert_epoch
    [(offsetof(vmpx_dyn_event_t, epoch) == VMPX_CODEC_EV_OFF_EPOCH) ? 1 : -1];
typedef char vmpx_codec_assert_producer
    [(offsetof(vmpx_dyn_event_t, producer) == VMPX_CODEC_EV_OFF_PRODUCER) ? 1 : -1];
typedef char vmpx_codec_assert_tid
    [(offsetof(vmpx_dyn_event_t, tid) == VMPX_CODEC_EV_OFF_TID) ? 1 : -1];
typedef char vmpx_codec_assert_tick
    [(offsetof(vmpx_dyn_event_t, tick) == VMPX_CODEC_EV_OFF_TICK) ? 1 : -1];
typedef char vmpx_codec_assert_seq
    [(offsetof(vmpx_dyn_event_t, seq) == VMPX_CODEC_EV_OFF_SEQ) ? 1 : -1];
typedef char vmpx_codec_assert_type
    [(offsetof(vmpx_dyn_event_t, type) == VMPX_CODEC_EV_OFF_TYPE) ? 1 : -1];
typedef char vmpx_codec_assert_flags
    [(offsetof(vmpx_dyn_event_t, flags) == VMPX_CODEC_EV_OFF_FLAGS) ? 1 : -1];
typedef char vmpx_codec_assert_len
    [(offsetof(vmpx_dyn_event_t, len) == VMPX_CODEC_EV_OFF_LEN) ? 1 : -1];
typedef char vmpx_codec_assert_crc32
    [(offsetof(vmpx_dyn_event_t, crc32) == VMPX_CODEC_EV_OFF_CRC32) ? 1 : -1];
typedef char vmpx_codec_assert_hash_algo
    [(offsetof(vmpx_dyn_event_t, hash_algo) == VMPX_CODEC_EV_OFF_HASH_ALGO) ? 1 : -1];
typedef char vmpx_codec_assert_aux
    [(offsetof(vmpx_dyn_event_t, aux) == VMPX_CODEC_EV_OFF_AUX) ? 1 : -1];
typedef char vmpx_codec_assert_aux2
    [(offsetof(vmpx_dyn_event_t, aux2) == VMPX_CODEC_EV_OFF_AUX2) ? 1 : -1];
typedef char vmpx_codec_assert_addr
    [(offsetof(vmpx_dyn_event_t, addr) == VMPX_CODEC_EV_OFF_ADDR) ? 1 : -1];
typedef char vmpx_codec_assert_ev_size
    [(offsetof(vmpx_dyn_event_t, size) == VMPX_CODEC_EV_OFF_SIZE) ? 1 : -1];
typedef char vmpx_codec_assert_eip
    [(offsetof(vmpx_dyn_event_t, eip) == VMPX_CODEC_EV_OFF_EIP) ? 1 : -1];
typedef char vmpx_codec_assert_esp
    [(offsetof(vmpx_dyn_event_t, esp) == VMPX_CODEC_EV_OFF_ESP) ? 1 : -1];
typedef char vmpx_codec_assert_data
    [(offsetof(vmpx_dyn_event_t, data) == VMPX_CODEC_EV_OFF_DATA) ? 1 : -1];
typedef char vmpx_codec_assert_reserved
    [(offsetof(vmpx_dyn_event_t, reserved) == VMPX_CODEC_EV_OFF_RESERVED) ? 1 : -1];
typedef char vmpx_codec_assert_page_epoch
    [(offsetof(vmpx_dyn_event_t, page_epoch) == VMPX_CODEC_EV_OFF_PAGE_EPOCH) ? 1 : -1];
