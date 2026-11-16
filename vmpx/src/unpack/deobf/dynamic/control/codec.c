/* codec.c - explicit little-endian wire codec for the dynamic control plane
 *
 * Every field is read and written at a named offset with a named width. The
 * 296-byte event and the control header are decoded independently of the C
 * struct layout so a producer built with a different packing, alignment, or
 * endianness is rejected with a typed status instead of being reinterpreted.
 *
 * Field order matches vmpx_dyn_event_t exactly, so a decoded record is
 * byte-compatible with the current producer. The assertions in codec.h hold
 * the offsets to offsetof() at compile time.
 */
#include "unpack/deobf/dynamic/control/codec.h"
#include <string.h>

/* --- width-aware accessors (host-endian neutral, little-endian wire) ------ */

static uint32_t get_u32(const uint8_t* p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static uint64_t get_u64(const uint8_t* p) {
    return (uint64_t)get_u32(p) | ((uint64_t)get_u32(p + 4) << 32);
}

static void put_u32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static void put_u64(uint8_t* p, uint64_t v) {
    put_u32(p, (uint32_t)(v & 0xFFFFFFFFu));
    put_u32(p + 4, (uint32_t)(v >> 32));
}

/* Bounded, offset-checked header accessors. A field whose bytes are not
 * covered by `size` reads as zero: the layout fields are always covered, the
 * derived fields degrade to a defined value instead of a partial read. */
static uint32_t hget_u32(const uint8_t* b, uint32_t size, size_t off) {
    if ((uint64_t)off + 4u > (uint64_t)size) return 0;
    return get_u32(b + off);
}

static uint64_t hget_u64(const uint8_t* b, uint32_t size, size_t off) {
    if ((uint64_t)off + 8u > (uint64_t)size) return 0;
    return get_u64(b + off);
}

static void hput_u32(uint8_t* b, uint32_t size, size_t off, uint32_t v) {
    if ((uint64_t)off + 4u > (uint64_t)size) return;
    put_u32(b + off, v);
}

static void hput_u64(uint8_t* b, uint32_t size, size_t off, uint64_t v) {
    if ((uint64_t)off + 8u > (uint64_t)size) return;
    put_u64(b + off, v);
}

/* --- status --------------------------------------------------------------- */

const char* codec_status_name(codec_status_t st) {
    switch (st) {
    case CODEC_OK:                    return "ok";
    case CODEC_ERR_NULL:              return "null";
    case CODEC_ERR_SHORT:             return "short";
    case CODEC_ERR_MAGIC:             return "magic";
    case CODEC_ERR_VERSION:           return "version";
    case CODEC_ERR_HEADER_SIZE:       return "header_size";
    case CODEC_ERR_RECORD_SIZE:       return "record_size";
    case CODEC_ERR_POINTER_WIDTH:     return "pointer_width";
    case CODEC_ERR_ENDIANNESS:        return "endianness";
    case CODEC_ERR_SHARD_COUNT:       return "shard_count";
    case CODEC_ERR_SHARD_EVENTS:      return "shard_events";
    case CODEC_ERR_LEN_RANGE:         return "len_range";
    case CODEC_ERR_PREVIEW_TRUNCATED: return "preview_truncated";
    default:                          return "unknown";
    }
}

/* --- event ---------------------------------------------------------------- */

codec_status_t codec_decode_event(const uint8_t* slot, uint32_t slot_size,
                                  vmpx_dyn_event_t* out) {
    if (!slot || !out) return CODEC_ERR_NULL;
    if (slot_size < VMPX_CODEC_EVENT_SIZE) return CODEC_ERR_SHORT;

    uint32_t len = get_u32(slot + VMPX_CODEC_EV_OFF_LEN);
    if (len > VMPX_DYN_DATA) return CODEC_ERR_LEN_RANGE;
    if ((uint64_t)VMPX_CODEC_EV_OFF_DATA + (uint64_t)len > (uint64_t)slot_size)
        return CODEC_ERR_PREVIEW_TRUNCATED;

    out->ready = get_u32(slot + VMPX_CODEC_EV_OFF_READY);
    out->epoch = get_u32(slot + VMPX_CODEC_EV_OFF_EPOCH);
    out->producer = get_u32(slot + VMPX_CODEC_EV_OFF_PRODUCER);
    out->tid = get_u32(slot + VMPX_CODEC_EV_OFF_TID);
    out->tick = get_u64(slot + VMPX_CODEC_EV_OFF_TICK);
    out->seq = get_u64(slot + VMPX_CODEC_EV_OFF_SEQ);
    out->type = get_u32(slot + VMPX_CODEC_EV_OFF_TYPE);
    out->flags = get_u32(slot + VMPX_CODEC_EV_OFF_FLAGS);
    out->len = len;
    out->crc32 = get_u32(slot + VMPX_CODEC_EV_OFF_CRC32);
    out->hash_algo = get_u32(slot + VMPX_CODEC_EV_OFF_HASH_ALGO);
    out->aux = get_u32(slot + VMPX_CODEC_EV_OFF_AUX);
    out->aux2 = get_u32(slot + VMPX_CODEC_EV_OFF_AUX2);
    out->addr = get_u64(slot + VMPX_CODEC_EV_OFF_ADDR);
    out->size = get_u64(slot + VMPX_CODEC_EV_OFF_SIZE);
    out->eip = get_u64(slot + VMPX_CODEC_EV_OFF_EIP);
    out->esp = get_u64(slot + VMPX_CODEC_EV_OFF_ESP);

    /* The full preview window is copied byte for byte so a decoded record is
     * byte-identical to the mapped slot, not just up to len. */
    for (uint32_t i = 0; i < VMPX_DYN_DATA; i++)
        out->data[i] = slot[VMPX_CODEC_EV_OFF_DATA + i];

    out->reserved = get_u32(slot + VMPX_CODEC_EV_OFF_RESERVED);
    out->page_epoch = get_u32(slot + VMPX_CODEC_EV_OFF_PAGE_EPOCH);
    return CODEC_OK;
}

codec_status_t codec_encode_event(const vmpx_dyn_event_t* in, uint8_t* slot,
                                  uint32_t slot_size) {
    if (!in || !slot) return CODEC_ERR_NULL;
    if (slot_size < VMPX_CODEC_EVENT_SIZE) return CODEC_ERR_SHORT;
    if (in->len > VMPX_DYN_DATA) return CODEC_ERR_LEN_RANGE;

    put_u32(slot + VMPX_CODEC_EV_OFF_READY, in->ready);
    put_u32(slot + VMPX_CODEC_EV_OFF_EPOCH, in->epoch);
    put_u32(slot + VMPX_CODEC_EV_OFF_PRODUCER, in->producer);
    put_u32(slot + VMPX_CODEC_EV_OFF_TID, in->tid);
    put_u64(slot + VMPX_CODEC_EV_OFF_TICK, in->tick);
    put_u64(slot + VMPX_CODEC_EV_OFF_SEQ, in->seq);
    put_u32(slot + VMPX_CODEC_EV_OFF_TYPE, in->type);
    put_u32(slot + VMPX_CODEC_EV_OFF_FLAGS, in->flags);
    put_u32(slot + VMPX_CODEC_EV_OFF_LEN, in->len);
    put_u32(slot + VMPX_CODEC_EV_OFF_CRC32, in->crc32);
    put_u32(slot + VMPX_CODEC_EV_OFF_HASH_ALGO, in->hash_algo);
    put_u32(slot + VMPX_CODEC_EV_OFF_AUX, in->aux);
    put_u32(slot + VMPX_CODEC_EV_OFF_AUX2, in->aux2);
    put_u64(slot + VMPX_CODEC_EV_OFF_ADDR, in->addr);
    put_u64(slot + VMPX_CODEC_EV_OFF_SIZE, in->size);
    put_u64(slot + VMPX_CODEC_EV_OFF_EIP, in->eip);
    put_u64(slot + VMPX_CODEC_EV_OFF_ESP, in->esp);

    for (uint32_t i = 0; i < VMPX_DYN_DATA; i++)
        slot[VMPX_CODEC_EV_OFF_DATA + i] = in->data[i];

    put_u32(slot + VMPX_CODEC_EV_OFF_RESERVED, in->reserved);
    put_u32(slot + VMPX_CODEC_EV_OFF_PAGE_EPOCH, in->page_epoch);
    return CODEC_OK;
}

/* --- header --------------------------------------------------------------- */

void codec_header_default(vmpx_dyn_hdr_t* out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->magic = VMPX_DYN_MAGIC;
    out->version = VMPX_DYN_VERSION;
    out->header_size = (uint32_t)sizeof(vmpx_dyn_ctl_t);
    out->record_size = VMPX_CODEC_EVENT_SIZE;
    out->pointer_width = (uint32_t)sizeof(void*);
    out->endianness = VMPX_DYN_ENDIAN;
    out->shard_count = VMPX_DYN_MAX_PRODUCERS;
    out->shard_events = VMPX_DYN_SHARD_EVENTS;
    out->page_size = VMPX_DYN_PAGE;
}

codec_status_t codec_decode_header(const uint8_t* base, uint32_t size,
                                   vmpx_dyn_hdr_t* out) {
    if (!base || !out) return CODEC_ERR_NULL;
    if (size < VMPX_CODEC_HDR_MIN) return CODEC_ERR_SHORT;

    uint32_t magic = get_u32(base + offsetof(vmpx_dyn_ctl_t, magic));
    if (magic != VMPX_DYN_MAGIC) return CODEC_ERR_MAGIC;

    uint32_t version = get_u32(base + offsetof(vmpx_dyn_ctl_t, version));
    if (version != VMPX_DYN_VERSION) return CODEC_ERR_VERSION;

    uint32_t header_size = get_u32(base + offsetof(vmpx_dyn_ctl_t, header_size));
    if (header_size != (uint32_t)sizeof(vmpx_dyn_ctl_t))
        return CODEC_ERR_HEADER_SIZE;

    uint32_t record_size = get_u32(base + offsetof(vmpx_dyn_ctl_t, record_size));
    if (record_size != VMPX_CODEC_EVENT_SIZE) return CODEC_ERR_RECORD_SIZE;

    uint32_t pointer_width =
        get_u32(base + offsetof(vmpx_dyn_ctl_t, pointer_width));
    if (pointer_width != (uint32_t)sizeof(void*))
        return CODEC_ERR_POINTER_WIDTH;

    uint32_t endianness = get_u32(base + offsetof(vmpx_dyn_ctl_t, endianness));
    if (endianness != VMPX_DYN_ENDIAN) return CODEC_ERR_ENDIANNESS;

    uint32_t shard_count =
        get_u32(base + offsetof(vmpx_dyn_ctl_t, shard_count));
    if (shard_count != VMPX_DYN_MAX_PRODUCERS) return CODEC_ERR_SHARD_COUNT;

    uint32_t shard_events =
        get_u32(base + offsetof(vmpx_dyn_ctl_t, shard_events));
    if (shard_events != VMPX_DYN_SHARD_EVENTS) return CODEC_ERR_SHARD_EVENTS;

    memset(out, 0, sizeof(*out));
    out->magic = magic;
    out->version = version;
    out->pid = hget_u32(base, size, offsetof(vmpx_dyn_ctl_t, pid));
    out->header_size = header_size;
    out->record_size = record_size;
    out->pointer_width = pointer_width;
    out->endianness = endianness;
    out->shard_count = shard_count;
    out->shard_events = shard_events;

    out->epoch = hget_u32(base, size, offsetof(vmpx_dyn_ctl_t, epoch));
    out->total = hget_u32(base, size, offsetof(vmpx_dyn_ctl_t, total));
    out->flags = hget_u32(base, size, offsetof(vmpx_dyn_ctl_t, flags));
    out->range_count =
        hget_u32(base, size, offsetof(vmpx_dyn_ctl_t, range_count));
    out->image_base = hget_u64(base, size, offsetof(vmpx_dyn_ctl_t, image_base));
    out->image_size = hget_u32(base, size, offsetof(vmpx_dyn_ctl_t, image_size));
    out->page_size = hget_u32(base, size, offsetof(vmpx_dyn_ctl_t, page_size));

    if (out->range_count > VMPX_DYN_MAX_RANGES)
        out->range_count = VMPX_DYN_MAX_RANGES;
    size_t rb = offsetof(vmpx_dyn_ctl_t, range_base);
    size_t rs = offsetof(vmpx_dyn_ctl_t, range_size);
    size_t rf = offsetof(vmpx_dyn_ctl_t, range_flags);
    for (uint32_t i = 0; i < VMPX_DYN_MAX_RANGES; i++) {
        out->range_base[i] = hget_u64(base, size, rb + (size_t)i * 8u);
        out->range_size[i] = hget_u64(base, size, rs + (size_t)i * 8u);
        out->range_flags[i] = hget_u32(base, size, rf + (size_t)i * 4u);
    }
    return CODEC_OK;
}

codec_status_t codec_encode_header(const vmpx_dyn_hdr_t* in, uint8_t* base,
                                   uint32_t size) {
    if (!in || !base) return CODEC_ERR_NULL;
    if ((uint64_t)size < (uint64_t)sizeof(vmpx_dyn_ctl_t)) return CODEC_ERR_SHORT;

    hput_u32(base, size, offsetof(vmpx_dyn_ctl_t, magic), in->magic);
    hput_u32(base, size, offsetof(vmpx_dyn_ctl_t, version), in->version);
    hput_u32(base, size, offsetof(vmpx_dyn_ctl_t, pid), in->pid);
    hput_u32(base, size, offsetof(vmpx_dyn_ctl_t, header_size), in->header_size);
    hput_u32(base, size, offsetof(vmpx_dyn_ctl_t, record_size), in->record_size);
    hput_u32(base, size, offsetof(vmpx_dyn_ctl_t, pointer_width), in->pointer_width);
    hput_u32(base, size, offsetof(vmpx_dyn_ctl_t, endianness), in->endianness);
    hput_u32(base, size, offsetof(vmpx_dyn_ctl_t, shard_count), in->shard_count);
    hput_u32(base, size, offsetof(vmpx_dyn_ctl_t, shard_events), in->shard_events);
    hput_u32(base, size, offsetof(vmpx_dyn_ctl_t, epoch), in->epoch);
    hput_u32(base, size, offsetof(vmpx_dyn_ctl_t, total), in->total);
    hput_u32(base, size, offsetof(vmpx_dyn_ctl_t, flags), in->flags);
    hput_u32(base, size, offsetof(vmpx_dyn_ctl_t, range_count), in->range_count);
    hput_u64(base, size, offsetof(vmpx_dyn_ctl_t, image_base), in->image_base);
    hput_u32(base, size, offsetof(vmpx_dyn_ctl_t, image_size), in->image_size);
    hput_u32(base, size, offsetof(vmpx_dyn_ctl_t, page_size), in->page_size);

    size_t rb = offsetof(vmpx_dyn_ctl_t, range_base);
    size_t rs = offsetof(vmpx_dyn_ctl_t, range_size);
    size_t rf = offsetof(vmpx_dyn_ctl_t, range_flags);
    for (uint32_t i = 0; i < VMPX_DYN_MAX_RANGES; i++) {
        hput_u64(base, size, rb + (size_t)i * 8u, in->range_base[i]);
        hput_u64(base, size, rs + (size_t)i * 8u, in->range_size[i]);
        hput_u32(base, size, rf + (size_t)i * 4u, in->range_flags[i]);
    }
    return CODEC_OK;
}
