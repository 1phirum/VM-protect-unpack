/* watch.h - shared memory-hook control plane between vmpx and the agent
 *
 * The agent owns a named mapping. The CLI writes a small range list and raises
 * an event; the agent arms PAGE_GUARD on the range and logs guard violations
 * through a VEH. The existing NtProtectVirtualMemory/NtWriteVirtualMemory hooks
 * also publish API events, so a dump can distinguish "page became executable"
 * from "page was written".
 *
 * Mapping protocol
 * ----------------
 * Local\VMPX_WATCH_<pid> is its own protocol, with its own version counter, and
 * is deliberately kept separate from the dynamic control mapping
 * (Local\VMPX_DYN_<pid>). The two blocks have different producers, different
 * publication rules and different lifetimes; a change to this one must not
 * invalidate the other's mapping.
 *
 * Ring publication (version 2)
 * ----------------------------
 * head and tail are absolute 32-bit position counters, never slot indices. A
 * producer claims position pos with a CAS on head that only succeeds while
 * (uint32_t)(pos - tail) < VMPX_WATCH_MAX_EVENTS, so head never advances past
 * a full ring and a drop cannot leave behind a slot no producer will fill.
 *
 * Publication is sealed per slot. The producer clears the seal, writes the
 * payload, then release-stores vmpx_watch_gen_for(pos). A consumer copies a
 * slot only when the seal equals that generation both before and after the
 * copy, so a slot recycled mid-copy is reported as stalled instead of being
 * emitted torn.
 *
 * Each slot also carries the ctl->epoch it was published under, and a reader
 * bumps that epoch when it clears the ring. Position counters restart at zero
 * on that reset, so without the epoch a producer caught mid-publication could
 * seal a slot with a generation the next run also expects. A producer re-reads
 * the epoch after claiming a position and abandons the claim if a reset landed
 * underneath it; the reader rejects any slot tagged with another epoch.
 */
#pragma once

#include <windows.h>
#include <stdint.h>

#define VMPX_WATCH_MAGIC   0x48435457u   /* "WTCH" little-endian */
#define VMPX_WATCH_VERSION 2u
#define VMPX_WATCH_MAX_RANGES 8
#define VMPX_WATCH_MAX_EVENTS 4096

#if (VMPX_WATCH_MAX_EVENTS & (VMPX_WATCH_MAX_EVENTS - 1)) != 0
#error VMPX_WATCH_MAX_EVENTS must be a power of two for slot masking
#endif

#define VMPX_WATCH_EVENT_MASK (VMPX_WATCH_MAX_EVENTS - 1u)

#define VMPX_WATCH_GEN_IDLE 0u   /* slot seal: payload is not published */

/* Reader-side grace for a slot that head already points at but the producer
 * has not sealed yet. A producer that dies between claiming a position and
 * sealing it can never publish, so the wait is bounded: after this many poll
 * rounds the slot is skipped and counted in ctl->stalled. */
#define VMPX_WATCH_STALL_RETRIES 32u

#define VMPX_WATCH_MODE_READ  1u
#define VMPX_WATCH_MODE_WRITE 2u
#define VMPX_WATCH_MODE_EXEC  4u

#define VMPX_WATCH_EV_GUARD   1u
#define VMPX_WATCH_EV_PROTECT 2u
#define VMPX_WATCH_EV_WRITE   3u

/* Absolute generation for ring position pos. Zero is reserved for "slot is
 * being written", so a counter step that would land on zero is biased to one
 * instead. All comparisons are exact uint32_t equality; ordering arithmetic
 * uses (uint32_t)(a - b), which stays correct across the 32-bit wrap.
 *
 * The bias makes gen_for(0xFFFFFFFF) == gen_for(0) == 1. That alias needs a
 * full 2^32-position wrap between the two uses of the same slot to matter,
 * which is far outside a single watch session and is the same wrap budget any
 * 32-bit position counter carries. */
static inline uint32_t vmpx_watch_gen_for(uint32_t pos) {
    uint32_t gen = pos + 1u;
    return gen ? gen : 1u;
}

/* Saturating 32-bit counter. A watch can run for hours; a diagnostic count
 * that wrapped would be worse than useless, so it stops at UINT32_MAX. */
static inline void vmpx_watch_counter_bump(volatile uint32_t* p) {
    for (;;) {
        uint32_t v = *p;
        if (v == UINT32_MAX) return;
        if ((uint32_t)InterlockedCompareExchange((volatile LONG*)p,
                                                 (LONG)(v + 1u), (LONG)v) == v)
            return;
    }
}

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t pid;
    uint32_t capacity;          /* ring slots; fixed when the mapping is created */
    volatile uint32_t active;
    volatile uint32_t mode;
    volatile uint32_t range_count;
    volatile uint32_t epoch;    /* reset generation, bumped by every reader reset */
    volatile uint32_t head;     /* next absolute position to claim */
    volatile uint32_t tail;     /* next absolute position to consume */
    volatile uint32_t dropped;  /* events lost because the ring was full */
    volatile uint32_t stalled;  /* slots skipped by a reader: seal did not match */
    volatile uint32_t total;    /* events published, cumulative */
    uint64_t range_base[VMPX_WATCH_MAX_RANGES];
    uint64_t range_size[VMPX_WATCH_MAX_RANGES];
    uint32_t range_prot[VMPX_WATCH_MAX_RANGES];
    uint32_t reserved;
} vmpx_watch_ctl_t;

typedef struct {
    volatile uint32_t seal;     /* vmpx_watch_gen_for(pos) once published,
                                 * VMPX_WATCH_GEN_IDLE while being written */
    uint32_t epoch;             /* ctl->epoch the payload was published under;
                                 * a reader rejects a slot from another run */
    uint32_t seq;               /* same value as the seal, carried in the payload */
    uint32_t tid;
    uint32_t type;
    uint32_t access_or_old;
    uint64_t addr;
    uint64_t size;
    uint64_t ip;
    uint32_t newprot;
    uint32_t reserved;
} vmpx_watch_event_t;

#define VMPX_WATCH_MAP_SIZE (sizeof(vmpx_watch_ctl_t) + \
                             sizeof(vmpx_watch_event_t) * VMPX_WATCH_MAX_EVENTS)

int  watch_init(HMODULE self);
void watch_stop(void);
void watch_api_event(uint32_t type, uint64_t addr, uint64_t size,
                     uint32_t oldprot, uint32_t newprot);
