/* control.h - live deobfuscation control plane between vmpx and the agent
 *
 * Everything in this subtree is dynamic. The CLI attaches to a running
 * process, the agent publishes runtime events through a named section, and
 * the report reader consumes the rings while the target is still executing.
 * No dump file, no on-disk section table, and no static scanner is involved.
 *
 * Protocol v2 uses one bounded SPSC shard per publishing thread. A producer
 * reserves a slot, fills it privately, then release-publishes the slot
 * generation in `ready`. The host copies only slots whose generation matches
 * the expected sequence and acknowledges them through the shard tail.
 */
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stddef.h>

#define VMPX_DYN_MAGIC   0x4E59444Bu   /* "KDYN" little-endian */
#define VMPX_DYN_VERSION 2u
#define VMPX_DYN_ENDIAN  0x01020304u

#define VMPX_DYN_MAX_RANGES 16
#define VMPX_DYN_MAX_PRODUCERS 16
#define VMPX_DYN_SHARD_EVENTS  2048
#define VMPX_DYN_MAX_EVENTS    (VMPX_DYN_MAX_PRODUCERS * VMPX_DYN_SHARD_EVENTS)
#define VMPX_DYN_DATA       192
#define VMPX_DYN_PAGE       0x1000u
#define VMPX_DYN_POINTER_WIDTH ((uint32_t)sizeof(void*))

/* collection modes */
#define VMPX_DYN_MODE_MEM    1u
#define VMPX_DYN_MODE_EXEC   2u
#define VMPX_DYN_MODE_THREAD 4u
#define VMPX_DYN_MODE_API    8u
#define VMPX_DYN_MODE_ALL    0xFu

/* event types */
#define VMPX_DYN_EV_MEM     1u
#define VMPX_DYN_EV_EXEC    2u
#define VMPX_DYN_EV_THREAD  3u
#define VMPX_DYN_EV_WRITE   4u
#define VMPX_DYN_EV_PROTECT 5u
#define VMPX_DYN_EV_MARK    6u
#define VMPX_DYN_EV_ERROR   7u
#define VMPX_DYN_EV_VM      8u

/* event flags */
#define VMPX_DYN_F_EXEC    1u
#define VMPX_DYN_F_IMAGE   2u
#define VMPX_DYN_F_PRIVATE 4u
#define VMPX_DYN_F_TRUNC   8u
#define VMPX_DYN_F_NEW     16u
#define VMPX_DYN_F_CHANGED 32u
#define VMPX_DYN_F_THREAD  64u
#define VMPX_DYN_F_VM_ENTER   0x100u
#define VMPX_DYN_F_VM_LEAVE   0x200u
#define VMPX_DYN_F_VM_PRIVATE 0x400u
#define VMPX_DYN_F_VM_IMAGE   0x800u
#define VMPX_DYN_F_VM         0x80u

/* control flags */
#define VMPX_DYN_F_MEM_TRUNC    1u
#define VMPX_DYN_F_MEM_STARTED  2u
#define VMPX_DYN_F_EXEC_STARTED 4u
#define VMPX_DYN_F_THR_STARTED  8u

/* First instruction observed in the application's lowest executable section.
 * The thread sampler fills this once and never overwrites it, so a CLI or an
 * OEP capture can read the unpacked entry context without DR, guard pages, or
 * breakpoint patches. */
typedef struct {
    volatile uint32_t valid;
    volatile uint32_t ready;
    uint32_t tid;
    uint64_t eip;
    uint64_t esp;
    uint64_t ebp;
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t esi;
    uint32_t edi;
    uint32_t eflags;
    uint32_t stack_dwords;
    uint32_t stack[64];
} vmpx_dyn_entry_t;

/* Logical record schema. The fields are fixed-width so the shared layout does
 * not depend on compiler packing. `ready` is written last by the producer and
 * carries the per-shard sequence that owns this slot; zero means private. */
typedef struct {
    volatile uint32_t ready;
    uint32_t epoch;
    uint32_t producer;
    uint32_t tid;
    uint64_t tick;
    uint64_t seq;
    uint32_t type;
    uint32_t flags;
    uint32_t len;
    uint32_t crc32;
    uint32_t aux;
    uint32_t aux2;
    uint64_t addr;
    uint64_t size;
    uint64_t eip;
    uint64_t esp;
    uint8_t  data[VMPX_DYN_DATA];
    uint32_t reserved;
} vmpx_dyn_event_t;

/* One shard per publishing OS thread. `head` is the last reserved sequence,
 * `tail` is the last sequence acknowledged by the host, and `ready` lives in
 * each event slot. `owner_tid` is the registration token. */
typedef struct {
    volatile uint32_t owner_tid;
    volatile uint32_t epoch;
    volatile uint32_t head;
    volatile uint32_t tail;
    volatile uint32_t dropped;
    volatile uint32_t committed;
    uint32_t reserved;
    vmpx_dyn_event_t events[VMPX_DYN_SHARD_EVENTS];
} vmpx_dyn_shard_t;

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
    volatile uint32_t active;
    volatile uint32_t mode;
    volatile uint32_t mem_interval_ms;
    volatile uint32_t thread_interval_ms;
    volatile uint32_t dropped;
    volatile uint32_t total;
    volatile uint32_t epoch;
    volatile uint32_t producer_overflow;
    volatile uint32_t reentrant;
    volatile uint32_t mem_pages;
    volatile uint32_t mem_changed;
    volatile uint32_t exec_pages;
    volatile uint32_t exec_hits;
    volatile uint32_t thread_samples;
    uint64_t image_base;
    uint32_t image_size;
    uint32_t page_size;
    uint32_t flags;
    uint32_t range_count;
    volatile uint32_t mem_ticks;
    volatile uint32_t exec_ticks;
    volatile uint32_t thread_ticks;
    uint64_t range_base[VMPX_DYN_MAX_RANGES];
    uint64_t range_size[VMPX_DYN_MAX_RANGES];
    uint32_t range_flags[VMPX_DYN_MAX_RANGES];
    volatile uint32_t mem_ranges;
    volatile uint32_t mem_errors;
    uint64_t app_lo;                 /* first executable section start */
    uint64_t app_hi;                 /* first executable section end   */
    vmpx_dyn_entry_t entry;          /* first observed app instruction */
    vmpx_dyn_shard_t shards[VMPX_DYN_MAX_PRODUCERS];
} vmpx_dyn_ctl_t;

#define VMPX_DYN_MAP_SIZE ((DWORD)sizeof(vmpx_dyn_ctl_t))

/* Compile-time layout checks. These fail the build rather than allowing an
 * accidental struct change to become a silent wire-format change. */
typedef char vmpx_dyn_assert_event_ready[(offsetof(vmpx_dyn_event_t, ready) == 0) ? 1 : -1];
typedef char vmpx_dyn_assert_event_data[(offsetof(vmpx_dyn_event_t, data) == 88) ? 1 : -1];
typedef char vmpx_dyn_assert_event_size[(sizeof(vmpx_dyn_event_t) == 288) ? 1 : -1];
typedef char vmpx_dyn_assert_shard_events[(offsetof(vmpx_dyn_shard_t, events) == 32) ? 1 : -1];

int  dyn_control_init(HMODULE self);
void dyn_control_stop(void);
vmpx_dyn_ctl_t* dyn_control_get(void);
HANDLE dyn_control_event(void);
int  dyn_control_active(void);
int  dyn_control_stopping(void);
int  dyn_control_hidden(uint64_t addr, uint64_t len);
void dyn_api_suppress(int on);

void dyn_event_publish(uint32_t type, uint32_t flags, uint64_t addr,
                       uint64_t size, uint64_t eip, uint64_t esp,
                       uint32_t crc32, const void* data, uint32_t len,
                       uint32_t aux, uint32_t aux2);
void dyn_event_api(uint32_t type, uint64_t addr, uint64_t size,
                   uint32_t oldprot, uint32_t newprot);

int  dyn_memdelta_start(HMODULE self);
int  dyn_codecov_start(void);
int  dyn_threadctx_start(void);
