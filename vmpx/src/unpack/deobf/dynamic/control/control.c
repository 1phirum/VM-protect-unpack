/* control.c - named section creation and lock-free event publication */
#include "unpack/deobf/dynamic/control/control.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static HANDLE g_map = NULL;
static HANDLE g_evt = NULL;
static vmpx_dyn_ctl_t* g_ctl = NULL;
static volatile LONG g_stopping = 0;
static __declspec(thread) int g_api_suppress = 0;
static __declspec(thread) vmpx_dyn_shard_t* g_shard = NULL;
static __declspec(thread) int g_publishing = 0;

static void control_names(wchar_t* map_name, size_t map_cap,
                          wchar_t* evt_name, size_t evt_cap) {
    DWORD pid = GetCurrentProcessId();
    swprintf_s(map_name, map_cap, L"Local\\VMPX_DYN_%u", pid);
    swprintf_s(evt_name, evt_cap, L"Local\\VMPX_DYN_EVT_%u", pid);
}

static void read_main_image(vmpx_dyn_ctl_t* ctl) {
    uint8_t* base = (uint8_t*)GetModuleHandleW(NULL);
    if (!base) return;
    __try {
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
        IMAGE_NT_HEADERS32* nt =
            (IMAGE_NT_HEADERS32*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return;
        ctl->image_base = (uint64_t)(uintptr_t)base;
        ctl->image_size = nt->OptionalHeader.SizeOfImage;
        ctl->page_size = VMPX_DYN_PAGE;

        /* The first executable section is the application code for a protected
         * twin whose later executable sections hold the packer. */
        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        uint32_t best = 0xFFFFFFFFu;
        uint64_t lo = 0, hi = 0;
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            if (!sec[i].Misc.VirtualSize) continue;
            if (sec[i].VirtualAddress >= best) continue;
            best = sec[i].VirtualAddress;
            lo = ctl->image_base + sec[i].VirtualAddress;
            hi = lo + sec[i].Misc.VirtualSize;
        }
        ctl->app_lo = lo;
        ctl->app_hi = hi;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ctl->image_base = 0;
        ctl->image_size = 0;
        ctl->app_lo = 0;
        ctl->app_hi = 0;
    }
}

int dyn_control_init(HMODULE self) {
    (void)self;
    if (g_ctl) return 0;

    wchar_t map_name[96];
    wchar_t evt_name[96];
    control_names(map_name, 96, evt_name, 96);

    g_map = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0,
                               (DWORD)VMPX_DYN_MAP_SIZE, map_name);
    if (!g_map) return -1;

    g_ctl = (vmpx_dyn_ctl_t*)MapViewOfFile(g_map, FILE_MAP_ALL_ACCESS, 0, 0,
                                           VMPX_DYN_MAP_SIZE);
    if (!g_ctl) {
        CloseHandle(g_map);
        g_map = NULL;
        return -1;
    }
    if (g_ctl->magic != VMPX_DYN_MAGIC || g_ctl->version != VMPX_DYN_VERSION ||
        g_ctl->pid != GetCurrentProcessId() ||
        g_ctl->header_size != sizeof(vmpx_dyn_ctl_t) ||
        g_ctl->record_size != sizeof(vmpx_dyn_event_t) ||
        g_ctl->shard_count != VMPX_DYN_MAX_PRODUCERS ||
        g_ctl->shard_events != VMPX_DYN_SHARD_EVENTS) {
        memset(g_ctl, 0, VMPX_DYN_MAP_SIZE);
        g_ctl->magic = VMPX_DYN_MAGIC;
        g_ctl->version = VMPX_DYN_VERSION;
        g_ctl->pid = GetCurrentProcessId();
        g_ctl->header_size = sizeof(vmpx_dyn_ctl_t);
        g_ctl->record_size = sizeof(vmpx_dyn_event_t);
        g_ctl->pointer_width = VMPX_DYN_POINTER_WIDTH;
        g_ctl->endianness = VMPX_DYN_ENDIAN;
        g_ctl->shard_count = VMPX_DYN_MAX_PRODUCERS;
        g_ctl->shard_events = VMPX_DYN_SHARD_EVENTS;
        g_ctl->epoch = 1;
        g_ctl->page_size = VMPX_DYN_PAGE;
        g_ctl->mode = VMPX_DYN_MODE_ALL;
        g_ctl->mem_interval_ms = 1000;
        g_ctl->thread_interval_ms = 25;
        read_main_image(g_ctl);
    }

    /* Boot capture: keep the collectors live from DLL_PROCESS_ATTACH so the
     * unpacking transition is recorded before a CLI can attach. */
    char boot[16] = { 0 };
    DWORD boot_n = GetEnvironmentVariableA("VMPX_DYN_BOOT", boot, sizeof(boot));
    if (boot_n > 0 && boot[0] != '0') {
        if (boot[0] == '2') {
            /* Thread-only boot capture: find the first instruction in the
             * application code section without touching DR, guard pages or
             * instruction bytes. */
            g_ctl->mode = VMPX_DYN_MODE_THREAD;
            char ms[16] = { 0 };
            DWORD n = GetEnvironmentVariableA("VMPX_DYN_THREAD_MS", ms,
                                              sizeof(ms));
            uint32_t v = (n > 0) ? (uint32_t)strtoul(ms, NULL, 0) : 1u;
            g_ctl->thread_interval_ms = v ? v : 1u;
        } else {
            g_ctl->mode = VMPX_DYN_MODE_EXEC | VMPX_DYN_MODE_THREAD;
            g_ctl->thread_interval_ms = 5;
        }
        g_ctl->entry.valid = 0;
        g_ctl->active = 1;
    }

    g_evt = CreateEventW(NULL, FALSE, FALSE, evt_name);
    if (!g_evt) {
        UnmapViewOfFile(g_ctl);
        g_ctl = NULL;
        CloseHandle(g_map);
        g_map = NULL;
        return -1;
    }
    g_stopping = 0;
    return 0;
}

void dyn_control_stop(void) {
    g_stopping = 1;
    if (g_ctl) g_ctl->active = 0;
    if (g_evt) SetEvent(g_evt);
}

vmpx_dyn_ctl_t* dyn_control_get(void) {
    return g_ctl;
}

HANDLE dyn_control_event(void) {
    return g_evt;
}

int dyn_control_active(void) {
    return g_ctl && g_ctl->active != 0 && !g_stopping;
}

int dyn_control_stopping(void) {
    return g_stopping != 0;
}

int dyn_control_hidden(uint64_t addr, uint64_t len) {
    if (!g_ctl || !addr || !len) return 0;
    uint64_t base = (uint64_t)(uintptr_t)g_ctl;
    uint64_t end = base + VMPX_DYN_MAP_SIZE;
    return addr < end && addr + len > base;
}

void dyn_api_suppress(int on) {
    g_api_suppress = on;
}

/* True when a registered owner has settled for the current reset epoch: it has
 * published departure (`reset_ack == epoch`) or the shard holds no reservation
 * and nothing unread (`head == tail`). */
static int dyn_shard_settled(const vmpx_dyn_shard_t* s, uint32_t epoch) {
    if (!s->owner_tid) return 1;
    if (s->reset_ack == epoch) return 1;
    if (s->head == s->tail) return 1;
    return 0;
}

uint32_t dyn_control_reset_wait(vmpx_dyn_ctl_t* ctl, uint32_t timeout_ms,
                                uint32_t* out_shard, uint32_t* out_tid,
                                uint32_t cap) {
    if (!ctl) return 0;

    uint32_t epoch =
        (uint32_t)InterlockedIncrement((volatile LONG*)&ctl->epoch);
    uint32_t start = (uint32_t)GetTickCount();
    if (!timeout_ms) timeout_ms = VMPX_DYN_RESET_WAIT_MS;

    for (;;) {
        uint32_t pending = 0;
        for (uint32_t i = 0; i < VMPX_DYN_MAX_PRODUCERS; i++) {
            const vmpx_dyn_shard_t* s = &ctl->shards[i];
            if (dyn_shard_settled(s, epoch)) continue;
            if (out_shard && out_tid && pending < cap) {
                out_shard[pending] = i;
                out_tid[pending] = s->owner_tid;
            }
            pending++;
        }
        if (!pending) return 0;
        if ((uint32_t)(GetTickCount() - start) >= timeout_ms) return pending;
        Sleep(5);
    }
}

void dyn_control_reset_clear(vmpx_dyn_ctl_t* ctl) {
    if (!ctl) return;
    for (uint32_t i = 0; i < VMPX_DYN_MAX_PRODUCERS; i++) {
        vmpx_dyn_shard_t* s = &ctl->shards[i];
        InterlockedExchange((volatile LONG*)&s->owner_tid, 0);
        s->reset_ack = 0;
        s->epoch = 0;
        s->head = 0;
        s->tail = 0;
        s->dropped = 0;
        s->committed = 0;
    }
    MemoryBarrier();
}

static void dyn_shard_ack_reset(vmpx_dyn_shard_t* s) {
    if (!s || !g_ctl) return;
    uint32_t epoch = g_ctl->epoch;
    if (s->epoch != epoch) s->reset_ack = epoch;
}

static vmpx_dyn_shard_t* dyn_shard_acquire(void) {
    if (!g_ctl) return NULL;

    DWORD tid = GetCurrentThreadId();
    uint32_t epoch = g_ctl->epoch;
    vmpx_dyn_shard_t* s = g_shard;
    if (s && s->owner_tid == tid && s->epoch == epoch) return s;

    /* Leaving a shard from a superseded generation publishes departure before
     * the slot is dropped, so a host reset rendezvous can observe the owner. */
    if (s) dyn_shard_ack_reset(s);

    g_shard = NULL;
    for (uint32_t i = 0; i < VMPX_DYN_MAX_PRODUCERS; i++) {
        s = &g_ctl->shards[i];
        if (InterlockedCompareExchange((volatile LONG*)&s->owner_tid,
                                       (LONG)tid, 0) == 0) {
            s->epoch = epoch;
            s->reset_ack = epoch;   /* fresh owner is current, nothing to wait on */
            g_shard = s;
            return s;
        }
    }

    InterlockedIncrement((volatile LONG*)&g_ctl->producer_overflow);
    InterlockedIncrement((volatile LONG*)&g_ctl->dropped);
    return NULL;
}

static uint32_t dyn_shard_reserve(vmpx_dyn_shard_t* s) {
    for (;;) {
        uint32_t head = s->head;
        uint32_t tail = s->tail;
        if ((uint32_t)(head - tail) >= VMPX_DYN_SHARD_EVENTS) return 0;
        if (InterlockedCompareExchange((volatile LONG*)&s->head,
                                       (LONG)(head + 1), (LONG)head) ==
            (LONG)head)
            return head + 1;
    }
}

void dyn_event_publish(uint32_t type, uint32_t flags, uint64_t addr,
                       uint64_t size, uint64_t eip, uint64_t esp,
                       uint32_t crc32, uint32_t hash_algo,
                       uint32_t page_epoch, const void* data, uint32_t len,
                       uint32_t aux, uint32_t aux2) {
    if (!g_ctl) return;

    /* Publish departure for a superseded generation before the active gate, so
     * a reset in flight observes this owner even when it is idle and returns. */
    dyn_shard_ack_reset(g_shard);

    if (!g_ctl->active) return;

    uint32_t mode = g_ctl->mode;
    if ((type == VMPX_DYN_EV_WRITE || type == VMPX_DYN_EV_PROTECT) &&
        !(mode & VMPX_DYN_MODE_API))
        return;

    if (g_publishing) {
        InterlockedIncrement((volatile LONG*)&g_ctl->reentrant);
        return;
    }
    g_publishing = 1;

    vmpx_dyn_shard_t* s = dyn_shard_acquire();
    /* Tag the slot with the epoch the reservation belongs to, captured before
     * the reserve: a host reset landing mid-publish must leave this event
     * stale (and rejected by the host), not re-labelled with the new epoch. */
    uint32_t epoch = s ? s->epoch : 0;
    uint32_t seq = s ? dyn_shard_reserve(s) : 0;
    if (!s || !seq) {
        if (s) {
            InterlockedIncrement((volatile LONG*)&s->dropped);
            dyn_shard_ack_reset(s);
        }
        InterlockedIncrement((volatile LONG*)&g_ctl->dropped);
        g_publishing = 0;
        return;
    }

    vmpx_dyn_event_t* ev =
        &s->events[seq & (uint32_t)(VMPX_DYN_SHARD_EVENTS - 1)];
    ev->ready = 0;
    ev->epoch = epoch;
    ev->producer = (uint32_t)(s - &g_ctl->shards[0]);
    ev->tid = GetCurrentThreadId();
    ev->seq = seq;
    ev->type = type;
    ev->flags = flags;
    ev->addr = addr;
    ev->size = size;
    ev->eip = eip;
    ev->esp = esp;
    ev->crc32 = crc32;
    ev->hash_algo = hash_algo;
    ev->aux = aux;
    ev->aux2 = aux2;
    ev->page_epoch = page_epoch;

    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    ev->tick = (uint64_t)qpc.QuadPart;

    uint32_t n = len;
    if (n > VMPX_DYN_DATA) {
        n = VMPX_DYN_DATA;
        ev->flags |= VMPX_DYN_F_TRUNC;
    }
    ev->len = n;
    if (data && n) memcpy(ev->data, data, n);

    MemoryBarrier();
    ev->ready = seq;
    MemoryBarrier();
    s->committed = seq;
    InterlockedIncrement((volatile LONG*)&g_ctl->total);

    if (!(seq & 63) && g_evt) SetEvent(g_evt);
    dyn_shard_ack_reset(s);
    g_publishing = 0;
}

void dyn_event_api(uint32_t type, uint64_t addr, uint64_t size,
                   uint32_t oldprot, uint32_t newprot) {
    if (g_api_suppress) return;
    if (!g_ctl || !g_ctl->active ||
        !(g_ctl->mode & VMPX_DYN_MODE_API))
        return;

    uint8_t preview[VMPX_DYN_DATA];
    uint32_t len = 0;
    uint32_t crc = 0;
    uint32_t algo = VMPX_HASH_NONE;
    if (type == VMPX_DYN_EV_WRITE && addr && size) {
        uint32_t n = size > VMPX_DYN_DATA ? VMPX_DYN_DATA : (uint32_t)size;
        __try {
            memcpy(preview, (const void*)(uintptr_t)addr, n);
            len = n;
            crc = checksum_fnv1a32(preview, n);
            algo = VMPX_HASH_FNV1A32;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            len = 0;
            crc = 0;
            algo = VMPX_HASH_NONE;
        }
    }
    dyn_event_publish(type, 0, addr, size, 0, 0, crc, algo, 0, preview, len,
                      oldprot, newprot);
}
