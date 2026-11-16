/* watch.c - in-agent guard-page and API-event memory monitor */
#include "unpack/hook/watch.h"
#include <stdio.h>
#include <string.h>

static HANDLE g_map = NULL;
static HANDLE g_event = NULL;
static HANDLE g_thread = NULL;
static vmpx_watch_ctl_t* g_ctl = NULL;
static vmpx_watch_event_t* g_events = NULL;
static PVOID g_veh = NULL;
static volatile LONG g_stop = 0;
static volatile LONG g_armed = 0;
static uint32_t g_sig = 0;

static uint32_t range_sig(void) {
    uint32_t s = g_ctl ? (g_ctl->mode * 2654435761u + g_ctl->range_count) : 0;
    if (g_ctl) {
        for (uint32_t i = 0; i < g_ctl->range_count && i < VMPX_WATCH_MAX_RANGES; i++) {
            s ^= (uint32_t)g_ctl->range_base[i];
            s += (uint32_t)(g_ctl->range_base[i] >> 32) * 40503u;
            s ^= (uint32_t)g_ctl->range_size[i];
        }
    }
    return s;
}

/* Keep total monotonic when producers publish out of order. The difference is
 * evaluated as int32_t so the comparison stays correct across the 32-bit wrap
 * (a difference of more than 2^31 positions cannot be live by construction). */
static void total_publish(volatile uint32_t* total, uint32_t value) {
    for (;;) {
        uint32_t cur = *total;
        if ((int32_t)(value - cur) <= 0) return;
        if ((uint32_t)InterlockedCompareExchange((volatile LONG*)total,
                                                 (LONG)value, (LONG)cur) == cur)
            return;
    }
}

/* Reserve a ring position, then publish the slot under a release seal.
 *
 * head is only advanced by the CAS that wins a position while the ring still
 * has room, so a full ring loses the event and leaves head/tail unchanged.
 * The old InterlockedIncrement advanced head unconditionally: readers then
 * walked slots the producer had bailed on and emitted whatever the previous
 * generation left behind. */
static void log_event(uint32_t type, uint64_t addr, uint64_t size,
                      uint32_t access_or_old, uint32_t newprot, uint64_t ip) {
    vmpx_watch_ctl_t* ctl = g_ctl;
    if (!ctl || !ctl->active || !g_events) return;

    uint32_t epoch = ctl->epoch;
    uint32_t pos = 0;
    for (;;) {
        pos = ctl->head;
        uint32_t tail = ctl->tail;
        if ((uint32_t)(pos - tail) >= VMPX_WATCH_MAX_EVENTS) {
            vmpx_watch_counter_bump(&ctl->dropped);
            return;
        }
        if ((uint32_t)InterlockedCompareExchange((volatile LONG*)&ctl->head,
                                                 (LONG)(pos + 1u), (LONG)pos) == pos)
            break;
        /* Another producer won this position; re-read head and retry. */
    }
    /* A reader reset that raced the claim makes this position meaningless:
     * publishing it would file the event under the previous run's epoch. The
     * claim stays unsealed, and the reader's bounded stall path retires it. */
    if (ctl->epoch != epoch) return;

    vmpx_watch_event_t* ev = &g_events[pos & VMPX_WATCH_EVENT_MASK];
    uint32_t gen = vmpx_watch_gen_for(pos);
    /* Seal first. A reader holding the previous generation, or one that
     * catches the slot mid-write, must fail the seal check. */
    InterlockedExchange((volatile LONG*)&ev->seal, (LONG)VMPX_WATCH_GEN_IDLE);
    ev->epoch = epoch;
    ev->seq = gen;
    ev->tid = GetCurrentThreadId();
    ev->type = type;
    ev->access_or_old = access_or_old;
    ev->addr = addr;
    ev->size = size;
    ev->ip = ip;
    ev->newprot = newprot;
    ev->reserved = 0;
    /* InterlockedExchange is a full barrier on x86: every payload store above
     * is visible before the seal becomes gen. */
    InterlockedExchange((volatile LONG*)&ev->seal, (LONG)gen);
    total_publish(&ctl->total, pos + 1u);
}

void watch_api_event(uint32_t type, uint64_t addr, uint64_t size,
                     uint32_t oldprot, uint32_t newprot) {
    if (!g_ctl || !g_ctl->active) return;
    log_event(type, addr, size, oldprot, newprot, 0);
}

static int in_range(uint64_t addr, uint32_t* index) {
    if (!g_ctl) return 0;
    for (uint32_t i = 0; i < g_ctl->range_count && i < VMPX_WATCH_MAX_RANGES; i++) {
        uint64_t b = g_ctl->range_base[i];
        uint64_t e = b + g_ctl->range_size[i];
        if (addr >= b && addr < e) { if (index) *index = i; return 1; }
    }
    return 0;
}

static void arm_one(uint32_t i) {
    if (!g_ctl || i >= g_ctl->range_count) return;
    uint64_t addr = g_ctl->range_base[i];
    uint64_t end = addr + g_ctl->range_size[i];
    g_ctl->range_prot[i] = 0;
    while (addr < end) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi))) break;
        uint64_t base = (uint64_t)(uintptr_t)mbi.BaseAddress;
        uint64_t size = (uint64_t)mbi.RegionSize;
        if (base < addr) { size -= addr - base; base = addr; }
        if (!size) break;
        uint64_t stop = base + size;
        if (stop > end) stop = end;
        uint64_t len = stop - base;
        if (mbi.State == MEM_COMMIT && (mbi.Protect & 0xFF) != PAGE_NOACCESS) {
            DWORD old = 0;
            DWORD prot = mbi.Protect & 0xFF;
            if (!prot || prot == PAGE_NOACCESS) prot = PAGE_READWRITE;
            if (!g_ctl->range_prot[i]) g_ctl->range_prot[i] = prot;
            /* A guard page must remain usable for the instruction that will
             * follow the exception. RWX is the only protection that does not
             * turn an execute-only code watch into an access violation. */
            VirtualProtect((LPVOID)(uintptr_t)base, (SIZE_T)len,
                           PAGE_EXECUTE_READWRITE | PAGE_GUARD, &old);
        }
        addr = stop;
    }
}

static void disarm_all(void) {
    if (!g_ctl) return;
    for (uint32_t i = 0; i < g_ctl->range_count && i < VMPX_WATCH_MAX_RANGES; i++) {
        uint64_t base = g_ctl->range_base[i];
        uint64_t size = g_ctl->range_size[i];
        DWORD prot = g_ctl->range_prot[i];
        if (!base || !size || !prot) continue;
        DWORD old = 0;
        VirtualProtect((LPVOID)(uintptr_t)base, (SIZE_T)size, prot, &old);
    }
    g_armed = 0;
}

static LONG CALLBACK watch_veh(EXCEPTION_POINTERS* ep) {
    if (!ep || !ep->ExceptionRecord || !g_ctl || !g_ctl->active) return EXCEPTION_CONTINUE_SEARCH;
    if (ep->ExceptionRecord->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;

    uint64_t addr = (uint64_t)(uintptr_t)ep->ExceptionRecord->ExceptionInformation[1];
    uint32_t access = (uint32_t)ep->ExceptionRecord->ExceptionInformation[0];
    uint32_t index = 0;
    if (!in_range(addr, &index)) return EXCEPTION_CONTINUE_SEARCH;

    uint64_t ip = 0;
    if (ep->ContextRecord) ip = (uint64_t)ep->ContextRecord->Eip;
    log_event(VMPX_WATCH_EV_GUARD, addr, 1, access, 0, ip);

    /* The guard bit is cleared when the exception is delivered. Re-arm the
     * containing page so the next access is visible too. */
    MEMORY_BASIC_INFORMATION mbi;
    uint64_t page = addr & ~(uint64_t)0xFFF;
    if (VirtualQuery((LPCVOID)(uintptr_t)page, &mbi, sizeof(mbi))) {
        DWORD prot = mbi.Protect & 0xFF;
        if (!prot || prot == PAGE_NOACCESS) prot = PAGE_READWRITE;
        DWORD old = 0;
        VirtualProtect((LPVOID)(uintptr_t)page, 0x1000, prot | PAGE_GUARD, &old);
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

static DWORD WINAPI watch_worker(LPVOID param) {
    (void)param;
    while (!g_stop) {
        WaitForSingleObject(g_event, 250);
        if (!g_ctl) continue;
        uint32_t sig = range_sig();
        if (g_ctl->active) {
            if (!g_armed || sig != g_sig) {
                if (g_armed) disarm_all();
                g_sig = sig;
                for (uint32_t i = 0; i < g_ctl->range_count &&
                                     i < VMPX_WATCH_MAX_RANGES; i++)
                    arm_one(i);
                g_armed = 1;
            }
        } else if (g_armed) {
            disarm_all();
        }
    }
    return 0;
}

int watch_init(HMODULE self) {
    (void)self;
    wchar_t name[128];
    swprintf_s(name, 128, L"Local\\VMPX_WATCH_%u", GetCurrentProcessId());
    g_map = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0,
                               (DWORD)VMPX_WATCH_MAP_SIZE, name);
    if (!g_map) return -1;
    g_ctl = (vmpx_watch_ctl_t*)MapViewOfFile(g_map, FILE_MAP_ALL_ACCESS, 0, 0,
                                             VMPX_WATCH_MAP_SIZE);
    if (!g_ctl) { CloseHandle(g_map); g_map = NULL; return -1; }

    if (g_ctl->magic != VMPX_WATCH_MAGIC) {
        memset(g_ctl, 0, VMPX_WATCH_MAP_SIZE);
        g_ctl->magic = VMPX_WATCH_MAGIC;
        g_ctl->version = VMPX_WATCH_VERSION;
        g_ctl->pid = GetCurrentProcessId();
        g_ctl->capacity = VMPX_WATCH_MAX_EVENTS;
    }
    /* The slot count is part of the mapping contract: a reader that computed a
     * different ring size from its own headers must be refused, not trusted. */
    if (g_ctl->version != VMPX_WATCH_VERSION ||
        g_ctl->capacity != VMPX_WATCH_MAX_EVENTS) {
        UnmapViewOfFile(g_ctl);
        g_ctl = NULL;
        CloseHandle(g_map);
        g_map = NULL;
        return -1;
    }
    g_events = (vmpx_watch_event_t*)((uint8_t*)g_ctl + sizeof(vmpx_watch_ctl_t));

    swprintf_s(name, 128, L"Local\\VMPX_WATCH_EVT_%u", GetCurrentProcessId());
    g_event = CreateEventW(NULL, FALSE, FALSE, name);
    if (!g_event) return -1;

    g_veh = AddVectoredExceptionHandler(1, watch_veh);
    g_stop = 0;
    g_thread = CreateThread(NULL, 0, watch_worker, NULL, 0, NULL);
    if (!g_thread) return -1;
    return 0;
}

void watch_stop(void) {
    g_stop = 1;
    if (g_event) SetEvent(g_event);
    if (g_thread) {
        WaitForSingleObject(g_thread, 500);
        CloseHandle(g_thread);
        g_thread = NULL;
    }
    if (g_veh) { RemoveVectoredExceptionHandler(g_veh); g_veh = NULL; }
    void* view = g_ctl;
    g_ctl = NULL;
    g_events = NULL;
    if (g_event) { CloseHandle(g_event); g_event = NULL; }
    if (g_map) {
        if (view) UnmapViewOfFile(view);
        CloseHandle(g_map);
        g_map = NULL;
    }
}
