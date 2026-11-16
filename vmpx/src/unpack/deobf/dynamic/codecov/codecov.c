/* codecov.c - dynamic first-execution coverage through PAGE_GUARD
 *
 * Every executable page in the selected image range is guarded once. The
 * first instruction fetch on a page raises STATUS_GUARD_PAGE_VIOLATION; the
 * VEH records EIP, ESP, and a short code preview, then restores the page. This
 * yields the runtime execution map without reading a file section table.
 */
#include "unpack/deobf/dynamic/control/control.h"
#include "armor/stealth/stealth.h"
#include <stdlib.h>

#define COV_MAX_PAGES 65536u

typedef struct {
    uint32_t page;
    uint32_t protect;
    uint32_t type;
    volatile LONG armed;
} cov_page_t;

static cov_page_t g_cov[COV_MAX_PAGES];
static uint32_t g_cov_n = 0;
static PVOID g_veh = NULL;
static HANDLE g_thread = NULL;

static int executable(DWORD prot) {
    DWORD p = prot & 0xFF;
    return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
           p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

static int cov_cmp(const void* a, const void* b) {
    uint32_t x = ((const cov_page_t*)a)->page;
    uint32_t y = ((const cov_page_t*)b)->page;
    return x < y ? -1 : (x > y ? 1 : 0);
}

static int cov_find(uint32_t page) {
    uint32_t lo = 0, hi = g_cov_n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (g_cov[mid].page < page) lo = mid + 1;
        else hi = mid;
    }
    if (lo < g_cov_n && g_cov[lo].page == page) return (int)lo;
    return -1;
}

static void cov_add_range(uint64_t base, uint64_t size) {
    uint64_t addr = base & ~(uint64_t)(VMPX_DYN_PAGE - 1);
    uint64_t end = base + size;
    if (end < base) end = 0x7FFFFFFFu;
    while (addr < end && g_cov_n < COV_MAX_PAGES) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi))) {
            addr += VMPX_DYN_PAGE;
            continue;
        }
        uint64_t b = (uint64_t)(uintptr_t)mbi.BaseAddress;
        uint64_t sz = (uint64_t)mbi.RegionSize;
        if (b < addr) { sz -= addr - b; b = addr; }
        if (!sz) break;
        uint64_t stop = b + sz;
        if (stop > end) stop = end;
        if (mbi.State == MEM_COMMIT && executable(mbi.Protect) &&
            !(mbi.Protect & PAGE_GUARD) &&
            !stealth_hidden_region(b, stop - b)) {
            uint64_t page = b & ~(uint64_t)(VMPX_DYN_PAGE - 1);
            while (page < stop && g_cov_n < COV_MAX_PAGES) {
                if (!stealth_hidden_region(page, VMPX_DYN_PAGE)) {
                    g_cov[g_cov_n].page = (uint32_t)page;
                    g_cov[g_cov_n].protect = mbi.Protect;
                    g_cov[g_cov_n].type = mbi.Type;
                    g_cov[g_cov_n].armed = 0;
                    g_cov_n++;
                }
                page += VMPX_DYN_PAGE;
            }
        }
        addr = stop;
    }
}

static void cov_collect(vmpx_dyn_ctl_t* ctl) {
    g_cov_n = 0;
    if (ctl->range_count) {
        uint32_t count = ctl->range_count;
        if (count > VMPX_DYN_MAX_RANGES) count = VMPX_DYN_MAX_RANGES;
        for (uint32_t i = 0; i < count; i++)
            cov_add_range(ctl->range_base[i], ctl->range_size[i]);
    } else if (ctl->image_base && ctl->image_size) {
        cov_add_range(ctl->image_base, ctl->image_size);
    }
    qsort(g_cov, g_cov_n, sizeof(g_cov[0]), cov_cmp);
    ctl->exec_pages = g_cov_n;
}

static uint32_t code_crc(const uint8_t* p, uint32_t n) {
    uint32_t h = 2166136261u;
    for (uint32_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

static void cov_arm_all(void) {
    dyn_api_suppress(1);
    for (uint32_t i = 0; i < g_cov_n; i++) {
        DWORD old = 0;
        uint32_t page = g_cov[i].page;
        if (!page) continue;
        if (InterlockedCompareExchange(&g_cov[i].armed, 1, 0) != 0)
            continue;
        DWORD guard = (g_cov[i].protect & 0xFF) | PAGE_GUARD;
        if (!VirtualProtect((LPVOID)(uintptr_t)page, VMPX_DYN_PAGE,
                            guard, &old)) {
            InterlockedExchange(&g_cov[i].armed, 0);
        }
    }
    dyn_api_suppress(0);
}

static void cov_disarm_all(void) {
    dyn_api_suppress(1);
    for (uint32_t i = 0; i < g_cov_n; i++) {
        if (InterlockedExchange(&g_cov[i].armed, 0) == 1) {
            DWORD old = 0;
            VirtualProtect((LPVOID)(uintptr_t)g_cov[i].page, VMPX_DYN_PAGE,
                           g_cov[i].protect, &old);
        }
    }
    dyn_api_suppress(0);
}

static LONG CALLBACK cov_veh(EXCEPTION_POINTERS* ep) {
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord) return EXCEPTION_CONTINUE_SEARCH;
    if (ep->ExceptionRecord->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;

    ULONG_PTR access = ep->ExceptionRecord->ExceptionInformation[0];
    uint64_t fault = (uint64_t)ep->ExceptionRecord->ExceptionInformation[1];
    uint32_t page = (uint32_t)(fault & ~(uint64_t)(VMPX_DYN_PAGE - 1));
    int idx = cov_find(page);
    if (idx < 0) return EXCEPTION_CONTINUE_SEARCH;

    /* A read or write through a guarded code page is not an instruction
     * fetch. The kernel clears PAGE_GUARD on the faulting page before the
     * instruction retries, so re-arming here would fault again on the retry
     * and loop forever. Drop this pass's coverage on the page instead; the
     * next arm cycle picks it up again. */
    if (access != 8) {
        if (InterlockedExchange(&g_cov[idx].armed, 0) == 1) {
            DWORD old = 0;
            dyn_api_suppress(1);
            VirtualProtect((LPVOID)(uintptr_t)page, VMPX_DYN_PAGE,
                           g_cov[idx].protect, &old);
            dyn_api_suppress(0);
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (InterlockedExchange(&g_cov[idx].armed, 0) != 1)
        return EXCEPTION_CONTINUE_EXECUTION;

    uint32_t eip = (uint32_t)ep->ContextRecord->Eip;
    uint8_t preview[96];
    uint32_t n = 96;
    uint32_t crc = 0;
    __try {
        memcpy(preview, (const void*)(uintptr_t)eip, n);
        crc = code_crc(preview, n);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        n = 0;
    }

    uint32_t flags = VMPX_DYN_F_EXEC;
    if (g_cov[idx].type == MEM_IMAGE) flags |= VMPX_DYN_F_IMAGE;
    if (g_cov[idx].type == MEM_PRIVATE) flags |= VMPX_DYN_F_PRIVATE;

    dyn_event_publish(VMPX_DYN_EV_EXEC, flags, eip, 1, eip,
                      (uint64_t)ep->ContextRecord->Esp, crc, preview, n,
                      page, 0);

    DWORD old = 0;
    dyn_api_suppress(1);
    VirtualProtect((LPVOID)(uintptr_t)page, VMPX_DYN_PAGE,
                   g_cov[idx].protect, &old);
    dyn_api_suppress(0);

    vmpx_dyn_ctl_t* ctl = dyn_control_get();
    if (ctl) ctl->exec_hits++;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static DWORD WINAPI cov_worker(LPVOID param) {
    (void)param;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    vmpx_dyn_ctl_t* ctl = dyn_control_get();
    if (!ctl) return 0;

    for (;;) {
        while (!ctl->active) {
            if (dyn_control_stopping()) return 0;
            Sleep(50);
        }
        if (!(ctl->mode & VMPX_DYN_MODE_EXEC)) {
            while (ctl->active) {
                if (dyn_control_stopping()) return 0;
                Sleep(100);
            }
            continue;
        }

        cov_collect(ctl);
        cov_arm_all();
        ctl->exec_ticks++;

        while (ctl->active) {
            if (dyn_control_stopping()) break;
            Sleep(100);
        }
        cov_disarm_all();
        if (dyn_control_stopping()) return 0;
    }
}

int dyn_codecov_start(void) {
    if (g_thread) return 0;
    g_veh = AddVectoredExceptionHandler(1, cov_veh);
    if (!g_veh) return -1;
    g_thread = CreateThread(NULL, 0, cov_worker, NULL, 0, NULL);
    if (!g_thread) {
        RemoveVectoredExceptionHandler(g_veh);
        g_veh = NULL;
        return -1;
    }
    CloseHandle(g_thread);
    g_thread = (HANDLE)(uintptr_t)1;
    vmpx_dyn_ctl_t* ctl = dyn_control_get();
    if (ctl) ctl->flags |= VMPX_DYN_F_EXEC_STARTED;
    return 0;
}
