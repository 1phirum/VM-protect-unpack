/* memdelta.c - dynamic page-delta collector for a live target
 *
 * VMProtect writes decoded payload and VM context into private pages while
 * the process runs. This collector hashes committed readable pages, compares
 * the page set against the previous pass, and publishes changed pages with a
 * bounded preview. The CLI re-reads the full page from the live process.
 */
#include "unpack/deobf/dynamic/control/control.h"
#include "armor/stealth/stealth.h"
#include <stdlib.h>

#define DYN_MAX_RANGES 4096
#define DYN_MAX_PAGES  262144u       /* 1 GiB / 4 KiB */
#define DYN_EMIT_CAP   512u          /* page events published per tick */

typedef struct {
    uint64_t base;
    uint64_t size;
    uint32_t type;
    uint32_t protect;
} dyn_range_t;

typedef struct {
    uint64_t addr;
    uint64_t hash;
    uint32_t crc;
    uint32_t spare;   /* MEM_IMAGE | MEM_MAPPED | MEM_PRIVATE */
    uint32_t protect; /* protection observed when this page was hashed */
    uint32_t epoch;   /* identity epoch of (hash, crc, protect); never 0 */
} dyn_page_t;

/* Per-page change classification for one tick. */
enum {
    DYN_KIND_UNCHANGED = 0,
    DYN_KIND_NEW,      /* allocation/commit: page absent last tick */
    DYN_KIND_WRITE,    /* in-place content change */
    DYN_KIND_PROTECT,  /* protection change, content equal or unreadable */
    DYN_KIND_FREE      /* released / decommitted */
};

static dyn_range_t g_ranges[DYN_MAX_RANGES];
static dyn_page_t* g_prev = NULL;
static dyn_page_t* g_cur = NULL;
static uint32_t g_prev_n = 0;
static uint32_t g_have_prev = 0;
static HANDLE g_thread = NULL;
static uint32_t g_epoch_next = 0;

/* Monotonic, never-zero page identity epoch. Advances when a page's identity
 * tuple (hash, crc, protection) changes, when it first appears, or when it is
 * released; unchanged pages keep the epoch they were first observed with. */
static uint32_t next_epoch(void) {
    uint32_t e = ++g_epoch_next;
    return e ? e : ++g_epoch_next;
}

static int readable(DWORD prot) {
    DWORD p = prot & 0xFF;
    return p == PAGE_READONLY || p == PAGE_READWRITE ||
           p == PAGE_WRITECOPY || p == PAGE_EXECUTE_READ ||
           p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

static void add_range(uint64_t base, uint64_t size, uint32_t* n) {
    if (!size || *n >= DYN_MAX_RANGES) return;
    uint64_t addr = base;
    uint64_t end = base + size;
    if (end < base) end = 0x7FFFFFFFu;
    while (addr < end && *n < DYN_MAX_RANGES) {
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
        uint64_t len = stop - b;
        if (mbi.State == MEM_COMMIT && readable(mbi.Protect) &&
            !(mbi.Protect & PAGE_GUARD) && len &&
            !stealth_hidden_region(b, len)) {
            g_ranges[*n].base = b;
            g_ranges[*n].size = len;
            g_ranges[*n].type = mbi.Type;
            g_ranges[*n].protect = mbi.Protect;
            (*n)++;
        }
        addr = stop;
    }
}

static uint32_t collect_ranges(vmpx_dyn_ctl_t* ctl) {
    uint32_t n = 0;
    if (ctl && ctl->range_count) {
        uint32_t count = ctl->range_count;
        if (count > VMPX_DYN_MAX_RANGES) count = VMPX_DYN_MAX_RANGES;
        for (uint32_t i = 0; i < count; i++)
            add_range(ctl->range_base[i], ctl->range_size[i], &n);
        return n;
    }

    uint64_t addr = 0;
    while (addr < 0x7FFF0000u && n < DYN_MAX_RANGES) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi))) {
            addr += VMPX_DYN_PAGE;
            continue;
        }
        uint64_t b = (uint64_t)(uintptr_t)mbi.BaseAddress;
        uint64_t sz = (uint64_t)mbi.RegionSize;
        if (!sz) break;
        uint64_t stop = b + sz;
        if (stop <= addr) stop = addr + VMPX_DYN_PAGE;
        if (mbi.State == MEM_COMMIT && readable(mbi.Protect) &&
            !(mbi.Protect & PAGE_GUARD) &&
            !stealth_hidden_region(b, sz)) {
            g_ranges[n].base = b;
            g_ranges[n].size = sz;
            g_ranges[n].type = mbi.Type;
            g_ranges[n].protect = mbi.Protect;
            n++;
        }
        addr = stop;
    }
    return n;
}

static int hash_page(uint64_t addr, uint64_t* hash, uint32_t* crc) {
    __try {
        const uint8_t* p = (const uint8_t*)(uintptr_t)addr;
        uint64_t h = 1469598103934665603ULL;
        uint32_t c = 2166136261u;
        for (uint32_t i = 0; i < VMPX_DYN_PAGE; i++) {
            h ^= p[i];
            h *= 1099511628211ULL;
            c = (c ^ p[i]) * 16777619u;
        }
        *hash = h;
        *crc = c;
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
}

static uint32_t copy_preview(uint64_t addr, uint8_t* out, uint32_t cap) {
    __try {
        const uint8_t* p = (const uint8_t*)(uintptr_t)addr;
        uint32_t n = cap;
        if (n > VMPX_DYN_PAGE) n = VMPX_DYN_PAGE;
        memcpy(out, p, n);
        return n;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

static int page_cmp(const void* a, const void* b) {
    const dyn_page_t* x = (const dyn_page_t*)a;
    const dyn_page_t* y = (const dyn_page_t*)b;
    if (x->addr < y->addr) return -1;
    if (x->addr > y->addr) return 1;
    return 0;
}

static int find_page(const dyn_page_t* arr, uint32_t n, uint64_t addr,
                     dyn_page_t* page) {
    uint32_t lo = 0, hi = n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (arr[mid].addr < addr) lo = mid + 1;
        else hi = mid;
    }
    if (lo < n && arr[lo].addr == addr) {
        if (page) *page = arr[lo];
        return 1;
    }
    return 0;
}

static uint32_t build_cur(vmpx_dyn_ctl_t* ctl) {
    uint32_t nranges = collect_ranges(ctl);
    ctl->mem_ranges = nranges;
    uint32_t n = 0;
    for (uint32_t r = 0; r < nranges && n < DYN_MAX_PAGES; r++) {
        uint64_t addr = g_ranges[r].base & ~(uint64_t)(VMPX_DYN_PAGE - 1);
        uint64_t end = g_ranges[r].base + g_ranges[r].size;
        while (addr < end && n < DYN_MAX_PAGES) {
            uint64_t h = 0;
            uint32_t c = 0;
            if (hash_page(addr, &h, &c) == 0) {
                DWORD prot = g_ranges[r].protect;
                dyn_page_t old;
                uint32_t epoch;
                if (g_have_prev && find_page(g_prev, g_prev_n, addr, &old) &&
                    old.hash == h && old.crc == c && old.protect == prot &&
                    old.epoch) {
                    epoch = old.epoch;      /* identity unchanged */
                } else {
                    epoch = next_epoch();   /* new or changed */
                }
                g_cur[n].addr = addr;
                g_cur[n].hash = h;
                g_cur[n].crc = c;
                g_cur[n].spare = g_ranges[r].type;
                g_cur[n].protect = prot;
                g_cur[n].epoch = epoch;
                n++;
            } else {
                ctl->mem_errors++;
            }
            addr += VMPX_DYN_PAGE;
        }
    }
    qsort(g_cur, n, sizeof(g_cur[0]), page_cmp);
    return n;
}

/* Publish one classified page change. `page` is the page's current record,
 * or its last record for a release. The distinct type is used where the host
 * can receive it; where control.c suppresses EV_WRITE/EV_PROTECT outside API
 * mode, the legacy generic EV_MEM event is published instead so coverage is
 * unchanged. Work is capped at DYN_EMIT_CAP per tick; overflow is counted as
 * deferred and surfaced through VMPX_DYN_F_MEM_TRUNC. */
static void emit_change(vmpx_dyn_ctl_t* ctl, uint32_t kind,
                        const dyn_page_t* page, uint32_t oldprot,
                        uint32_t* emitted, uint32_t* deferred) {
    if (*emitted >= DYN_EMIT_CAP) {
        (*deferred)++;
        return;
    }

    uint32_t type = page->spare;
    uint32_t flags = VMPX_DYN_F_CHANGED;
    if (type == MEM_IMAGE) flags |= VMPX_DYN_F_IMAGE;
    if (type == MEM_PRIVATE) flags |= VMPX_DYN_F_PRIVATE;

    uint8_t preview[VMPX_DYN_DATA];
    uint32_t plen = 0;
    uint32_t etype = VMPX_DYN_EV_MEM;
    uint32_t aux = type;
    uint32_t aux2 = 0;
    int have_api = (ctl->mode & VMPX_DYN_MODE_API) != 0;

    switch (kind) {
    case DYN_KIND_NEW:
        flags |= VMPX_DYN_F_NEW;
        plen = copy_preview(page->addr, preview, VMPX_DYN_DATA);
        break;

    case DYN_KIND_WRITE:
        if (have_api) etype = VMPX_DYN_EV_WRITE;
        plen = copy_preview(page->addr, preview, VMPX_DYN_DATA);
        break;

    case DYN_KIND_PROTECT:
        if (have_api) {
            etype = VMPX_DYN_EV_PROTECT;
            aux = oldprot;
            aux2 = page->protect;
        } else {
            plen = copy_preview(page->addr, preview, VMPX_DYN_DATA);
        }
        break;

    case DYN_KIND_FREE:
        etype = VMPX_DYN_EV_FREE;
        aux2 = oldprot;
        break;

    default:
        return;
    }

    if (plen > VMPX_DYN_DATA) {
        plen = VMPX_DYN_DATA;
        flags |= VMPX_DYN_F_TRUNC;
    }

    dyn_event_publish(etype, flags, page->addr, VMPX_DYN_PAGE, 0, 0,
                      page->crc, VMPX_HASH_FNV1A32, page->epoch,
                      plen ? preview : NULL, plen, aux, aux2);
    (*emitted)++;
}

static void poll_delta(vmpx_dyn_ctl_t* ctl) {
    uint32_t n = build_cur(ctl);
    ctl->mem_pages = n;
    if (n >= DYN_MAX_PAGES)
        ctl->flags |= VMPX_DYN_F_MEM_TRUNC;

    if (!g_have_prev) {
        memcpy(g_prev, g_cur, (size_t)n * sizeof(g_cur[0]));
        g_prev_n = n;
        g_have_prev = 1;
        return;
    }

    uint32_t emitted = 0;
    uint32_t deferred = 0;

    /* Pass 1: pages committed and readable now - new, written, protection
     * change, or unchanged-hash skip. */
    for (uint32_t i = 0; i < n; i++) {
        dyn_page_t old;
        int found = find_page(g_prev, g_prev_n, g_cur[i].addr, &old);
        uint32_t kind;
        if (!found) {
            kind = DYN_KIND_NEW;
        } else if (old.hash != g_cur[i].hash || old.crc != g_cur[i].crc) {
            kind = DYN_KIND_WRITE;
        } else if (old.protect != g_cur[i].protect) {
            kind = DYN_KIND_PROTECT;
        } else {
            continue;                    /* unchanged-hash skip */
        }
        ctl->mem_changed++;
        emit_change(ctl, kind, &g_cur[i], found ? old.protect : 0,
                    &emitted, &deferred);
    }

    /* Pass 2: pages readable last tick but absent now. A live query separates
     * release from a protection change that removed read access. A page that
     * is readable again is a collection race, and the failed query is
     * unreadable: both keep the legacy silence. */
    for (uint32_t j = 0; j < g_prev_n; j++) {
        if (find_page(g_cur, n, g_prev[j].addr, NULL))
            continue;
        MEMORY_BASIC_INFORMATION mbi;
        uint32_t kind = DYN_KIND_UNCHANGED;
        uint32_t oldprot = g_prev[j].protect;
        dyn_page_t now = g_prev[j];
        if (VirtualQuery((LPCVOID)(uintptr_t)g_prev[j].addr, &mbi,
                         sizeof(mbi))) {
            if (mbi.State == MEM_FREE || mbi.State == MEM_RESERVE) {
                kind = DYN_KIND_FREE;
            } else if (mbi.State == MEM_COMMIT &&
                       ((mbi.Protect & PAGE_GUARD) || !readable(mbi.Protect))) {
                kind = DYN_KIND_PROTECT;
                now.protect = mbi.Protect;
            }
        }
        if (kind == DYN_KIND_UNCHANGED)
            continue;
        now.epoch = next_epoch();   /* release or protection change */
        ctl->mem_changed++;
        emit_change(ctl, kind, &now, oldprot, &emitted, &deferred);
    }

    if (deferred)
        ctl->flags |= VMPX_DYN_F_MEM_TRUNC;

    memcpy(g_prev, g_cur, (size_t)n * sizeof(g_cur[0]));
    g_prev_n = n;
}

static DWORD WINAPI memdelta_worker(LPVOID param) {
    (void)param;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    vmpx_dyn_ctl_t* ctl = dyn_control_get();
    HANDLE evt = dyn_control_event();
    if (!ctl) return 0;

    for (;;) {
        while (!ctl->active) {
            if (dyn_control_stopping()) return 0;
            Sleep(50);
        }

        g_have_prev = 0;
        while (ctl->active) {
            ctl->mem_ticks++;
            uint32_t ms = ctl->mem_interval_ms;
            if (ms < 100) ms = 100;
            if (ms > 60000) ms = 60000;
            if (evt) WaitForSingleObject(evt, ms);
            else Sleep(ms);
            if (!ctl->active) break;
            if (!(ctl->mode & VMPX_DYN_MODE_MEM)) {
                g_have_prev = 0;
                continue;
            }
            poll_delta(ctl);
        }
        if (dyn_control_stopping()) return 0;
    }
}

int dyn_memdelta_start(HMODULE self) {
    (void)self;
    if (g_thread) return 0;
    g_prev = (dyn_page_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                    DYN_MAX_PAGES * sizeof(dyn_page_t));
    g_cur = (dyn_page_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                   DYN_MAX_PAGES * sizeof(dyn_page_t));
    if (!g_prev || !g_cur) {
        if (g_prev) HeapFree(GetProcessHeap(), 0, g_prev);
        if (g_cur) HeapFree(GetProcessHeap(), 0, g_cur);
        g_prev = NULL;
        g_cur = NULL;
        return -1;
    }
    g_thread = CreateThread(NULL, 0, memdelta_worker, NULL, 0, NULL);
    if (!g_thread) return -1;
    CloseHandle(g_thread);
    g_thread = (HANDLE)(uintptr_t)1;
    vmpx_dyn_ctl_t* ctl = dyn_control_get();
    if (ctl) ctl->flags |= VMPX_DYN_F_MEM_STARTED;
    return 0;
}
