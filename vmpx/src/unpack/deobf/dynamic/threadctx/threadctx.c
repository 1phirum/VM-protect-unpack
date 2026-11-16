/* threadctx.c - runtime thread-context sampler for OEP and VM transitions
 *
 * The sampler suspends one thread at a time, reads its x86 context, its code
 * bytes, and the top of its stack, then resumes it. Events are emitted when a
 * thread's EIP changes, which gives an execution timeline across VM handlers,
 * unpacking stubs, and the eventual unpacked OEP.
 */
#include "unpack/deobf/dynamic/control/control.h"
#include "unpack/deobf/dynamic/vmtrans/vmtrans.h"
#include "armor/stealth/stealth.h"
#include <tlhelp32.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#define TC_CODE  32u
#define TC_REGS  9u
#define TC_STACK 16u
#define TC_LEN   (TC_CODE + TC_REGS * 4u + TC_STACK * 4u)
#define TC_MAX   512u

typedef struct {
    uint32_t tid;
    uint32_t eip;
    uint32_t used;
} tc_state_t;

static tc_state_t g_states[TC_MAX];
static HANDLE g_thread = NULL;
static uint32_t g_main_tid = 0;
static HANDLE g_main_thread = NULL;

static uint32_t find_main_tid(void) {
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    uint32_t best = 0;
    FILETIME best_ct;
    best_ct.dwLowDateTime = 0xFFFFFFFFu;
    best_ct.dwHighDateTime = 0xFFFFFFFFu;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE th = OpenThread(THREAD_QUERY_INFORMATION, FALSE,
                                   te.th32ThreadID);
            if (!th) continue;
            FILETIME ct, et, kt, ut;
            if (GetThreadTimes(th, &ct, &et, &kt, &ut) &&
                CompareFileTime(&ct, &best_ct) < 0) {
                best_ct = ct;
                best = te.th32ThreadID;
            }
            CloseHandle(th);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return best;
}

static void tc_log(const char* fmt, ...) {
    char gate[8] = { 0 };
    if (GetEnvironmentVariableA("VMPX_TC_LOG", gate, sizeof(gate)) == 0 ||
        gate[0] == '0')
        return;
    char path[MAX_PATH] = { 0 };
    DWORD n = GetTempPathA(MAX_PATH, path);
    if (!n || n + 11 >= MAX_PATH) return;
    strcat_s(path, MAX_PATH, "vmpx_tc.log");
    FILE* f = NULL;
    if (fopen_s(&f, path, "a") != 0 || !f) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fclose(f);
}

static tc_state_t* state_for(uint32_t tid) {
    for (uint32_t i = 0; i < TC_MAX; i++) {
        if (g_states[i].used && g_states[i].tid == tid) return &g_states[i];
    }
    for (uint32_t i = 0; i < TC_MAX; i++) {
        if (!g_states[i].used) {
            g_states[i].used = 1;
            g_states[i].tid = tid;
            g_states[i].eip = 0;
            return &g_states[i];
        }
    }
    return NULL;
}

static int is_main_tid(DWORD tid) {
    return g_main_tid == 0 || tid == g_main_tid;
}

static int executable_prot(DWORD prot) {
    DWORD p = prot & 0xFF;
    return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
           p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

static uint32_t fnv32(const uint8_t* p, uint32_t n) {
    uint32_t h = 2166136261u;
    for (uint32_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

static uint32_t copy_code(uint32_t eip, uint8_t* out, uint32_t cap) {
    __try {
        memcpy(out, (const void*)(uintptr_t)eip, cap);
        return cap;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

static uint32_t copy_stack(uint32_t esp, uint8_t* out, uint32_t cap) {
    __try {
        memcpy(out, (const void*)(uintptr_t)esp, cap);
        return cap;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

/* Record the first main-thread instruction inside the application code
 * section. Returns 1 when this call won the race and filled the entry. */
static int record_entry(vmpx_dyn_ctl_t* ctl, DWORD tid, const CONTEXT* ctx) {
    if (!ctl->app_lo || !is_main_tid(tid)) return 0;
    if (ctx->Eip < ctl->app_lo || ctx->Eip >= ctl->app_hi) return 0;
    if (ctl->entry.ready) return 0;
    if (InterlockedCompareExchange((volatile LONG*)&ctl->entry.valid, 1, 0) != 0)
        return 0;
    ctl->entry.tid = tid;
    ctl->entry.eip = ctx->Eip;
    ctl->entry.esp = ctx->Esp;
    ctl->entry.ebp = ctx->Ebp;
    ctl->entry.eax = ctx->Eax;
    ctl->entry.ebx = ctx->Ebx;
    ctl->entry.ecx = ctx->Ecx;
    ctl->entry.edx = ctx->Edx;
    ctl->entry.esi = ctx->Esi;
    ctl->entry.edi = ctx->Edi;
    ctl->entry.eflags = ctx->EFlags;
    uint32_t sb = copy_stack(ctx->Esp, (uint8_t*)ctl->entry.stack,
                             sizeof(ctl->entry.stack));
    ctl->entry.stack_dwords = sb / 4u;
    MemoryBarrier();
    InterlockedExchange((volatile LONG*)&ctl->entry.ready, 1);
    return 1;
}

/* Tight main-thread sampler: suspend, read context, resume, repeat with no
 * Toolhelp snapshot in the loop. This reaches the application entry within a
 * few instructions instead of the ~30 ms cadence of the all-thread walk. */
static void sample_main_fast(vmpx_dyn_ctl_t* ctl) {
    if (!g_main_thread || ctl->entry.ready) return;
    if (SuspendThread(g_main_thread) == (DWORD)-1) return;
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(g_main_thread, &ctx)) {
        ResumeThread(g_main_thread);
        return;
    }
    ctl->thread_samples++;
    if (ctl->mode & VMPX_DYN_MODE_THREAD) {
        if (record_entry(ctl, g_main_tid, &ctx)) {
            tc_log("fast app eip=%08lX tid=%lu esp=%08lX ebp=%08lX\n",
                   (unsigned long)ctx.Eip, (unsigned long)g_main_tid,
                   (unsigned long)ctx.Esp, (unsigned long)ctx.Ebp);
            return;                 /* parked: leave the thread suspended */
        }
    }
    ResumeThread(g_main_thread);
}

/* Safe fast path -----------------------------------------------------------
 *
 * The tight path above re-suspends the main thread with no delay between
 * passes. The target then runs for microseconds per resume instead of a full
 * scheduler quantum, the unpacker never progresses, and the application
 * section stays zero. The default path below does unpack, but every loop it
 * walks every thread on the system through a fresh Toolhelp snapshot, which
 * costs tens of milliseconds and lands at ~28 Hz.
 *
 * This path caches handles for this process's threads only, refreshes the
 * list at most every TC_REFRESH_MS, and suspends / reads / resumes one cached
 * thread at a time in rotating order, then yields a millisecond. The main
 * thread sits in the cache like any other thread, so it is still sampled
 * several hundred times a second, but it also gets the CPU to itself between
 * samples. */
#define TC_CACHE_MAX  128u
#define TC_REFRESH_MS 500u

typedef struct {
    DWORD  tid;
    HANDLE h;
} tc_cached_t;

static tc_cached_t g_cache[TC_CACHE_MAX];
static uint32_t    g_cache_n = 0;
static uint32_t    g_cache_rr = 0;
static DWORD       g_cache_tick = 0;
static int         g_fast_safe = 0;
static int         g_timer_1ms = 0;

/* VMPX_TC_FAST_SAFE selects this path when present with any value that does
 * not start with '0'. Read once at worker start, not per loop. */
static int fast_safe_enabled(void) {
    char v[8] = { 0 };
    if (GetEnvironmentVariableA("VMPX_TC_FAST_SAFE", v, sizeof(v)) == 0)
        return 0;
    return v[0] != '0';
}

/* timeBeginPeriod lives in winmm, which the backend does not link. Resolve it
 * at runtime so this file stays the only one that changes. */
static int timer_resolution_1ms(void) {
    HMODULE m = LoadLibraryA("winmm.dll");
    if (!m) return 0;
    typedef UINT (WINAPI *tb_fn)(UINT);
    tb_fn tb = (tb_fn)(void*)GetProcAddress(m, "timeBeginPeriod");
    if (!tb) return 0;
    return tb(1) == 0;                  /* TIMERR_NOERROR */
}

static int cache_find(DWORD tid) {
    for (uint32_t i = 0; i < g_cache_n; i++)
        if (g_cache[i].tid == tid) return (int)i;
    return -1;
}

/* Drop entry i; the last entry takes its slot. Called for a thread that has
 * exited or refuses suspension, and the handle goes with it. */
static void cache_drop(uint32_t i) {
    if (i >= g_cache_n) return;
    if (g_cache[i].h) CloseHandle(g_cache[i].h);
    g_cache_n--;
    if (i != g_cache_n) g_cache[i] = g_cache[g_cache_n];
    if (g_cache_rr >= g_cache_n) g_cache_rr = 0;
}

/* Rebuild the cache from Toolhelp. Handles for threads still present are moved
 * across rather than reopened. Only this process's threads are kept, and the
 * worker is skipped because a thread cannot suspend itself. */
static void cache_refresh(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    DWORD pid = GetCurrentProcessId();
    DWORD self = GetCurrentThreadId();
    DWORD keep = (g_cache_n && g_cache_rr < g_cache_n)
                     ? g_cache[g_cache_rr].tid : 0;
    tc_cached_t next[TC_CACHE_MAX];
    uint8_t moved[TC_CACHE_MAX] = { 0 };
    uint32_t n = 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            if (te.th32ThreadID == self) continue;
            if (n >= TC_CACHE_MAX) break;
            int old = cache_find(te.th32ThreadID);
            if (old >= 0 && !moved[old]) {
                moved[old] = 1;
                next[n].tid = g_cache[old].tid;
                next[n].h = g_cache[old].h;
                n++;
                continue;
            }
            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                                  THREAD_QUERY_INFORMATION, FALSE,
                                  te.th32ThreadID);
            if (!h) continue;
            next[n].tid = te.th32ThreadID;
            next[n].h = h;
            n++;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    for (uint32_t i = 0; i < g_cache_n; i++)
        if (!moved[i] && g_cache[i].h) CloseHandle(g_cache[i].h);
    memcpy(g_cache, next, sizeof(tc_cached_t) * n);
    g_cache_n = n;
    g_cache_rr = 0;
    if (keep) {
        for (uint32_t i = 0; i < n; i++) {
            if (g_cache[i].tid == keep) { g_cache_rr = i; break; }
        }
    }
    g_cache_tick = GetTickCount();
    tc_log("safe cache n=%lu\n", (unsigned long)n);
}

/* One pass over the cache, starting where the previous pass stopped. Returns 1
 * when the application-section entry was recorded; the hit thread is then left
 * suspended and the remainder of the pass is skipped. */
static int cache_sample_pass(vmpx_dyn_ctl_t* ctl) {
    if (!g_cache_n) return 0;
    uint32_t i = g_cache_rr % g_cache_n;
    uint32_t budget = g_cache_n * 2u + 8u;

    while (budget-- && g_cache_n && !ctl->entry.ready) {
        if (i >= g_cache_n) i = 0;
        HANDLE th = g_cache[i].h;
        if (!th) {
            cache_drop(i);
            continue;
        }
        if (SuspendThread(th) == (DWORD)-1) {
            cache_drop(i);              /* exited: handle goes, slot reused */
            continue;
        }
        CONTEXT ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (!GetThreadContext(th, &ctx)) {
            ResumeThread(th);
            cache_drop(i);
            continue;
        }
        ctl->thread_samples++;
        if (ctl->mode & VMPX_DYN_MODE_THREAD) {
            DWORD tid = g_cache[i].tid;
            if (record_entry(ctl, tid, &ctx)) {
                tc_log("safe app eip=%08lX tid=%lu esp=%08lX ebp=%08lX\n",
                       (unsigned long)ctx.Eip, (unsigned long)tid,
                       (unsigned long)ctx.Esp, (unsigned long)ctx.Ebp);
                g_cache_rr = i;
                return 1;               /* parked: leave the thread suspended */
            }
        }
        ResumeThread(th);
        i++;
    }
    g_cache_rr = g_cache_n ? (i % g_cache_n) : 0;
    return 0;
}

static void sample_safe(vmpx_dyn_ctl_t* ctl) {
    if (ctl->entry.ready) return;
    DWORD now = GetTickCount();
    if (!g_cache_n || (DWORD)(now - g_cache_tick) >= TC_REFRESH_MS)
        cache_refresh();
    cache_sample_pass(ctl);
}

static void sample_thread(vmpx_dyn_ctl_t* ctl, DWORD tid) {
    if (tid == GetCurrentThreadId()) return;
    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                           THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!th) return;
    if (SuspendThread(th) == (DWORD)-1) {
        CloseHandle(th);
        return;
    }

    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(th, &ctx)) {
        ResumeThread(th);
        CloseHandle(th);
        return;
    }

    ctl->thread_samples++;
    if (stealth_hidden_region(ctx.Eip, 1)) {
        ResumeThread(th);
        CloseHandle(th);
        return;
    }

    tc_state_t* st = state_for(tid);
    if (!st) {
        ResumeThread(th);
        CloseHandle(th);
        return;
    }

    uint32_t changed = (st->eip != ctx.Eip) ? 1u : 0u;
    if (!changed) {
        ResumeThread(th);
        CloseHandle(th);
        return;
    }
    st->eip = ctx.Eip;

    uint8_t data[TC_LEN];
    memset(data, 0, sizeof(data));
    uint32_t code_n = copy_code(ctx.Eip, data, TC_CODE);
    uint32_t* regs = (uint32_t*)(void*)(data + TC_CODE);
    regs[0] = ctx.Eax;
    regs[1] = ctx.Ecx;
    regs[2] = ctx.Edx;
    regs[3] = ctx.Ebx;
    regs[4] = ctx.Esp;
    regs[5] = ctx.Ebp;
    regs[6] = ctx.Esi;
    regs[7] = ctx.Edi;
    regs[8] = ctx.EFlags;
    uint32_t stack_n = copy_stack(ctx.Esp, data + TC_CODE + TC_REGS * 4u,
                                  TC_STACK * 4u);

    int in_image = (ctl->image_base && ctx.Eip >= ctl->image_base &&
                    ctx.Eip < ctl->image_base + ctl->image_size);
    uint32_t flags = VMPX_DYN_F_THREAD | VMPX_DYN_F_CHANGED;
    if (in_image) flags |= VMPX_DYN_F_IMAGE;

    MEMORY_BASIC_INFORMATION mbi;
    int private_exec = 0;
    if (VirtualQuery((LPCVOID)(uintptr_t)ctx.Eip, &mbi, sizeof(mbi))) {
        if (mbi.Type == MEM_PRIVATE) {
            flags |= VMPX_DYN_F_PRIVATE;
            private_exec = executable_prot(mbi.Protect);
        }
    }

    uint32_t crc = code_n ? fnv32(data, code_n) : 0;
    vmtrans_track(tid, ctx.Eip, ctx.Esp, private_exec, in_image, data, TC_LEN);

    /* First instruction seen in the lowest executable section: the unpacked
     * application entry. Recorded once, without touching the thread's debug
     * registers, page protections, or instruction bytes. The thread is left
     * suspended so the entry context and the process image are consistent
     * when a capture reads them. */
    int park = 0;
    int is_main = (g_main_tid == 0 || tid == g_main_tid);
    if (is_main && ctl->app_lo && ctx.Eip >= ctl->app_lo &&
        ctx.Eip < ctl->app_hi) {
        tc_log("app eip=%08lX tid=%lu main=%lu esp=%08lX ebp=%08lX ready=%lu valid=%lu\n",
               (unsigned long)ctx.Eip, (unsigned long)tid,
               (unsigned long)g_main_tid,
               (unsigned long)ctx.Esp, (unsigned long)ctx.Ebp,
               (unsigned long)ctl->entry.ready, (unsigned long)ctl->entry.valid);
    }
    if (is_main && ctl->app_lo && ctx.Eip >= ctl->app_lo &&
        ctx.Eip < ctl->app_hi &&
        !ctl->entry.ready &&
        InterlockedCompareExchange((volatile LONG*)&ctl->entry.valid, 1, 0) == 0) {
        ctl->entry.tid = tid;
        ctl->entry.eip = ctx.Eip;
        ctl->entry.esp = ctx.Esp;
        ctl->entry.ebp = ctx.Ebp;
        ctl->entry.eax = ctx.Eax;
        ctl->entry.ebx = ctx.Ebx;
        ctl->entry.ecx = ctx.Ecx;
        ctl->entry.edx = ctx.Edx;
        ctl->entry.esi = ctx.Esi;
        ctl->entry.edi = ctx.Edi;
        ctl->entry.eflags = ctx.EFlags;
        uint32_t sb = copy_stack(ctx.Esp, (uint8_t*)ctl->entry.stack,
                                 sizeof(ctl->entry.stack));
        ctl->entry.stack_dwords = sb / 4u;
        MemoryBarrier();
        InterlockedExchange((volatile LONG*)&ctl->entry.ready, 1);
        park = 1;
    }

    dyn_event_publish(VMPX_DYN_EV_THREAD, flags, ctx.Eip, 1,
                      ctx.Eip, ctx.Esp, crc, data, TC_LEN,
                      tid, code_n | (stack_n ? 0x10000u : 0));

    if (!park) ResumeThread(th);
    CloseHandle(th);
}

static DWORD WINAPI thread_worker(LPVOID param) {
    (void)param;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    vmpx_dyn_ctl_t* ctl = dyn_control_get();
    if (!ctl) return 0;

    g_main_tid = find_main_tid();
    if (g_main_tid)
        g_main_thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                                   THREAD_QUERY_INFORMATION, FALSE, g_main_tid);
    tc_log("main tid=%lu fast=%d\n", (unsigned long)g_main_tid,
           g_main_thread ? 1 : 0);

    g_fast_safe = fast_safe_enabled();
    if (g_fast_safe) {
        g_timer_1ms = timer_resolution_1ms();
        tc_log("safe sampler on timer=%d\n", g_timer_1ms);
    }

    while (1) {
        if (!ctl->active || !(ctl->mode & VMPX_DYN_MODE_THREAD)) {
            Sleep(200);
            continue;
        }
        ctl->thread_ticks++;
        uint32_t ms = ctl->thread_interval_ms;
        if (ms < 1) ms = 1;
        if (ms > 2000) ms = 2000;

        if (g_fast_safe && ms <= 1) {
            sample_safe(ctl);
            Sleep(1);
            continue;
        }

        char fast[8];
        int use_fast = GetEnvironmentVariableA("VMPX_TC_FAST", fast,
                                               sizeof(fast)) > 0;
        if (ms <= 1 && g_main_thread && use_fast) {
            sample_main_fast(ctl);
            continue;
        }
        Sleep(ms);
        if (!ctl->active || !(ctl->mode & VMPX_DYN_MODE_THREAD)) continue;

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) continue;
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        uint32_t emitted = 0;
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != GetCurrentProcessId()) continue;
                sample_thread(ctl, te.th32ThreadID);
                emitted++;
                if (emitted >= 256) break;
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }
    return 0;
}

int dyn_threadctx_start(void) {
    if (g_thread) return 0;
    memset(g_states, 0, sizeof(g_states));
    g_thread = CreateThread(NULL, 0, thread_worker, NULL, 0, NULL);
    if (!g_thread) return -1;
    CloseHandle(g_thread);
    g_thread = (HANDLE)(uintptr_t)1;
    vmpx_dyn_ctl_t* ctl = dyn_control_get();
    if (ctl) ctl->flags |= VMPX_DYN_F_THR_STARTED;
    if (ctl)
        tc_log("start app=[%08llX..%08llX) interval=%lu mode=%lu\n",
               (unsigned long long)ctl->app_lo,
               (unsigned long long)ctl->app_hi,
               (unsigned long)ctl->thread_interval_ms,
               (unsigned long)ctl->mode);
    return 0;
}
