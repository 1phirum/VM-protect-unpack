/* oep.c - in-process entry capture with DR, INT3, or guarded-range probes
 *
 * Three capture modes share one parked-thread handoff:
 *   - DR: DR0 holds the entry VA on every target thread.
 *   - SW: the entry byte is patched to INT3 after a delay.
 *   - GUARD: a whole executable range is guarded. Read/write touches are
 *     stepped over and re-armed; the first instruction fetch in the range is
 *     the unpacked entry.
 *
 * GUARD is the mode that survives packers which write the entry section after
 * the anti-debug window: the guard write faults are absorbed, then the guard is
 * re-armed before the entry executes.
 */
#include "unpack/deobf/dynamic/oep/oep.h"
#include "unpack/deobf/dynamic/control/control.h"
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#ifndef STATUS_GUARD_PAGE_VIOLATION
#define STATUS_GUARD_PAGE_VIOLATION 0x80000001u
#endif
#ifndef STATUS_SINGLE_STEP
#define STATUS_SINGLE_STEP 0x80000004u
#endif

#define OEP_GUARD_MAX 65536u

typedef struct {
    uint32_t page;
    uint32_t prot;
    volatile LONG armed;
} oep_guard_page_t;

static HANDLE g_map = NULL;
static HANDLE g_evt = NULL;
static vmpx_oep_ctx_t* g_ctx = NULL;
static PVOID g_veh = NULL;
static volatile LONG g_hit = 0;
static volatile uint32_t g_oep = 0;
static int g_sw_mode = 0;
static int g_guard_mode = 0;
static int g_hook_mode = 0;
static int g_sw_patched = 0;
static uint8_t g_orig_byte = 0;
static uint32_t g_guard_size = 0;
static oep_guard_page_t g_guard[OEP_GUARD_MAX];
static uint32_t g_guard_n = 0;
static volatile LONG g_arming = 0;
static volatile LONG g_hook_ready = 0;
static __declspec(thread) uint32_t t_step_page = 0;
static __declspec(thread) uint32_t t_step_prot = 0;

static void oep_log(const char* fmt, ...) {
    char gate[8] = { 0 };
    if (GetEnvironmentVariableA("VMPX_OEP_LOG", gate, sizeof(gate)) == 0 ||
        gate[0] == '0')
        return;
    char path[MAX_PATH] = { 0 };
    DWORD n = GetTempPathA(MAX_PATH, path);
    if (!n || n + 13 >= MAX_PATH) return;
    strcat_s(path, MAX_PATH, "vmpx_oep.log");
    FILE* f = NULL;
    if (fopen_s(&f, path, "a") != 0 || !f) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fclose(f);
}

static void publish_hit(CONTEXT* c, uint32_t report_eip) {
    if (InterlockedExchange(&g_hit, 1) != 0) return;
    vmpx_oep_ctx_t* ctx = g_ctx;
    if (ctx) {
        memset(ctx, 0, sizeof(*ctx));
        ctx->magic = VMPX_OEP_MAGIC;
        ctx->version = VMPX_OEP_VERSION;
        ctx->pid = GetCurrentProcessId();
        ctx->oep_va = report_eip;
        ctx->page_base = report_eip & ~0xFFFu;
        ctx->page_prot = 0;
        ctx->tid = GetCurrentThreadId();
        ctx->eip = report_eip;
        ctx->esp = c->Esp;
        ctx->ebp = c->Ebp;
        ctx->eax = c->Eax;
        ctx->ebx = c->Ebx;
        ctx->ecx = c->Ecx;
        ctx->edx = c->Edx;
        ctx->esi = c->Esi;
        ctx->edi = c->Edi;
        ctx->eflags = c->EFlags;
        ctx->dr0 = c->Dr0;
        ctx->dr7 = c->Dr7;
        InterlockedExchange((volatile LONG*)&ctx->hit, 1);
    }
    if (g_evt) SetEvent(g_evt);
    oep_log("hit eip=%08lX esp=%08lX ebp=%08lX eax=%08lX ebx=%08lX ecx=%08lX edx=%08lX\n",
            (unsigned long)report_eip, (unsigned long)c->Esp,
            (unsigned long)c->Ebp, (unsigned long)c->Eax,
            (unsigned long)c->Ebx, (unsigned long)c->Ecx,
            (unsigned long)c->Edx);
    /* The entry stack is still live above ESP. The parent suspends the process
     * and snapshots this exact state; this thread never returns to user code. */
    Sleep(INFINITE);
}

static void arm_thread(DWORD tid) {
    if (tid == GetCurrentThreadId()) return;
    HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                           THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                           FALSE, tid);
    if (!th) {
        oep_log("arm tid=%lu open=fail err=%lu\n", (unsigned long)tid,
                (unsigned long)GetLastError());
        return;
    }
    SuspendThread(th);
    CONTEXT c;
    memset(&c, 0, sizeof(c));
    c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
    int got = GetThreadContext(th, &c);
    int set = 0;
    if (got) {
        c.Dr0 = g_oep;
        c.Dr1 = 0;
        c.Dr2 = 0;
        c.Dr3 = 0;
        c.Dr6 = 0;
        c.Dr7 = 0x1u;                 /* L0 only; execute breakpoint */
        set = SetThreadContext(th, &c) != 0;
    }
    uint32_t dr0 = 0, dr7 = 0;
    if (set) {
        memset(&c, 0, sizeof(c));
        c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(th, &c)) {
            dr0 = c.Dr0;
            dr7 = c.Dr7;
        }
    }
    ResumeThread(th);
    CloseHandle(th);
    oep_log("arm tid=%lu get=%d set=%d dr0=%08lX dr7=%08lX\n",
            (unsigned long)tid, got, set, (unsigned long)dr0,
            (unsigned long)dr7);
}

static void arm_all_threads(void) {
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        oep_log("arm_all snapshot=fail err=%lu\n", (unsigned long)GetLastError());
        return;
    }
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) arm_thread(te.th32ThreadID);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

static void log_threads(const char* tag) {
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                                   FALSE, te.th32ThreadID);
            if (!th) continue;
            CONTEXT c;
            memset(&c, 0, sizeof(c));
            c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(th, &c))
                oep_log("%s tid=%lu dr0=%08lX dr7=%08lX\n", tag,
                        (unsigned long)te.th32ThreadID,
                        (unsigned long)c.Dr0, (unsigned long)c.Dr7);
            CloseHandle(th);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

static int sw_patch(void) {
    DWORD old = 0;
    if (!VirtualProtect((LPVOID)(uintptr_t)g_oep, 1, PAGE_EXECUTE_READWRITE, &old)) {
        oep_log("sw patch protect=fail err=%lu\n", (unsigned long)GetLastError());
        return 0;
    }
    g_orig_byte = *(volatile uint8_t*)(uintptr_t)g_oep;
    *(volatile uint8_t*)(uintptr_t)g_oep = 0xCC;
    FlushInstructionCache(GetCurrentProcess(), (LPCVOID)(uintptr_t)g_oep, 1);
    DWORD tmp = 0;
    VirtualProtect((LPVOID)(uintptr_t)g_oep, 1, old, &tmp);
    g_sw_patched = 1;
    oep_log("sw patch oep=%08lX orig=%02X prot=%08lX\n",
            (unsigned long)g_oep, g_orig_byte, (unsigned long)old);
    return 1;
}

static int guard_cmp(const void* a, const void* b) {
    uint32_t x = ((const oep_guard_page_t*)a)->page;
    uint32_t y = ((const oep_guard_page_t*)b)->page;
    return x < y ? -1 : (x > y ? 1 : 0);
}

static int guard_find(uint32_t page) {
    uint32_t lo = 0, hi = g_guard_n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (g_guard[mid].page < page) lo = mid + 1;
        else hi = mid;
    }
    if (lo < g_guard_n && g_guard[lo].page == page) return (int)lo;
    return -1;
}

static int guard_arm(uint32_t base, uint32_t size) {
    g_guard_n = 0;
    InterlockedExchange(&g_arming, 1);
    uint64_t start = (uint64_t)base & ~(uint64_t)(VMPX_DYN_PAGE - 1);
    uint64_t end = (uint64_t)base + size;
    for (uint64_t a = start; a < end && g_guard_n < OEP_GUARD_MAX;
         a += VMPX_DYN_PAGE) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((LPCVOID)(uintptr_t)a, &mbi, sizeof(mbi))) continue;
        if (mbi.State != MEM_COMMIT) continue;
        DWORD p = mbi.Protect & 0xFF;
        if (p != PAGE_EXECUTE && p != PAGE_EXECUTE_READ &&
            p != PAGE_EXECUTE_READWRITE && p != PAGE_EXECUTE_WRITECOPY)
            continue;
        if (mbi.Protect & PAGE_GUARD) continue;
        DWORD old = 0;
        if (!VirtualProtect((LPVOID)(uintptr_t)a, VMPX_DYN_PAGE,
                            p | PAGE_GUARD, &old))
            continue;
        g_guard[g_guard_n].page = (uint32_t)a;
        g_guard[g_guard_n].prot = p;
        g_guard[g_guard_n].armed = 1;
        g_guard_n++;
    }
    InterlockedExchange(&g_arming, 0);
    qsort(g_guard, g_guard_n, sizeof(g_guard[0]), guard_cmp);
    oep_log("guard arm base=%08lX size=%08lX pages=%lu\n",
            (unsigned long)base, (unsigned long)size,
            (unsigned long)g_guard_n);
    return g_guard_n > 0;
}

/* NtProtectVirtualMemory hook: when the packer makes a page executable, the
 * guard bit is gone. Put it back before the first instruction fetch. In hook
 * mode, patch the exact entry byte with INT3 after the page is executable. */
void dyn_oep_on_protect(uint64_t addr, uint64_t size, uint32_t prot) {
    if ((!g_guard_mode && !g_hook_mode) || g_hit || g_arming) return;
    if (g_hook_mode) {
        static volatile LONG plog = 0;
        if (InterlockedIncrement(&plog) <= 400)
            oep_log("onprotect addr=%08llX size=%08llX prot=%08X ready=%d\n",
                    (unsigned long long)addr, (unsigned long long)size,
                    prot, (int)g_hook_ready);
    }
    DWORD p = prot & 0xFF;
    if (p != PAGE_EXECUTE && p != PAGE_EXECUTE_READ &&
        p != PAGE_EXECUTE_READWRITE && p != PAGE_EXECUTE_WRITECOPY)
        return;
    if (prot & PAGE_GUARD) return;

    if (g_hook_mode) {
        if (!g_hook_ready) return;
        uint64_t start = addr & ~(uint64_t)(VMPX_DYN_PAGE - 1);
        uint64_t end = addr + size;
        if ((uint64_t)g_oep < start || (uint64_t)g_oep >= end) return;
        uint8_t b = *(volatile uint8_t*)(uintptr_t)g_oep;
        if (!b || b == 0xCC) {
            oep_log("hook protect oep=%08lX byte=%02X (deferred)\n",
                    (unsigned long)g_oep, b);
            return;
        }
        InterlockedExchange(&g_arming, 1);
        g_sw_patched = 0;
        int ok = sw_patch();
        InterlockedExchange(&g_arming, 0);
        oep_log("hook protect oep=%08lX byte=%02X patch=%d\n",
                (unsigned long)g_oep, b, ok);
        return;
    }

    if (!g_guard_n || !g_guard_size) return;
    uint64_t start = addr & ~(uint64_t)(VMPX_DYN_PAGE - 1);
    uint64_t end = addr + size;
    uint64_t gs = g_oep;
    uint64_t ge = (uint64_t)g_oep + g_guard_size;
    if (end <= gs || start >= ge) return;
    if (start < gs) start = gs & ~(uint64_t)(VMPX_DYN_PAGE - 1);
    if (end > ge) end = ge;
    for (uint64_t a = start; a < end; a += VMPX_DYN_PAGE) {
        int idx = guard_find((uint32_t)a);
        if (idx < 0) continue;
        if (InterlockedCompareExchange(&g_guard[idx].armed, 1, 0) != 0)
            continue;
        InterlockedExchange(&g_arming, 1);
        DWORD old = 0;
        if (!VirtualProtect((LPVOID)(uintptr_t)a, VMPX_DYN_PAGE,
                            p | PAGE_GUARD, &old)) {
            InterlockedExchange(&g_guard[idx].armed, 0);
        } else {
            g_guard[idx].prot = p;
        }
        InterlockedExchange(&g_arming, 0);
    }
}

static DWORD WINAPI oep_delayed(LPVOID param) {
    uint32_t delay = (uint32_t)(uintptr_t)param;
    if (delay) Sleep(delay);
    if (g_hit) return 0;
    oep_log("delayed fire delay=%lu mode=%s\n", (unsigned long)delay,
            g_guard_mode ? "guard" : (g_hook_mode ? "hook" :
                                      (g_sw_mode ? "sw" : "dr")));
    if (g_hook_mode) {
        /* The protect hook normally patches before the packer returns. If the
         * packer protected first and wrote later, poll until the entry byte is
         * real and the page is executable. Arm only after the anti-debug window
         * so the patch is not present while the target checks DR/contexts. */
        InterlockedExchange(&g_hook_ready, 1);
        for (int i = 0; i < 600 && !g_hit; i++) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery((LPCVOID)(uintptr_t)g_oep, &mbi, sizeof(mbi))) {
                DWORD p = mbi.Protect & 0xFF;
                if (p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
                    p == PAGE_EXECUTE_READWRITE ||
                    p == PAGE_EXECUTE_WRITECOPY) {
                    uint8_t b = *(volatile uint8_t*)(uintptr_t)g_oep;
                    if (b && b != 0xCC) {
                        InterlockedExchange(&g_arming, 1);
                        g_sw_patched = 0;
                        sw_patch();
                        InterlockedExchange(&g_arming, 0);
                        break;
                    }
                }
            }
            Sleep(10);
        }
        return 0;
    }
    if (g_guard_mode) guard_arm(g_oep, g_guard_size);
    else if (g_sw_mode) sw_patch();
    else arm_all_threads();
    Sleep(500);
    if (!g_guard_mode) log_threads(g_sw_mode ? "post-sw" : "post-dr");
    return 0;
}

static LONG CALLBACK oep_veh(PEXCEPTION_POINTERS ep) {
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord)
        return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT* c = ep->ContextRecord;
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    if (code == STATUS_GUARD_PAGE_VIOLATION && g_guard_mode) {
        ULONG_PTR access = ep->ExceptionRecord->ExceptionInformation[0];
        uint64_t fault = (uint64_t)ep->ExceptionRecord->ExceptionInformation[1];
        uint32_t page = (uint32_t)(fault & ~(uint64_t)(VMPX_DYN_PAGE - 1));
        int idx = guard_find(page);
        if (idx < 0) return EXCEPTION_CONTINUE_SEARCH;
        if (access == 8) {
            if (g_hit) return EXCEPTION_CONTINUE_SEARCH;
            InterlockedExchange(&g_guard[idx].armed, 0);
            DWORD old = 0;
            VirtualProtect((LPVOID)(uintptr_t)page, VMPX_DYN_PAGE,
                           g_guard[idx].prot, &old);
            publish_hit(c, (uint32_t)c->Eip);
        }
        /* A read or write cleared the guard. Set TF, let the access complete,
         * then re-arm the same page in the single-step handler. */
        InterlockedExchange(&g_guard[idx].armed, 0);
        t_step_page = page;
        t_step_prot = g_guard[idx].prot;
        c->EFlags |= 0x100u;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code == STATUS_SINGLE_STEP && g_guard_mode && t_step_page) {
        DWORD old = 0;
        if (VirtualProtect((LPVOID)(uintptr_t)t_step_page, VMPX_DYN_PAGE,
                           t_step_prot | PAGE_GUARD, &old)) {
            int idx = guard_find(t_step_page);
            if (idx >= 0) InterlockedExchange(&g_guard[idx].armed, 1);
        }
        c->EFlags &= ~0x100u;
        t_step_page = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code == EXCEPTION_SINGLE_STEP) {
        if (c->Eip != g_oep || !(c->Dr6 & 1) || g_hit)
            return EXCEPTION_CONTINUE_SEARCH;
        publish_hit(c, g_oep);
    }

    if (code == EXCEPTION_BREAKPOINT && (g_sw_mode || g_hook_mode) && g_sw_patched) {
        uint32_t addr = (uint32_t)(uintptr_t)ep->ExceptionRecord->ExceptionAddress;
        if (addr != g_oep && c->Eip != g_oep + 1)
            return EXCEPTION_CONTINUE_SEARCH;
        DWORD old = 0;
        if (VirtualProtect((LPVOID)(uintptr_t)g_oep, 1,
                           PAGE_EXECUTE_READWRITE, &old)) {
            *(volatile uint8_t*)(uintptr_t)g_oep = g_orig_byte;
            FlushInstructionCache(GetCurrentProcess(),
                                  (LPCVOID)(uintptr_t)g_oep, 1);
            DWORD tmp = 0;
            VirtualProtect((LPVOID)(uintptr_t)g_oep, 1, old, &tmp);
        }
        g_sw_patched = 0;
        c->Eip = g_oep;
        publish_hit(c, g_oep);
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

int dyn_oep_arm(uint32_t oep_va) {
    if (!oep_va) return 0;
    if (g_ctx) return 1;

    char mode[16] = { 0 };
    GetEnvironmentVariableA("VMPX_OEP_MODE", mode, sizeof(mode));
    g_sw_mode = (mode[0] == 's' || mode[0] == 'S');
    g_guard_mode = (mode[0] == 'g' || mode[0] == 'G');
    g_hook_mode = (mode[0] == 'h' || mode[0] == 'H');

    char gs[32] = { 0 };
    if (GetEnvironmentVariableA("VMPX_OEP_GUARD", gs, sizeof(gs)) > 0)
        g_guard_size = (uint32_t)strtoul(gs, NULL, 0);
    if (!g_guard_size) g_guard_size = VMPX_DYN_PAGE;

    DWORD pid = GetCurrentProcessId();
    wchar_t map_name[96];
    wchar_t evt_name[96];
    swprintf_s(map_name, 96, L"Local\\VMPX_OEP_CTX_%u", pid);
    swprintf_s(evt_name, 96, L"Local\\VMPX_OEP_EVT_%u", pid);

    g_map = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0,
                               (DWORD)sizeof(vmpx_oep_ctx_t), map_name);
    if (!g_map) return 0;
    g_ctx = (vmpx_oep_ctx_t*)MapViewOfFile(g_map, FILE_MAP_ALL_ACCESS, 0, 0,
                                           sizeof(vmpx_oep_ctx_t));
    if (!g_ctx) return 0;
    memset(g_ctx, 0, sizeof(*g_ctx));
    g_ctx->magic = VMPX_OEP_MAGIC;
    g_ctx->version = VMPX_OEP_VERSION;
    g_ctx->pid = pid;
    g_ctx->oep_va = oep_va;

    g_evt = CreateEventW(NULL, TRUE, FALSE, evt_name);
    if (!g_evt) return 0;

    g_oep = oep_va;
    g_hit = 0;

    g_veh = AddVectoredExceptionHandler(1, oep_veh);
    if (!g_veh) return 0;

    wchar_t delay_buf[32] = { 0 };
    DWORD delay = 0;
    if (GetEnvironmentVariableW(L"VMPX_OEP_DELAY", delay_buf, 32) > 0)
        delay = (DWORD)_wtoi(delay_buf);

    oep_log("arm oep=%08lX mode=%s delay=%lu guard=%08lX\n",
            (unsigned long)oep_va,
            g_guard_mode ? "guard" : (g_hook_mode ? "hook" :
                                      (g_sw_mode ? "sw" : "dr")),
            (unsigned long)delay, (unsigned long)g_guard_size);

    if (delay || g_hook_mode) {
        HANDLE th = CreateThread(NULL, 0, oep_delayed,
                                 (LPVOID)(uintptr_t)delay, 0, NULL);
        if (th) CloseHandle(th);
    } else {
        if (g_guard_mode) guard_arm(g_oep, g_guard_size);
        else if (g_sw_mode) sw_patch();
        else arm_all_threads();
    }

    dyn_event_publish(VMPX_DYN_EV_MARK, 0, oep_va, 0, 0, 0, 0,
                      VMPX_HASH_NONE, 0, "oep-armed", 10, 0, 0);
    return 1;
}
