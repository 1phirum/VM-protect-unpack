/* install.c - hook table and lifecycle (L1)
 *
 * The table is indexed by the ST_HK_* enum. ntdll hooks go first so the
 * engine can patch through untouched memory APIs; NtProtectVirtualMemory and
 * NtWriteVirtualMemory are installed last and then guard the agent, every
 * trampoline, and every patched prologue against target-side writes.
 */
#include "armor/stealth/stealth.h"
#include "armor/stealth/handlers.h"

typedef struct {
    const wchar_t* module;
    const char*    name;
    void*          handler;
    const char*    label;
} stealth_def_t;

static const stealth_def_t DEFS[ST_HK_COUNT] = {
    { L"ntdll.dll",   "NtQueryInformationProcess", (void*)stealth_h_qip,    "NtQueryInformationProcess" },
    { L"ntdll.dll",   "NtQuerySystemInformation",  (void*)stealth_h_qsi,    "NtQuerySystemInformation" },
    { L"ntdll.dll",   "NtQueryInformationThread",  (void*)stealth_h_qit,    "NtQueryInformationThread" },
    { L"ntdll.dll",   "NtSetInformationThread",    (void*)stealth_h_sit,    "NtSetInformationThread" },
    { L"ntdll.dll",   "NtGetContextThread",        (void*)stealth_h_gct,    "NtGetContextThread" },
    { L"ntdll.dll",   "NtSetContextThread",        (void*)stealth_h_sct,    "NtSetContextThread" },
    { L"ntdll.dll",   "NtQueryVirtualMemory",      (void*)stealth_h_qvm,    "NtQueryVirtualMemory" },
    { L"ntdll.dll",   "NtQueryPerformanceCounter", (void*)stealth_h_qpc,    "NtQueryPerformanceCounter" },
    { L"ntdll.dll",   "NtQuerySystemTime",         (void*)stealth_h_qst,    "NtQuerySystemTime" },
    { L"ntdll.dll",   "NtCreateThreadEx",          (void*)stealth_h_ctex,   "NtCreateThreadEx" },
    { L"ntdll.dll",   "NtSystemDebugControl",      (void*)stealth_h_sdc,    "NtSystemDebugControl" },
    { L"kernel32.dll","IsDebuggerPresent",         (void*)stealth_h_isdbg,  "IsDebuggerPresent" },
    { L"kernel32.dll","CheckRemoteDebuggerPresent",(void*)stealth_h_crdbg,  "CheckRemoteDebuggerPresent" },
    { L"kernel32.dll","OutputDebugStringW",        (void*)stealth_h_odsw,   "OutputDebugStringW" },
    { L"kernel32.dll","OutputDebugStringA",        (void*)stealth_h_odsa,   "OutputDebugStringA" },
    { L"kernel32.dll","GetTickCount",              (void*)stealth_h_tick,   "GetTickCount" },
    { L"kernel32.dll","GetTickCount64",            (void*)stealth_h_tick64, "GetTickCount64" },
    { L"kernel32.dll","GetSystemTimeAsFileTime",   (void*)stealth_h_gstaft, "GetSystemTimeAsFileTime" },
    { L"kernel32.dll","GetSystemTimePreciseAsFileTime", (void*)stealth_h_gstpft, "GetSystemTimePreciseAsFileTime" },
    { L"user32.dll",  "EnumWindows",               (void*)stealth_h_enumw,  "EnumWindows" },
    { L"user32.dll",  "FindWindowW",               (void*)stealth_h_findw,  "FindWindowW" },
    { L"user32.dll",  "FindWindowExW",             (void*)stealth_h_findexw,"FindWindowExW" },
    { L"user32.dll",  "FindWindowA",               (void*)stealth_h_finda,  "FindWindowA" },
    { L"user32.dll",  "FindWindowExA",             (void*)stealth_h_findexa,"FindWindowExA" },
    { L"ntdll.dll",   "NtReadVirtualMemory",       (void*)stealth_h_rvm,    "NtReadVirtualMemory" },
    { L"ntdll.dll",   "NtProtectVirtualMemory",    (void*)stealth_h_pvm,    "NtProtectVirtualMemory" },
    { L"ntdll.dll",   "NtWriteVirtualMemory",      (void*)stealth_h_wvm,    "NtWriteVirtualMemory" },
};

static int g_installed;
static int g_ok;
static int g_fail;

int stealth_install(void) {
    if (g_installed) return g_ok;
    g_installed = 1;
    g_ok = 0;
    g_fail = 0;

    stealth_init_identity();

    /* Phase 1: everything except the two memory mutators. The engine uses
     * VirtualAlloc/VirtualProtect, so hooking those before the rest would make
     * the installation path re-enter its own guard. */
    for (int i = 0; i < ST_HK_COUNT; i++) {
        if (i == ST_HK_PVM || i == ST_HK_WVM) continue;
        if (stealth_hook_install(&g_stealth_hooks[i], DEFS[i].module,
                                 DEFS[i].name, DEFS[i].handler,
                                 DEFS[i].label) == 0)
            g_ok++;
        else
            g_fail++;
    }

    /* Phase 2: memory mutators. These guard the hides for the rest of the
     * target's lifetime, including writes aimed at the agent image. */
    const int late[2] = { ST_HK_PVM, ST_HK_WVM };
    for (int k = 0; k < 2; k++) {
        int i = late[k];
        if (stealth_hook_install(&g_stealth_hooks[i], DEFS[i].module,
                                 DEFS[i].name, DEFS[i].handler,
                                 DEFS[i].label) == 0)
            g_ok++;
        else
            g_fail++;
    }
    return g_ok;
}

int stealth_hook_count(void) { return g_ok; }
int stealth_hook_fail_count(void) { return g_fail; }

const char* stealth_hook_name(int index) {
    if (index < 0 || index >= ST_HK_COUNT) return "";
    if (!g_stealth_hooks[index].active) return "";
    return g_stealth_hooks[index].label ? g_stealth_hooks[index].label : "";
}

void* stealth_trampoline(int index) {
    if (index < 0 || index >= ST_HK_COUNT) return NULL;
    if (!g_stealth_hooks[index].active) return NULL;
    return g_stealth_hooks[index].trampoline;
}
