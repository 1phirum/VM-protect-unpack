/* install.c - hook table, status counters, one install per process (L1) */
#include "armor/anti/anti.h"

typedef void (*fnv_t)(void);

typedef struct {
    const char* export_name;
    const char* short_name;
    fnv_t       handler;
} hook_def_t;

LONG NTAPI anti_h_qip(HANDLE, ULONG, PVOID, ULONG, PULONG);
LONG NTAPI anti_h_qsi(ULONG, PVOID, ULONG, PULONG);
LONG NTAPI anti_h_sit(HANDLE, ULONG, PVOID, ULONG);
LONG NTAPI anti_h_gct(HANDLE, PCONTEXT);
LONG NTAPI anti_h_sct(HANDLE, PCONTEXT);
LONG NTAPI anti_h_qvm(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
LONG NTAPI anti_h_pvm(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
LONG NTAPI anti_h_qpc(PLARGE_INTEGER, PLARGE_INTEGER);

static const hook_def_t HOOKS[ANTI_HOOK_COUNT] = {
    { "NtQueryInformationProcess", "NtQueryInformationProcess", (fnv_t)anti_h_qip },
    { "NtQuerySystemInformation",  "NtQuerySystemInformation",  (fnv_t)anti_h_qsi },
    { "NtSetInformationThread",    "NtSetInformationThread",    (fnv_t)anti_h_sit },
    { "NtGetContextThread",        "NtGetContextThread",        (fnv_t)anti_h_gct },
    { "NtSetContextThread",        "NtSetContextThread",        (fnv_t)anti_h_sct },
    { "NtQueryVirtualMemory",      "NtQueryVirtualMemory",      (fnv_t)anti_h_qvm },
    { "NtProtectVirtualMemory",    "NtProtectVirtualMemory",    (fnv_t)anti_h_pvm },
    { "NtQueryPerformanceCounter", "NtQueryPerformanceCounter", (fnv_t)anti_h_qpc },
};

static void* g_thunk[ANTI_HOOK_COUNT];
static int    g_ok;
static int    g_installed;

void* anti_thunk(int index) {
    if (index < 0 || index >= ANTI_HOOK_COUNT) return NULL;
    return g_thunk[index];
}

int anti_install(void) {
    if (g_installed) return g_ok;
    g_installed = 1;
    g_ok = 0;

    uint8_t* ntdll = anti_find_ntdll();
    if (!ntdll) return 0;

    for (int i = 0; i < ANTI_HOOK_COUNT; i++) {
        uint8_t* fn = (uint8_t*)anti_export_by_name(ntdll, HOOKS[i].export_name);
        if (!fn || fn[0] != 0xB8) continue;
        void* thunk = NULL;
        if (anti_hook_patch(fn, (void*)HOOKS[i].handler, &thunk) != 0) continue;
        g_thunk[i] = thunk;
        g_ok++;
    }
    return g_ok;
}

int anti_hook_count(void) {
    return g_ok;
}

int anti_hook_fail_count(void) {
    return ANTI_HOOK_COUNT - g_ok;
}

const char* anti_hook_name(int index) {
    if (index < 0 || index >= ANTI_HOOK_COUNT || !g_thunk[index]) return "";
    return HOOKS[index].short_name;
}
