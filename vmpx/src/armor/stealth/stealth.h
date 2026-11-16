/* armor/stealth/stealth.h - advanced anti-debug neutralization (L1)
 *
 * This layer replaces the baseline anti-debug hook set. It is installed from
 * the agent's DllMain before the first TLS callback, so every hook is live
 * before the packer's startup checks run. Nothing here writes to stdout or
 * creates a window: the target must observe a process that looks unmodified.
 */
#pragma once

#include <windows.h>
#include <winternl.h>
#include <stdint.h>

#define STEALTH_MAX_HOOKS 32
#define STEALTH_MAX_NAME  32

/* Hook slots. Order is the installation order except PVM/WVM, which are
 * installed last so the hook engine can still patch ntdll while they are
 * being created. */
enum {
    ST_HK_QIP = 0,      /* NtQueryInformationProcess */
    ST_HK_QSI,          /* NtQuerySystemInformation */
    ST_HK_QIT,          /* NtQueryInformationThread */
    ST_HK_SIT,          /* NtSetInformationThread */
    ST_HK_GCT,          /* NtGetContextThread */
    ST_HK_SCT,          /* NtSetContextThread */
    ST_HK_QVM,          /* NtQueryVirtualMemory */
    ST_HK_QPC,          /* NtQueryPerformanceCounter */
    ST_HK_QST,          /* NtQuerySystemTime */
    ST_HK_CTX,          /* NtCreateThreadEx */
    ST_HK_SDC,          /* NtSystemDebugControl */
    ST_HK_ISDBG,        /* kernel32!IsDebuggerPresent */
    ST_HK_CRDBG,        /* kernel32!CheckRemoteDebuggerPresent */
    ST_HK_ODSW,         /* kernel32!OutputDebugStringW */
    ST_HK_ODSA,         /* kernel32!OutputDebugStringA */
    ST_HK_TICK,         /* kernel32!GetTickCount */
    ST_HK_TICK64,       /* kernel32!GetTickCount64 */
    ST_HK_GSTAFT,       /* kernel32!GetSystemTimeAsFileTime */
    ST_HK_GSTPFT,       /* kernel32!GetSystemTimePreciseAsFileTime */
    ST_HK_ENUMW,        /* user32!EnumWindows */
    ST_HK_FINDW,        /* user32!FindWindowW */
    ST_HK_FINDEXW,      /* user32!FindWindowExW */
    ST_HK_FINDA,        /* user32!FindWindowA */
    ST_HK_FINDEXA,      /* user32!FindWindowExA */
    ST_HK_RVM,          /* NtReadVirtualMemory */
    ST_HK_PVM,          /* NtProtectVirtualMemory - last */
    ST_HK_WVM,          /* NtWriteVirtualMemory - last */
    ST_HK_COUNT
};

typedef struct {
    uint8_t* target;        /* resolved function entry */
    uint8_t* trampoline;    /* executable copy + jump back */
    uint8_t  original[16];
    uint32_t copy_len;      /* whole instructions copied */
    uint32_t patch_len;     /* bytes overwritten at target */
    uint32_t active;
    const char* label;
} stealth_hook_t;

extern stealth_hook_t g_stealth_hooks[ST_HK_COUNT];

/* lifecycle */
void stealth_set_self(HMODULE self);
int  stealth_install(void);
int  stealth_hook_count(void);
int  stealth_hook_fail_count(void);
const char* stealth_hook_name(int index);
int  stealth_hook_install(stealth_hook_t* hook, const wchar_t* module,
                          const char* name, void* handler, const char* label);

/* original-function trampolines */
void* stealth_trampoline(int index);

/* launch identity / timing state */
void     stealth_set_parent(uint32_t parent_pid);
uint32_t stealth_parent(void);
void     stealth_set_tool(uint32_t tool_pid);
uint32_t stealth_tool_pid(void);
int      stealth_under_debugger(void);

/* memory hiding: agent image + trampolines + hook pages */
int      stealth_hidden_region(uint64_t addr, uint64_t len);
int      stealth_is_hook_range(uint64_t addr, uint64_t len);
uint64_t stealth_agent_base(void);
uint64_t stealth_agent_size(void);

/* shared by handlers */
int  stealth_hidden_pid(uint32_t pid);
void stealth_note_hidden_pid(uint32_t pid);
int  stealth_window_is_debugger(const wchar_t* cls, const wchar_t* title);
int  stealth_init_identity(void);

/* ntdll helpers */
uint8_t* stealth_module_base(const wchar_t* name);
void*    stealth_export(const wchar_t* module, const char* name);
