/* state.c - shared stealth state, identity probing, hidden-region registry */
#include "armor/stealth/stealth.h"
#include "unpack/deobf/dynamic/control/control.h"
#include <wchar.h>

stealth_hook_t g_stealth_hooks[ST_HK_COUNT];

static uint64_t g_agent_base;
static uint64_t g_agent_size;
static uint32_t g_parent_pid;
static uint32_t g_tool_pid;
static int      g_under_debugger;
static uint32_t g_hidden_pids[16];
static int      g_hidden_pid_count;

typedef LONG (NTAPI* qip_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef struct {
    ULONG  magic;
    ULONG  parent;
    ULONG  tool;
} parent_hint_t;

#define PARENT_HINT_MAGIC 0x48505856u   /* "VXPH" */

void stealth_set_self(HMODULE self) {
    if (!self) return;
    uint8_t* base = (uint8_t*)self;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    g_agent_base = (uint64_t)(uintptr_t)base;
    g_agent_size = nt->OptionalHeader.SizeOfImage;
}

uint64_t stealth_agent_base(void) { return g_agent_base; }
uint64_t stealth_agent_size(void) { return g_agent_size; }

void stealth_set_parent(uint32_t pid) { g_parent_pid = pid; }
uint32_t stealth_parent(void) { return g_parent_pid; }
void stealth_set_tool(uint32_t pid) { g_tool_pid = pid; }
uint32_t stealth_tool_pid(void) { return g_tool_pid; }
int stealth_under_debugger(void) { return g_under_debugger; }

static uint32_t query_parent_pid(void) {
    static const ULONG ProcessBasicInformation = 0;
    typedef struct {
        LONG     ExitStatus;
        uint32_t PebBaseAddress;
        uint32_t AffinityMask;
        LONG     BasePriority;
        uint32_t UniqueProcessId;
        uint32_t InheritedFromUniqueProcessId;
    } pbi_t;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;
    qip_fn fn = (qip_fn)(void*)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!fn) return 0;

    pbi_t pbi;
    memset(&pbi, 0, sizeof(pbi));
    ULONG ret = 0;
    LONG st = fn(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &ret);
    return st == 0 ? pbi.InheritedFromUniqueProcessId : 0;
}

static int read_parent_hint(uint32_t* parent, uint32_t* tool) {
    wchar_t name[64];
    swprintf_s(name, 64, L"Local\\VMPX_PARENT_%u", GetCurrentProcessId());
    HANDLE map = OpenFileMappingW(FILE_MAP_READ, FALSE, name);
    if (!map) return 0;

    parent_hint_t* p = (parent_hint_t*)MapViewOfFile(map, FILE_MAP_READ, 0, 0,
                                                     sizeof(parent_hint_t));
    int ok = 0;
    if (p && p->magic == PARENT_HINT_MAGIC) {
        if (parent && p->parent) *parent = p->parent;
        if (tool && p->tool) *tool = p->tool;
        ok = 1;
    }
    if (p) UnmapViewOfFile(p);
    CloseHandle(map);
    return ok;
}

int stealth_init_identity(void) {
    if (g_agent_base && g_parent_pid && g_tool_pid) return 0;

    uint32_t hint = 0, tool = 0;
    if (read_parent_hint(&hint, &tool)) {
        if (hint) g_parent_pid = hint;
        if (tool) {
            g_tool_pid = tool;
            stealth_note_hidden_pid(tool);
        }
    }
    if (!g_parent_pid) {
        hint = query_parent_pid();
        if (hint) g_parent_pid = hint;
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        qip_fn fn = (qip_fn)(void*)GetProcAddress(ntdll, "NtQueryInformationProcess");
        if (fn) {
            ULONG port = 0;
            LONG st = fn(GetCurrentProcess(), 7, &port, sizeof(port), NULL);
            if (st == 0 && port) g_under_debugger = 1;
        }
    }
    return 0;
}

int stealth_hidden_pid(uint32_t pid) {
    for (int i = 0; i < g_hidden_pid_count; i++)
        if (g_hidden_pids[i] == pid) return 1;
    return 0;
}

void stealth_note_hidden_pid(uint32_t pid) {
    if (!pid || stealth_hidden_pid(pid)) return;
    if (g_hidden_pid_count >= (int)(sizeof(g_hidden_pids) / sizeof(g_hidden_pids[0])))
        return;
    g_hidden_pids[g_hidden_pid_count++] = pid;
}

int stealth_hidden_region(uint64_t addr, uint64_t len) {
    if (!addr || !len) return 0;
    uint64_t end = addr + len;
    if (end < addr) return 0;

    if (g_agent_base && g_agent_size) {
        uint64_t aend = g_agent_base + g_agent_size;
        if (addr < aend && end > g_agent_base) return 1;
    }
    if (dyn_control_hidden(addr, len)) return 1;
    for (int i = 0; i < ST_HK_COUNT; i++) {
        uint8_t* tr = g_stealth_hooks[i].trampoline;
        if (!tr) continue;
        uint64_t tb = (uint64_t)(uintptr_t)tr;
        if (addr < tb + 0x1000 && end > tb) return 1;
    }
    return 0;
}

int stealth_is_hook_range(uint64_t addr, uint64_t len) {
    if (!addr || !len) return 0;
    uint64_t end = addr + len;
    if (end < addr) return 0;

    if (stealth_hidden_region(addr, len)) return 1;
    for (int i = 0; i < ST_HK_COUNT; i++) {
        uint8_t* t = g_stealth_hooks[i].target;
        if (!t) continue;
        uint64_t tb = (uint64_t)(uintptr_t)t;
        if (addr < tb + 16 && end > tb) return 1;
    }
    return 0;
}
