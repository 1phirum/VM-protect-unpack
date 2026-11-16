/* cmd_agentstatus.c - read the live agent status block for a process */
#include "vmpx.h"

int cmd_agentstatus(int argc, char** argv) {
    uint32_t pid = 0;
    if (resolve_pid(argc, argv, &pid) != 0) return 1;

    wchar_t name[64];
    swprintf_s(name, 64, L"Local\\VMPX_AGENT_%u", pid);

    HANDLE map = OpenFileMappingW(FILE_MAP_READ, FALSE, name);
    if (!map) {
        printf("[-] no agent status for pid %u (agent not injected or already exited)\n", pid);
        return 1;
    }

    const vmpx_agent_status_t* st = (const vmpx_agent_status_t*)MapViewOfFile(
        map, FILE_MAP_READ, 0, 0, sizeof(vmpx_agent_status_t));
    if (!st) {
        printf("[-] map view failed: %lu\n", GetLastError());
        CloseHandle(map);
        return 1;
    }

    if (st->magic != VMPX_AGENT_STATUS_MAGIC || st->version != VMPX_AGENT_STATUS_VERSION) {
        printf("[-] bad status block magic=0x%08X version=%u\n", st->magic, st->version);
        UnmapViewOfFile(st);
        CloseHandle(map);
        return 1;
    }

    printf("attached pid=%u agent=0x%08X peb=0x%08X hooks=%u fail=%u stealth=%u/%u hidden=%u parent=%u tool=%u dbg=%u\n",
           st->pid, st->agent_base, st->peb, st->hooks_ok, st->hooks_fail,
           st->stealth_ok, st->stealth_fail, st->hidden,
           st->parent_pid, st->tool_pid, st->under_debugger);
    for (int i = 0; i < VMPX_AGENT_MAX_HOOKS; i++) {
        if (st->hooks[i][0]) printf("  hook %s\n", st->hooks[i]);
    }
    for (int i = 0; i < VMPX_AGENT_MAX_STEALTH; i++) {
        if (st->stealth[i][0]) printf("  stealth %s\n", st->stealth[i]);
    }
    printf("STATUS agentstatus ok pid=%u hooks=%u fail=%u stealth=%u hidden=%u parent=%u\n",
           st->pid, st->hooks_ok, st->hooks_fail, st->stealth_ok, st->hidden,
           st->parent_pid);

    uint32_t hooks = st->hooks_ok;             /* read before the view goes away */
    UnmapViewOfFile(st);
    CloseHandle(map);
    return hooks ? 0 : 1;
}
