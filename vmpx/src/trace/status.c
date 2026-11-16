/* status.c - named shared status block Local\VMPX_AGENT_<pid> (v2) */
#include "vmpx.h"
#include "trace/agent.h"
#include "armor/stealth/stealth.h"

static HANDLE g_status_map = NULL;

static void status_name(uint32_t pid, wchar_t* out, size_t cap) {
    swprintf_s(out, cap, L"Local\\VMPX_AGENT_%u", pid);
}

static void add_feature(vmpx_agent_status_t* st, int* n, const char* name) {
    if (*n >= VMPX_AGENT_MAX_STEALTH || !name || !name[0]) return;
    strncpy_s(st->stealth[*n], sizeof(st->stealth[*n]), name, _TRUNCATE);
    (*n)++;
}

void trace_publish_status(uint32_t pid, uint32_t peb, int hidden,
                          int hooks, int fail, uint32_t parent,
                          uint32_t tool, int under_debug) {
    wchar_t name[64];
    status_name(pid, name, 64);

    g_status_map = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0,
                                      sizeof(vmpx_agent_status_t), name);
    if (!g_status_map) return;

    vmpx_agent_status_t* st = (vmpx_agent_status_t*)MapViewOfFile(
        g_status_map, FILE_MAP_WRITE, 0, 0, sizeof(vmpx_agent_status_t));
    if (!st) return;

    memset(st, 0, sizeof(*st));
    st->magic = VMPX_AGENT_STATUS_MAGIC;
    st->version = VMPX_AGENT_STATUS_VERSION;
    st->pid = pid;
    st->hooks_ok = (uint32_t)hooks;
    st->hooks_fail = (uint32_t)fail;
    st->hidden = hidden ? 1u : 0u;
    st->peb = peb;
    st->parent_pid = parent;
    st->tool_pid = tool;
    st->under_debugger = under_debug ? 1u : 0u;
    st->flags = (under_debug ? 1u : 0u) | (hidden ? 2u : 0u);
    st->agent_base = (uint32_t)stealth_agent_base();

    for (int i = 0; i < VMPX_AGENT_MAX_HOOKS; i++) {
        const char* n = stealth_hook_name(i);
        if (n && n[0])
            strncpy_s(st->hooks[i], sizeof(st->hooks[i]), n, _TRUNCATE);
    }

    int features = 0;
    if (peb) add_feature(st, &features, "peb-sanitize");
    if (parent) add_feature(st, &features, "parent-spoof");
    if (tool) add_feature(st, &features, "tool-hide");
    if (stealth_hook_name(ST_HK_QSI)[0]) add_feature(st, &features, "process-hide");
    if (stealth_hook_name(ST_HK_QVM)[0]) add_feature(st, &features, "image-hide");
    if (stealth_hook_name(ST_HK_RVM)[0]) add_feature(st, &features, "read-mask");
    if (stealth_hook_name(ST_HK_PVM)[0]) add_feature(st, &features, "write-guard");
    if (stealth_hook_name(ST_HK_QPC)[0]) add_feature(st, &features, "timing-virtual");
    if (stealth_hook_name(ST_HK_ENUMW)[0]) add_feature(st, &features, "window-filter");
    if (stealth_hook_name(ST_HK_GCT)[0]) add_feature(st, &features, "debug-reg-mask");
    if (stealth_hook_name(ST_HK_SIT)[0]) add_feature(st, &features, "thread-hide");
    if (hidden) add_feature(st, &features, "loader-unlink");

    st->stealth_ok = (uint32_t)features;
    st->stealth_fail = (uint32_t)fail;

    UnmapViewOfFile(st);                       /* mapping stays alive via handle */
}

void trace_set_hidden(uint32_t pid, int hidden) {
    wchar_t name[64];
    status_name(pid, name, 64);

    HANDLE map = OpenFileMappingW(FILE_MAP_WRITE, FALSE, name);
    if (!map) return;
    vmpx_agent_status_t* st = (vmpx_agent_status_t*)MapViewOfFile(
        map, FILE_MAP_WRITE, 0, 0, sizeof(vmpx_agent_status_t));
    if (st) {
        st->hidden = hidden ? 1u : 0u;
        if (hidden) {
            st->flags |= 2u;
            for (int i = 0; i < VMPX_AGENT_MAX_STEALTH; i++) {
                if (st->stealth[i][0] == 0) {
                    strncpy_s(st->stealth[i], sizeof(st->stealth[i]),
                              "loader-unlink", _TRUNCATE);
                    st->stealth_ok++;
                    break;
                }
            }
        } else {
            st->flags &= ~2u;
        }
        UnmapViewOfFile(st);
    }
    CloseHandle(map);
}
