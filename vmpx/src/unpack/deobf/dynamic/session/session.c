/* session.c - identity, lifecycle, module reloads and region refreshes */
#include "unpack/deobf/dynamic/session/session.h"
#include <bcrypt.h>
#include <psapi.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void set_err(char* err, size_t cap, const char* fmt, ...) {
    if (!err || !cap) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf_s(err, cap, _TRUNCATE, fmt, ap);
    va_end(ap);
}

static int wide_to_utf8(const wchar_t* w, char* out, size_t cap) {
    if (!w || !out || !cap) return -1;
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cap, NULL, NULL);
    return n > 0 ? 0 : -1;
}

static uint64_t fallback_nonce(uint32_t pid, uint64_t create_time) {
    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    uint64_t x = (uint64_t)pid ^ create_time ^ (uint64_t)qpc.QuadPart ^
                 GetTickCount64() ^ (uint64_t)(uintptr_t)&qpc;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return x;
}

static uint64_t make_nonce(uint32_t pid, uint64_t create_time) {
    uint64_t nonce = 0;
    NTSTATUS st = BCryptGenRandom(NULL, (PUCHAR)&nonce, sizeof(nonce),
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st < 0 || !nonce) nonce = fallback_nonce(pid, create_time);
    return nonce;
}

int vmpx_session_make_id(uint32_t pid, uint64_t create_time, uint64_t nonce,
                         char* out, size_t cap) {
    if (!out || !cap) return -1;
    int n = _snprintf_s(out, cap, _TRUNCATE, "%u-%016llX-%016llX", pid,
                        (unsigned long long)create_time,
                        (unsigned long long)nonce);
    return n > 0 ? 0 : -1;
}

const char* vmpx_session_state_name(vmpx_session_state_t state) {
    switch (state) {
    case VMPX_SESSION_CREATED: return "created";
    case VMPX_SESSION_IDENTIFIED: return "identified";
    case VMPX_SESSION_BASELINING: return "baselining";
    case VMPX_SESSION_OBSERVING: return "observing";
    case VMPX_SESSION_FOCUSED_CAPTURE: return "focused-capture";
    case VMPX_SESSION_CHECKPOINTING: return "checkpointing";
    case VMPX_SESSION_RECONSTRUCTING: return "reconstructing";
    case VMPX_SESSION_VALIDATING: return "validating";
    case VMPX_SESSION_COMPLETED: return "completed";
    case VMPX_SESSION_STOPPING: return "stopping";
    case VMPX_SESSION_STOPPED: return "stopped";
    case VMPX_SESSION_FAILED: return "failed";
    default: return "unknown";
    }
}

static int transition_ok(vmpx_session_state_t from, vmpx_session_state_t to) {
    if (from == to) return 1;
    switch (from) {
    case VMPX_SESSION_CREATED:
        return to == VMPX_SESSION_IDENTIFIED || to == VMPX_SESSION_FAILED ||
               to == VMPX_SESSION_STOPPING;
    case VMPX_SESSION_IDENTIFIED:
        return to == VMPX_SESSION_BASELINING || to == VMPX_SESSION_STOPPING ||
               to == VMPX_SESSION_FAILED;
    case VMPX_SESSION_BASELINING:
        return to == VMPX_SESSION_OBSERVING || to == VMPX_SESSION_STOPPING ||
               to == VMPX_SESSION_FAILED;
    case VMPX_SESSION_OBSERVING:
        return to == VMPX_SESSION_FOCUSED_CAPTURE ||
               to == VMPX_SESSION_CHECKPOINTING ||
               to == VMPX_SESSION_RECONSTRUCTING ||
               to == VMPX_SESSION_STOPPING || to == VMPX_SESSION_FAILED;
    case VMPX_SESSION_FOCUSED_CAPTURE:
    case VMPX_SESSION_CHECKPOINTING:
        return to == VMPX_SESSION_OBSERVING ||
               to == VMPX_SESSION_STOPPING || to == VMPX_SESSION_FAILED;
    case VMPX_SESSION_RECONSTRUCTING:
        return to == VMPX_SESSION_VALIDATING ||
               to == VMPX_SESSION_STOPPING || to == VMPX_SESSION_FAILED;
    case VMPX_SESSION_VALIDATING:
        return to == VMPX_SESSION_COMPLETED || to == VMPX_SESSION_STOPPING ||
               to == VMPX_SESSION_FAILED;
    case VMPX_SESSION_COMPLETED:
    case VMPX_SESSION_FAILED:
        return to == VMPX_SESSION_STOPPING;
    case VMPX_SESSION_STOPPING:
        return to == VMPX_SESSION_STOPPED;
    case VMPX_SESSION_STOPPED:
        return 0;
    default:
        return 0;
    }
}

int vmpx_session_enter(vmpx_session_t* s, vmpx_session_state_t next,
                       char* err, size_t err_cap) {
    if (!s) return -1;
    if (!transition_ok(s->state, next)) {
        set_err(err, err_cap, "session: invalid transition %s -> %s",
                vmpx_session_state_name(s->state),
                vmpx_session_state_name(next));
        return -1;
    }
    s->state = next;
    return 0;
}

static int module_path(HANDLE proc, HMODULE mod, char* out, size_t cap) {
    wchar_t wpath[VMPX_SESSION_PATH_CAP];
    DWORD n = GetModuleFileNameExW(proc, mod, wpath,
                                   (DWORD)(sizeof(wpath) / sizeof(wpath[0])));
    if (!n || n >= sizeof(wpath) / sizeof(wpath[0])) return -1;
    return wide_to_utf8(wpath, out, cap);
}

static void module_basename(const char* path, char* name, size_t cap) {
    if (!cap) return;
    const char* base = path;
    for (const char* p = path; p && *p; p++) {
        if (*p == '\\' || *p == '/') base = p + 1;
    }
    _snprintf_s(name, cap, _TRUNCATE, "%s", base);
}

static int find_module_in(const vmpx_session_module_t* mods, uint32_t count,
                          const char* path, uint64_t base) {
    for (uint32_t i = 0; i < count; i++) {
        if (mods[i].path[0] && path[0] &&
            _stricmp(mods[i].path, path) == 0)
            return (int)i;
        if (!mods[i].path[0] && mods[i].base == base) return (int)i;
    }
    return -1;
}

int vmpx_session_refresh_modules(vmpx_session_t* s) {
    if (!s || !s->proc || !s->scratch) return -1;
    HMODULE mods[VMPX_SESSION_MAX_MODULES];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(s->proc, mods, sizeof(mods), &needed,
                              LIST_MODULES_ALL))
        return -1;
    if (needed > sizeof(mods)) return -1;
    uint32_t n = needed / sizeof(HMODULE);
    uint32_t count = s->module_count;
    uint32_t generation = s->next_module_generation;

    memcpy(s->scratch, s->modules, count * sizeof(*s->scratch));
    for (uint32_t i = 0; i < count; i++) s->scratch[i].seen = 0;

    for (uint32_t i = 0; i < n; i++) {
        char path[VMPX_SESSION_PATH_CAP] = { 0 };
        char name[64] = { 0 };
        MODULEINFO mi;
        memset(&mi, 0, sizeof(mi));
        if (!GetModuleInformation(s->proc, mods[i], &mi, sizeof(mi)))
            return -1;
        int have_path = module_path(s->proc, mods[i], path, sizeof(path)) == 0;
        if (have_path) module_basename(path, name, sizeof(name));
        else _snprintf_s(name, sizeof(name), _TRUNCATE, "<unknown>");

        uint64_t base = (uint64_t)(uintptr_t)mi.lpBaseOfDll;
        int idx = find_module_in(s->scratch, count, path, base);
        if (idx < 0) {
            if (count >= VMPX_SESSION_MAX_MODULES) return -1;
            idx = (int)count++;
            memset(&s->scratch[idx], 0, sizeof(s->scratch[idx]));
            s->scratch[idx].generation = ++generation;
        } else if (!s->scratch[idx].present ||
                   s->scratch[idx].base != base ||
                   s->scratch[idx].size != mi.SizeOfImage) {
            s->scratch[idx].generation = ++generation;
        }
        vmpx_session_module_t* m = &s->scratch[idx];
        m->base = base;
        m->size = mi.SizeOfImage;
        m->present = 1;
        m->seen = 1;
        _snprintf_s(m->name, sizeof(m->name), _TRUNCATE, "%s", name);
        _snprintf_s(m->path, sizeof(m->path), _TRUNCATE, "%s", path);
    }
    for (uint32_t i = 0; i < count; i++) {
        if (!s->scratch[i].seen) s->scratch[i].present = 0;
    }
    memcpy(s->modules, s->scratch, count * sizeof(*s->modules));
    s->module_count = count;
    s->next_module_generation = generation;
    return 0;
}

int vmpx_session_refresh_regions(vmpx_session_t* s) {
    if (!s || !s->proc) return -1;
    return vmpx_region_map_refresh(&s->regions, s->proc);
}

const vmpx_session_module_t* vmpx_session_module_by_name(
    const vmpx_session_t* s, const char* name) {
    if (!s || !name) return NULL;
    for (uint32_t i = 0; i < s->module_count; i++) {
        if (!s->modules[i].present) continue;
        if (_stricmp(s->modules[i].name, name) == 0 ||
            _stricmp(s->modules[i].path, name) == 0)
            return &s->modules[i];
    }
    return NULL;
}

const vmpx_session_module_t* vmpx_session_module_at(const vmpx_session_t* s,
                                                    uint64_t addr) {
    if (!s) return NULL;
    for (uint32_t i = 0; i < s->module_count; i++) {
        const vmpx_session_module_t* m = &s->modules[i];
        if (!m->present) continue;
        uint64_t end = m->base + m->size;
        if (end >= m->base && addr >= m->base && addr < end) return m;
    }
    return NULL;
}

int vmpx_session_open(uint32_t pid, const char* out_dir, vmpx_session_t* s,
                      char* err, size_t err_cap) {
    if (!s || !pid || !out_dir || !*out_dir) return -1;
    memset(s, 0, sizeof(*s));
    s->state = VMPX_SESSION_CREATED;

    s->proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
                          pid);
    if (!s->proc) {
        s->proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
                                  PROCESS_VM_READ,
                              FALSE, pid);
    }
    if (!s->proc) {
        set_err(err, err_cap, "session: OpenProcess %u failed (%lu)", pid,
                GetLastError());
        return -1;
    }

    FILETIME create, exit, kernel, user;
    if (!GetProcessTimes(s->proc, &create, &exit, &kernel, &user)) {
        set_err(err, err_cap, "session: GetProcessTimes failed (%lu)",
                GetLastError());
        vmpx_session_close(s);
        return -1;
    }
    s->id.pid = pid;
    s->id.create_time = ((uint64_t)create.dwHighDateTime << 32) |
                        create.dwLowDateTime;
    s->id.nonce = make_nonce(pid, s->id.create_time);

    wchar_t wpath[VMPX_SESSION_PATH_CAP];
    DWORD wcap = (DWORD)(sizeof(wpath) / sizeof(wpath[0]));
    if (!QueryFullProcessImageNameW(s->proc, 0, wpath, &wcap)) {
        set_err(err, err_cap, "session: image path unavailable (%lu)",
                GetLastError());
        vmpx_session_close(s);
        return -1;
    }
    if (wide_to_utf8(wpath, s->id.image_path, sizeof(s->id.image_path)) != 0) {
        set_err(err, err_cap, "session: image path conversion failed");
        vmpx_session_close(s);
        return -1;
    }

    HMODULE main_mod = NULL;
    DWORD needed = 0;
    if (!EnumProcessModulesEx(s->proc, &main_mod, sizeof(main_mod), &needed,
                              LIST_MODULES_ALL) ||
        !main_mod) {
        set_err(err, err_cap, "session: main module unavailable (%lu)",
                GetLastError());
        vmpx_session_close(s);
        return -1;
    }
    MODULEINFO mi;
    memset(&mi, 0, sizeof(mi));
    if (!GetModuleInformation(s->proc, main_mod, &mi, sizeof(mi))) {
        set_err(err, err_cap, "session: main module info unavailable (%lu)",
                GetLastError());
        vmpx_session_close(s);
        return -1;
    }
    s->id.image_base = (uint64_t)(uintptr_t)mi.lpBaseOfDll;
    s->id.image_size = mi.SizeOfImage;
    if (vmpx_session_make_id(pid, s->id.create_time, s->id.nonce, s->id.id,
                             sizeof(s->id.id)) != 0) {
        set_err(err, err_cap, "session: identity formatting failed");
        vmpx_session_close(s);
        return -1;
    }

    s->scratch = (vmpx_session_module_t*)calloc(
        VMPX_SESSION_MAX_MODULES, sizeof(*s->scratch));
    if (!s->scratch) {
        set_err(err, err_cap, "session: module scratch allocation failed");
        vmpx_session_close(s);
        return -1;
    }
    if (vmpx_region_map_init(&s->regions, 8192) != 0) {
        set_err(err, err_cap, "session: region map allocation failed");
        vmpx_session_close(s);
        return -1;
    }
    if (vmpx_session_refresh_regions(s) != 0) {
        set_err(err, err_cap, "session: region refresh failed");
        vmpx_session_close(s);
        return -1;
    }
    if (vmpx_session_refresh_modules(s) != 0) {
        set_err(err, err_cap, "session: module enumeration failed");
        vmpx_session_close(s);
        return -1;
    }

    _snprintf_s(s->out_dir, sizeof(s->out_dir), _TRUNCATE, "%s", out_dir);
    if (vmpx_session_enter(s, VMPX_SESSION_IDENTIFIED, err, err_cap) != 0) {
        vmpx_session_close(s);
        return -1;
    }
    return 0;
}

void vmpx_session_close(vmpx_session_t* s) {
    if (!s) return;
    free(s->scratch);
    s->scratch = NULL;
    vmpx_region_map_close(&s->regions);
    if (s->proc) CloseHandle(s->proc);
    s->proc = NULL;
}
