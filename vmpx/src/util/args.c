/* args.c - CLI parsing and target resolution shared by all commands (L0) */
#include "vmpx.h"
#include "util/str.h"

const char* arg_get(int argc, char** argv, const char* key) {
    for (int i = 2; i + 1 < argc; i++)
        if (strcmp(argv[i], key) == 0) return argv[i + 1];
    return NULL;
}

int arg_has(int argc, char** argv, const char* key) {
    for (int i = 2; i < argc; i++)
        if (strcmp(argv[i], key) == 0) return 1;
    return 0;
}

uint64_t arg_num(int argc, char** argv, const char* key, uint64_t dflt) {
    const char* s = arg_get(argc, argv, key);
    return s ? (uint64_t)_strtoui64(s, NULL, 0) : dflt;
}

static int widen(const char* src, wchar_t* out, size_t cap) {
    return str_widen(src, out, cap);
}

/* Resolve the target executable without any hard-coded path:
 *   1. explicit override (--exe or token after --)
 *   2. VMPX_TARGET environment variable
 *   3. the single .exe in the current directory (vmpx.exe itself excluded)
 */
int resolve_target(const char* override_path, wchar_t* out, size_t cap) {
    if (override_path && *override_path) return widen(override_path, out, cap);

    const wchar_t* env = _wgetenv(L"VMPX_TARGET");
    if (env && *env) {
        wcsncpy_s(out, cap, env, _TRUNCATE);
        return 0;
    }

    wchar_t self[MAX_PATH] = { 0 };
    GetModuleFileNameW(NULL, self, MAX_PATH);

    wchar_t cwd[MAX_PATH] = { 0 };
    if (!GetCurrentDirectoryW(MAX_PATH, cwd)) return -1;

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(L"*.exe", &fd);
    if (h == INVALID_HANDLE_VALUE) {
        printf("[-] no .exe in %ls; pass --exe <path> or set VMPX_TARGET\n", cwd);
        return -1;
    }

    wchar_t found[MAX_PATH * 2] = { 0 };
    int count = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        wchar_t full[MAX_PATH * 2];
        _snwprintf_s(full, MAX_PATH * 2, _TRUNCATE, L"%ls\\%ls", cwd, fd.cFileName);
        if (_wcsicmp(full, self) == 0) continue;
        if (count == 0) wcsncpy_s(found, MAX_PATH * 2, full, _TRUNCATE);
        else printf("[*] candidate: %ls\n", full);
        count++;
    } while (FindNextFileW(h, &fd));
    FindClose(h);

    if (count == 1) {
        wcsncpy_s(out, cap, found, _TRUNCATE);
        return 0;
    }
    if (count == 0) printf("[-] no candidate .exe in %ls; pass --exe <path>\n", cwd);
    else            printf("[-] %d candidates in %ls; pass --exe <path>\n", count, cwd);
    return -1;
}

int resolve_pid(int argc, char** argv, uint32_t* pid_out) {
    const char* s = arg_get(argc, argv, "--pid");
    if (s) {
        *pid_out = (uint32_t)_strtoui64(s, NULL, 0);
        return *pid_out ? 0 : -1;
    }

    wchar_t wname[260] = { 0 };
    const char* name = arg_get(argc, argv, "--name");
    if (name) {
        if (widen(name, wname, 260) != 0) return -1;
    } else {
        wchar_t target[MAX_PATH * 2] = { 0 };
        if (resolve_target(arg_get(argc, argv, "--exe"), target, MAX_PATH * 2) != 0)
            return -1;
        const wchar_t* base = wcsrchr(target, L'\\');
        wcsncpy_s(wname, 260, base ? base + 1 : target, _TRUNCATE);
    }

    if (!proc_find_by_name(wname, pid_out)) {
        printf("[-] process not running: %ls\n", wname);
        return -1;
    }
    return 0;
}

int parse_hex_bytes(const char* s, uint8_t* out, size_t cap, size_t* outlen) {
    size_t n = 0;
    while (*s && n < cap) {
        while (*s == ' ' || *s == ',' || *s == '\t') s++;
        if (!*s) break;
        char* end = NULL;
        unsigned long v = strtoul(s, &end, 16);
        if (end == s) return -1;
        out[n++] = (uint8_t)v;
        s = end;
    }
    *outlen = n;
    return n ? 0 : -1;
}
