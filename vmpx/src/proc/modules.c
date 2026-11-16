/* modules.c - module enumeration, base lookup, main-module resolution (L0) */
#include "vmpx.h"
#include "util/str.h"
#include <tlhelp32.h>

void proc_list_modules(uint32_t pid, const char* filter) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        printf("[-] module snapshot failed: %lu\n", GetLastError());
        return;
    }
    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    int count = 0;
    if (Module32FirstW(snap, &me)) {
        do {
            char name[260];
            str_narrow(me.szModule, name, sizeof(name));
            if (filter && *filter && !str_i_contains(name, filter)) continue;
            printf("%016llX  %08X  %s\n",
                   (unsigned long long)(uintptr_t)me.modBaseAddr, me.modBaseSize, name);
            count++;
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    printf("[+] %d module(s)\n", count);
}

int proc_modules_snapshot(uint32_t pid, proc_mod_t* out, int cap) {
    if (!out || cap <= 0) return 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return -1;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    int n = 0;
    if (Module32FirstW(snap, &me)) {
        do {
            if (n >= cap) break;
            wcsncpy_s(out[n].name, 64, me.szModule, _TRUNCATE);
            out[n].base = (uint64_t)(uintptr_t)me.modBaseAddr;
            out[n].size = me.modBaseSize;
            n++;
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return n;
}

int proc_module_base(uint32_t pid, const wchar_t* name, uint64_t* base, uint32_t* size) {
    if (!name) return 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    int found = 0;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, name) == 0) {
                if (base) *base = (uint64_t)(uintptr_t)me.modBaseAddr;
                if (size) *size = me.modBaseSize;
                found = 1;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

/* Main module = the entry whose basename matches the process image name;
 * falls back to the first module when the image path is unavailable. */
int proc_main_module(uint32_t pid, uint64_t* base, uint32_t* size) {
    wchar_t image[MAX_PATH * 2] = { 0 };
    DWORD len = MAX_PATH * 2;
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hp) {
        QueryFullProcessImageNameW(hp, 0, image, &len);
        CloseHandle(hp);
    }
    const wchar_t* image_name = str_wide_leaf(image);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    int found = 0;
    uint64_t first_base = 0;
    uint32_t first_size = 0;

    if (Module32FirstW(snap, &me)) {
        first_base = (uint64_t)(uintptr_t)me.modBaseAddr;
        first_size = me.modBaseSize;
        do {
            if (image_name[0] && _wcsicmp(me.szModule, image_name) == 0) {
                if (base) *base = (uint64_t)(uintptr_t)me.modBaseAddr;
                if (size) *size = me.modBaseSize;
                found = 1;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);

    if (!found && first_base) {
        if (base) *base = first_base;
        if (size) *size = first_size;
        found = 1;
    }
    return found;
}
