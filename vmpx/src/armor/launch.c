/* launch.c - suspended launch, agent injection, application-window gate (L1) */
#include "vmpx.h"
#include "armor/elev.h"
#include "armor/winwait.h"
#include "armor/parent.h"

static int agent_path(wchar_t* out, size_t cap) {
    if (!GetModuleFileNameW(NULL, out, (DWORD)cap)) return -1;
    wchar_t* slash = wcsrchr(out, L'\\');
    if (!slash) return -1;
    slash[1] = 0;
    if (wcslen(out) + wcslen(L"vmpxagent.dll") + 1 >= cap) return -1;
    wcscat_s(out, cap, L"vmpxagent.dll");
    return 0;
}

int launch_armored_ex(const wchar_t* exe, int armor, int wait_ms,
                      const wchar_t* window_class) {
    if (!exe) return -1;
    if (wait_ms <= 0) wait_ms = 180000;
    if (!armor_is_elevated()) {
        if (wcsstr(GetCommandLineW(), L"--elevated")) {
            printf("[-] still not elevated after relaunch\n");
            return -1;
        }
        if (armor_relaunch_elevated() != 0) return -1;
        printf("[*] elevated instance started via UAC\n");
        return 0;
    }

    wchar_t agent[MAX_PATH] = { 0 };
    if (agent_path(agent, MAX_PATH) != 0) {
        printf("[-] cannot resolve vmpxagent.dll location\n");
        return -1;
    }

    wchar_t dir[MAX_PATH] = { 0 };
    wcsncpy_s(dir, MAX_PATH, exe, _TRUNCATE);
    wchar_t* last = wcsrchr(dir, L'\\');
    if (last) *last = 0;

    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    uint32_t parent_pid = 0;
    if (armor_spawn_parented(exe, dir[0] ? dir : NULL, &pi, &parent_pid) != 0) {
        printf("[-] CreateProcess failed: %lu\n", GetLastError());
        return -1;
    }
    printf("[*] created pid=%lu suspended parent=%lu\n",
           pi.dwProcessId, parent_pid);
    if (parent_pid)
        printf("[*] parent spoof: explorer pid=%lu\n", parent_pid);
    else
        printf("[!] parent spoof unavailable, launcher remains parent\n");

    armor_hint_t hint;
    memset(&hint, 0, sizeof(hint));
    if (armor) {
        if (armor_hint_open(pi.dwProcessId, parent_pid, GetCurrentProcessId(),
                            &hint) != 0)
            printf("[!] parent hint mapping failed\n");
        if (inject_dll(pi.dwProcessId, agent) != 0)
            printf("[-] agent injection failed, resuming unarmored\n");
    } else {
        printf("[*] armor disabled\n");
    }
    armor_hint_close(&hint);

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    printf("[*] resumed pid=%lu\n", pi.dwProcessId);

    HWND hwnd = NULL;
    wchar_t title[256] = { 0 };
    wchar_t cls[128] = { 0 };
    int count = 0;
    int up = winwait_for_class(pi.dwProcessId, window_class, wait_ms,
                               &hwnd, title, 256, &count);
    if (up) {
        if (hwnd) GetClassNameW(hwnd, cls, 128);
        printf("[+] window up: hwnd=0x%llX class=\"%ls\" title=\"%ls\" "
               "top_level=%d\n",
               (unsigned long long)(uintptr_t)hwnd, cls, title, count);
        CloseHandle(pi.hProcess);
        return 0;
    }

    printf("[!] no application window within %d ms, process alive=%d\n",
           wait_ms, proc_alive(pi.dwProcessId));
    windump_for_pid(pi.dwProcessId);
    CloseHandle(pi.hProcess);
    return -1;
}

int launch_armored(const wchar_t* exe, int armor, int wait_ms) {
    return launch_armored_ex(exe, armor, wait_ms, NULL);
}
