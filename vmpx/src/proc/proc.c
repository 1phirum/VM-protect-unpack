/* proc.c - process lookup, liveness, debug privilege (L0) */
#include "vmpx.h"
#include <tlhelp32.h>

int proc_find_by_name(const wchar_t* exe, uint32_t* pid_out) {
    if (!exe || !pid_out) return 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);
    int found = 0;
    if (Process32FirstW(snap, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, exe) == 0) {
                *pid_out = pe32.th32ProcessID;
                found = 1;
                break;
            }
        } while (Process32NextW(snap, &pe32));
    }
    CloseHandle(snap);
    return found;
}

int proc_alive(uint32_t pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return 0;
    DWORD code = 0;
    GetExitCodeProcess(h, &code);
    CloseHandle(h);
    return code == STILL_ACTIVE;
}

void enable_debug_privilege(void) {
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &tp.Privileges[0].Luid))
        AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(tok);
}
