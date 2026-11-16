/* parent_probe.c - verify PROCESS_CREATE_PROCESS and parent attribute support */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdarg.h>

static DWORD find_explorer(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static void out(const char* fmt, ...) {
    FILE* f = fopen("artifacts\\parent_probe.txt", "a");
    if (!f) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fclose(f);
}

int main(void) {
    DeleteFileA("artifacts\\parent_probe.txt");
    DWORD explorer = find_explorer();
    out("explorer=%lu\n", explorer);

    HWND shell = GetShellWindow();
    DWORD shell_pid = 0;
    if (shell) GetWindowThreadProcessId(shell, &shell_pid);
    out("shell=0x%p shell_pid=%lu\n", (void*)shell, shell_pid);

    HANDLE ph = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, explorer);
    out("OpenProcess(PROCESS_CREATE_PROCESS) = %p err=%lu\n", (void*)ph,
        ph ? 0ul : GetLastError());
    if (!ph) {
        ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, explorer);
        out("OpenProcess(PROCESS_ALL_ACCESS) = %p err=%lu\n", (void*)ph,
            ph ? 0ul : GetLastError());
    }
    if (!ph) return 1;

    SIZE_T size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    LPPROC_THREAD_ATTRIBUTE_LIST attrs =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
    BOOL init = attrs && InitializeProcThreadAttributeList(attrs, 1, 0, &size);
    BOOL upd = init && UpdateProcThreadAttribute(attrs, 0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &ph, sizeof(ph), NULL, NULL);
    out("attrs=%p init=%d update=%d err=%lu\n", (void*)attrs, init, upd,
        GetLastError());

    STARTUPINFOEXW si;
    memset(&si, 0, sizeof(si));
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = attrs;
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    wchar_t cmd[] = L"C:\\Windows\\SysWOW64\\cmd.exe /c exit 0";
    BOOL created = CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, NULL, NULL,
        &si.StartupInfo, &pi);
    out("CreateProcess = %d err=%lu", created, created ? 0ul : GetLastError());
    if (created) {
        out(" pid=%lu", pi.dwProcessId);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    out("\n");

    if (attrs) {
        DeleteProcThreadAttributeList(attrs);
        HeapFree(GetProcessHeap(), 0, attrs);
    }
    CloseHandle(ph);
    return created ? 0 : 1;
}
