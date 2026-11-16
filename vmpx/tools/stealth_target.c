/* stealth_target.c - behavior probe for the in-process stealth layer.
 *
 * Phase 1 records the agent DLL base and the address of a dummy vmpx-named
 * process from the process list. Phase 2 runs after injection and asks the
 * same questions through the hooked APIs.
 */
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

typedef LONG (NTAPI* qip_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI* qsi_t)(ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI* rvm_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef LONG (NTAPI* wvm_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

static FILE* g_out;
static void line(const char* fmt, ...) {
    if (!g_out) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_out, fmt, ap);
    va_end(ap);
    fputc('\n', g_out);
    fflush(g_out);
}

static int process_list_has(const char* leaf) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    qsi_t qsi = (qsi_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!qsi) return -1;

    DWORD cap = 2u * 1024u * 1024u;
    BYTE* buf = (BYTE*)malloc(cap);
    if (!buf) return -1;
    ULONG ret = 0;
    LONG st = qsi(5, buf, cap, &ret);
    if (st < 0) { free(buf); return -1; }

    int found = 0;
    BYTE* p = buf;
    for (;;) {
        ULONG next = *(ULONG*)(p + 0x00);
        USHORT len = *(USHORT*)(p + 0x38);
        WCHAR* name = *(WCHAR**)(p + 0x3C);
        if (name && len) {
            char ansi[128];
            int n = WideCharToMultiByte(CP_ACP, 0, name, len / 2, ansi,
                                        sizeof(ansi) - 1, NULL, NULL);
            if (n > 0) {
                ansi[n] = 0;
                const char* b = strrchr(ansi, '\\');
                b = b ? b + 1 : ansi;
                if (_stricmp(b, leaf) == 0) { found = 1; break; }
            }
        }
        if (!next) break;
        p += next;
    }
    free(buf);
    return found;
}

int main(void) {
    g_out = fopen("artifacts\\stealth_target.txt", "w");
    if (!g_out) return 1;

    HMODULE agent = GetModuleHandleW(L"vmpxagent.dll");
    line("phase1 agent=%p", (void*)agent);
    line("phase1 vmpx-process-present=%d", process_list_has("vmpx.exe"));
    line("phase1 is-debugger=%d", IsDebuggerPresent());

    Sleep(3000);

    if (!agent) {
        wchar_t name[64];
        swprintf_s(name, 64, L"Local\\VMPX_AGENT_%u", GetCurrentProcessId());
        HANDLE map = OpenFileMappingW(FILE_MAP_READ, FALSE, name);
        if (map) {
            const unsigned char* view = (const unsigned char*)MapViewOfFile(
                map, FILE_MAP_READ, 0, 0, 64);
            if (view) {
                uint32_t base = *(const uint32_t*)(view + 52);
                if (base) agent = (HMODULE)(uintptr_t)base;
                UnmapViewOfFile(view);
            }
            CloseHandle(map);
        }
    }
    line("phase2 agent=%p", (void*)agent);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    qip_t qip = (qip_t)GetProcAddress(ntdll, "NtQueryInformationProcess");
    rvm_t rvm = (rvm_t)GetProcAddress(ntdll, "NtReadVirtualMemory");
    wvm_t wvm = (wvm_t)GetProcAddress(ntdll, "NtWriteVirtualMemory");

    BOOL remote = TRUE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    line("phase2 is-debugger=%d remote=%d hidden-vmpx=%d",
         IsDebuggerPresent(), remote, process_list_has("vmpx.exe"));

    ULONG port = 0xdead, flags = 0;
    LONG st_port = qip ? qip(GetCurrentProcess(), 7, &port, sizeof(port), NULL) : -1;
    LONG st_flags = qip ? qip(GetCurrentProcess(), 0x1F, &flags, sizeof(flags), NULL) : -1;
    line("phase2 debug-port st=0x%08X port=%lu debug-flags st=0x%08X flags=%lu",
         (unsigned)st_port, port, (unsigned)st_flags, flags);

    if (agent && rvm) {
        unsigned char buf[16] = { 0 };
        SIZE_T got = 0;
        LONG st = rvm(GetCurrentProcess(), agent, buf, sizeof(buf), &got);
        line("phase2 read-agent st=0x%08X got=%lu bytes=%02X %02X %02X %02X",
             (unsigned)st, (unsigned long)got, buf[0], buf[1], buf[2], buf[3]);
    }

    MEMORY_BASIC_INFORMATION mbi;
    memset(&mbi, 0, sizeof(mbi));
    SIZE_T q = VirtualQuery(agent, &mbi, sizeof(mbi));
    line("phase2 vquery-agent n=%lu state=0x%lX protect=0x%lX base=%p",
         (unsigned long)q, mbi.State, mbi.Protect, mbi.BaseAddress);

    if (agent && wvm) {
        unsigned char patch[4] = { 0x90, 0x90, 0x90, 0x90 };
        SIZE_T wrote = 0;
        LONG st = wvm(GetCurrentProcess(), agent, patch, sizeof(patch), &wrote);
        unsigned char first[4] = { 0 };
        SIZE_T got = 0;
        if (rvm) rvm(GetCurrentProcess(), agent, first, sizeof(first), &got);
        line("phase2 write-agent st=0x%08X wrote=%lu first=%02X %02X %02X %02X",
             (unsigned)st, (unsigned long)wrote, first[0], first[1], first[2], first[3]);
    }

    line("phase2 find-windbg=%p", FindWindowW(L"WinDbgFrameClass", NULL));
    line("phase2 tick=%lu", GetTickCount());
    line("done");
    fclose(g_out);
    return 0;
}
