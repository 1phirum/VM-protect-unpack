/* inject.c - LoadLibraryW remote injection with bitness guard and verification */
#include "vmpx.h"
#include <tlhelp32.h>

static uintptr_t remote_kernel32(uint32_t pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W me; me.dwSize = sizeof(me);
    uintptr_t base = 0;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, L"kernel32.dll") == 0) { base = (uintptr_t)me.modBaseAddr; break; }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

int module_present(uint32_t pid, const wchar_t* name) {
    uint64_t base = 0;
    return proc_module_base(pid, name, &base, NULL);
}

static int target_bits(uint32_t pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return -1;
    USHORT proc_machine = 0, native = 0;
    int bits = -1;
    if (IsWow64Process2(h, &proc_machine, &native)) {
        bits = (proc_machine == IMAGE_FILE_MACHINE_I386) ? 32 : 64;
    } else {
        BOOL wow = FALSE;
        if (IsWow64Process(h, &wow)) bits = wow ? 32 : ((sizeof(void*) == 8) ? 64 : 32);
    }
    CloseHandle(h);
    return bits;
}

int inject_dll_base(uint32_t pid, const wchar_t* dll, uintptr_t* base_out) {
    if (base_out) *base_out = 0;
    const int our_bits = (sizeof(void*) == 8) ? 64 : 32;
    int bits = target_bits(pid);
    if (bits < 0) { printf("[-] cannot query target bitness\n"); return -1; }
    if (bits != our_bits) {
        printf("[-] bitness mismatch: tool is %d-bit, target is %d-bit\n", our_bits, bits);
        return -1;
    }

    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) { printf("[-] OpenProcess failed: %lu\n", GetLastError()); return -1; }

    uintptr_t lk32 = (uintptr_t)GetModuleHandleW(L"kernel32.dll");
    uintptr_t lload = (uintptr_t)GetProcAddress((HMODULE)lk32, "LoadLibraryW");
    uintptr_t rk32 = remote_kernel32(pid);
    uintptr_t rload = rk32 ? rk32 + (lload - lk32) : lload;
    printf("[*] local k32=%p remote k32=%p LoadLibraryW=%p\n",
           (void*)lk32, (void*)rk32, (void*)rload);

    SIZE_T bytes = (wcslen(dll) + 1) * sizeof(wchar_t);
    void* mem = VirtualAllocEx(proc, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { printf("[-] VirtualAllocEx: %lu\n", GetLastError()); CloseHandle(proc); return -1; }

    SIZE_T wrote = 0;
    if (!WriteProcessMemory(proc, mem, dll, bytes, &wrote)) {
        printf("[-] WriteProcessMemory: %lu\n", GetLastError());
        VirtualFreeEx(proc, mem, 0, MEM_RELEASE); CloseHandle(proc); return -1;
    }

    DWORD tid = 0;
    HANDLE th = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)rload, mem, 0, &tid);
    if (!th) {
        printf("[-] CreateRemoteThread: %lu\n", GetLastError());
        VirtualFreeEx(proc, mem, 0, MEM_RELEASE); CloseHandle(proc); return -1;
    }

    DWORD wait = WaitForSingleObject(th, 20000);
    DWORD code = 0;
    GetExitCodeThread(th, &code);
    printf("[*] thread wait=%lu exit=0x%lX\n", wait, code);
    CloseHandle(th);
    VirtualFreeEx(proc, mem, 0, MEM_RELEASE);
    CloseHandle(proc);

    /* LoadLibraryW returns the module handle through the thread exit code;
     * that is authoritative even when a suspended process cannot be
     * enumerated with toolhelp. */
    int success = (wait == WAIT_OBJECT_0 && code != 0) ? 1 : 0;

    const wchar_t* leaf = wcsrchr(dll, L'\\');
    leaf = leaf ? leaf + 1 : dll;
    Sleep(800);
    int present = module_present(pid, leaf);
    if (present) success = 1;
    printf("[%c] module %ls %s (exit=0x%lX present=%d)\n",
           success ? '+' : '-', leaf, success ? "loaded" : "NOT loaded", code, present);
    if (success && base_out && code) *base_out = (uintptr_t)code;
    return success ? 0 : -1;
}

int inject_dll(uint32_t pid, const wchar_t* dll) {
    return inject_dll_base(pid, dll, NULL);
}
