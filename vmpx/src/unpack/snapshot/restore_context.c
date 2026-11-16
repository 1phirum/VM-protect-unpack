/* restore_context.c - entry gate and captured thread state application */
#include "unpack/snapshot/restore_int.h"

/* Minimal THREAD_BASIC_INFORMATION for NtQueryInformationThread(0). */
typedef struct {
    LONG  ExitStatus;
    PVOID TebBaseAddress;
    PVOID UniqueProcess;
    PVOID UniqueThread;
    ULONG AffinityMask;
    LONG  Priority;
    LONG  BasePriority;
} thread_basic_t;

typedef LONG (WINAPI* nt_qit_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

/* Write an EB FE self-loop at the image entry so the loader completes, then
 * parks the primary thread where the parent can swap in the captured OEP
 * context. The page may already be a mapped image page or may be free. */
int restore_write_entry_gate(HANDLE proc, uint32_t va) {
    uint8_t code[2] = { 0xEB, 0xFE };
    uint32_t page = va & ~0xFFFu;
    DWORD old = 0;
    int ok = 0;
    if (VirtualProtectEx(proc, (LPVOID)(uintptr_t)page, 0x1000,
                         PAGE_EXECUTE_READWRITE, &old)) {
        SIZE_T wrote = 0;
        ok = WriteProcessMemory(proc, (LPVOID)(uintptr_t)va, code, 2, &wrote) &&
             wrote == 2;
        DWORD tmp = 0;
        VirtualProtectEx(proc, (LPVOID)(uintptr_t)page, 0x1000,
                         old ? old : PAGE_EXECUTE_READ, &tmp);
    } else {
        void* p = VirtualAllocEx(proc, (LPVOID)(uintptr_t)page, 0x1000,
                                 MEM_COMMIT | MEM_RESERVE,
                                 PAGE_EXECUTE_READWRITE);
        if (p) {
            SIZE_T wrote = 0;
            ok = WriteProcessMemory(proc, (LPVOID)(uintptr_t)va, code, 2,
                                    &wrote) && wrote == 2;
        }
    }
    if (ok) FlushInstructionCache(proc, (LPVOID)(uintptr_t)va, 2);
    return ok ? 0 : -1;
}

/* Returns with the thread still suspended when the gate is reached. */
int restore_wait_entry_gate(HANDLE thread, uint32_t va, int timeout_ms) {
    uint64_t start = GetTickCount64();
    for (;;) {
        if (GetTickCount64() - start > (uint64_t)timeout_ms) return -1;
        DWORD prev = SuspendThread(thread);
        if (prev == (DWORD)-1) return -1;
        CONTEXT c;
        memset(&c, 0, sizeof(c));
        c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        int ok = GetThreadContext(thread, &c) != 0;
        if (ok && c.Eip == va) return 0;   /* leave the thread suspended */
        ResumeThread(thread);
        Sleep(5);
    }
}

int restore_apply_entry_ctx(HANDLE proc, HANDLE thread, const entry_ctx_t* ec,
                            uint32_t stack_base, uint32_t stack_limit,
                            const uint8_t* teb_data, uint32_t orig_teb,
                            uint32_t child_tls_index_va,
                            const uint8_t* tls_block) {
    if (!proc || !thread || !ec) return -1;
    CONTEXT c;
    memset(&c, 0, sizeof(c));
    c.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(thread, &c)) return -1;
    c.Eip = ec->eip;
    c.Esp = ec->esp;
    c.Ebp = ec->ebp;
    c.Eax = ec->eax;
    c.Ebx = ec->ebx;
    c.Ecx = ec->ecx;
    c.Edx = ec->edx;
    c.Esi = ec->esi;
    c.Edi = ec->edi;
    c.EFlags = ec->eflags;
    if (!SetThreadContext(thread, &c)) return -1;

    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    nt_qit_t qit = nt ? (nt_qit_t)GetProcAddress(nt, "NtQueryInformationThread")
                      : NULL;
    if (!qit) {
        printf("[!] run: NtQueryInformationThread unavailable; live TEB not "
               "reused\n");
        return -1;
    }
    thread_basic_t tbi;
    memset(&tbi, 0, sizeof(tbi));
    ULONG ret = 0;
    if (qit(thread, 0, &tbi, sizeof(tbi), &ret) < 0 || !tbi.TebBaseAddress) {
        printf("[!] run: live TEB query failed (ntstatus=0x%08lX)\n",
               (unsigned long)ret);
        return -1;
    }
    int ok = 1;
    uint32_t teb = (uint32_t)(uintptr_t)tbi.TebBaseAddress;
    uint32_t ctls = 0;
    /* The live thread still runs on the loader's TEB, whose TLS array
     * is empty for the captured app. Copy the snapshot TEB from the
     * restore payload, then repair the fields that must describe the
     * live thread. The captured PEB pointer is replaced with the live
     * PEB so heap and module lookups stay valid. */
    if (teb_data) {
        uint8_t page[0x1000];
        memcpy(page, teb_data, sizeof(page));
        uint32_t cpid = 0, ctid = 0, cpeb = 0;
        SIZE_T r = 0;
        if (!ReadProcessMemory(proc, (LPCVOID)(uintptr_t)(teb + 0x20),
                               &cpid, 4, &r) || r != 4)
            ok = 0;
        if (!ReadProcessMemory(proc, (LPCVOID)(uintptr_t)(teb + 0x24),
                               &ctid, 4, &r) || r != 4)
            ok = 0;
        if (!ReadProcessMemory(proc, (LPCVOID)(uintptr_t)(teb + 0x2C),
                               &ctls, 4, &r) || r != 4)
            ok = 0;
        if (!ReadProcessMemory(proc, (LPCVOID)(uintptr_t)(teb + 0x30),
                               &cpeb, 4, &r) || r != 4)
            ok = 0;
        *(uint32_t*)(page + 0x04) = stack_base;
        *(uint32_t*)(page + 0x08) = stack_limit;
        *(uint32_t*)(page + 0x18) = teb;
        if (cpid) *(uint32_t*)(page + 0x20) = cpid;
        if (ctid) *(uint32_t*)(page + 0x24) = ctid;
        if (ctls) *(uint32_t*)(page + 0x2C) = ctls;
        if (cpeb) *(uint32_t*)(page + 0x30) = cpeb;
        DWORD old = 0;
        if (VirtualProtectEx(proc, (LPVOID)(uintptr_t)teb, 0x1000,
                             PAGE_READWRITE, &old)) {
            SIZE_T wrote = 0;
            if (WriteProcessMemory(proc, (LPVOID)(uintptr_t)teb, page,
                                   sizeof(page), &wrote) &&
                wrote == sizeof(page)) {
                printf("[+] run: teb 0x%08lX copied into live TEB "
                       "0x%08lX peb=0x%08lX\n",
                       (unsigned long)orig_teb, (unsigned long)teb,
                       (unsigned long)cpeb);
            } else {
                printf("[!] run: teb 0x%08lX not copied into live TEB "
                       "0x%08lX error=%lu\n",
                       (unsigned long)orig_teb, (unsigned long)teb,
                       (unsigned long)GetLastError());
                ok = 0;
            }
            DWORD tmp = 0;
            VirtualProtectEx(proc, (LPVOID)(uintptr_t)teb, 0x1000,
                             old, &tmp);
        } else {
            printf("[!] run: live TEB 0x%08lX not writable error=%lu\n",
                   (unsigned long)teb, (unsigned long)GetLastError());
            ok = 0;
        }
    }
    if (tls_block &&
        restore_relocate_tls_block(proc, ctls, child_tls_index_va, tls_block) != 0)
        ok = 0;
    /* Best effort by design: the stale exception object is only zeroed when its
     * page is free, and a raise path that never reads it is unaffected. */
    restore_fix_tls_exception(proc, teb, child_tls_index_va);
    SIZE_T w = 0;
    if (!WriteProcessMemory(proc, (LPVOID)(uintptr_t)(teb + 4),
                            &stack_base, 4, &w) || w != 4)
        ok = 0;
    if (!WriteProcessMemory(proc, (LPVOID)(uintptr_t)(teb + 8),
                            &stack_limit, 4, &w) || w != 4)
        ok = 0;
    printf("[%c] run: entry context eip=0x%08lX esp=0x%08lX "
           "live_teb=0x%08lX stack=0x%08lX..0x%08lX\n",
           ok ? '+' : '!', (unsigned long)ec->eip, (unsigned long)ec->esp,
           (unsigned long)teb, (unsigned long)stack_limit,
           (unsigned long)stack_base);
    return ok ? 0 : -1;
}
