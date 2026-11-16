/* mem.c - raw cross-process read/write with protection restore (L0) */
#include "vmpx.h"

int proc_read(uint32_t pid, uint64_t addr, void* buf, size_t len) {
    if (!buf || !len) return -1;
    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return -1;
    SIZE_T got = 0;
    BOOL ok = ReadProcessMemory(h, (LPCVOID)(uintptr_t)addr, buf, len, &got);
    CloseHandle(h);
    return (ok && got == len) ? 0 : -1;
}

int proc_mem_snapshot(uint32_t pid, uint64_t lo, uint64_t hi,
                      vmpx_mem_region_t** out, size_t* count) {
    if (!out || !count) return -1;
    *out = NULL;
    *count = 0;

    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!proc) return -1;

    if (!hi) hi = 0x80000000ull;
    if (lo >= hi) { CloseHandle(proc); return -1; }

    size_t cap = 512, n = 0;
    vmpx_mem_region_t* list = (vmpx_mem_region_t*)calloc(cap, sizeof(*list));
    if (!list) { CloseHandle(proc); return -1; }

    uint64_t addr = lo;
    while (addr < hi) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T got = VirtualQueryEx(proc, (LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi));
        if (!got || !mbi.RegionSize) break;

        uint64_t rbase = (uint64_t)(uintptr_t)mbi.BaseAddress;
        uint64_t rsize = (uint64_t)mbi.RegionSize;
        if (rbase < addr) {
            rsize -= addr - rbase;
            rbase = addr;
        }
        if (!rsize) break;

        if (n == cap) {
            size_t ncap = cap * 2;
            vmpx_mem_region_t* grown =
                (vmpx_mem_region_t*)realloc(list, ncap * sizeof(*list));
            if (!grown) {
                free(list);
                CloseHandle(proc);
                return -1;
            }
            list = grown;
            cap = ncap;
        }
        list[n].base = rbase;
        list[n].size = rsize;
        list[n].state = (uint32_t)mbi.State;
        list[n].protect = (uint32_t)mbi.Protect;
        list[n].type = (uint32_t)mbi.Type;
        n++;

        uint64_t next = rbase + rsize;
        if (next <= addr) break;
        addr = next;
    }

    CloseHandle(proc);
    *out = list;
    *count = n;
    return n ? 0 : -1;
}

void proc_mem_free(vmpx_mem_region_t* regions) {
    free(regions);
}

int proc_write(uint32_t pid, uint64_t addr, const void* buf, size_t len) {
    if (!buf || !len) return -1;
    HANDLE h = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
                           PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return -1;

    DWORD old = 0;
    if (!VirtualProtectEx(h, (LPVOID)(uintptr_t)addr, len, PAGE_EXECUTE_READWRITE, &old)) {
        CloseHandle(h);
        return -1;
    }
    SIZE_T wrote = 0;
    BOOL ok = WriteProcessMemory(h, (LPVOID)(uintptr_t)addr, buf, len, &wrote);
    DWORD tmp = 0;
    VirtualProtectEx(h, (LPVOID)(uintptr_t)addr, len, old, &tmp);
    if (ok) FlushInstructionCache(h, (LPCVOID)(uintptr_t)addr, len);
    CloseHandle(h);
    return (ok && wrote == len) ? 0 : -1;
}
