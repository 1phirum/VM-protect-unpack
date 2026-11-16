/* sanity.c - classify the live image mapping before a dump (L2)
 *
 * A dump is representative only when the module's SizeOfImage range is fully
 * committed. Reserved or free pages inside that range mean the unpacker has not
 * materialized a segment yet, and the rebuilt image would carry holes.
 */
#include "vmpx.h"

int image_sanity(uint32_t pid, uint64_t base, uint32_t size) {
    if (!pid || !base || !size) return -1;

    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!proc) {
        printf("[-] sanity: OpenProcess failed: %lu\n", GetLastError());
        return -1;
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uint64_t page = si.dwPageSize ? si.dwPageSize : 0x1000;

    uint64_t end = base + size;
    uint64_t addr = base;
    uint64_t committed = 0, reserved = 0, freed = 0, guard = 0;
    int regions = 0;

    while (addr < end) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T got = VirtualQueryEx(proc, (LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi));
        if (!got || !mbi.RegionSize) {
            printf("[-] sanity: VirtualQueryEx failed at 0x%llX\n",
                   (unsigned long long)addr);
            CloseHandle(proc);
            return -1;
        }
        uint64_t rbase = (uint64_t)(uintptr_t)mbi.BaseAddress;
        uint64_t rsize = (uint64_t)mbi.RegionSize;
        if (rbase < addr) {
            rsize -= addr - rbase;
            rbase = addr;
        }
        uint64_t rend = rbase + rsize;
        if (rend > end) rend = end;
        uint64_t pages = (rend - rbase) / page;
        if (!pages) pages = 1;

        if (mbi.State == MEM_COMMIT) {
            committed += pages;
            if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) guard += pages;
        } else if (mbi.State == MEM_RESERVE) {
            reserved += pages;
        } else {
            freed += pages;
        }
        regions++;
        if (rend <= addr) break;
        addr = rend;
    }

    CloseHandle(proc);
    printf("[*] sanity: 0x%llX bytes, %d regions, committed=%llu reserved=%llu free=%llu guard=%llu pages\n",
           (unsigned long long)size, regions,
           (unsigned long long)committed, (unsigned long long)reserved,
           (unsigned long long)freed, (unsigned long long)guard);
    if (reserved || freed) {
        printf("[!] sanity: %llu page(s) inside the image are not committed\n",
               (unsigned long long)(reserved + freed));
        return -1;
    }
    return 0;
}
