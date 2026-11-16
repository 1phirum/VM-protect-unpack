/* restore_tls.c - child TLS index lookup, block relocation, exception repair
 *
 * The TLS index is read from the child image's AddressOfIndex field, which is
 * discovered from the rebuilt PE's TLS directory. No absolute target address
 * lives in this file. The captured block is copied into a fresh private page
 * and the child slot is repointed at the copy; the original block remains
 * available as evidence.
 */
#include "unpack/snapshot/restore_int.h"

int restore_tls_index(HANDLE proc, uint32_t index_va, uint32_t* index_out) {
    if (!proc || !index_va || !index_out) return -1;
    SIZE_T r = 0;
    uint32_t index = 0;
    if (!ReadProcessMemory(proc, (LPCVOID)(uintptr_t)index_va, &index, 4, &r) ||
        r != 4)
        return -1;
    if (index >= 64) return -1;
    *index_out = index;
    return 0;
}

/* The copied TEB restores the original TLS array. Some slots hold pointers
 * into heap pages that were allocated after the snapshot, so the page is not
 * in the payload. Commit a zero page for the current exception object so a
 * runtime raise path can read its fields instead of faulting. */
void restore_fix_tls_exception(HANDLE proc, uint32_t teb, uint32_t index_va) {
    if (!proc || !teb || !index_va) return;
    SIZE_T r = 0;
    uint32_t tls_array = 0;
    if (!ReadProcessMemory(proc, (LPCVOID)(uintptr_t)(teb + 0x2C),
                           &tls_array, 4, &r) ||
        r != 4 || !tls_array)
        return;
    uint32_t index = 0;
    if (restore_tls_index(proc, index_va, &index) != 0) return;
    uint32_t block = 0;
    if (!ReadProcessMemory(proc,
                           (LPCVOID)(uintptr_t)(tls_array + index * 4),
                           &block, 4, &r) ||
        r != 4 || !block)
        return;
    uint32_t obj = 0;
    if (!ReadProcessMemory(proc, (LPCVOID)(uintptr_t)block, &obj, 4, &r) ||
        r != 4)
        return;
    if (!obj) {
        printf("[dbg] run: tls exception object is zero (block 0x%08lX)\n",
               (unsigned long)block);
        return;
    }
    if (!restore_page_is_free(proc, obj)) return;
    uint32_t page = obj & ~0xFFFu;
    if (!restore_page_is_free(proc, page)) return;
    /* Reservations are 64 KiB. Committing a single page inside a free block
     * fails with ERROR_INVALID_ADDRESS, so reserve the whole block that
     * contains the stale exception object. */
    uint32_t block_base = page & ~0xFFFFu;
    void* p = VirtualAllocEx(proc, (LPVOID)(uintptr_t)block_base, 0x10000,
                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (p)
        printf("[*] run: tls exception block 0x%08lX zeroed (obj 0x%08lX)\n",
               (unsigned long)block_base, (unsigned long)obj);
    else
        printf("[!] run: tls exception block 0x%08lX failed %lu\n",
               (unsigned long)block_base, GetLastError());
}

int restore_relocate_tls_block(HANDLE proc, uint32_t child_tls_array,
                               uint32_t index_va, const uint8_t* block) {
    if (!proc || !child_tls_array || !index_va || !block) return -1;
    uint32_t index = 0;
    if (restore_tls_index(proc, index_va, &index) != 0) return -1;

    void* nb = VirtualAllocEx(proc, NULL, 0x1000,
                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!nb) {
        printf("[!] run: tls block allocation failed %lu\n", GetLastError());
        return -1;
    }
    SIZE_T w = 0;
    if (!WriteProcessMemory(proc, nb, block, 0x1000, &w) || w != 0x1000) {
        printf("[!] run: tls block copy failed %lu\n", GetLastError());
        VirtualFreeEx(proc, nb, 0, MEM_RELEASE);
        return -1;
    }
    uint32_t nb32 = (uint32_t)(uintptr_t)nb;
    if (!WriteProcessMemory(proc, (LPVOID)(uintptr_t)(child_tls_array + index * 4),
                            &nb32, 4, &w) || w != 4) {
        printf("[!] run: tls block slot write failed %lu\n", GetLastError());
        VirtualFreeEx(proc, nb, 0, MEM_RELEASE);
        return -1;
    }
    printf("[*] run: tls block relocated to 0x%08lX slot=%u\n",
           (unsigned long)nb32, (unsigned)index);
    return 0;
}
