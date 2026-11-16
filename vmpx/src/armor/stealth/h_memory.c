/* h_memory.c - memory map and debugger-write filtering
 *
 * The target scans its own address space for foreign allocations and may try
 * to restore bytes under an inline hook.  Hidden pages are reported as free,
 * writes into them are acknowledged but dropped, and reads of patched code
 * return the original instruction bytes.
 */
#include "armor/stealth/stealth.h"
#include "unpack/hook/watch.h"
#include "unpack/deobf/dynamic/control/control.h"
#include <string.h>

#define ST_INFO_LEN_MISMATCH ((LONG)0xC0000004L)
#define ST_ACCESS_DENIED     ((LONG)0xC0000022L)

typedef LONG (NTAPI* ntqvm_t)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
typedef LONG (NTAPI* ntvm_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef LONG (NTAPI* ntpvm_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

void dyn_oep_on_protect(uint64_t addr, uint64_t size, uint32_t prot);

extern stealth_hook_t g_stealth_hooks[ST_HK_COUNT];

static uint64_t page_base(uint64_t addr) { return addr & ~(uint64_t)0xFFF; }

static int overlaps_hidden(uint64_t addr, uint64_t len, int include_hooks) {
    if (!addr || !len) return 0;
    if (stealth_hidden_region(addr, len)) return 1;
    return include_hooks ? stealth_is_hook_range(addr, len) : 0;
}

static void mask_hook_bytes(uint64_t addr, uint8_t* buf, size_t len) {
    if (!buf || !len) return;
    for (int i = 0; i < ST_HK_COUNT; i++) {
        stealth_hook_t* h = &g_stealth_hooks[i];
        if (!h->active || !h->target || !h->copy_len) continue;
        uint64_t tb = (uint64_t)(uintptr_t)h->target;
        uint64_t te = tb + h->copy_len;
        uint64_t rs = addr > tb ? addr : tb;
        uint64_t re = addr + len < te ? addr + len : te;
        if (rs >= re) continue;
        memcpy(buf + (size_t)(rs - addr), h->original + (size_t)(rs - tb),
               (size_t)(re - rs));
    }
}

LONG NTAPI stealth_h_qvm(HANDLE proc, PVOID addr, ULONG cls, PVOID info,
                         SIZE_T len, PSIZE_T ret) {
    ntqvm_t orig = (ntqvm_t)stealth_trampoline(ST_HK_QVM);
    if (!orig) return ST_ACCESS_DENIED;

    uint64_t a = (uint64_t)(uintptr_t)addr;

    if (cls == 0 && info && len >= sizeof(MEMORY_BASIC_INFORMATION) &&
        stealth_hidden_region(a, 1)) {
        MEMORY_BASIC_INFORMATION* mbi = (MEMORY_BASIC_INFORMATION*)info;
        memset(mbi, 0, sizeof(*mbi));
        mbi->BaseAddress = (PVOID)(uintptr_t)page_base(a);
        mbi->RegionSize = 0x1000;
        mbi->State = MEM_FREE;
        mbi->Protect = PAGE_NOACCESS;
        if (ret) *ret = sizeof(*mbi);
        return 0;
    }

    if (cls == 2 && stealth_hidden_region(a, 1))
        return ST_ACCESS_DENIED;

    return orig(proc, addr, cls, info, len, ret);
}

LONG NTAPI stealth_h_rvm(HANDLE proc, PVOID addr, PVOID buf, SIZE_T len,
                         PSIZE_T ret) {
    ntvm_t orig = (ntvm_t)stealth_trampoline(ST_HK_RVM);
    if (!orig) return ST_ACCESS_DENIED;

    uint64_t a = (uint64_t)(uintptr_t)addr;
    if (!buf || !len) return orig(proc, addr, buf, len, ret);

    LONG st = orig(proc, addr, buf, len, ret);
    if (stealth_hidden_region(a, len)) {
        memset(buf, 0, len);
        if (ret) *ret = len;
        return 0;
    }
    if (st == 0) {
        SIZE_T got = ret ? *ret : len;
        if (got > len) got = len;
        mask_hook_bytes(a, (uint8_t*)buf, got);
    }
    return st;
}

LONG NTAPI stealth_h_pvm(HANDLE proc, PVOID* addr, PSIZE_T size, ULONG prot,
                         PULONG old) {
    ntpvm_t orig = (ntpvm_t)stealth_trampoline(ST_HK_PVM);
    if (!orig) return ST_ACCESS_DENIED;
    if (!addr || !size) return orig(proc, addr, size, prot, old);

    uint64_t a = (uint64_t)(uintptr_t)*addr;
    if (overlaps_hidden(a, *size, 1)) {
        if (old) *old = PAGE_EXECUTE_READ;
        return 0;
    }
    LONG st = orig(proc, addr, size, prot, old);
    if (st == 0) {
        watch_api_event(VMPX_WATCH_EV_PROTECT, a, *size,
                        old ? *old : 0, prot);
        dyn_event_api(VMPX_DYN_EV_PROTECT, a, *size,
                      old ? *old : 0, prot);
        dyn_oep_on_protect(a, *size, prot);
    }
    return st;
}

LONG NTAPI stealth_h_wvm(HANDLE proc, PVOID addr, PVOID buf, SIZE_T len,
                         PSIZE_T ret) {
    ntvm_t orig = (ntvm_t)stealth_trampoline(ST_HK_WVM);
    if (!orig) return ST_ACCESS_DENIED;

    uint64_t a = (uint64_t)(uintptr_t)addr;
    if (overlaps_hidden(a, len, 1)) {
        if (ret) *ret = len;
        return 0;                                /* silent drop */
    }
    LONG st = orig(proc, addr, buf, len, ret);
    if (st == 0) {
        watch_api_event(VMPX_WATCH_EV_WRITE, a, len, 0, 0);
        dyn_event_api(VMPX_DYN_EV_WRITE, a, len, 0, 0);
    }
    return st;
}
