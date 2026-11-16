/* restore_modules.c - child module identity and image-data rebasing
 *
 * The child loader places system DLLs at its own bases. Captured data pages can
 * contain absolute pointers to the original bases, so after mapping them the
 * restore translates only dwords that fall inside an original module range and
 * leaves loader-resolved IAT/TLS fields alone.
 */
#include "unpack/snapshot/restore_int.h"

/* Toolhelp can fail on a freshly created suspended process. The child handle
 * from CreateProcess has the necessary access for a PEB module walk. */
int restore_enum_child_modules(HANDLE proc, proc_mod_t* out, int cap) {
    if (!proc || !out || cap <= 0) return 0;
    HMODULE mods[VMPX_SNAP_MAX_MODULES];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(proc, mods, sizeof(mods), &needed,
                              LIST_MODULES_ALL))
        return 0;
    DWORD have = needed / sizeof(HMODULE);
    if (have > (DWORD)cap) have = (DWORD)cap;
    if (have > VMPX_SNAP_MAX_MODULES) have = VMPX_SNAP_MAX_MODULES;

    int n = 0;
    for (DWORD i = 0; i < have; i++) {
        MODULEINFO mi;
        memset(&mi, 0, sizeof(mi));
        if (!GetModuleInformation(proc, mods[i], &mi, sizeof(mi))) continue;
        if (!mi.lpBaseOfDll || !mi.SizeOfImage) continue;
        wchar_t name[64] = { 0 };
        GetModuleBaseNameW(proc, mods[i], name, 64);
        if (!name[0]) continue;
        wcsncpy_s(out[n].name, 64, name, _TRUNCATE);
        out[n].base = (uint64_t)(uintptr_t)mi.lpBaseOfDll;
        out[n].size = mi.SizeOfImage;
        n++;
    }
    return n;
}

uint32_t restore_find_child_base(const char* name, const proc_mod_t* child,
                                 int nchild) {
    if (!name || !*name || !child) return 0;
    for (int i = 0; i < nchild; i++) {
        char cname[128];
        str_narrow(child[i].name, cname, sizeof(cname));
        if (_stricmp(cname, name) == 0) return (uint32_t)child[i].base;
    }
    return 0;
}

int restore_rebase_image_pointers(map_state_t* m) {
    if (!m || !m->in) return -1;
    const restore_input_t* in = m->in;
    if (!in->h.image_base || !in->h.image_size) {
        printf("[!] run: snapshot has no image extent; image rebase skipped\n");
        return 0;
    }
    uint32_t n = in->h.module_count;
    if (!n || n > VMPX_SNAP_MAX_MODULES) return 0;
    uint16_t order[VMPX_SNAP_MAX_MODULES];
    for (uint32_t i = 0; i < n; i++) order[i] = (uint16_t)i;
    for (uint32_t i = 1; i < n; i++) {
        uint16_t k = order[i];
        uint32_t kb = m->orig_base[k];
        int j = (int)i - 1;
        while (j >= 0 && m->orig_base[order[j]] > kb) {
            order[j + 1] = order[j];
            j--;
        }
        order[j + 1] = k;
    }

    /* Scan the child's copy of the rebuilt image, not the captured base: a
     * renamed or relocated executable can land somewhere else. The captured
     * image extent remains the scan size, so a rebuilt image larger than the
     * capture is a documented limitation. */
    uint64_t start = m->main_base ? (uint64_t)m->main_base : in->h.image_base;
    uint64_t end = start + in->h.image_size;
    uint8_t* buf = (uint8_t*)malloc(0x100000);
    if (!buf) {
        printf("[-] run: out of memory for the image rebase buffer\n");
        return -1;
    }
    uint64_t changes = 0;
    uint64_t write_fails = 0;

    for (uint64_t p = start; p < end;) {
        MEMORY_BASIC_INFORMATION mbi;
        memset(&mbi, 0, sizeof(mbi));
        if (!VirtualQueryEx(m->proc, (LPCVOID)(uintptr_t)p, &mbi,
                            sizeof(mbi)))
            break;
        uint64_t rb = (uint64_t)(uintptr_t)mbi.BaseAddress;
        uint64_t rs = mbi.RegionSize;
        if (rb < p) { rs -= (p - rb); rb = p; }
        if (rb + rs > end) rs = end - rb;

        DWORD prot = mbi.Protect & 0xFF;
        int ro = 0;
        int scan = 0;
        if (mbi.State == MEM_COMMIT) {
            if (prot == PAGE_READONLY) {
                scan = 1;
                ro = 1;
            } else if (prot == PAGE_READWRITE || prot == PAGE_WRITECOPY ||
                       prot == PAGE_EXECUTE_READWRITE ||
                       prot == PAGE_EXECUTE_WRITECOPY) {
                scan = 1;
            }
        }

        if (scan) {
            for (uint64_t off = 0; off < rs; off += 0x100000) {
                SIZE_T chunk = (SIZE_T)((rs - off) > 0x100000
                                            ? 0x100000
                                            : (rs - off));
                SIZE_T got = 0;
                if (!ReadProcessMemory(m->proc, (LPCVOID)(uintptr_t)(rb + off),
                                       buf, chunk, &got) ||
                    got < 4)
                    continue;
                int dirty = 0;
                for (SIZE_T i = 0; i + 4 <= got; i += 4) {
                    uint32_t v = *(uint32_t*)(buf + i);
                    int lo = 0, hi = (int)n - 1, found = -1;
                    while (lo <= hi) {
                        int mid = (lo + hi) / 2;
                        uint32_t b = m->orig_base[order[mid]];
                        uint32_t s = m->orig_size[order[mid]];
                        if (v < b) {
                            hi = mid - 1;
                        } else if (s && (uint64_t)v < (uint64_t)b + s) {
                            found = order[mid];
                            break;
                        } else {
                            lo = mid + 1;
                        }
                    }
                    if (found < 0) continue;
                    uint32_t cb = m->child_base[found];
                    uint32_t ob = m->orig_base[found];
                    if (!cb || cb == ob) continue;
                    uint32_t nv = cb + (v - ob);
                    if (nv == v) continue;
                    *(uint32_t*)(buf + i) = nv;
                    dirty = 1;
                    changes++;
                }
                if (!dirty) continue;
                DWORD old = 0;
                int prot_done = 1;
                if (ro)
                    prot_done = VirtualProtectEx(
                        m->proc, (LPVOID)(uintptr_t)(rb + off), got,
                        PAGE_READWRITE, &old);
                SIZE_T wrote = 0;
                if (!WriteProcessMemory(m->proc, (LPVOID)(uintptr_t)(rb + off),
                                        buf, got, &wrote) ||
                    wrote != got)
                    write_fails++;
                if (ro && prot_done) {
                    DWORD tmp = 0;
                    VirtualProtectEx(m->proc, (LPVOID)(uintptr_t)(rb + off),
                                     got, old, &tmp);
                }
            }
        }

        uint64_t next = rb + mbi.RegionSize;
        if (next <= p) break;
        p = next;
    }
    free(buf);
    if (write_fails) {
        printf("[!] run: image pointer rebase write failures=%llu "
               "changes=%llu\n",
               (unsigned long long)write_fails,
               (unsigned long long)changes);
        return -1;
    }
    if (changes)
        printf("[*] run: image pointer rebase changes=%llu\n",
               (unsigned long long)changes);
    return 0;
}
