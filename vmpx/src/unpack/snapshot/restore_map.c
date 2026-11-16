/* restore_map.c - page-level mapping of a captured private payload
 *
 * The mapping unit is a 64 KiB reservation block, because x86 Windows does not
 * let a caller reserve a single 4 KiB page inside an occupied block. When a
 * block cannot be reserved wholesale, each page is committed or made writable
 * in place. System module images are never overwritten; the rebuilt main image
 * is allowed to keep captured tails because live TLS and heap pages can sit
 * there.
 */
#include "unpack/snapshot/restore_int.h"

int restore_page_is_free(HANDLE proc, uint32_t va) {
    MEMORY_BASIC_INFORMATION mbi;
    memset(&mbi, 0, sizeof(mbi));
    if (!VirtualQueryEx(proc, (LPCVOID)(uintptr_t)(va & ~0xFFFull), &mbi,
                        sizeof(mbi)))
        return 0;
    return mbi.State != MEM_COMMIT;
}

int restore_page_is_child_image(HANDLE proc, uint64_t page, uint64_t main_base) {
    MEMORY_BASIC_INFORMATION mbi;
    memset(&mbi, 0, sizeof(mbi));
    if (!VirtualQueryEx(proc, (LPCVOID)(uintptr_t)page, &mbi, sizeof(mbi)))
        return 1;
    if (mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE) return 0;
    return (uint64_t)(uintptr_t)mbi.AllocationBase != main_base;
}

void restore_map_payload_filtered(map_state_t* m, const uint8_t* skip,
                                  int rebase) {
    if (!m || !m->in || !m->proc) return;
    const restore_input_t* in = m->in;

    memset(in->bmap, 0, 0x8000);
    memset(in->region_ok, 1, in->h.region_count);
    m->mapped = 0;
    m->failed = 0;
    m->pages_mapped = 0;
    m->pages_failed = 0;

    uint8_t* rskip = (uint8_t*)calloc(in->h.region_count, 1);
    if (!rskip) {
        /* Every region is now unaccounted for; report the whole capture as
         * failed instead of leaving mapped=failed=0, which reads as success. */
        printf("[-] run: out of memory for the region skip map\n");
        m->failed = in->h.region_count;
        return;
    }
    for (uint32_t i = 0; i < in->h.region_count; i++) {
        if (skip && skip[i]) rskip[i] = 1;
    }

    if (rebase) {
        memset(m->owner, 0xFF, 0x100000 * sizeof(*m->owner));
        for (uint32_t i = 0; i < in->h.module_count; i++) {
            m->orig_base[i] = in->md[i].base;
            m->orig_size[i] = in->md[i].size;
            m->child_base[i] = restore_find_child_base(in->md[i].name, m->child,
                                                       m->nchild);
            if (!m->orig_size[i]) continue;
            uint32_t first = m->orig_base[i] >> 12;
            uint64_t last = ((uint64_t)m->orig_base[i] + m->orig_size[i] +
                             0xFFF) >> 12;
            if (last > 0x100000) last = 0x100000;
            for (uint64_t p = first; p < last; p++) m->owner[p] = (uint16_t)i;
        }
        /* The rebuilt exe can carry a different file name from the captured
         * main image, so name matching cannot resolve it. Pin the snapshot
         * module that covers the captured image base to the discovered child
         * base; otherwise pointers into the main image are never translated. */
        if (m->main_base && in->h.image_base) {
            for (uint32_t i = 0; i < in->h.module_count; i++) {
                if (in->md[i].base == in->h.image_base) {
                    m->child_base[i] = m->main_base;
                    break;
                }
            }
        }
        snap_rebase_payload(in->all, in->roff, in->rd, in->h.region_count,
                            m->owner, m->child_base, m->orig_base,
                            m->orig_size);
    }

    for (uint32_t i = 0; i < in->h.region_count; i++) {
        if (rskip[i]) continue;
        if (in->rd[i].base >= 0x7FFE0000ull) continue;
        uint64_t first = in->rd[i].base >> 16;
        uint64_t last = (in->rd[i].base + in->rd[i].size - 1) >> 16;
        if (last >= 0x8000) last = 0x7FFF;
        for (uint64_t b = first; b <= last; b++) in->bmap[b] = 1;
    }

    const uint32_t page = 0x1000;
    const uint64_t page_mask = 0xFFFFull;
    const uint32_t block_size = 0x10000;
    /* The rebuilt main image can land at a base other than the captured one,
     * so image ownership follows the discovered child base. */
    const uint64_t main_base = m->main_base ? (uint64_t)m->main_base
                                            : in->h.image_base;
    for (int b = 0; b < 0x8000; b++) {
        if (!in->bmap[b]) continue;
        uint64_t bb = (uint64_t)b << 16;
        uint64_t be = bb + block_size;
        int has_image = 0;
        for (uint64_t q = bb; q < be; q += page) {
            if (restore_page_is_child_image(m->proc, q, main_base)) {
                has_image = 1;
                break;
            }
        }
        void* dest = NULL;
        if (!has_image)
            dest = VirtualAllocEx(m->proc, (LPVOID)(uintptr_t)bb, block_size,
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
        int block_ok = 0;
        if (dest) {
            block_ok = 1;
            for (uint32_t i = 0; i < in->h.region_count; i++) {
                if (rskip[i]) continue;
                uint64_t rs = in->rd[i].base;
                uint64_t re = rs + in->rd[i].size;
                uint64_t s = rs > bb ? rs : bb;
                uint64_t e = re < be ? re : be;
                if (s >= e) continue;
                SIZE_T wrote = 0;
                if (!WriteProcessMemory(m->proc, (LPVOID)(uintptr_t)s,
                                        in->all + in->roff[i] + (size_t)(s - rs),
                                        (SIZE_T)(e - s), &wrote) ||
                    wrote != (SIZE_T)(e - s)) {
                    in->region_ok[i] = 0;
                    block_ok = 0;
                    continue;
                }
                DWORD old = 0;
                DWORD prot = in->rd[i].protect & 0xFF;
                if (!prot || prot == PAGE_NOACCESS) prot = PAGE_READWRITE;
                VirtualProtectEx(m->proc, (LPVOID)(uintptr_t)s, (SIZE_T)(e - s),
                                 prot, &old);
                m->pages_mapped += (e - s + page - 1) / page;
            }
        }

        if (!block_ok) {
            if (dest) VirtualFreeEx(m->proc, dest, 0, MEM_RELEASE);
            for (uint32_t i = 0; i < in->h.region_count; i++) {
                if (rskip[i]) continue;
                uint64_t rs = in->rd[i].base;
                uint64_t re = rs + in->rd[i].size;
                uint64_t s = rs > bb ? rs : bb;
                uint64_t e = re < be ? re : be;
                if (s >= e) continue;
                uint64_t p = s & ~page_mask;
                uint64_t pend = (e + page_mask) & ~page_mask;
                if (p < rs) p = rs;
                if (pend > re) pend = re;
                for (; p < pend; p += page) {
                    if (restore_page_is_child_image(m->proc, p, main_base))
                        continue;
                    void* pr = VirtualAllocEx(m->proc, (LPVOID)(uintptr_t)p, page,
                                              MEM_COMMIT | MEM_RESERVE,
                                              PAGE_EXECUTE_READWRITE);
                    DWORD old = 0;
                    if (!pr) {
                        /* Already owned by the loader or child heap: commit in
                         * place, or make the committed page writable. */
                        pr = VirtualAllocEx(m->proc, (LPVOID)(uintptr_t)p, page,
                                            MEM_COMMIT, PAGE_READWRITE);
                        if (!pr && VirtualProtectEx(m->proc,
                                                    (LPVOID)(uintptr_t)p, page,
                                                    PAGE_READWRITE, &old))
                            pr = (void*)(uintptr_t)p;
                        if (!pr && VirtualProtectEx(m->proc,
                                                    (LPVOID)(uintptr_t)p, page,
                                                    PAGE_WRITECOPY, &old))
                            pr = (void*)(uintptr_t)p;
                        if (!pr && VirtualProtectEx(m->proc,
                                                    (LPVOID)(uintptr_t)p, page,
                                                    PAGE_EXECUTE_WRITECOPY,
                                                    &old))
                            pr = (void*)(uintptr_t)p;
                    }
                    if (!pr) {
                        m->pages_failed++;
                        in->region_ok[i] = 0;
                        continue;
                    }
                    SIZE_T wrote = 0;
                    if (!WriteProcessMemory(m->proc, pr,
                                            in->all + in->roff[i] +
                                                (size_t)(p - rs),
                                            page, &wrote) || wrote != page) {
                        if (pr != (void*)(uintptr_t)p)
                            VirtualFreeEx(m->proc, pr, 0, MEM_RELEASE);
                        m->pages_failed++;
                        in->region_ok[i] = 0;
                        continue;
                    }
                    DWORD prot = in->rd[i].protect & 0xFF;
                    if (!prot || prot == PAGE_NOACCESS) prot = PAGE_READWRITE;
                    VirtualProtectEx(m->proc, pr, page, prot, &old);
                    m->pages_mapped++;
                }
            }
        }
    }

    for (uint32_t i = 0; i < in->h.region_count; i++) {
        if (rskip[i]) continue;
        if (in->rd[i].base >= 0x7FFE0000ull) {
            in->region_ok[i] = 0;
        } else if (!in->region_ok[i]) {
            m->failed++;
            if (m->failed <= 16)
                printf("[!] run: unmapped region %u base=0x%llX size=0x%llX "
                       "(occupied or write denied)\n",
                       i, (unsigned long long)in->rd[i].base,
                       (unsigned long long)in->rd[i].size);
        } else {
            m->mapped++;
        }
    }
    free(rskip);
}

void restore_map_payload(map_state_t* m) {
    restore_map_payload_filtered(m, NULL, 1);
}
