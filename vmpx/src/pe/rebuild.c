/* rebuild.c - turn a live identity-layout dump into a loadable PE (stage B)
 *
 * Inputs: the original file headers (VMProtect wipes the in-memory copy), the
 * dump, the live image base, and a recovered import table. Output uses an
 * identity file layout (PointerToRawData == VirtualAddress) so every RVA in the
 * dump stays valid. A new section at the end carries descriptors, an INT, and
 * fresh hint/name records; the original live IAT becomes FirstThunk.
 */
#include "vmpx.h"
#include "pe/hdr.h"
#include "pe/iat_table.h"
#include "util/bin.h"
#include "util/file.h"
#include <stdlib.h>
#include <string.h>

#define IAT_SECTION_NAME ".vmpiat"

static uint32_t opt_dir_offset(const pehdr_t* h) {
    return pehdr_is_64(h) ? 112 : 96;
}

static void write_dir(uint8_t* out, const pehdr_t* h, int idx, uint32_t rva, uint32_t size) {
    uint32_t opt_off = (uint32_t)(h->opt - h->data);
    uint8_t* dd = out + opt_off + opt_dir_offset(h) + (size_t)idx * 8;
    bin_wr32(dd, rva);
    bin_wr32(dd + 4, size);
}

static int section_contains(const uint8_t* sec, uint32_t rva) {
    uint32_t vsize = bin_rd32(sec + 8);
    uint32_t va = bin_rd32(sec + 12);
    uint32_t rawsz = bin_rd32(sec + 16);
    uint32_t span = vsize > rawsz ? vsize : rawsz;
    return rva >= va && rva < va + span;
}

static int iat_in_section(const pehdr_t* h, const iat_table_t* tab, uint16_t idx) {
    const uint8_t* sec = pehdr_section(h, idx);
    uint32_t va = bin_rd32(sec + 12);
    uint32_t vsize = bin_rd32(sec + 8);
    uint32_t rawsz = bin_rd32(sec + 16);
    uint32_t span = vsize > rawsz ? vsize : rawsz;
    if (!span) return 0;
    for (uint32_t m = 0; m < tab->nmods; m++) {
        uint32_t start = tab->mods[m].first_thunk;
        if (start >= va && start < va + span) return 1;
    }
    return 0;
}

int pe_rebuild(const uint8_t* file_hdr, uint64_t file_size, uint64_t live_base,
               uint32_t entry_rva, int clean_data, const char* dump_path,
               const char* out_path, const iat_table_t* tab) {
    if (!file_hdr || !dump_path || !out_path || !tab || tab->nmods == 0) {
        printf("[-] rebuild: missing header, dump, output, or import table\n");
        return -1;
    }
    if (!tab->funcs || iat_table_unresolved(tab) != 0) {
        printf("[-] rebuild: %u unresolved import slot(s)\n", iat_table_unresolved(tab));
        return -1;
    }

    pehdr_t h;
    if (pehdr_parse(file_hdr, file_size, &h) != 0) {
        printf("[-] rebuild: source headers are not a valid PE\n");
        return -1;
    }

    uint8_t* dump = NULL;
    uint64_t dump_size = 0;
    if (file_read_all(dump_path, &dump, &dump_size) != 0) {
        printf("[-] rebuild: cannot read %s\n", dump_path);
        return -1;
    }

    uint32_t sec_align = bin_rd32(h.opt + 32);
    uint32_t file_align = bin_rd32(h.opt + 36);
    if (sec_align < 0x1000) sec_align = 0x1000;
    if (file_align < 0x200) file_align = 0x200;

    uint64_t image_size = h.size_image;
    for (uint16_t i = 0; i < h.sections; i++) {
        const uint8_t* s = pehdr_section(&h, i);
        uint32_t vsize = bin_rd32(s + 8);
        uint32_t va = bin_rd32(s + 12);
        uint32_t rawsz = bin_rd32(s + 16);
        uint64_t end = (uint64_t)va + (vsize > rawsz ? vsize : rawsz);
        if (end > image_size) image_size = end;
    }
    if (!image_size) {
        printf("[-] rebuild: source image size is zero\n");
        free(dump);
        return -1;
    }
    image_size = bin_align_up(image_size, sec_align);

    uint64_t hdr_need = (uint64_t)h.sec_off + ((uint64_t)h.sections + 1) * 40;
    uint64_t hdr_size = h.headers_size ? h.headers_size : bin_align_up(hdr_need, file_align);
    if (hdr_size < hdr_need) hdr_size = bin_align_up(hdr_need, file_align);

    uint32_t first_va = 0xFFFFFFFFu;
    for (uint16_t i = 0; i < h.sections; i++) {
        uint32_t va = bin_rd32(pehdr_section(&h, i) + 12);
        if (va && va < first_va) first_va = va;
    }
    if (first_va == 0xFFFFFFFFu) first_va = (uint32_t)bin_align_up(hdr_size, sec_align);
    if (hdr_size > first_va) {
        printf("[-] rebuild: header needs 0x%llX bytes but the first section is at 0x%X\n",
               (unsigned long long)hdr_size, first_va);
        free(dump);
        return -1;
    }

    uint64_t iat_va = bin_align_up(image_size, sec_align);
    uint64_t off = ((uint64_t)tab->nmods + 1) * 20;
    uint32_t* int_rva = (uint32_t*)calloc(tab->nmods, sizeof(uint32_t));
    uint32_t* dll_rva = (uint32_t*)calloc(tab->nmods, sizeof(uint32_t));
    uint32_t* slot_rva = (uint32_t*)calloc(tab->nfuncs ? tab->nfuncs : 1, sizeof(uint32_t));
    if (!int_rva || !dll_rva || !slot_rva) {
        printf("[-] rebuild: out of memory for import layout\n");
        free(int_rva); free(dll_rva); free(slot_rva); free(dump);
        return -1;
    }

    int layout_ok = 1;
    for (uint32_t m = 0; m < tab->nmods && layout_ok; m++) {
        const iat_mod_t* mod = &tab->mods[m];
        if (!mod->count || mod->first_func + mod->count > tab->nfuncs) {
            layout_ok = 0;
            break;
        }
        if (iat_va + off > 0xFFFFFFFFull) { layout_ok = 0; break; }
        int_rva[m] = (uint32_t)(iat_va + off);
        off += (uint64_t)mod->count * 4;
        off += 4;                                  /* null terminator for this INT */

        for (uint32_t k = 0; k < mod->count; k++) {
            const iat_func_t* f = &tab->funcs[mod->first_func + k];
            if (f->by_ordinal) continue;
            if (!f->name[0]) { layout_ok = 0; break; }
            if (iat_va + off > 0xFFFFFFFFull) { layout_ok = 0; break; }
            slot_rva[mod->first_func + k] = (uint32_t)(iat_va + off);
            off += 2 + strlen(f->name) + 1;
            off = bin_align_up(off, 2);
        }
        if (!layout_ok) break;
        if (iat_va + off > 0xFFFFFFFFull) { layout_ok = 0; break; }
        dll_rva[m] = (uint32_t)(iat_va + off);
        off += strlen(mod->dll) + 1;
        off = bin_align_up(off, 2);
    }
    if (!layout_ok || off > 0xFFFFFFFFull - iat_va) {
        printf("[-] rebuild: import layout does not fit in 32-bit RVAs\n");
        free(int_rva); free(dll_rva); free(slot_rva); free(dump);
        return -1;
    }

    uint64_t iat_size = off;
    uint64_t new_image_size = bin_align_up(iat_va + iat_size, sec_align);
    uint64_t out_size = bin_align_up(iat_va + iat_size, file_align);
    if (new_image_size > 0xFFFFFFFFull || out_size > 0xFFFFFFFFull) {
        printf("[-] rebuild: output exceeds 32-bit PE limits\n");
        free(int_rva); free(dll_rva); free(slot_rva); free(dump);
        return -1;
    }

    uint8_t* out = (uint8_t*)calloc(1, (size_t)out_size);
    if (!out) {
        printf("[-] rebuild: out of memory for %llu-byte image\n",
               (unsigned long long)out_size);
        free(int_rva); free(dll_rva); free(slot_rva); free(dump);
        return -1;
    }

    uint64_t copy = dump_size < new_image_size ? dump_size : new_image_size;
    memcpy(out, dump, (size_t)copy);
    memset(out, 0, (size_t)hdr_size);
    uint64_t hdr_copy = file_size < hdr_size ? file_size : hdr_size;
    memcpy(out, file_hdr, (size_t)hdr_copy);

    /* The live dump carries post-VMProtect globals. Re-running the original
     * entry with those values makes the stub read pointers into its old private
     * context. For a clean run, restore writable non-executable sections from
     * the on-disk image and let the loader/stub initialize them again. */
    if (clean_data) {
        for (uint16_t i = 0; i < h.sections; i++) {
            const uint8_t* s = pehdr_section(&h, i);
            uint32_t chars = bin_rd32(s + 36);
            if (!(chars & 0x80000000u) || (chars & 0x20000000u)) continue;
            uint32_t vsize = bin_rd32(s + 8);
            uint32_t va = bin_rd32(s + 12);
            uint32_t rawsz = bin_rd32(s + 16);
            uint32_t rawptr = bin_rd32(s + 20);
            uint64_t span = vsize > rawsz ? vsize : rawsz;
            if (!va || !span || (uint64_t)va + span > new_image_size) continue;
            memset(out + va, 0, (size_t)span);
            if (rawptr && rawsz && (uint64_t)rawptr + rawsz <= file_size)
                memcpy(out + va, file_hdr + rawptr, rawsz);
        }
    }

    uint32_t fh_off = (uint32_t)((h.nt - h.data) + 4);
    uint32_t opt_off = (uint32_t)(h.opt - h.data);

    bin_wr16(out + fh_off + 2, (uint16_t)(h.sections + 1));
    uint16_t chars = bin_rd16(out + fh_off + 18);
    chars |= 0x0001;                                  /* RELOCS_STRIPPED */
    bin_wr16(out + fh_off + 18, chars);

    bin_wr32(out + opt_off + 32, sec_align);
    bin_wr32(out + opt_off + 36, file_align);
    bin_wr32(out + opt_off + 56, (uint32_t)new_image_size);
    if (entry_rva && entry_rva < new_image_size)
        bin_wr32(out + opt_off + 16, entry_rva);
    bin_wr32(out + opt_off + 60, (uint32_t)hdr_size);
    bin_wr32(out + opt_off + 64, 0);                  /* CheckSum */
    bin_wr32(out + opt_off + (pehdr_is_64(&h) ? 108 : 92), PEHDR_DIR_COUNT);
    uint16_t dll_chars = bin_rd16(out + opt_off + 70);
    dll_chars = (uint16_t)(dll_chars & ~0x0040u & ~0x0020u); /* no ASLR / high-entropy */
    bin_wr16(out + opt_off + 70, dll_chars);

    if (pehdr_is_64(&h)) bin_wr64(out + opt_off + 24, live_base);
    else                  bin_wr32(out + opt_off + 28, (uint32_t)live_base);

    write_dir(out, &h, PEHDR_DIR_IMPORT, (uint32_t)iat_va, (tab->nmods + 1) * 20);
    write_dir(out, &h, PEHDR_DIR_IAT, 0, 0);
    write_dir(out, &h, PEHDR_DIR_BASERELOC, 0, 0);
    write_dir(out, &h, PEHDR_DIR_SECURITY, 0, 0);
    write_dir(out, &h, PEHDR_DIR_DEBUG, 0, 0);
    write_dir(out, &h, PEHDR_DIR_BOUNDIMPORT, 0, 0);

    for (uint16_t i = 0; i < h.sections; i++) {
        uint8_t* s = out + h.sec_off + (size_t)i * 40;
        uint32_t vsize = bin_rd32(s + 8);
        uint32_t va = bin_rd32(s + 12);
        uint32_t rawsz = bin_rd32(s + 16);
        uint64_t effective = vsize > rawsz ? vsize : rawsz;
        if (!va || !effective) {
            bin_wr32(s + 16, 0);
            bin_wr32(s + 20, 0);
            continue;
        }
        uint64_t rsz = bin_align_up(effective, file_align);
        if (va + rsz > new_image_size) rsz = new_image_size - va;
        bin_wr32(s + 16, (uint32_t)rsz);
        bin_wr32(s + 20, va);
        if (iat_in_section(&h, tab, i)) {
            uint32_t sc = bin_rd32(s + 36);
            sc |= 0x80000000u | 0x40000000u;           /* MEM_WRITE | MEM_READ */
            bin_wr32(s + 36, sc);
        }
    }

    uint8_t* ns = out + h.sec_off + (size_t)h.sections * 40;
    memcpy(ns, IAT_SECTION_NAME, 8);
    bin_wr32(ns + 8, (uint32_t)iat_size);
    bin_wr32(ns + 12, (uint32_t)iat_va);
    bin_wr32(ns + 16, (uint32_t)bin_align_up(iat_size, file_align));
    bin_wr32(ns + 20, (uint32_t)iat_va);
    bin_wr32(ns + 36, 0xC0000040u);                    /* RDATA | MEM_READ | MEM_WRITE */

    uint8_t* iat = out + iat_va;
    for (uint32_t m = 0; m < tab->nmods; m++) {
        const iat_mod_t* mod = &tab->mods[m];
        uint8_t* desc = iat + (size_t)m * 20;
        bin_wr32(desc + 0, int_rva[m]);
        bin_wr32(desc + 4, 0);
        bin_wr32(desc + 8, 0);
        bin_wr32(desc + 12, dll_rva[m]);
        bin_wr32(desc + 16, mod->first_thunk);

        uint8_t* ints = iat + (int_rva[m] - iat_va);
        for (uint32_t k = 0; k < mod->count; k++) {
            const iat_func_t* f = &tab->funcs[mod->first_func + k];
            if (f->by_ordinal) {
                bin_wr32(ints + (size_t)k * 4, 0x80000000u | (uint32_t)f->ordinal);
            } else {
                bin_wr32(ints + (size_t)k * 4, slot_rva[mod->first_func + k]);
                uint8_t* rec = iat + (slot_rva[mod->first_func + k] - iat_va);
                bin_wr16(rec, 0);
                memcpy(rec + 2, f->name, strlen(f->name) + 1);
            }
        }
        memcpy(iat + (dll_rva[m] - iat_va), mod->dll, strlen(mod->dll) + 1);
    }

    int rc = file_write_all(out_path, out, out_size);
    if (rc == 0) {
        printf("[+] rebuilt %s\n", out_path);
        printf("    base=0x%llX image=0x%llX file=0x%llX\n",
               (unsigned long long)live_base,
               (unsigned long long)new_image_size,
               (unsigned long long)out_size);
        printf("    sections=%u imports=%u funcs=%u iat_rva=0x%llX iat_size=0x%llX\n",
               (unsigned)(h.sections + 1), tab->nmods, tab->nfuncs,
               (unsigned long long)iat_va, (unsigned long long)iat_size);
    } else {
        printf("[-] rebuild: write failed for %s\n", out_path);
    }

    free(out);
    free(int_rva);
    free(dll_rva);
    free(slot_rva);
    free(dump);
    return rc;
}
