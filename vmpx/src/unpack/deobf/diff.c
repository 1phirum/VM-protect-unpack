/* diff.c - compare on-disk sections with the evolved live image */
#include "unpack/deobf/deobf.h"
#include "pe/hdr.h"
#include "util/bin.h"
#include <stdio.h>
#include <string.h>

static void sname(const uint8_t* s, char* out, size_t cap) {
    size_t n = 0;
    if (!out || !cap) return;
    while (n + 1 < cap && n < 8 && s[n]) { out[n] = (char)s[n]; n++; }
    out[n] = 0;
}

int deobf_diff(const uint8_t* file, uint64_t flen, const uint8_t* dump,
               uint64_t dlen, const char* out_path, deobf_stats_t* st) {
    if (!file || !dump || !flen || !dlen || !out_path) return -1;
    FILE* f = NULL;
    if (fopen_s(&f, out_path, "w") != 0 || !f) return -1;

    pehdr_t h;
    int have_pe = pehdr_parse(file, flen, &h) == 0;
    fprintf(f, "VMPX disk/live diff report\n");
    fprintf(f, "file_size=0x%llX dump_size=0x%llX pe=%s\n",
            (unsigned long long)flen, (unsigned long long)dlen,
            have_pe ? "yes" : "no");
    if (!have_pe) { fclose(f); return 0; }

    for (uint16_t i = 0; i < h.sections; i++) {
        const uint8_t* s = pehdr_section(&h, i);
        uint32_t vsize = bin_rd32(s + 8);
        uint32_t va = bin_rd32(s + 12);
        uint32_t rawsz = bin_rd32(s + 16);
        uint32_t rawptr = bin_rd32(s + 20);
        uint32_t chars = bin_rd32(s + 36);
        if (!va || !rawsz || !rawptr) continue;
        if ((uint64_t)rawptr + rawsz > flen || va >= dlen) continue;
        uint64_t span = rawsz;
        if (vsize && vsize < span) span = vsize;
        if (va + span > dlen) span = dlen - va;
        if (!span) continue;

        const uint8_t* a = file + rawptr;
        const uint8_t* b = dump + va;
        uint64_t changed = 0;
        uint32_t first = 0, last = 0;
        for (uint64_t k = 0; k < span; k++) {
            if (a[k] != b[k]) {
                if (!changed) first = (uint32_t)k;
                last = (uint32_t)k;
                changed++;
            }
        }
        char name[16];
        sname(s, name, sizeof(name));
        double pct = span ? (100.0 * (double)changed / (double)span) : 0.0;
        fprintf(f, "SECTION %-8s va=0x%08X raw=0x%08X size=0x%llX changed=%llu "
                   "%.2f%% exec=%d first=0x%X last=0x%X\n",
                name, va, rawptr, (unsigned long long)span,
                (unsigned long long)changed, pct,
                (chars & 0x20000000u) != 0, first, last);
        if (changed) st->changed_sections++;

        /* 4K page detail only for sections that actually changed. */
        if (changed) {
            uint32_t page = 0x1000;
            uint64_t pages = (span + page - 1) / page;
            uint32_t shown = 0;
            for (uint64_t p = 0; p < pages && shown < 48; p++) {
                uint64_t off = p * page;
                uint64_t end = off + page;
                if (end > span) end = span;
                uint64_t pc = 0;
                for (uint64_t k = off; k < end; k++) if (a[k] != b[k]) pc++;
                if (pc >= 32) {
                    fprintf(f, "  PAGE rva=0x%08llX changed=%llu/%llu\n",
                            (unsigned long long)(va + off),
                            (unsigned long long)pc,
                            (unsigned long long)(end - off));
                    shown++;
                }
            }
        }
    }

    fclose(f);
    return 0;
}
