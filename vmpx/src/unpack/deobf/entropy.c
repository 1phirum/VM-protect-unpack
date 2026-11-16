/* entropy.c - section and page entropy map for a live image dump */
#include "unpack/deobf/deobf.h"
#include "pe/hdr.h"
#include "util/bin.h"
#include <math.h>
#include <stdio.h>
#include <string.h>

static double shannon(const uint8_t* p, size_t n) {
    if (!p || !n) return 0.0;
    uint64_t freq[256];
    memset(freq, 0, sizeof(freq));
    for (size_t i = 0; i < n; i++) freq[p[i]]++;
    double h = 0.0;
    double dn = (double)n;
    for (int i = 0; i < 256; i++) {
        if (!freq[i]) continue;
        double q = (double)freq[i] / dn;
        h -= q * (log(q) / log(2.0));
    }
    return h;
}

static void section_name(const uint8_t* s, char* out, size_t cap) {
    if (!out || !cap) return;
    size_t n = 0;
    while (n + 1 < cap && n < 8 && s[n]) {
        out[n] = (char)s[n];
        n++;
    }
    out[n] = 0;
}

int deobf_entropy(const uint8_t* dump, uint64_t len, const char* out_path,
                  deobf_stats_t* st) {
    if (!dump || !len || !out_path) return -1;
    FILE* f = NULL;
    if (fopen_s(&f, out_path, "w") != 0 || !f) return -1;

    pehdr_t h;
    int have_pe = pehdr_parse(dump, len, &h) == 0;
    fprintf(f, "VMPX entropy report\n");
    fprintf(f, "dump_size=0x%llX pe=%s\n", (unsigned long long)len,
            have_pe ? "yes" : "no");

    if (have_pe) {
        fprintf(f, "image_base=0x%llX image_size=0x%X sections=%u entry=0x%X\n",
                (unsigned long long)h.image_base, h.size_image,
                (unsigned)h.sections, h.entry);
        for (uint16_t i = 0; i < h.sections; i++) {
            const uint8_t* s = pehdr_section(&h, i);
            uint32_t vsize = bin_rd32(s + 8);
            uint32_t va = bin_rd32(s + 12);
            uint32_t rawsz = bin_rd32(s + 16);
            uint32_t chars = bin_rd32(s + 36);
            uint32_t span = vsize > rawsz ? vsize : rawsz;
            if (va >= len) continue;
            uint64_t avail = len - va;
            if (span > avail) span = (uint32_t)avail;
            if (!span) continue;

            char name[16];
            section_name(s, name, sizeof(name));
            double e = shannon(dump + va, span);
            if (e >= 7.2) st->high_entropy_ranges++;
            fprintf(f, "SECTION %-8s rva=0x%08X size=0x%08X entropy=%.4f "
                       "exec=%d write=%d\n",
                    name, va, span, e,
                    (chars & 0x20000000u) != 0,
                    (chars & 0x80000000u) != 0);
            st->sections++;
        }
    }

    /* Page-level map: group contiguous pages above 7.25 bits/byte. */
    const uint32_t page = 0x1000;
    uint32_t start = 0;
    double best = 0.0;
    int in_run = 0;
    uint32_t run_pages = 0;
    for (uint64_t off = 0; off + page <= len; off += page) {
        double e = shannon(dump + off, page);
        st->pages_scanned++;
        if (e >= 7.25) {
            if (!in_run) { start = (uint32_t)off; in_run = 1; run_pages = 0; best = 0.0; }
            run_pages++;
            if (e > best) best = e;
        } else if (in_run) {
            if (run_pages >= 4) {
                fprintf(f, "HIGH rva=0x%08X size=0x%08X pages=%u max=%.3f\n",
                        start, run_pages * page, run_pages, best);
                st->high_entropy_ranges++;
            }
            in_run = 0;
        }
    }
    if (in_run && run_pages >= 4) {
        fprintf(f, "HIGH rva=0x%08X size=0x%08X pages=%u max=%.3f\n",
                start, run_pages * page, run_pages, best);
        st->high_entropy_ranges++;
    }

    fclose(f);
    return 0;
}
