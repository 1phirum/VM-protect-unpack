/* carve.c - locate nested PE images in an unpacked memory dump */
#include "vmpx.h"
#include "unpack/deobf/deobf.h"
#include "pe/hdr.h"
#include "util/bin.h"
#include "util/file.h"
#include <stdio.h>
#include <string.h>

static void ensure_dir(const char* dir) {
    if (!dir || !*dir) return;
    CreateDirectoryA(dir, NULL);
}

static int plausible_pe(const pehdr_t* h, uint64_t avail) {
    if (!h || h->size_image < 0x1000 || h->size_image > 0x40000000u) return 0;
    if (!h->sections || h->sections > 96) return 0;
    if (h->headers_size < 0x40 || h->headers_size > h->size_image) return 0;
    if (h->machine != 0x14C && h->machine != 0x8664) return 0;
    if (h->entry && h->entry >= h->size_image) return 0;
    if (h->size_image > avail + 0x1000) return 0;
    return 1;
}

int deobf_carve(const uint8_t* dump, uint64_t len, const char* out_dir,
                deobf_stats_t* st) {
    if (!dump || !len || !out_dir) return -1;
    ensure_dir(out_dir);

    FILE* report = NULL;
    char path[MAX_PATH * 2];
    _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\carve.txt", out_dir);
    if (fopen_s(&report, path, "w") != 0 || !report) return -1;
    fprintf(report, "VMPX carve report\n");

    uint32_t found = 0;
    const uint32_t limit = 32;
    for (uint64_t off = 4; off + 0x40 < len && found < limit; off += 4) {
        if (dump[off] != 'M' || dump[off + 1] != 'Z') continue;
        pehdr_t h;
        if (pehdr_parse(dump + off, len - off, &h) != 0) continue;
        if (!plausible_pe(&h, len - off)) continue;

        uint64_t image = h.size_image;
        if (image > len - off) image = len - off;
        if (image < 0x1000) continue;

        _snprintf_s(path, sizeof(path), _TRUNCATE,
                    "%s\\carve_%08llX_%08llX.bin", out_dir,
                    (unsigned long long)off, (unsigned long long)h.image_base);
        if (file_write_all(path, dump + off, image) != 0) {
            fprintf(report, "FAIL off=0x%llX image=0x%X\n",
                    (unsigned long long)off, h.size_image);
            continue;
        }
        fprintf(report, "CARVE off=0x%llX base=0x%llX image=0x%X sections=%u "
                        "entry=0x%X file=%s\n",
                (unsigned long long)off, (unsigned long long)h.image_base,
                h.size_image, (unsigned)h.sections, h.entry, path);
        found++;
        st->carved_images++;
    }
    fprintf(report, "TOTAL %u\n", found);
    fclose(report);
    return 0;
}
