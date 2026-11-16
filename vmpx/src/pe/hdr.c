/* hdr.c - bounds-checked PE header parser shared by every PE consumer (L0) */
#include "pe/hdr.h"
#include "util/bin.h"
#include <string.h>

int pehdr_is_64(const pehdr_t* h) {
    return h && h->magic == 0x20B;
}

int pehdr_parse(const uint8_t* data, uint64_t size, pehdr_t* h) {
    if (!data || !h) return -1;
    memset(h, 0, sizeof(*h));
    h->data = data;
    h->size = size;
    if (size < 0x40) return -1;
    if (bin_rd16(data) != 0x5A4D) return -1;

    uint32_t lfanew = bin_rd32(data + 0x3C);
    if ((uint64_t)lfanew + 0x18 > size) return -1;
    const uint8_t* nt = data + lfanew;
    if (bin_rd32(nt) != 0x00004550) return -1;

    const uint8_t* fh = nt + 4;
    if ((uint64_t)(fh - data) + 20 > size) return -1;
    uint16_t opt_size = bin_rd16(fh + 16);
    if ((uint64_t)(fh - data) + 20 + opt_size > size) return -1;

    const uint8_t* opt = fh + 20;
    uint16_t magic = bin_rd16(opt);
    if (magic != 0x10B && magic != 0x20B) return -1;

    uint16_t sections = bin_rd16(fh + 2);
    if (sections > 96) return -1;
    const uint8_t* sec = opt + opt_size;
    if ((uint64_t)(sec - data) + (uint64_t)sections * 40 > size) return -1;

    h->nt = nt;
    h->opt = opt;
    h->sec = sec;
    h->sec_off = (uint32_t)(sec - data);
    h->machine = bin_rd16(fh);
    h->sections = sections;
    h->opt_size = opt_size;
    h->magic = magic;
    h->entry = bin_rd32(opt + 16);
    h->size_image = bin_rd32(opt + 56);
    h->headers_size = bin_rd32(opt + 60);
    h->num_dirs = bin_rd32(opt + (magic == 0x20B ? 108 : 92));
    if (h->num_dirs > PEHDR_DIR_COUNT) h->num_dirs = PEHDR_DIR_COUNT;
    h->image_base = (magic == 0x20B) ? bin_rd64(opt + 24) : (uint64_t)bin_rd32(opt + 28);
    return 0;
}

const uint8_t* pehdr_section(const pehdr_t* h, uint16_t index) {
    if (!h || index >= h->sections) return NULL;
    return h->sec + (size_t)index * 40;
}

uint32_t pehdr_dir_rva(const pehdr_t* h, int index) {
    if (!h || index < 0 || index >= (int)h->num_dirs) return 0;
    const uint8_t* dd = h->opt + (pehdr_is_64(h) ? 112 : 96);
    return bin_rd32(dd + (size_t)index * 8);
}

uint32_t pehdr_dir_size(const pehdr_t* h, int index) {
    if (!h || index < 0 || index >= (int)h->num_dirs) return 0;
    const uint8_t* dd = h->opt + (pehdr_is_64(h) ? 112 : 96);
    return bin_rd32(dd + (size_t)index * 8 + 4);
}

int pehdr_rva_to_off(const pehdr_t* h, uint32_t rva, uint32_t* off) {
    if (!h || !off) return -1;
    if (rva < h->headers_size) {
        *off = rva;
        return 0;
    }
    for (uint16_t i = 0; i < h->sections; i++) {
        const uint8_t* s = pehdr_section(h, i);
        uint32_t vsize = bin_rd32(s + 8);
        uint32_t va = bin_rd32(s + 12);
        uint32_t rawsz = bin_rd32(s + 16);
        uint32_t rawpt = bin_rd32(s + 20);
        uint32_t span = vsize > rawsz ? vsize : rawsz;
        if (rva >= va && rva < va + span) {
            *off = rva - va + rawpt;
            return 0;
        }
    }
    return -1;
}
