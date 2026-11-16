/* mempe.c - parse a PE header that is mapped inside a live process (L1) */
#include "vmpx.h"
#include "pe/hdr.h"
#include "unpack/mempe.h"
#include <string.h>

int mempe_read(uint32_t pid, uint64_t base, mempe_t* m) {
    if (!m) return -1;
    memset(m, 0, sizeof(*m));
    uint8_t hdr[0x1000];
    if (proc_read(pid, base, hdr, sizeof(hdr)) != 0) return -1;

    pehdr_t h;
    if (pehdr_parse(hdr, sizeof(hdr), &h) != 0) return -1;
    m->magic = h.magic;
    m->sections = h.sections;
    m->opt_size = h.opt_size;
    m->entry = h.entry;
    m->size_image = h.size_image;
    m->sec_off = h.sec_off;
    m->image_base = h.image_base;
    return 0;
}
