/* mempe.h - parse a PE header that is mapped inside a live process (L1) */
#pragma once

#include <stdint.h>

typedef struct {
    uint16_t magic;
    uint16_t sections;
    uint16_t opt_size;
    uint32_t entry;
    uint32_t size_image;
    uint32_t sec_off;
    uint64_t image_base;
} mempe_t;

int mempe_read(uint32_t pid, uint64_t base, mempe_t* m);
