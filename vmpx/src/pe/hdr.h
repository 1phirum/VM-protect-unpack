/* hdr.h - bounds-checked PE header parser shared by every PE consumer (L0) */
#pragma once

#include <stdint.h>
#include <stddef.h>

enum {
    PEHDR_DIR_EXPORT = 0,
    PEHDR_DIR_IMPORT = 1,
    PEHDR_DIR_RESOURCE = 2,
    PEHDR_DIR_EXCEPTION = 3,
    PEHDR_DIR_SECURITY = 4,
    PEHDR_DIR_BASERELOC = 5,
    PEHDR_DIR_DEBUG = 6,
    PEHDR_DIR_TLS = 9,
    PEHDR_DIR_LOADCONFIG = 10,
    PEHDR_DIR_IAT = 12,
    PEHDR_DIR_BOUNDIMPORT = 11,
    PEHDR_DIR_COUNT = 16
};

typedef struct {
    const uint8_t* data;
    uint64_t       size;
    const uint8_t* nt;
    const uint8_t* opt;
    const uint8_t* sec;
    uint32_t       sec_off;
    uint16_t       machine;
    uint16_t       sections;
    uint16_t       opt_size;
    uint16_t       magic;
    uint32_t       entry;
    uint32_t       size_image;
    uint32_t       headers_size;
    uint32_t       num_dirs;
    uint64_t       image_base;
} pehdr_t;

int            pehdr_parse(const uint8_t* data, uint64_t size, pehdr_t* h);
int            pehdr_is_64(const pehdr_t* h);
const uint8_t* pehdr_section(const pehdr_t* h, uint16_t index);
int            pehdr_rva_to_off(const pehdr_t* h, uint32_t rva, uint32_t* off);
uint32_t       pehdr_dir_rva(const pehdr_t* h, int index);
uint32_t       pehdr_dir_size(const pehdr_t* h, int index);
