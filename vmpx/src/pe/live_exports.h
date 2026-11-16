/* live_exports.h - export-directory cache for a module mapped in another process (L1) */
#pragma once

#include <stdint.h>
#include <stddef.h>

typedef int (*live_read_fn)(void* user, uint64_t addr, void* buf, size_t len);

typedef struct {
    uint32_t rva;
    char     name[64];
} live_exp_ent_t;

typedef struct {
    int             built;
    uint32_t        count;
    live_exp_ent_t* ents;
    uint32_t        ord_base;
    uint32_t        nfuncs;
    uint32_t*       func_rvas;
} live_exports_t;

int  live_exports_build(live_read_fn read, void* user, uint64_t base, live_exports_t* e);
int  live_exports_lookup(const live_exports_t* e, uint32_t rva, char* name, size_t cap,
                         uint16_t* ordinal, int* by_ordinal);
void live_exports_free(live_exports_t* e);
