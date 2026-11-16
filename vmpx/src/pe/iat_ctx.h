/* iat_ctx.h - process handle, module ranges, import directory, export caches (L1) */
#pragma once

#include "vmpx.h"
#include "pe/live_exports.h"

typedef struct {
    HANDLE         proc;
    uint32_t       pid;
    uint64_t       base;
    int            is64;
    int            nmods;
    proc_mod_t     mods[IAT_MAX_MODULES];
    live_exports_t exp[IAT_MAX_MODULES];
    uint32_t       imp_rva;
    uint32_t       imp_size;
} iat_ctx_t;

int  iat_ctx_open(iat_ctx_t* c, uint32_t pid, uint64_t base,
                  const uint8_t* file_hdr, uint64_t file_size);
void iat_ctx_close(iat_ctx_t* c);
int  iat_ctx_read(void* user, uint64_t addr, void* buf, size_t len);
int  iat_ctx_module(iat_ctx_t* c, uint64_t addr);
int  iat_ctx_resolve(iat_ctx_t* c, uint64_t addr, char* mod, size_t mod_cap,
                     char* name, size_t name_cap, uint16_t* ordinal,
                     int* by_ordinal);
