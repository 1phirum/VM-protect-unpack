/* snapshot_int.h - shared snapshot layout, file I/O and rebase internals */
#pragma once

#include "vmpx.h"
#include "unpack/result.h"
#include "unpack/memory/crc32.h"
#include "unpack/memory/peb_modules.h"
#include "unpack/memory/proc_reader.h"
#include "util/str.h"
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SNAP_CHUNK (1u << 20)
#define SNAP_MAX_REGION (256u << 20)

typedef struct {
    vmpx_snap_region_t d;
    uint32_t           desc_off;
} snap_meta_t;

int  snap_file_write(FILE* f, const void* buf, size_t len);
int  snap_file_read(FILE* f, void* buf, size_t len);
int  snap_file_seek(FILE* f, uint64_t off);
int  snap_file_size(FILE* f, uint64_t* out);

void snap_rebase_payload(uint8_t* all, const uint64_t* roff,
                         const vmpx_snap_region_t* rd, uint32_t region_count,
                         const uint16_t* owner,
                         const uint32_t* child_base,
                         const uint32_t* orig_base,
                         const uint32_t* orig_size);

int  snap_debug_enabled(void);
void snap_debug_run(uint32_t pid, HANDLE proc, const uint32_t* orig_base,
                    const uint32_t* orig_size, const uint32_t* child_base,
                    uint32_t module_count, vmpx_run_result_t* result);
