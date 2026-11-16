/* proc_reader.h - one-handle cross-process reader with explicit partial reads */
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stddef.h>

typedef struct {
    HANDLE   proc;
    uint32_t pid;
    uint64_t read_chunk;
    uint64_t total_read;
    uint64_t failed_reads;
} vmpx_proc_reader_t;

typedef struct {
    uint64_t addr;
    uint64_t requested;
    uint64_t read;
    uint64_t valid_span;
    DWORD    error;
    uint32_t partial;
} vmpx_read_result_t;

int  vmpx_proc_reader_open(vmpx_proc_reader_t* r, uint32_t pid);
int  vmpx_proc_reader_read(vmpx_proc_reader_t* r, uint64_t addr, void* buf,
                           size_t len);
int  vmpx_proc_reader_read_ex(vmpx_proc_reader_t* r, uint64_t addr, void* buf,
                              size_t len, vmpx_read_result_t* out);
void vmpx_proc_reader_close(vmpx_proc_reader_t* r);
