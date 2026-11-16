/* file_writer.h - buffered sequential writer for multi-hundred-MB dumps (L2) */
#pragma once

#include <windows.h>
#include <stdint.h>

typedef struct {
    HANDLE   file;
    uint8_t* buf;
    size_t   cap;
    size_t   len;
    uint64_t written;
    int      failed;
} vmpx_writer_t;

int  vmpx_writer_open(vmpx_writer_t* w, const char* path, size_t cap);
int  vmpx_writer_write(vmpx_writer_t* w, const void* data, size_t len);
int  vmpx_writer_close(vmpx_writer_t* w);
