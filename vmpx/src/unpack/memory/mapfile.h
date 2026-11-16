/* mapfile.h - read-only whole-file mapping for large dumps (L2)
 *
 * A 490 MB live image should not be copied into the 32-bit heap. The analyzer
 * maps it read-only and lets the OS page it; all callers get a bounded pointer
 * and size, and a close path that unmaps before closing the handles.
 */
#pragma once

#include <windows.h>
#include <stdint.h>

typedef struct {
    HANDLE         file;
    HANDLE         mapping;
    const uint8_t* data;
    uint64_t       size;
} vmpx_file_map_t;

int  vmpx_file_map_open(const char* path, vmpx_file_map_t* m);
void vmpx_file_map_close(vmpx_file_map_t* m);
int  vmpx_file_map_range(const vmpx_file_map_t* m, uint64_t off, uint64_t len);
