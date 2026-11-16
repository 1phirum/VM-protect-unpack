/* mapfile.c - read-only whole-file mapping with strict handle cleanup */
#include "unpack/memory/mapfile.h"
#include <string.h>

int vmpx_file_map_open(const char* path, vmpx_file_map_t* m) {
    if (!path || !m) return -1;
    memset(m, 0, sizeof(*m));
    m->file = INVALID_HANDLE_VALUE;

    HANDLE f = CreateFileA(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return -1;

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(f, &sz) || sz.QuadPart <= 0) {
        CloseHandle(f);
        return -1;
    }
    uint64_t size = (uint64_t)sz.QuadPart;
    if (size > (uint64_t)SIZE_MAX) {        /* 32-bit analyzer address space */
        CloseHandle(f);
        return -1;
    }

    HANDLE map = CreateFileMappingA(f, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!map) {
        CloseHandle(f);
        return -1;
    }
    const uint8_t* p = (const uint8_t*)MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    if (!p) {
        CloseHandle(map);
        CloseHandle(f);
        return -1;
    }

    m->file = f;
    m->mapping = map;
    m->data = p;
    m->size = size;
    return 0;
}

void vmpx_file_map_close(vmpx_file_map_t* m) {
    if (!m) return;
    if (m->data) UnmapViewOfFile((LPCVOID)m->data);
    if (m->mapping) CloseHandle(m->mapping);
    if (m->file != INVALID_HANDLE_VALUE && m->file) CloseHandle(m->file);
    memset(m, 0, sizeof(*m));
    m->file = INVALID_HANDLE_VALUE;
}

int vmpx_file_map_range(const vmpx_file_map_t* m, uint64_t off, uint64_t len) {
    if (!m || !m->data) return -1;
    if (off > m->size) return -1;
    if (len > m->size - off) return -1;
    return 0;
}
