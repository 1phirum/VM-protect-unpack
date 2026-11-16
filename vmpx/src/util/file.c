/* file.c - whole-file read/write for dumps and rebuilt images (L0) */
#include "util/file.h"
#include "util/bin.h"
#include <windows.h>
#include <stdlib.h>

int file_read_all(const char* path, uint8_t** out, uint64_t* size) {
    if (!path || !out || !size) return -1;
    *out = NULL;
    *size = 0;

    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return -1;

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(f, &sz) || sz.QuadPart <= 0) {
        CloseHandle(f);
        return -1;
    }

    uint8_t* buf = (uint8_t*)malloc((size_t)sz.QuadPart);
    if (!buf) {
        CloseHandle(f);
        return -1;
    }

    uint64_t done = 0;
    while (done < (uint64_t)sz.QuadPart) {
        DWORD want = 0x10000000u;
        uint64_t left = (uint64_t)sz.QuadPart - done;
        if (left < want) want = (DWORD)left;
        DWORD got = 0;
        if (!ReadFile(f, buf + done, want, &got, NULL) || got == 0) {
            free(buf);
            CloseHandle(f);
            return -1;
        }
        done += got;
    }
    CloseHandle(f);
    *out = buf;
    *size = done;
    return 0;
}

int file_write_all(const char* path, const void* data, uint64_t size) {
    if (!path || (!data && size)) return -1;
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return -1;

    const uint8_t* p = (const uint8_t*)data;
    uint64_t done = 0;
    while (done < size) {
        DWORD want = 0x10000000u;
        uint64_t left = size - done;
        if (left < want) want = (DWORD)left;
        DWORD wrote = 0;
        if (!WriteFile(f, p + done, want, &wrote, NULL) || wrote == 0) {
            CloseHandle(f);
            return -1;
        }
        done += wrote;
    }
    CloseHandle(f);
    return 0;
}
