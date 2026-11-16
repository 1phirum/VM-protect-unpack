/* file_writer.c - bounded buffer, partial-write-safe dump writer */
#include "unpack/memory/file_writer.h"
#include <stdlib.h>
#include <string.h>

static int write_raw(vmpx_writer_t* w, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    size_t left = len;
    while (left) {
        DWORD want = (DWORD)(left > 0x10000000u ? 0x10000000u : left);
        DWORD wrote = 0;
        if (!WriteFile(w->file, p, want, &wrote, NULL) || wrote == 0) {
            w->failed = 1;
            return -1;
        }
        p += wrote;
        left -= wrote;
        w->written += wrote;
    }
    return 0;
}

static int flush(vmpx_writer_t* w) {
    if (!w || w->failed) return -1;
    if (!w->len) return 0;
    if (write_raw(w, w->buf, w->len) != 0) return -1;
    w->len = 0;
    return 0;
}

int vmpx_writer_open(vmpx_writer_t* w, const char* path, size_t cap) {
    if (!w || !path) return -1;
    memset(w, 0, sizeof(*w));
    w->file = INVALID_HANDLE_VALUE;
    if (!cap) cap = 4u << 20;
    w->buf = (uint8_t*)malloc(cap);
    if (!w->buf) return -1;
    w->cap = cap;
    w->file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                          FILE_ATTRIBUTE_NORMAL, NULL);
    if (w->file == INVALID_HANDLE_VALUE) {
        free(w->buf);
        w->buf = NULL;
        return -1;
    }
    return 0;
}

int vmpx_writer_write(vmpx_writer_t* w, const void* data, size_t len) {
    if (!w || !data || w->failed) return -1;
    const uint8_t* p = (const uint8_t*)data;
    while (len) {
        if (w->len == w->cap) {
            if (flush(w) != 0) return -1;
        }
        size_t room = w->cap - w->len;
        size_t take = len < room ? len : room;
        memcpy(w->buf + w->len, p, take);
        w->len += take;
        p += take;
        len -= take;
        if (w->len == w->cap && flush(w) != 0) return -1;
    }
    return 0;
}

int vmpx_writer_close(vmpx_writer_t* w) {
    if (!w) return -1;
    int rc = flush(w);
    if (w->file != INVALID_HANDLE_VALUE && w->file) CloseHandle(w->file);
    free(w->buf);
    w->buf = NULL;
    w->file = INVALID_HANDLE_VALUE;
    return rc;
}
