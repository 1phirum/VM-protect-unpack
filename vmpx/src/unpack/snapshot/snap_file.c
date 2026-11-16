/* file.c - bounded stdio helpers for the snapshot container */
#include "unpack/snapshot/snapshot_int.h"

int snap_file_write(FILE* f, const void* buf, size_t len) {
    return len == 0 || fwrite(buf, 1, len, f) == len ? 0 : -1;
}

int snap_file_read(FILE* f, void* buf, size_t len) {
    return len == 0 || fread(buf, 1, len, f) == len ? 0 : -1;
}

int snap_file_seek(FILE* f, uint64_t off) {
    return _fseeki64(f, (__int64)off, SEEK_SET) == 0 ? 0 : -1;
}

int snap_file_size(FILE* f, uint64_t* out) {
    if (!out) return -1;
    if (_fseeki64(f, 0, SEEK_END) != 0) return -1;
    __int64 end = _ftelli64(f);
    if (end < 0) return -1;
    *out = (uint64_t)end;
    return 0;
}
