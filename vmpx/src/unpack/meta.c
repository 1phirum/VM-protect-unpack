/* meta.c - dump sidecar metadata, key=value text, versioned (L2) */
#include "vmpx.h"
#include <stdio.h>
#include <string.h>

static int meta_path(const char* dump_path, char* out, size_t cap) {
    if (!dump_path || !out || cap == 0) return -1;
    int n = _snprintf_s(out, cap, _TRUNCATE, "%s.meta", dump_path);
    return n > 0 ? 0 : -1;
}

int dump_meta_write(const char* dump_path, const vmpx_dump_meta_t* meta) {
    if (!dump_path || !meta) return -1;
    char path[MAX_PATH * 2];
    if (meta_path(dump_path, path, sizeof(path)) != 0) return -1;

    FILE* f = NULL;
    if (fopen_s(&f, path, "w") != 0 || !f) return -1;
    fprintf(f, "VXDM %u\n", VMPX_DUMP_VERSION);
    fprintf(f, "pid=%u\n", meta->pid);
    fprintf(f, "base=0x%llX\n", (unsigned long long)meta->base);
    fprintf(f, "module_size=0x%X\n", meta->module_size);
    fprintf(f, "dump_size=0x%llX\n", (unsigned long long)meta->dump_size);
    fprintf(f, "image_size=0x%llX\n", (unsigned long long)meta->image_size);
    fclose(f);
    return 0;
}

int dump_meta_read(const char* dump_path, vmpx_dump_meta_t* meta) {
    if (!dump_path || !meta) return -1;
    char path[MAX_PATH * 2];
    if (meta_path(dump_path, path, sizeof(path)) != 0) return -1;

    FILE* f = NULL;
    if (fopen_s(&f, path, "r") != 0 || !f) return -1;

    memset(meta, 0, sizeof(*meta));
    char line[256];
    int version = 0;
    if (!fgets(line, sizeof(line), f) ||
        sscanf_s(line, "VXDM %d", &version) != 1 || version != (int)VMPX_DUMP_VERSION) {
        fclose(f);
        return -1;
    }

    while (fgets(line, sizeof(line), f)) {
        unsigned u = 0;
        unsigned long long v = 0;
        if (sscanf_s(line, "pid=%u", &u) == 1) meta->pid = u;
        else if (sscanf_s(line, "base=0x%llX", &v) == 1) meta->base = v;
        else if (sscanf_s(line, "module_size=0x%X", &u) == 1) meta->module_size = u;
        else if (sscanf_s(line, "dump_size=0x%llX", &v) == 1) meta->dump_size = v;
        else if (sscanf_s(line, "image_size=0x%llX", &v) == 1) meta->image_size = v;
    }
    fclose(f);

    meta->magic = VMPX_DUMP_MAGIC;
    meta->version = VMPX_DUMP_VERSION;
    return 0;
}
