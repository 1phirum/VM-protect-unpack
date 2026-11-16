/* capture.c - private-region snapshot writer (v2) */
#include "unpack/snapshot/snapshot_int.h"

static int write_descriptor(FILE* f, uint32_t index, const snap_meta_t* m) {
    if (!f || !m) return -1;
    if (snap_file_seek(f, m[index].desc_off) != 0) return -1;
    if (snap_file_write(f, &m[index].d, sizeof(m[index].d)) != 0) return -1;
    if (_fseeki64(f, 0, SEEK_END) != 0) return -1;
    return 0;
}

int snap_write(uint32_t pid, uint64_t min_base, const char* out) {
    if (!pid || !out) return -1;

    uint64_t image_base = 0;
    uint32_t image_size = 0;
    proc_mod_t mods[VMPX_SNAP_MAX_MODULES];
    int nmods = proc_modules_snapshot(pid, mods, VMPX_SNAP_MAX_MODULES);
    if (nmods <= 0) {
        printf("[-] snap: module snapshot failed for pid %u\n", pid);
        return -1;
    }
    image_base = mods[0].base;
    image_size = mods[0].size;
    if (proc_main_module(pid, &image_base, &image_size) != 0) {
        image_base = mods[0].base;
        image_size = mods[0].size;
    }
    if (!min_base) min_base = image_base + image_size;

    vmpx_mem_region_t* regions = NULL;
    size_t count = 0;
    if (proc_mem_snapshot(pid, 0, 0x80000000ull, &regions, &count) != 0) {
        printf("[-] snap: memory map failed for pid %u\n", pid);
        return -1;
    }

    snap_meta_t* meta = (snap_meta_t*)calloc(count ? count : 1, sizeof(*meta));
    if (!meta) {
        proc_mem_free(regions);
        return -1;
    }

    size_t n = 0;
    uint64_t total = 0;
    for (size_t i = 0; i < count; i++) {
        const vmpx_mem_region_t* r = &regions[i];
        if (r->state != MEM_COMMIT) continue;
        if (r->type != MEM_PRIVATE) continue;
        if (r->base < min_base) continue;
        if (r->protect & PAGE_GUARD) continue;
        if ((r->protect & 0xFF) == PAGE_NOACCESS) continue;
        if (!r->size || r->size > SNAP_MAX_REGION) continue;

        meta[n].d.base = r->base;
        meta[n].d.size = r->size;
        meta[n].d.protect = r->protect;
        meta[n].d.type = r->type;
        meta[n].d.crc32 = 0;
        meta[n].d.flags = 0;
        total += r->size;
        n++;
    }
    proc_mem_free(regions);

    if (!n) {
        printf("[-] snap: no private regions above 0x%llX\n",
               (unsigned long long)min_base);
        free(meta);
        return -1;
    }

    vmpx_proc_reader_t reader;
    if (vmpx_proc_reader_open(&reader, pid) != 0) {
        printf("[-] snap: OpenProcess failed (%lu)\n", GetLastError());
        free(meta);
        return -1;
    }

    FILE* f = NULL;
    if (fopen_s(&f, out, "wb+") != 0 || !f) {
        printf("[-] snap: cannot create %s\n", out);
        vmpx_proc_reader_close(&reader);
        free(meta);
        return -1;
    }

    vmpx_snap_hdr_t h;
    memset(&h, 0, sizeof(h));
    h.magic = VMPX_SNAP_MAGIC;
    h.version = VMPX_SNAP_VERSION;
    h.region_count = (uint32_t)n;
    h.module_count = (uint32_t)nmods;
    h.image_base = image_base;
    h.image_size = image_size;
    h.data_offset = (uint64_t)sizeof(h) +
                    (uint64_t)n * sizeof(vmpx_snap_region_t) +
                    (uint64_t)nmods * sizeof(vmpx_snap_module_t);

    vmpx_snap_module_t* smods =
        (vmpx_snap_module_t*)calloc((size_t)nmods, sizeof(*smods));
    if (!smods) {
        fclose(f);
        vmpx_proc_reader_close(&reader);
        free(meta);
        return -1;
    }
    for (int i = 0; i < nmods; i++) {
        smods[i].base = (uint32_t)mods[i].base;
        smods[i].size = mods[i].size;
        str_narrow(mods[i].name, smods[i].name, sizeof(smods[i].name));
    }

    int ok = 1;
    if (snap_file_write(f, &h, sizeof(h)) != 0) ok = 0;
    uint64_t desc = sizeof(h);
    for (size_t i = 0; ok && i < n; i++) {
        meta[i].desc_off = (uint32_t)desc;
        desc += sizeof(vmpx_snap_region_t);
        if (snap_file_write(f, &meta[i].d, sizeof(meta[i].d)) != 0) ok = 0;
    }
    for (int i = 0; ok && i < nmods; i++) {
        if (snap_file_write(f, &smods[i], sizeof(smods[i])) != 0) ok = 0;
    }

    uint8_t* chunk = (uint8_t*)malloc(SNAP_CHUNK);
    if (!chunk) ok = 0;
    uint64_t failures = 0;

    for (size_t i = 0; ok && i < n; i++) {
        uint64_t left = meta[i].d.size;
        uint64_t at = meta[i].d.base;
        uint32_t crc = vmpx_crc32_begin();
        int zeroed = 0;
        while (left) {
            size_t want = (size_t)(left > SNAP_CHUNK ? SNAP_CHUNK : left);
            if (vmpx_proc_reader_read(&reader, at, chunk, want) != 0) {
                memset(chunk, 0, want);
                zeroed = 1;
            }
            crc = vmpx_crc32_update(crc, chunk, want);
            if (snap_file_write(f, chunk, want) != 0) {
                ok = 0;
                break;
            }
            at += want;
            left -= want;
        }
        if (!ok) break;
        meta[i].d.crc32 = vmpx_crc32_final(crc);
        if (zeroed) {
            meta[i].d.flags |= VMPX_SNAP_REG_ZERO;
            failures++;
        }
        if (write_descriptor(f, (uint32_t)i, meta) != 0) ok = 0;
    }

    free(chunk);
    free(smods);
    free(meta);
    vmpx_proc_reader_close(&reader);

    if (fclose(f) != 0) ok = 0;
    if (!ok) {
        DeleteFileA(out);
        printf("[-] snap: write failed for %s\n", out);
        return -1;
    }

    printf("[+] snap: %zu regions, %llu bytes, %d modules, %llu zero-filled -> %s\n",
           n, (unsigned long long)total, nmods,
           (unsigned long long)failures, out);
    return 0;
}
