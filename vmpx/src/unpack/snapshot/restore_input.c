/* restore_input.c - snapshot load, entry-context parse and PE metadata
 *
 * The snapshot is fully read and CRC-checked before the child exists. That
 * keeps a truncated or corrupted capture from leaving a half-restored process
 * behind, and it makes every later mapping decision a preflight decision.
 */
#include "unpack/snapshot/restore_int.h"
#include "util/bin.h"

static uint32_t parse_hex(const char* s) {
    if (!s) return 0;
    while (*s == ' ' || *s == '\t') s++;
    return (uint32_t)strtoul(s, NULL, 0);
}

void restore_input_close(restore_input_t* in) {
    if (!in) return;
    free(in->rd);
    free(in->md);
    free(in->roff);
    free(in->all);
    free(in->region_ok);
    free(in->bmap);
    if (in->f) fclose(in->f);
    memset(in, 0, sizeof(*in));
}

int restore_input_open(const char* snap_path, restore_input_t* in) {
    if (!snap_path || !in) return -1;
    memset(in, 0, sizeof(*in));

    FILE* f = NULL;
    if (fopen_s(&f, snap_path, "rb") != 0 || !f) {
        printf("[-] run: cannot open %s\n", snap_path);
        return -1;
    }
    in->f = f;

    uint64_t fsize = 0;
    if (snap_file_size(f, &fsize) != 0 || snap_file_seek(f, 0) != 0) {
        printf("[-] run: cannot size snapshot\n");
        restore_input_close(in);
        return -1;
    }

    vmpx_snap_hdr_t h;
    if (snap_file_read(f, &h, sizeof(h)) != 0 ||
        h.magic != VMPX_SNAP_MAGIC || h.version != VMPX_SNAP_VERSION ||
        !h.region_count || h.region_count > VMPX_SNAP_MAX_REGIONS ||
        h.module_count > VMPX_SNAP_MAX_MODULES) {
        printf("[-] run: bad snapshot header\n");
        restore_input_close(in);
        return -1;
    }
    in->h = h;

    uint64_t tables = (uint64_t)sizeof(h) +
                      (uint64_t)h.region_count * sizeof(vmpx_snap_region_t) +
                      (uint64_t)h.module_count * sizeof(vmpx_snap_module_t);
    if (h.data_offset < tables || h.data_offset > fsize) {
        printf("[-] run: invalid snapshot data offset\n");
        restore_input_close(in);
        return -1;
    }

    in->rd = (vmpx_snap_region_t*)calloc(h.region_count, sizeof(*in->rd));
    in->md = (vmpx_snap_module_t*)calloc(h.module_count ? h.module_count : 1,
                                         sizeof(*in->md));
    if (!in->rd || !in->md) {
        printf("[-] run: out of memory for snapshot tables\n");
        restore_input_close(in);
        return -1;
    }

    for (uint32_t i = 0; i < h.region_count; i++) {
        if (snap_file_read(f, &in->rd[i], sizeof(in->rd[i])) != 0) {
            printf("[-] run: truncated snapshot\n");
            restore_input_close(in);
            return -1;
        }
    }
    for (uint32_t i = 0; i < h.module_count; i++) {
        if (snap_file_read(f, &in->md[i], sizeof(in->md[i])) != 0) {
            printf("[-] run: truncated snapshot\n");
            restore_input_close(in);
            return -1;
        }
    }
    if (snap_file_seek(f, h.data_offset) != 0) {
        printf("[-] run: truncated snapshot\n");
        restore_input_close(in);
        return -1;
    }

    uint64_t data_total = 0;
    for (uint32_t i = 0; i < h.region_count; i++) {
        if (!in->rd[i].size || in->rd[i].size > SNAP_MAX_REGION) {
            printf("[!] run: invalid region %u base=0x%llX size=0x%llX\n",
                   i, (unsigned long long)in->rd[i].base,
                   (unsigned long long)in->rd[i].size);
            restore_input_close(in);
            return -1;
        }
        if (data_total + in->rd[i].size > (1ull << 31)) {
            printf("[!] run: snapshot payload exceeds the 2 GiB restore cap\n");
            restore_input_close(in);
            return -1;
        }
        data_total += in->rd[i].size;
    }
    in->data_total = data_total;

    in->roff = (uint64_t*)calloc(h.region_count ? h.region_count : 1,
                                 sizeof(*in->roff));
    in->all = (uint8_t*)malloc((size_t)(data_total ? data_total : 1));
    in->region_ok = (uint8_t*)calloc(h.region_count ? h.region_count : 1, 1);
    in->bmap = (uint8_t*)calloc(0x8000, 1);
    if (!in->roff || !in->all || !in->region_ok || !in->bmap) {
        printf("[-] run: out of memory for snapshot restore\n");
        restore_input_close(in);
        return -1;
    }
    memset(in->region_ok, 1, h.region_count ? h.region_count : 1);

    uint64_t at_data = 0;
    for (uint32_t i = 0; i < h.region_count; i++) {
        in->roff[i] = at_data;
        if (snap_file_read(f, in->all + (size_t)at_data,
                           (size_t)in->rd[i].size) != 0) {
            printf("[-] run: snapshot data truncated at region %u\n", i);
            restore_input_close(in);
            return -1;
        }
        uint32_t crc = vmpx_crc32(in->all + (size_t)at_data,
                                  (size_t)in->rd[i].size);
        if (crc != in->rd[i].crc32) {
            printf("[!] run: CRC mismatch region %u at 0x%llX\n",
                   i, (unsigned long long)in->rd[i].base);
            restore_input_close(in);
            return -1;
        }
        at_data += in->rd[i].size;
    }
    return 0;
}

int restore_read_entry_ctx(const char* path, entry_ctx_t* c) {
    if (!path || !c) return -1;
    memset(c, 0, sizeof(*c));
    FILE* f = NULL;
    if (fopen_s(&f, path, "r") != 0 || !f) return -1;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        const char* key = line;
        const char* val = eq + 1;
        if (!strcmp(key, "eip")) c->eip = parse_hex(val);
        else if (!strcmp(key, "esp")) c->esp = parse_hex(val);
        else if (!strcmp(key, "ebp")) c->ebp = parse_hex(val);
        else if (!strcmp(key, "eax")) c->eax = parse_hex(val);
        else if (!strcmp(key, "ebx")) c->ebx = parse_hex(val);
        else if (!strcmp(key, "ecx")) c->ecx = parse_hex(val);
        else if (!strcmp(key, "edx")) c->edx = parse_hex(val);
        else if (!strcmp(key, "esi")) c->esi = parse_hex(val);
        else if (!strcmp(key, "edi")) c->edi = parse_hex(val);
        else if (!strcmp(key, "eflags")) c->eflags = parse_hex(val);
        else if (!strcmp(key, "tid")) c->tid = parse_hex(val);
        else if (!strcmp(key, "pid")) c->pid = parse_hex(val);
    }
    fclose(f);
    /* A context without a stack pointer or a process id cannot be applied:
     * restore_stack_bounds and the TEB lookup both need them. */
    return (c->eip && c->esp && c->pid) ? 0 : -1;
}

int restore_pe_info(const char* exe, restore_pe_t* out) {
    if (!exe || !out) return -1;
    memset(out, 0, sizeof(*out));

    FILE* f = NULL;
    if (fopen_s(&f, exe, "rb") != 0 || !f) return -1;
    uint8_t hdr[0x1000];
    size_t got = fread(hdr, 1, sizeof(hdr), f);
    pehdr_t ph;
    if (!got || pehdr_parse(hdr, got, &ph) != 0) {
        fclose(f);
        return -1;
    }
    out->image_base = ph.image_base;
    out->entry = ph.entry;

    uint32_t tls_rva = pehdr_dir_rva(&ph, PEHDR_DIR_TLS);
    uint32_t tls_size = pehdr_dir_size(&ph, PEHDR_DIR_TLS);
    if (tls_rva && tls_size >= 12) {
        uint32_t off = 0;
        if (pehdr_rva_to_off(&ph, tls_rva, &off) == 0 &&
            _fseeki64(f, (__int64)off, SEEK_SET) == 0) {
            uint8_t tls[12];
            if (fread(tls, 1, sizeof(tls), f) == sizeof(tls)) {
                uint32_t addr = bin_rd32(tls + 8);
                uint32_t base = (uint32_t)ph.image_base;
                if (addr >= base && addr - base < ph.size_image) {
                    out->tls_index_rva = addr - base;
                    out->has_tls = 1;
                }
            }
        }
    }
    fclose(f);
    return 0;
}

uint32_t restore_peek_dword(const restore_input_t* in, uint32_t va) {
    if (!in) return 0;
    for (uint32_t i = 0; i < in->h.region_count; i++) {
        uint64_t base = in->rd[i].base;
        if ((uint64_t)va >= base &&
            (uint64_t)va + 4 <= base + in->rd[i].size)
            return *(const uint32_t*)(in->all + in->roff[i] +
                                      (size_t)(va - base));
    }
    return 0;
}

const uint8_t* restore_peek_ptr(const restore_input_t* in, uint32_t va,
                                uint32_t size) {
    if (!in || !size) return NULL;
    for (uint32_t i = 0; i < in->h.region_count; i++) {
        uint64_t base = in->rd[i].base;
        if ((uint64_t)va >= base &&
            (uint64_t)va + size <= base + in->rd[i].size)
            return in->all + in->roff[i] + (size_t)(va - base);
    }
    return NULL;
}

const uint8_t* restore_find_teb_data(const restore_input_t* in, uint32_t pid,
                                     uint32_t* va_out) {
    if (!in || !pid) return NULL;
    for (uint32_t i = 0; i < in->h.region_count; i++) {
        uint64_t base = in->rd[i].base;
        uint64_t end = base + in->rd[i].size;
        uint64_t p = (base + 0xFFFull) & ~0xFFFull;
        for (; p + 0x40 <= end; p += 0x1000) {
            const uint8_t* page = in->all + in->roff[i] + (size_t)(p - base);
            if (*(const uint32_t*)(page + 0x18) == (uint32_t)p &&
                *(const uint32_t*)(page + 0x20) == pid) {
                if (va_out) *va_out = (uint32_t)p;
                return page;
            }
        }
    }
    return NULL;
}

int restore_stack_bounds(const restore_input_t* in, uint32_t esp,
                         uint32_t* base, uint32_t* limit) {
    if (!in || !base || !limit) return -1;
    *base = 0;
    *limit = 0;
    if (!esp) return -1;
    for (uint32_t i = 0; i < in->h.region_count; i++) {
        uint64_t rb = in->rd[i].base;
        uint64_t re = rb + in->rd[i].size;
        if ((uint64_t)esp >= rb && (uint64_t)esp < re) {
            *base = (uint32_t)(re & ~0xFFFull);
            *limit = (uint32_t)(rb & ~0xFFFull);
        }
    }
    if (!*base) {
        /* The captured stack page is not in the snapshot. Fill a bounded window
         * so the caller can still apply the registers, and return -1 so the run
         * is reported as a degraded restore instead of a clean one. */
        *base = (esp + 0xFFF) & ~0xFFFu;
        *limit = (*base > 0x100000) ? *base - 0x100000 : 0;
        return -1;
    }
    return 0;
}
