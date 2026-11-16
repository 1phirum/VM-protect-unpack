/* pe.c - file-backed PE parsing: headers, sections, entropy, imports (L0) */
#include "vmpx.h"
#include "pe/hdr.h"
#include "util/bin.h"
#include <math.h>
#include <string.h>

static int pe_header(const pe_t* pe, pehdr_t* h) {
    if (!pe || !pe->data) return -1;
    return pehdr_parse(pe->data, pe->size, h);
}

int pe_load(const char* path, pe_t* pe) {
    if (!path || !pe) return -1;
    memset(pe, 0, sizeof(*pe));
    pe->file = INVALID_HANDLE_VALUE;

    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        printf("[-] open failed: %lu\n", GetLastError());
        return -1;
    }
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(f, &sz) || sz.QuadPart < 64) {
        printf("[-] file too small or unreadable\n");
        CloseHandle(f);
        return -1;
    }
    HANDLE m = CreateFileMappingA(f, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!m) {
        printf("[-] mapping failed: %lu\n", GetLastError());
        CloseHandle(f);
        return -1;
    }
    const uint8_t* p = (const uint8_t*)MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
    if (!p) {
        printf("[-] MapViewOfFile failed: %lu\n", GetLastError());
        CloseHandle(m);
        CloseHandle(f);
        return -1;
    }
    pe->file = f;
    pe->map = m;
    pe->data = p;
    pe->size = (uint64_t)sz.QuadPart;
    return 0;
}

void pe_free(pe_t* pe) {
    if (!pe) return;
    if (pe->data) UnmapViewOfFile(pe->data);
    if (pe->map) CloseHandle(pe->map);
    if (pe->file != INVALID_HANDLE_VALUE && pe->file) CloseHandle(pe->file);
    memset(pe, 0, sizeof(*pe));
    pe->file = INVALID_HANDLE_VALUE;
}

uint32_t pe_entry_rva(const pe_t* pe) {
    pehdr_t h;
    return pe_header(pe, &h) == 0 ? h.entry : 0;
}

uint32_t pe_size_of_image(const pe_t* pe) {
    pehdr_t h;
    return pe_header(pe, &h) == 0 ? h.size_image : 0;
}

uint64_t pe_image_base(const pe_t* pe) {
    pehdr_t h;
    return pe_header(pe, &h) == 0 ? h.image_base : 0;
}

static double entropy(const uint8_t* p, size_t n) {
    if (!p || n == 0) return 0.0;
    size_t freq[256] = { 0 };
    for (size_t i = 0; i < n; i++) freq[p[i]]++;
    double e = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!freq[i]) continue;
        double q = (double)freq[i] / (double)n;
        e -= q * (log(q) / log(2.0));
    }
    return e;
}

static int is_section(const uint8_t* sec, const char* name) {
    size_t n = strlen(name);
    if (n > 8) n = 8;
    return memcmp(sec, name, n) == 0;
}

int pe_info(const pe_t* pe) {
    pehdr_t h;
    if (pe_header(pe, &h) != 0) {
        printf("[-] not a valid PE\n");
        return -1;
    }

    printf("file        : %llu bytes\n", (unsigned long long)pe->size);
    printf("machine     : %s (0x%04X)\n",
           h.machine == 0x14C ? "x86" : h.machine == 0x8664 ? "x64" : "other", h.machine);
    printf("magic       : 0x%03X (%s)\n", h.magic, pehdr_is_64(&h) ? "PE32+" : "PE32");
    printf("image base  : 0x%llX\n", (unsigned long long)h.image_base);
    printf("entry point : RVA 0x%X  VA 0x%llX\n", h.entry,
           (unsigned long long)(h.image_base + h.entry));
    printf("image size  : 0x%X (%u MB)\n", h.size_image, h.size_image >> 20);
    printf("sections    : %u\n", h.sections);
    printf("\n%-10s %-12s %-12s %-12s %-12s %-8s\n",
           "name", "VA", "VSIZE", "RAWSIZE", "RAWPTR", "ENTROPY");
    for (uint16_t i = 0; i < h.sections; i++) {
        const uint8_t* s = pehdr_section(&h, i);
        char name[9] = { 0 };
        memcpy(name, s, 8);
        uint32_t vsize = bin_rd32(s + 8);
        uint32_t va = bin_rd32(s + 12);
        uint32_t rawsz = bin_rd32(s + 16);
        uint32_t rawpt = bin_rd32(s + 20);
        uint32_t chars = bin_rd32(s + 36);
        size_t cap = rawsz > (8u << 20) ? (8u << 20) : rawsz;
        const uint8_t* data = NULL;
        if (rawpt && (uint64_t)rawpt + cap <= pe->size) data = pe->data + rawpt;
        double e = data ? entropy(data, cap) : 0.0;
        printf("%-10s 0x%-10X 0x%-10X 0x%-10X 0x%-10X %.3f%s\n",
               name, va, vsize, rawsz, rawpt, e,
               (chars & 0x20000000) ? "  [X]" : (chars & 0x80000000) ? "  [W]" : "");
    }

    const char* markers[] = { ".vmp0", ".vmp1", ".vmp2", ".themida", ".winlice",
                              ".enigma", ".aspack", ".upx0", ".packed" };
    printf("\nprotection markers: ");
    int found = 0;
    for (size_t m = 0; m < sizeof(markers) / sizeof(markers[0]); m++) {
        for (uint16_t i = 0; i < h.sections; i++) {
            if (is_section(pehdr_section(&h, i), markers[m])) {
                printf("%s ", markers[m]);
                found = 1;
                break;
            }
        }
    }
    printf("%s\n", found ? "" : "none matched (check entropy above)");
    return 0;
}

static size_t bounded_len(const uint8_t* p, uint64_t max) {
    size_t n = 0;
    while (n < max && p[n]) n++;
    return n;
}

int pe_imports(const pe_t* pe, int limit) {
    pehdr_t h;
    if (pe_header(pe, &h) != 0) return -1;
    uint32_t imp_rva = pehdr_dir_rva(&h, PEHDR_DIR_IMPORT);
    uint32_t imp_size = pehdr_dir_size(&h, PEHDR_DIR_IMPORT);
    if (!imp_rva) {
        printf("[*] no import directory\n");
        return 0;
    }
    const size_t step = pehdr_is_64(&h) ? 8 : 4;

    uint32_t off = 0;
    if (pehdr_rva_to_off(&h, imp_rva, &off) != 0 || off >= pe->size) {
        printf("[-] import dir RVA not mapped\n");
        return -1;
    }

    uint32_t ndesc = imp_size / 20;
    if (!ndesc || ndesc > 512) ndesc = 512;

    int modules = 0, total = 0, shown = 0;
    for (uint32_t d = 0; d < ndesc; d++) {
        uint64_t doff = (uint64_t)off + (uint64_t)d * 20;
        if (doff + 20 > pe->size) break;
        const uint8_t* desc = pe->data + doff;
        uint32_t name_rva = bin_rd32(desc + 12);
        if (!name_rva) break;

        uint32_t name_off = 0;
        if (pehdr_rva_to_off(&h, name_rva, &name_off) != 0 || name_off >= pe->size) break;
        size_t name_len = bounded_len(pe->data + name_off, pe->size - name_off);
        printf("\n%.*s\n", (int)name_len, (const char*)(pe->data + name_off));

        uint32_t oft = bin_rd32(desc);
        uint32_t ft = bin_rd32(desc + 16);
        uint32_t thunk_rva = oft ? oft : ft;
        uint32_t thunk_off = 0;
        if (!thunk_rva || pehdr_rva_to_off(&h, thunk_rva, &thunk_off) != 0) {
            modules++;
            continue;
        }

        for (int i = 0; i < 8192; i++) {
            uint64_t t = (uint64_t)thunk_off + (uint64_t)i * step;
            if (t + step > pe->size) break;
            uint64_t val = pehdr_is_64(&h) ? bin_rd64(pe->data + t)
                                           : (uint64_t)bin_rd32(pe->data + t);
            if (!val) break;
            total++;
            int is_ord = pehdr_is_64(&h) ? (val >> 63) != 0 : (val & 0x80000000u) != 0;
            if (shown < limit) {
                if (is_ord) {
                    printf("    #%llu\n", (unsigned long long)(val & 0xFFFF));
                } else {
                    uint32_t hint_off = 0;
                    if (pehdr_rva_to_off(&h, (uint32_t)(val & 0x7FFFFFFF), &hint_off) == 0 &&
                        (uint64_t)hint_off + 2 < pe->size) {
                        const uint8_t* nm = pe->data + hint_off + 2;
                        size_t len = bounded_len(nm, pe->size - (hint_off + 2));
                        printf("    %.*s\n", (int)len, (const char*)nm);
                    }
                }
            }
            shown++;
        }
        modules++;
    }
    printf("\n[+] %d modules, %d imported functions\n", modules, total);
    return 0;
}
