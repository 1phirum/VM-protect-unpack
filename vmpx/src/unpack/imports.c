/* imports.c - human-readable reconstruction of the live import table (L2) */
#include "vmpx.h"
#include "pe/hdr.h"
#include "unpack/mempe.h"
#include "util/bin.h"
#include <string.h>

int live_imports(uint32_t pid, uint64_t base, int limit) {
    mempe_t m;
    if (mempe_read(pid, base, &m) != 0) {
        printf("[-] no PE header\n");
        return -1;
    }

    uint8_t hdr[0x1000];
    if (proc_read(pid, base, hdr, sizeof(hdr)) != 0) return -1;
    pehdr_t h;
    if (pehdr_parse(hdr, sizeof(hdr), &h) != 0) {
        printf("[-] live header is not a parseable PE\n");
        return -1;
    }

    uint32_t imp_rva = pehdr_dir_rva(&h, PEHDR_DIR_IMPORT);
    uint32_t imp_size = pehdr_dir_size(&h, PEHDR_DIR_IMPORT);
    if (!imp_rva) {
        printf("[*] import directory is empty\n");
        return 0;
    }
    uint32_t ndesc = imp_size / 20;
    if (!ndesc || ndesc > 512) ndesc = 512;

    const size_t step = pehdr_is_64(&h) ? 8 : 4;
    uint8_t desc[20];
    int total = 0, shown = 0;

    for (uint32_t i = 0; i < ndesc; i++) {
        if (proc_read(pid, base + imp_rva + (uint64_t)i * 20, desc, sizeof(desc)) != 0)
            break;
        uint32_t name_rva = bin_rd32(desc + 12);
        uint32_t oft = bin_rd32(desc);
        uint32_t ft = bin_rd32(desc + 16);
        if (!name_rva && !oft && !ft) break;
        if (!name_rva) continue;

        char mod[256] = { 0 };
        if (proc_read(pid, base + name_rva, mod, sizeof(mod) - 1) != 0) continue;
        printf("\n%s\n", mod);

        uint32_t thunk_rva = oft ? oft : ft;
        if (!thunk_rva) continue;
        for (int t = 0; t < 8192; t++) {
            uint8_t raw[8] = { 0 };
            if (proc_read(pid, base + thunk_rva + (uint64_t)t * step, raw, step) != 0)
                break;
            uint64_t val = pehdr_is_64(&h) ? bin_rd64(raw) : (uint64_t)bin_rd32(raw);
            if (!val) break;
            total++;
            if (shown >= limit) continue;

            int is_ord = pehdr_is_64(&h) ? (val >> 63) != 0 : (val & 0x80000000u) != 0;
            if (is_ord) {
                printf("    #%llu\n", (unsigned long long)(val & 0xFFFF));
            } else {
                char fn[256] = { 0 };
                uint64_t hint = val & 0x7FFFFFFFull;
                if (proc_read(pid, base + hint + 2, fn, sizeof(fn) - 1) == 0)
                    printf("    %s\n", fn);
            }
            shown++;
        }
    }
    printf("\n[+] %d imported functions (live IAT)\n", total);
    return 0;
}
