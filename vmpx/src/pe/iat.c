/* iat.c - live import recovery: descriptor path (stage B)
 *
 * Reads the runtime IMAGE_IMPORT_DESCRIPTOR array, then resolves every thunk
 * to a module + export name by walking each module's export directory once.
 * No per-slot OpenProcess; one handle lives in iat_ctx_t for the whole parse.
 */
#include "vmpx.h"
#include "pe/iat_ctx.h"
#include "pe/iat_table.h"
#include "util/bin.h"
#include <string.h>

#define IAT_MAX_DESCRIPTORS 512
#define IAT_MAX_THUNKS      8192

int iat_from_live(uint32_t pid, uint64_t base, const uint8_t* file_hdr,
                  uint64_t file_size, iat_table_t* tab) {
    if (!tab) return -1;
    if (!tab->funcs) {
        if (iat_table_init(tab, 0) != 0) return -1;
    } else {
        iat_table_reset(tab);
    }

    iat_ctx_t c;
    if (iat_ctx_open(&c, pid, base, file_hdr, file_size) != 0) return -1;

    int result = 0;
    const size_t step = c.is64 ? 8 : 4;
    if (!c.imp_rva || c.imp_size < 20) goto done;

    uint32_t ndesc = c.imp_size / 20;
    if (ndesc > IAT_MAX_DESCRIPTORS) ndesc = IAT_MAX_DESCRIPTORS;

    for (uint32_t d = 0; d < ndesc; d++) {
        uint8_t desc[20];
        if (iat_ctx_read(&c, base + c.imp_rva + (uint64_t)d * 20, desc, sizeof(desc)) != 0)
            break;
        uint32_t name_rva = bin_rd32(desc + 12);
        uint32_t oft = bin_rd32(desc);
        uint32_t ft = bin_rd32(desc + 16);
        if (!name_rva && !oft && !ft) break;

        char dll[64] = { 0 };
        if (name_rva && iat_ctx_read(&c, base + name_rva, dll, sizeof(dll) - 1) != 0)
            dll[0] = 0;
        if (!dll[0]) continue;

        uint32_t arr = ft ? ft : oft;
        if (!arr) continue;

        int mi = iat_table_add_mod(tab, dll, arr);
        if (mi < 0) break;
        uint32_t first_func = tab->mods[mi].first_func;

        for (uint32_t t = 0; t < IAT_MAX_THUNKS; t++) {
            uint8_t raw[8] = { 0 };
            if (iat_ctx_read(&c, base + arr + (uint64_t)t * step, raw, step) != 0)
                break;
            uint64_t val = c.is64 ? bin_rd64(raw) : (uint64_t)bin_rd32(raw);
            if (!val) break;

            int fi = iat_table_add_func(tab);
            if (fi < 0) break;
            iat_func_t* f = &tab->funcs[fi];

            int is_ordinal = c.is64 ? (val >> 63) != 0 : (val & 0x80000000u) != 0;
            if (is_ordinal) {
                f->ordinal = (uint16_t)(val & 0xFFFF);
                f->by_ordinal = 1;
                f->resolved = 1;
                continue;
            }

            char mod[64] = { 0 }, fn[96] = { 0 };
            uint16_t ord = 0;
            int by_ord = 0;
            if (iat_ctx_resolve(&c, val, mod, sizeof(mod), fn, sizeof(fn),
                                &ord, &by_ord) == 0) {
                strncpy_s(f->name, sizeof(f->name), fn, _TRUNCATE);
                f->ordinal = ord;
                f->by_ordinal = (uint8_t)(by_ord ? 1 : 0);
                f->resolved = 1;
            }
        }

        tab->mods[mi].count = tab->nfuncs - first_func;
        if (tab->mods[mi].count == 0) {
            tab->nmods--;
            continue;
        }
        result++;
    }

done:
    iat_ctx_close(&c);
    return result > 0 ? (int)tab->nfuncs : -1;
}
