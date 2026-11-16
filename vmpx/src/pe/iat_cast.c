/* iat_cast.c - reverse IAT recovery: find pointer runs that resolve to exports (stage B)
 *
 * VMProtect may destroy the descriptor array after load. The slots themselves
 * still hold resolved VAs, so a run of pointers into loaded modules that all
 * name exports is an IAT block. Runs are scored by module dominance; a block
 * is accepted only when every slot resolves and >=60% point into one module.
 */
#include "vmpx.h"
#include "pe/hdr.h"
#include "pe/iat_ctx.h"
#include "pe/iat_table.h"
#include "util/bin.h"
#include "util/str.h"
#include <stdlib.h>
#include <string.h>

#define CAST_RUN_MAX 4096
#define CAST_BUDGET  (96ull << 20)

typedef struct {
    char     name[96];
    uint16_t ordinal;
    uint8_t  by_ordinal;
    int      mod_idx;
} cast_ent_t;

static int run_overlaps(const iat_table_t* tab, uint32_t start, uint32_t end, size_t step) {
    for (uint32_t m = 0; m < tab->nmods; m++) {
        uint64_t a = tab->mods[m].first_thunk;
        uint64_t b = a + (uint64_t)tab->mods[m].count * step;
        if ((uint64_t)start < b && a < (uint64_t)end) return 1;
    }
    return 0;
}

static int try_cast_run(iat_ctx_t* c, uint32_t run_start, const uint64_t* vals,
                        uint32_t n, iat_table_t* tab) {
    const size_t step = c->is64 ? 8 : 4;
    if (n < 8) return 0;
    if (run_overlaps(tab, run_start, (uint32_t)(run_start + (uint64_t)n * step), step))
        return 0;
    if (tab->nfuncs + n > tab->funcs_cap || tab->nmods >= IAT_MAX_MODULES) return 0;

    cast_ent_t* ents = (cast_ent_t*)calloc(n, sizeof(cast_ent_t));
    if (!ents) return 0;

    int freq[IAT_MAX_MODULES] = { 0 };
    int dom = -1, dom_count = 0;

    for (uint32_t i = 0; i < n; i++) {
        int mi = iat_ctx_module(c, vals[i]);
        if (mi < 0) {
            free(ents);
            return 0;
        }
        char mod[64] = { 0 }, fn[96] = { 0 };
        uint16_t ord = 0;
        int by_ord = 0;
        if (iat_ctx_resolve(c, vals[i], mod, sizeof(mod), fn, sizeof(fn),
                            &ord, &by_ord) != 0) {
            free(ents);
            return 0;
        }
        strncpy_s(ents[i].name, sizeof(ents[i].name), fn, _TRUNCATE);
        ents[i].ordinal = ord;
        ents[i].by_ordinal = (uint8_t)(by_ord ? 1 : 0);
        ents[i].mod_idx = mi;
        freq[mi]++;
    }
    for (int mi = 0; mi < c->nmods; mi++) {
        if (freq[mi] > dom_count) {
            dom = mi;
            dom_count = freq[mi];
        }
    }
    if (dom < 0 || (uint64_t)dom_count * 10 < (uint64_t)n * 6) {
        free(ents);
        return 0;
    }

    char dll[64] = { 0 };
    str_narrow_leaf(c->mods[dom].name, dll, sizeof(dll));
    int mi_mod = iat_table_add_mod(tab, dll, run_start);
    if (mi_mod < 0) {
        free(ents);
        return 0;
    }

    for (uint32_t i = 0; i < n; i++) {
        int fi = iat_table_add_func(tab);
        if (fi < 0) break;
        iat_func_t* f = &tab->funcs[fi];
        strncpy_s(f->name, sizeof(f->name), ents[i].name, _TRUNCATE);
        f->ordinal = ents[i].ordinal;
        f->by_ordinal = ents[i].by_ordinal;
        f->resolved = 1;
    }
    tab->mods[mi_mod].count = tab->nfuncs - tab->mods[mi_mod].first_func;
    free(ents);
    return 1;
}

int iat_cast(uint32_t pid, uint64_t base, const uint8_t* file_hdr,
             uint64_t file_size, iat_table_t* tab) {
    if (!tab || !file_hdr) return -1;
    if (!tab->funcs && iat_table_init(tab, 0) != 0) return -1;

    pehdr_t h;
    if (pehdr_parse(file_hdr, file_size, &h) != 0) return -1;

    iat_ctx_t c;
    if (iat_ctx_open(&c, pid, base, file_hdr, file_size) != 0) return -1;

    const size_t step = c.is64 ? 8 : 4;
    uint8_t* buf = (uint8_t*)malloc(65536);
    uint64_t* vals = (uint64_t*)malloc(CAST_RUN_MAX * sizeof(uint64_t));
    if (!buf || !vals) {
        free(buf);
        free(vals);
        iat_ctx_close(&c);
        return -1;
    }

    uint64_t scanned = 0;
    int blocks = 0;

    for (uint16_t s = 0; s < h.sections && scanned < CAST_BUDGET; s++) {
        const uint8_t* sec = pehdr_section(&h, s);
        uint32_t vsize = bin_rd32(sec + 8);
        uint32_t va = bin_rd32(sec + 12);
        uint32_t chars = bin_rd32(sec + 36);
        if (!(chars & 0x80000000u)) continue;       /* writable */
        if (chars & 0x20000000u) continue;          /* executable */
        if (vsize < 32 || vsize > (64u << 20)) continue;

        uint32_t todo = vsize;
        if (scanned + todo > CAST_BUDGET) todo = (uint32_t)(CAST_BUDGET - scanned);

        uint32_t off = 0;
        uint32_t run_start = 0;
        uint32_t run_len = 0;
        int run_bad = 0;

        while (off < todo) {
            uint32_t chunk = todo - off;
            if (chunk > 65536) chunk = 65536;
            if (iat_ctx_read(&c, base + va + off, buf, chunk) != 0) {
                if (run_len && !run_bad)
                    blocks += try_cast_run(&c, run_start, vals, run_len, tab);
                run_len = 0;
                run_bad = 0;
                off += chunk;
                continue;
            }

            uint32_t i = 0;
            for (; i + (uint32_t)step <= chunk; i += (uint32_t)step) {
                uint64_t v = c.is64 ? bin_rd64(buf + i) : (uint64_t)bin_rd32(buf + i);
                uint32_t rva = va + off + i;
                int idx = v && v < 0x100000000ull ? iat_ctx_module(&c, v) : -1;
                if (idx >= 0) {
                    if (run_len == 0) run_start = rva;
                    if (run_len < CAST_RUN_MAX) vals[run_len] = v;
                    else run_bad = 1;
                    run_len++;
                } else {
                    if (run_len && !run_bad)
                        blocks += try_cast_run(&c, run_start, vals, run_len, tab);
                    run_len = 0;
                    run_bad = 0;
                }
            }
            off += chunk;
        }
        if (run_len && !run_bad)
            blocks += try_cast_run(&c, run_start, vals, run_len, tab);
        scanned += todo;
    }

    free(buf);
    free(vals);
    iat_ctx_close(&c);
    return blocks;
}
