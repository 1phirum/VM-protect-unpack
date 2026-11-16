/* live_exports.c - export-directory cache for a module mapped in another process (L1)
 *
 * The export tables are read once per module. Resolution of an IAT slot is then
 * a binary search over export RVAs, so a 23k-slot IAT does not re-walk the
 * export directory 23k times.
 */
#include "pe/live_exports.h"
#include "pe/hdr.h"
#include "util/bin.h"
#include <stdlib.h>
#include <string.h>

#define EXP_MAX_NAMES 65536u
#define EXP_MAX_SIZE  (16u << 20)

static int exp_cmp(const void* a, const void* b) {
    uint32_t ra = ((const live_exp_ent_t*)a)->rva;
    uint32_t rb = ((const live_exp_ent_t*)b)->rva;
    return ra < rb ? -1 : ra > rb ? 1 : 0;
}

static int read_hdr(live_read_fn read, void* user, uint64_t base, pehdr_t* h) {
    uint8_t hdr[0x1000];
    if (read(user, base, hdr, sizeof(hdr)) != 0) return -1;
    return pehdr_parse(hdr, sizeof(hdr), h);
}

int live_exports_build(live_read_fn read, void* user, uint64_t base, live_exports_t* e) {
    if (!read || !e) return -1;
    if (e->built) return (int)e->count;
    e->built = 1;

    pehdr_t h;
    if (read_hdr(read, user, base, &h) != 0) return -1;
    uint32_t exp_rva = pehdr_dir_rva(&h, PEHDR_DIR_EXPORT);
    uint32_t exp_size = pehdr_dir_size(&h, PEHDR_DIR_EXPORT);
    if (!exp_rva || exp_size < 40 || exp_size > EXP_MAX_SIZE) return -1;

    uint8_t ed[40];
    if (read(user, base + exp_rva, ed, sizeof(ed)) != 0) return -1;
    uint32_t nfuncs = bin_rd32(ed + 20);
    uint32_t nnames = bin_rd32(ed + 24);
    uint32_t funcs_rva = bin_rd32(ed + 28);
    uint32_t names_rva = bin_rd32(ed + 32);
    uint32_t ords_rva = bin_rd32(ed + 36);
    if (nfuncs > EXP_MAX_NAMES || nnames > EXP_MAX_NAMES) return -1;

    uint32_t* funcs = nfuncs ? (uint32_t*)malloc((size_t)nfuncs * 4) : NULL;
    uint32_t* names = nnames ? (uint32_t*)malloc((size_t)nnames * 4) : NULL;
    uint16_t* ords = nnames ? (uint16_t*)malloc((size_t)nnames * 2) : NULL;
    live_exp_ent_t* ents = (live_exp_ent_t*)calloc(nnames ? nnames : 1, sizeof(live_exp_ent_t));
    if ((nfuncs && !funcs) || (nnames && (!names || !ords)) || !ents) {
        free(funcs);
        free(names);
        free(ords);
        free(ents);
        return -1;
    }

    if (nfuncs && read(user, base + funcs_rva, funcs, (size_t)nfuncs * 4) != 0) goto fail;
    if (nnames && (read(user, base + names_rva, names, (size_t)nnames * 4) != 0 ||
                   read(user, base + ords_rva, ords, (size_t)nnames * 2) != 0)) goto fail;

    uint32_t kept = 0;
    for (uint32_t i = 0; i < nnames; i++) {
        uint16_t ord = ords[i];
        if (ord >= nfuncs) continue;
        char nm[64] = { 0 };
        if (read(user, base + names[i], nm, sizeof(nm) - 1) != 0) continue;
        ents[kept].rva = funcs[ord];
        strncpy_s(ents[kept].name, sizeof(ents[kept].name), nm, _TRUNCATE);
        kept++;
    }

    qsort(ents, kept, sizeof(live_exp_ent_t), exp_cmp);
    e->ents = ents;
    e->count = kept;
    e->ord_base = bin_rd32(ed + 16);
    e->nfuncs = nfuncs;
    e->func_rvas = funcs;
    free(names);
    free(ords);
    return (int)kept;

fail:
    free(funcs);
    free(names);
    free(ords);
    free(ents);
    return -1;
}

int live_exports_lookup(const live_exports_t* e, uint32_t rva, char* name, size_t cap,
                        uint16_t* ordinal, int* by_ordinal) {
    if (!e || !name || cap == 0) return -1;
    name[0] = 0;
    if (e->count) {
        live_exp_ent_t key;
        key.rva = rva;
        const live_exp_ent_t* hit = (const live_exp_ent_t*)bsearch(
            &key, e->ents, e->count, sizeof(live_exp_ent_t), exp_cmp);
        if (hit) {
            strncpy_s(name, cap, hit->name, _TRUNCATE);
            if (ordinal) *ordinal = 0;
            if (by_ordinal) *by_ordinal = 0;
            return 0;
        }
    }
    for (uint32_t i = 0; i < e->nfuncs; i++) {
        if (e->func_rvas && e->func_rvas[i] == rva) {
            if (ordinal) *ordinal = (uint16_t)(e->ord_base + i);
            if (by_ordinal) *by_ordinal = 1;
            return 0;
        }
    }
    return -1;
}

void live_exports_free(live_exports_t* e) {
    if (!e) return;
    free(e->ents);
    free(e->func_rvas);
    memset(e, 0, sizeof(*e));
}
