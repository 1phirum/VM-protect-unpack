/* iat_table.c - caller-owned import table (modules + funcs) (L1) */
#include "pe/iat_table.h"
#include <string.h>

int iat_table_init(iat_table_t* tab, uint32_t func_cap) {
    if (!tab) return -1;
    memset(tab, 0, sizeof(*tab));
    if (func_cap == 0 || func_cap > IAT_MAX_FUNCS) func_cap = IAT_MAX_FUNCS;
    tab->funcs = (iat_func_t*)calloc(func_cap, sizeof(iat_func_t));
    if (!tab->funcs) return -1;
    tab->funcs_cap = func_cap;
    return 0;
}

void iat_table_reset(iat_table_t* tab) {
    if (!tab) return;
    tab->nmods = 0;
    tab->nfuncs = 0;
    if (tab->funcs && tab->funcs_cap)
        memset(tab->funcs, 0, (size_t)tab->funcs_cap * sizeof(iat_func_t));
}

void iat_table_free(iat_table_t* tab) {
    if (!tab) return;
    free(tab->funcs);
    memset(tab, 0, sizeof(*tab));
}

int iat_table_add_mod(iat_table_t* tab, const char* dll, uint32_t first_thunk) {
    if (!tab || !dll || tab->nmods >= IAT_MAX_MODULES) return -1;
    iat_mod_t* m = &tab->mods[tab->nmods];
    memset(m, 0, sizeof(*m));
    strncpy_s(m->dll, sizeof(m->dll), dll, _TRUNCATE);
    m->first_thunk = first_thunk;
    m->first_func = tab->nfuncs;
    return (int)tab->nmods++;
}

int iat_table_add_func(iat_table_t* tab) {
    if (!tab || !tab->funcs || tab->nfuncs >= tab->funcs_cap ||
        tab->nfuncs >= IAT_MAX_FUNCS)
        return -1;
    memset(&tab->funcs[tab->nfuncs], 0, sizeof(iat_func_t));
    return (int)tab->nfuncs++;
}

uint32_t iat_table_unresolved(const iat_table_t* tab) {
    if (!tab || !tab->funcs) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < tab->nfuncs; i++)
        if (!tab->funcs[i].resolved) n++;
    return n;
}
