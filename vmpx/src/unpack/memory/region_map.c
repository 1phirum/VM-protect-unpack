/* region_map.c - merge enumeration, generation bumps, readable spans */
#include "unpack/memory/region_map.h"
#include <stdlib.h>
#include <string.h>

#define VMPX_REGION_LIMIT 0x80000000ull

int vmpx_region_map_init(vmpx_region_map_t* m, uint32_t cap) {
    if (!m) return -1;
    memset(m, 0, sizeof(*m));
    if (!cap) cap = 8192;
    m->v = (vmpx_region_t*)calloc(cap, sizeof(vmpx_region_t));
    m->scratch = (vmpx_region_t*)calloc(cap, sizeof(vmpx_region_t));
    m->fresh = (vmpx_region_t*)calloc(cap, sizeof(vmpx_region_t));
    if (!m->v || !m->scratch || !m->fresh) {
        vmpx_region_map_close(m);
        return -1;
    }
    m->cap = cap;
    return 0;
}

void vmpx_region_map_close(vmpx_region_map_t* m) {
    if (!m) return;
    free(m->v);
    free(m->scratch);
    free(m->fresh);
    memset(m, 0, sizeof(*m));
}

int vmpx_region_readable(uint32_t protect) {
    if (protect & PAGE_GUARD) return 0;
    switch (protect & 0xFFu) {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return 1;
    default:
        return 0;
    }
}

static int same_props(const vmpx_region_t* a, const vmpx_region_t* b) {
    return a->size == b->size && a->state == b->state &&
           a->protect == b->protect && a->type == b->type;
}

int vmpx_region_map_apply(vmpx_region_map_t* m, const vmpx_region_t* fresh,
                          uint32_t n) {
    if (!m || !m->v || (n && !fresh)) return -1;
    if (n > m->cap || m->count > m->cap - n) return -1;

    for (uint32_t i = 1; i < n; i++) {
        uint64_t prev_end = fresh[i - 1].base + fresh[i - 1].size;
        if (prev_end < fresh[i - 1].base || fresh[i].base < prev_end)
            return -1;
    }

    uint32_t i = 0, j = 0, k = 0;
    while (i < m->count || j < n) {
        if (i < m->count && j < n && m->v[i].base == fresh[j].base) {
            vmpx_region_t* out = &m->scratch[k++];
            *out = m->v[i];
            if (!out->present || !same_props(out, &fresh[j]))
                out->generation = ++m->next_generation;
            out->size = fresh[j].size;
            out->state = fresh[j].state;
            out->protect = fresh[j].protect;
            out->type = fresh[j].type;
            out->present = 1;
            i++;
            j++;
        } else if (i < m->count &&
                   (j >= n || m->v[i].base < fresh[j].base)) {
            m->scratch[k] = m->v[i];
            m->scratch[k].present = 0;
            k++;
            i++;
        } else {
            m->scratch[k] = fresh[j];
            m->scratch[k].generation = ++m->next_generation;
            m->scratch[k].present = 1;
            k++;
            j++;
        }
    }

    vmpx_region_t* old = m->v;
    m->v = m->scratch;
    m->scratch = old;
    m->count = k;
    m->refresh_seq++;
    return 0;
}

int vmpx_region_map_refresh(vmpx_region_map_t* m, HANDLE proc) {
    if (!m || !m->fresh || !proc) return -1;
    uint32_t n = 0;
    uint64_t addr = 0;
    while (addr < VMPX_REGION_LIMIT) {
        if (n >= m->cap) return -1;
        MEMORY_BASIC_INFORMATION mbi;
        memset(&mbi, 0, sizeof(mbi));
        SIZE_T got = VirtualQueryEx(proc, (LPCVOID)(uintptr_t)addr, &mbi,
                                    sizeof(mbi));
        if (!got) break;
        uint64_t base = (uint64_t)(uintptr_t)mbi.BaseAddress;
        uint64_t size = (uint64_t)mbi.RegionSize;
        if (!size) break;
        if (mbi.State != MEM_FREE) {
            vmpx_region_t* r = &m->fresh[n++];
            memset(r, 0, sizeof(*r));
            r->base = base;
            r->size = size;
            r->state = mbi.State;
            r->protect = mbi.Protect;
            r->type = mbi.Type;
        }
        uint64_t next = base + size;
        if (next <= addr) break;
        addr = next;
    }
    return vmpx_region_map_apply(m, m->fresh, n);
}

const vmpx_region_t* vmpx_region_map_find(const vmpx_region_map_t* m,
                                          uint64_t addr) {
    if (!m || !m->v) return NULL;
    uint32_t lo = 0, hi = m->count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (m->v[mid].base <= addr) lo = mid + 1;
        else hi = mid;
    }
    if (!lo) return NULL;
    const vmpx_region_t* r = &m->v[lo - 1];
    uint64_t end = r->base + r->size;
    if (end < r->base || addr >= end || !r->present) return NULL;
    return r;
}

uint64_t vmpx_region_map_valid_span(const vmpx_region_map_t* m, uint64_t addr) {
    const vmpx_region_t* r = vmpx_region_map_find(m, addr);
    if (!r || r->state != MEM_COMMIT || !vmpx_region_readable(r->protect))
        return 0;
    uint64_t end = r->base + r->size;
    if (end < r->base || addr >= end) return 0;
    return end - addr;
}
