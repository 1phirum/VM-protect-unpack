/* pageepoch.c - bounded per-page identity epochs for a live target
 *
 * The region map supplies the committed readable region list; the process
 * reader supplies page bytes. Pages are visited in ascending address order,
 * so the previous table and the fresh enumeration merge in one O(n) pass with
 * two fixed tables and no per-tick allocation. Identity is (state, protect,
 * type, CRC32). A read failure forces an advance and is counted; it is never
 * folded into "unchanged".
 */
#include "unpack/deobf/dynamic/pageepoch/pageepoch.h"
#include "unpack/memory/crc32.h"
#include <stdlib.h>
#include <string.h>

static uint64_t page_align(uint64_t addr) {
    return addr & ~(uint64_t)(PAGE_EPOCH_PAGE - 1);
}

int pageepoch_init(pageepoch_t* pe, uint32_t cap) {
    if (!pe) return -1;
    memset(pe, 0, sizeof(*pe));
    pe->owns = 1;
    if (!cap) cap = PAGE_EPOCH_MAX_PAGES;
    pe->cur = (pageepoch_page_t*)calloc(cap, sizeof(pageepoch_page_t));
    pe->scratch = (pageepoch_page_t*)calloc(cap, sizeof(pageepoch_page_t));
    if (!pe->cur || !pe->scratch) {
        pageepoch_close(pe);
        return -1;
    }
    pe->cap = cap;
    return 0;
}

int pageepoch_init_arena(pageepoch_t* pe, pageepoch_page_t* cur,
                         pageepoch_page_t* scratch, uint32_t cap) {
    if (!pe || !cur || !scratch || !cap) return -1;
    memset(pe, 0, sizeof(*pe));
    pe->cur = cur;
    pe->scratch = scratch;
    pe->cap = cap;
    pe->owns = 0;
    memset(cur, 0, (size_t)cap * sizeof(pageepoch_page_t));
    memset(scratch, 0, (size_t)cap * sizeof(pageepoch_page_t));
    return 0;
}

void pageepoch_close(pageepoch_t* pe) {
    if (!pe) return;
    if (pe->owns) {
        free(pe->cur);
        free(pe->scratch);
    }
    memset(pe, 0, sizeof(*pe));
}

static int read_page_crc(vmpx_proc_reader_t* rd, uint64_t addr, uint32_t* crc) {
    uint8_t page[PAGE_EPOCH_PAGE];
    if (!rd) return -1;
    if (vmpx_proc_reader_read(rd, addr, page, PAGE_EPOCH_PAGE) != 0) return -1;
    *crc = vmpx_crc32(page, PAGE_EPOCH_PAGE);
    return 0;
}

int pageepoch_refresh(pageepoch_t* pe, vmpx_region_map_t* regions,
                      HANDLE proc, vmpx_proc_reader_t* rd) {
    if (!pe || !pe->cur || !pe->scratch) return -1;
    if (!regions || !regions->v || !rd) return -1;
    if (proc && vmpx_region_map_refresh(regions, proc) != 0) return -1;

    uint32_t i = 0;              /* cursor over the previous table */
    uint32_t k = 0;              /* write cursor into scratch */
    uint32_t truncated = 0;
    uint64_t last = 0;           /* last page address emitted */
    int have_last = 0;

    for (uint32_t r = 0; r < regions->count; r++) {
        const vmpx_region_t* reg = &regions->v[r];
        if (!reg->present || reg->state != (uint32_t)MEM_COMMIT) continue;
        if (!vmpx_region_readable(reg->protect)) continue;
        uint64_t end = reg->base + reg->size;
        if (end < reg->base) continue;

        uint64_t addr = page_align(reg->base);
        while (addr < end) {
            /* Adjacent regions can share a partial first page; never revisit
             * an address already emitted this pass. */
            if (have_last && addr <= last) {
                addr += PAGE_EPOCH_PAGE;
                continue;
            }
            if (k >= pe->cap) {
                truncated = 1;
                break;
            }

            uint32_t crc = 0;
            int failed = read_page_crc(rd, addr, &crc) != 0;

            while (i < pe->count && pe->cur[i].addr < addr) i++;
            pageepoch_page_t e;
            int had = 0;
            if (i < pe->count && pe->cur[i].addr == addr) {
                e = pe->cur[i];
                had = 1;
                i++;
            } else {
                memset(&e, 0, sizeof(e));
                e.addr = addr;
            }

            int changed = (!had || !e.present);
            if (!changed && (e.state != reg->state ||
                             e.protect != reg->protect ||
                             e.type != reg->type))
                changed = 1;
            if (!changed && (failed || e.failed)) changed = 1;
            if (!changed && e.crc != crc) changed = 1;

            e.state = reg->state;
            e.protect = reg->protect;
            e.type = reg->type;
            e.present = 1;
            if (failed) {
                e.failed = 1;
                pe->read_failures++;
            } else {
                e.failed = 0;
                e.crc = crc;
            }
            if (changed) {
                e.epoch = ++pe->next_epoch;
                pe->epochs_advanced++;
            }
            pe->scratch[k++] = e;

            last = addr;
            have_last = 1;
            addr += PAGE_EPOCH_PAGE;
        }
        if (truncated) break;
    }

    /* On truncation the unenumerated tail of the prior table is preserved
     * verbatim so epochs already handed out are not revoked. */
    if (truncated) {
        while (i < pe->count && k < pe->cap) pe->scratch[k++] = pe->cur[i++];
    }

    pageepoch_page_t* t = pe->cur;
    pe->cur = pe->scratch;
    pe->scratch = t;
    pe->count = k;
    pe->truncated = truncated;
    pe->refresh_seq++;
    return truncated ? -1 : 0;
}

uint32_t pageepoch_of(const pageepoch_t* pe, uint64_t addr) {
    if (!pe || !pe->cur) return 0;
    uint64_t page = page_align(addr);
    uint32_t lo = 0, hi = pe->count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (pe->cur[mid].addr < page) lo = mid + 1;
        else hi = mid;
    }
    if (lo < pe->count && pe->cur[lo].addr == page) return pe->cur[lo].epoch;
    return 0;
}

void pageepoch_stats(const pageepoch_t* pe, pageepoch_stats_t* out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!pe) return;
    out->pages_tracked = pe->count;
    out->epochs_advanced = pe->epochs_advanced;
    out->read_failures = pe->read_failures;
    out->capacity = pe->cap;
    out->truncated = pe->truncated;
    out->refresh_seq = pe->refresh_seq;
}
