/* memory_test.c - budget, arena, region generations and partial reads */
#include "unpack/memory/arena.h"
#include "unpack/memory/budget.h"
#include "unpack/memory/proc_reader.h"
#include "unpack/memory/region_map.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
static volatile uint32_t probe_word = 0x12345678u;

#define CHECK(cond) do {                                              \
    if (!(cond)) {                                                    \
        printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);         \
        failures++;                                                   \
    }                                                                 \
} while (0)

static void test_budget(void) {
    vmpx_budget_t b;
    vmpx_budget_init(&b, 1000, 100, 64);
    CHECK(vmpx_budget_available(&b, 0) == 1000);
    CHECK(vmpx_budget_chunk(&b, 4096) == 64);
    CHECK(vmpx_budget_charge(&b, 0, 100) == 0);
    CHECK(b.host_used == 100 && b.host_peak == 100);
    CHECK(vmpx_budget_available(&b, 0) == 900);
    CHECK(vmpx_budget_charge(&b, 0, 901) != 0);
    CHECK(b.host_used == 100 && b.host_refused == 1);
    CHECK(vmpx_budget_charge(&b, 1, 101) != 0);
    CHECK(vmpx_budget_charge(&b, 1, 100) == 0);
    CHECK(vmpx_budget_available(&b, 1) == 0);
    vmpx_budget_release(&b, 0, 1000);
    CHECK(b.host_used == 0);
    vmpx_budget_release(&b, 0, 1);
    CHECK(b.host_used == 0);

    vmpx_budget_init(&b, UINT64_MAX, 0, 0);
    b.host_used = UINT64_MAX - 10;
    CHECK(vmpx_budget_charge(&b, 0, 11) != 0);
    CHECK(vmpx_budget_charge(&b, 0, 10) == 0);
    CHECK(vmpx_budget_available(&b, 0) == 0);
}

static void test_arena(void) {
    vmpx_arena_t a;
    CHECK(vmpx_arena_init(&a, 4096, 8192) == 0);
    void* p1 = vmpx_arena_alloc(&a, 16, 16);
    void* p2 = vmpx_arena_alloc(&a, 16, 8);
    CHECK(p1 && p2 && p1 != p2);
    CHECK(((uintptr_t)p1 & 15u) == 0);
    CHECK(((uintptr_t)p2 & 7u) == 0);
    CHECK(vmpx_arena_alloc(&a, 9000, 8) == NULL);
    CHECK(a.refused == 1);
    CHECK(vmpx_arena_alloc(&a, 0, 8) == NULL);
    CHECK(vmpx_arena_alloc(&a, 16, 3) == NULL);
    vmpx_arena_reset(&a);
    CHECK(a.used == 0);
    CHECK(vmpx_arena_alloc(&a, 32, 16) != NULL);
    vmpx_arena_destroy(&a);
    CHECK(a.head == NULL && a.blocks == 0);
}

static vmpx_region_t reg(uint64_t base, uint64_t size, uint32_t state,
                         uint32_t protect, uint32_t type) {
    vmpx_region_t r;
    memset(&r, 0, sizeof(r));
    r.base = base;
    r.size = size;
    r.state = state;
    r.protect = protect;
    r.type = type;
    return r;
}

static void test_regions(void) {
    vmpx_region_map_t m;
    CHECK(vmpx_region_map_init(&m, 8) == 0);

    vmpx_region_t f1[2] = {
        reg(0x1000, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE),
        reg(0x3000, 0x2000, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE),
    };
    CHECK(vmpx_region_map_apply(&m, f1, 2) == 0);
    CHECK(m.count == 2 && m.next_generation == 2);
    const vmpx_region_t* r = vmpx_region_map_find(&m, 0x1800);
    CHECK(r && r->generation == 1);
    CHECK(vmpx_region_map_valid_span(&m, 0x1800) == 0x800);
    CHECK(vmpx_region_map_find(&m, 0x2000) == NULL);

    vmpx_region_t f2[1] = {
        reg(0x1000, 0x2000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE),
    };
    CHECK(vmpx_region_map_apply(&m, f2, 1) == 0);
    r = vmpx_region_map_find(&m, 0x1000);
    CHECK(r && r->generation == 3 && r->size == 0x2000);
    CHECK(vmpx_region_map_find(&m, 0x3000) == NULL); /* present=0 */
    CHECK(vmpx_region_map_valid_span(&m, 0x3000) == 0);

    vmpx_region_t f3[1] = {
        reg(0x3000, 0x2000, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE),
    };
    CHECK(vmpx_region_map_apply(&m, f3, 1) == 0);
    r = vmpx_region_map_find(&m, 0x3000);
    CHECK(r && r->generation == 4);

    vmpx_region_t f4[1] = {
        reg(0x5000, 0x1000, MEM_COMMIT, PAGE_NOACCESS, MEM_PRIVATE),
    };
    CHECK(vmpx_region_map_apply(&m, f4, 1) == 0);
    CHECK(vmpx_region_map_find(&m, 0x5000) != NULL);
    CHECK(vmpx_region_map_valid_span(&m, 0x5000) == 0);
    CHECK(vmpx_region_map_valid_span(&m, 0x9000) == 0);

    vmpx_region_t bad[2] = {
        reg(0x7000, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE),
        reg(0x6000, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE),
    };
    CHECK(vmpx_region_map_apply(&m, bad, 2) != 0);

    vmpx_region_map_t small;
    CHECK(vmpx_region_map_init(&small, 2) == 0);
    CHECK(vmpx_region_map_apply(&small, f1, 2) == 0);
    vmpx_region_t three[3] = {
        reg(0x1000, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE),
        reg(0x3000, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE),
        reg(0x5000, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE),
    };
    CHECK(vmpx_region_map_apply(&small, three, 3) != 0);
    CHECK(small.count == 2);
    vmpx_region_map_close(&small);

    vmpx_region_map_t live;
    CHECK(vmpx_region_map_init(&live, 8192) == 0);
    CHECK(vmpx_region_map_refresh(&live, GetCurrentProcess()) == 0);
    CHECK(live.count > 0);
    uint64_t span = vmpx_region_map_valid_span(
        &live, (uint64_t)(uintptr_t)&probe_word);
    CHECK(span >= sizeof(probe_word));
    vmpx_region_map_close(&live);
    vmpx_region_map_close(&m);
}

static void test_reader(void) {
    vmpx_proc_reader_t r;
    CHECK(vmpx_proc_reader_open(&r, GetCurrentProcessId()) == 0);

    uint32_t value = 0;
    CHECK(vmpx_proc_reader_read(&r, (uint64_t)(uintptr_t)&probe_word, &value,
                                sizeof(value)) == 0);
    CHECK(value == probe_word);

    vmpx_read_result_t rr;
    memset(&rr, 0xAA, sizeof(rr));
    uint8_t buf[8];
    CHECK(vmpx_proc_reader_read_ex(&r, 0, buf, sizeof(buf), &rr) != 0);
    CHECK(rr.read == 0 && rr.partial == 0);
    CHECK(rr.error != 0);
    CHECK(rr.valid_span == 0);
    CHECK(vmpx_proc_reader_read_ex(&r, 0, buf, 0, &rr) != 0);
    CHECK(vmpx_proc_reader_read(&r, 0, buf, sizeof(buf)) != 0);

    CHECK(vmpx_proc_reader_read_ex(&r, (uint64_t)(uintptr_t)&probe_word, &value,
                                   sizeof(value), &rr) == 0);
    CHECK(rr.read == sizeof(value) && rr.requested == sizeof(value));
    CHECK(rr.valid_span >= sizeof(value));
    CHECK(value == probe_word);

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    size_t page = si.dwPageSize;
    uint8_t* mem = (uint8_t*)VirtualAlloc(NULL, page * 2, MEM_COMMIT |
                                          MEM_RESERVE, PAGE_READWRITE);
    CHECK(mem != NULL);
    uint8_t* cross = (uint8_t*)malloc(page + 16);
    CHECK(cross != NULL);
    if (mem && cross) {
        memset(mem, 0x5A, page);
        DWORD old = 0;
        CHECK(VirtualProtect(mem + page, page, PAGE_NOACCESS, &old) != 0);
        memset(cross, 0, page + 16);
        CHECK(vmpx_proc_reader_read_ex(
                  &r, (uint64_t)(uintptr_t)mem, cross, page + 16, &rr) != 0);
        CHECK(rr.read == page);
        CHECK(rr.partial == 1);
        CHECK(rr.valid_span >= page);
        CHECK(cross[0] == 0x5A && cross[page - 1] == 0x5A);
        CHECK(vmpx_proc_reader_read_ex(
                  &r, (uint64_t)(uintptr_t)(mem + page), cross, 16, &rr) != 0);
        CHECK(rr.read == 0 && rr.error == ERROR_NOACCESS);
    }
    free(cross);
    if (mem) VirtualFree(mem, 0, MEM_RELEASE);

    vmpx_proc_reader_close(&r);
    CHECK(r.proc == NULL && r.pid == 0);
}

int main(void) {
    test_budget();
    test_arena();
    test_regions();
    test_reader();
    if (failures) {
        printf("memory_test: %d failure(s)\n", failures);
        return 1;
    }
    printf("memory_test: ok\n");
    return 0;
}
