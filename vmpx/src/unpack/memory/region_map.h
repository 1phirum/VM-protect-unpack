/* region_map.h - sorted region generations and readable-span lookup
 *
 * A refresh merges the previous map with a fresh enumeration. An entry keeps
 * its generation when base, size, state, protection, and type are unchanged.
 * A new base, a property change, or reactivation after absence gets a new
 * generation. Address reuse that happens entirely between two refreshes is
 * not observable here and must be reported by an event source.
 */
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

typedef struct {
    uint64_t base;
    uint64_t size;
    uint32_t state;
    uint32_t protect;
    uint32_t type;
    uint32_t generation;
    uint32_t present;
} vmpx_region_t;

typedef struct {
    vmpx_region_t* v;
    vmpx_region_t* scratch;
    vmpx_region_t* fresh;
    uint32_t count;
    uint32_t cap;
    uint32_t next_generation;
    uint64_t refresh_seq;
} vmpx_region_map_t;

int  vmpx_region_map_init(vmpx_region_map_t* m, uint32_t cap);
void vmpx_region_map_close(vmpx_region_map_t* m);
int  vmpx_region_map_apply(vmpx_region_map_t* m, const vmpx_region_t* fresh,
                           uint32_t n);
int  vmpx_region_map_refresh(vmpx_region_map_t* m, HANDLE proc);
const vmpx_region_t* vmpx_region_map_find(const vmpx_region_map_t* m,
                                          uint64_t addr);
uint64_t vmpx_region_map_valid_span(const vmpx_region_map_t* m, uint64_t addr);
int  vmpx_region_readable(uint32_t protect);
