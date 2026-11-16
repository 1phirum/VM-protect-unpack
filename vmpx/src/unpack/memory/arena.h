/* arena.h - host-side monotonic arena with an explicit block ceiling
 *
 * The arena is not shared with the target. It exists so a collector can
 * allocate bounded scratch storage without relying on the process heap state
 * left by previous stages. reset() keeps the blocks and makes them reusable.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct vmpx_arena_block vmpx_arena_block_t;

typedef struct {
    vmpx_arena_block_t* head;
    size_t block_size;
    size_t max_block;
    size_t used;
    size_t peak;
    uint32_t blocks;
    uint32_t refused;
} vmpx_arena_t;

int   vmpx_arena_init(vmpx_arena_t* a, size_t block_size, size_t max_block);
void* vmpx_arena_alloc(vmpx_arena_t* a, size_t bytes, size_t align);
void  vmpx_arena_reset(vmpx_arena_t* a);
void  vmpx_arena_destroy(vmpx_arena_t* a);
