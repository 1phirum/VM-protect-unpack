/* arena.c - block list, alignment, and bounded allocation */
#include "unpack/memory/arena.h"
#include <stdlib.h>
#include <string.h>

struct vmpx_arena_block {
    struct vmpx_arena_block* next;
    uint8_t* data;
    size_t cap;
    size_t used;
};

static size_t align_up(size_t value, size_t align) {
    if (align < 2) return value;
    size_t mask = align - 1;
    if (value > (size_t)-1 - mask) return 0;
    return (value + mask) & ~mask;
}

static uint8_t* align_ptr(void* p, size_t align) {
    uintptr_t x = (uintptr_t)p;
    return (uint8_t*)((x + (align - 1)) & ~(uintptr_t)(align - 1));
}

int vmpx_arena_init(vmpx_arena_t* a, size_t block_size, size_t max_block) {
    if (!a) return -1;
    memset(a, 0, sizeof(*a));
    if (!block_size) block_size = 0x10000;
    if (block_size < 0x1000) block_size = 0x1000;
    if (!max_block) max_block = 16u << 20;
    if (max_block < block_size) max_block = block_size;
    a->block_size = block_size;
    a->max_block = max_block;
    return 0;
}

static vmpx_arena_block_t* new_block(size_t cap) {
    if (cap > (size_t)-1 - sizeof(vmpx_arena_block_t) - 16) return NULL;
    vmpx_arena_block_t* b = (vmpx_arena_block_t*)malloc(
        sizeof(vmpx_arena_block_t) + cap + 16);
    if (!b) return NULL;
    b->next = NULL;
    b->data = align_ptr((uint8_t*)(b + 1), 16);
    b->cap = cap;
    b->used = 0;
    return b;
}

void* vmpx_arena_alloc(vmpx_arena_t* a, size_t bytes, size_t align) {
    if (!a || !bytes) return NULL;
    if (!align) align = 8;
    if (align > 16 || (align & (align - 1))) return NULL;
    if (align < 8) align = 8;

    size_t need = align_up(bytes, align);
    if (!need || need > a->max_block) {
        a->refused++;
        return NULL;
    }

    for (vmpx_arena_block_t* b = a->head; b; b = b->next) {
        size_t at = align_up(b->used, align);
        if (!at || at > b->cap || need > b->cap - at) continue;
        b->used = at + need;
        a->used += need;
        if (a->used > a->peak) a->peak = a->used;
        return b->data + at;
    }

    size_t cap = a->block_size > need ? a->block_size : need;
    if (cap > a->max_block) cap = a->max_block;
    if (cap < need) {
        a->refused++;
        return NULL;
    }
    vmpx_arena_block_t* b = new_block(cap);
    if (!b) {
        a->refused++;
        return NULL;
    }
    b->next = a->head;
    a->head = b;
    a->blocks++;

    size_t at = align_up(0, align);
    b->used = at + need;
    a->used += need;
    if (a->used > a->peak) a->peak = a->used;
    return b->data + at;
}

void vmpx_arena_reset(vmpx_arena_t* a) {
    if (!a) return;
    for (vmpx_arena_block_t* b = a->head; b; b = b->next) b->used = 0;
    a->used = 0;
}

void vmpx_arena_destroy(vmpx_arena_t* a) {
    if (!a) return;
    vmpx_arena_block_t* b = a->head;
    while (b) {
        vmpx_arena_block_t* next = b->next;
        free(b);
        b = next;
    }
    memset(a, 0, sizeof(*a));
}
