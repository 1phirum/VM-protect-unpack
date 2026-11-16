/* bin.c - little-endian scalar access and alignment (L0) */
#include "util/bin.h"

uint16_t bin_rd16(const uint8_t* p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

uint32_t bin_rd32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

uint64_t bin_rd64(const uint8_t* p) {
    return (uint64_t)bin_rd32(p) | ((uint64_t)bin_rd32(p + 4) << 32);
}

void bin_wr16(uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)(v >> 8);
}

void bin_wr32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

void bin_wr64(uint8_t* p, uint64_t v) {
    bin_wr32(p, (uint32_t)v);
    bin_wr32(p + 4, (uint32_t)(v >> 32));
}

uint64_t bin_align_up(uint64_t value, uint64_t alignment) {
    if (alignment < 2) return value;
    uint64_t rem = value % alignment;
    return rem ? value + (alignment - rem) : value;
}
