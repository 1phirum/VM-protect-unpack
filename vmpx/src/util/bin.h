/* bin.h - little-endian scalar access and alignment (L0) */
#pragma once

#include <stdint.h>
#include <stddef.h>

uint16_t bin_rd16(const uint8_t* p);
uint32_t bin_rd32(const uint8_t* p);
uint64_t bin_rd64(const uint8_t* p);

void bin_wr16(uint8_t* p, uint16_t v);
void bin_wr32(uint8_t* p, uint32_t v);
void bin_wr64(uint8_t* p, uint64_t v);

uint64_t bin_align_up(uint64_t value, uint64_t alignment);
