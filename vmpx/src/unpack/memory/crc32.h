/* crc32.h - small streaming CRC32 for snapshot integrity */
#pragma once

#include <stdint.h>
#include <stddef.h>

uint32_t vmpx_crc32_begin(void);
uint32_t vmpx_crc32_update(uint32_t crc, const void* data, size_t len);
uint32_t vmpx_crc32_final(uint32_t crc);
uint32_t vmpx_crc32(const void* data, size_t len);
