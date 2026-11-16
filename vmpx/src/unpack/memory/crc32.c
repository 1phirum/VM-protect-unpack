/* crc32.c - standard reflected CRC32, initialized once */
#include "unpack/memory/crc32.h"

static uint32_t g_table[256];
static int g_ready = 0;

static void build_table(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        g_table[i] = c;
    }
    g_ready = 1;
}

uint32_t vmpx_crc32_begin(void) {
    if (!g_ready) build_table();
    return 0xFFFFFFFFu;
}

uint32_t vmpx_crc32_update(uint32_t crc, const void* data, size_t len) {
    if (!g_ready) build_table();
    const uint8_t* p = (const uint8_t*)data;
    while (len--) crc = g_table[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
    return crc;
}

uint32_t vmpx_crc32_final(uint32_t crc) {
    return crc ^ 0xFFFFFFFFu;
}

uint32_t vmpx_crc32(const void* data, size_t len) {
    return vmpx_crc32_final(vmpx_crc32_update(vmpx_crc32_begin(), data, len));
}
