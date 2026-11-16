/* file.h - whole-file read/write for dumps and rebuilt images (L0) */
#pragma once

#include <stdint.h>

int file_read_all(const char* path, uint8_t** out, uint64_t* size);
int file_write_all(const char* path, const void* data, uint64_t size);
