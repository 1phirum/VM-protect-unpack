/* deobf.h - offline analysis of a live image dump (L3)
 *
 * The suite works beside VMProtect rather than through its VM: it compares the
 * on-disk image with its live mapping, measures entropy, carves nested PEs, and
 * recovers single-byte-transformed strings from the unpacked regions.
 */
#pragma once

#include <stdint.h>

typedef struct {
    uint32_t sections;
    uint32_t high_entropy_ranges;
    uint32_t changed_sections;
    uint32_t carved_images;
    uint32_t recovered_strings;
    uint32_t pages_scanned;
} deobf_stats_t;

int deobf_run(const char* dump_path, const char* file_path, const char* out_dir,
              int scan_strings);

int deobf_entropy(const uint8_t* dump, uint64_t len, const char* out_path,
                  deobf_stats_t* st);
int deobf_diff(const uint8_t* file, uint64_t flen, const uint8_t* dump,
               uint64_t dlen, const char* out_path, deobf_stats_t* st);
int deobf_carve(const uint8_t* dump, uint64_t len, const char* out_dir,
                deobf_stats_t* st);
int deobf_strings(const uint8_t* dump, uint64_t len, const char* out_path,
                  deobf_stats_t* st);
