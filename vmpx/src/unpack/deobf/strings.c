/* strings.c - direct, XOR- and ADD-transformed string recovery */
#include "unpack/deobf/deobf.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK       0x10000u
#define MIN_STRING  6
#define MAX_LINES   100000

static int printable(uint8_t c) { return c >= 0x20 && c <= 0x7E; }

static uint32_t emit_strings(FILE* f, const uint8_t* buf, size_t n,
                             uint64_t base, const char* kind, int key,
                             uint32_t* lines, deobf_stats_t* st) {
    uint32_t made = 0;
    size_t i = 0;
    while (i < n && *lines < MAX_LINES) {
        if (!printable(buf[i])) { i++; continue; }
        size_t start = i;
        while (i < n && printable(buf[i])) i++;
        size_t len = i - start;
        if (len < MIN_STRING) continue;
        if (len > 512) len = 512;
        char text[520];
        memcpy(text, buf + start, len);
        text[len] = 0;
        if (key >= 0)
            fprintf(f, "%s off=0x%llX key=0x%02X text=\"%s\"\n",
                    kind, (unsigned long long)(base + start), key, text);
        else
            fprintf(f, "ascii off=0x%llX text=\"%s\"\n",
                    (unsigned long long)(base + start), text);
        made++;
        (*lines)++;
        st->recovered_strings++;
    }
    return made;
}

static void best_keys(const uint64_t* freq, size_t n, int add,
                      int* k1, int* k2) {
    *k1 = 0;
    *k2 = 0;
    uint64_t best1 = 0, best2 = 0;
    for (int k = 1; k < 256; k++) {
        uint64_t score = 0;
        for (int p = 0x20; p <= 0x7E; p++) {
            int c = add ? ((p + k) & 0xFF) : (p ^ k);
            score += freq[c];
        }
        if (score > best1) {
            best2 = best1; *k2 = *k1;
            best1 = score; *k1 = k;
        } else if (score > best2) {
            best2 = score; *k2 = k;
        }
    }
    if (n && best1 < (uint64_t)(n * 55 / 100)) *k1 = 0;
    if (n && best2 < (uint64_t)(n * 55 / 100)) *k2 = 0;
}

int deobf_strings(const uint8_t* dump, uint64_t len, const char* out_path,
                  deobf_stats_t* st) {
    if (!dump || !len || !out_path) return -1;
    FILE* f = NULL;
    if (fopen_s(&f, out_path, "w") != 0 || !f) return -1;
    fprintf(f, "VMPX recovered strings\n");

    uint32_t lines = 0;
    /* Direct ASCII first; reserve half of the output budget for transformed
     * text so a string-dense image does not starve the XOR/ADD scan. */
    const uint32_t direct_limit = MAX_LINES / 2;
    uint64_t i = 0;
    while (i < len && lines < direct_limit) {
        if (!printable(dump[i])) { i++; continue; }
        uint64_t start = i;
        while (i < len && printable(dump[i])) i++;
        uint64_t n = i - start;
        if (n >= MIN_STRING) {
            if (n > 512) n = 512;
            char text[520];
            memcpy(text, dump + start, (size_t)n);
            text[n] = 0;
            fprintf(f, "ascii off=0x%llX text=\"%s\"\n",
                    (unsigned long long)start, text);
            lines++;
            st->recovered_strings++;
        }
    }

    uint8_t* decoded = (uint8_t*)malloc(BLOCK);
    if (!decoded) { fclose(f); return -1; }

    for (uint64_t base = 0; base + 64 <= len && lines < MAX_LINES; base += BLOCK) {
        size_t n = (size_t)((len - base) < BLOCK ? (len - base) : BLOCK);
        uint64_t freq[256];
        memset(freq, 0, sizeof(freq));
        uint64_t raw_print = 0;
        for (size_t j = 0; j < n; j++) {
            freq[dump[base + j]]++;
            if (printable(dump[base + j])) raw_print++;
        }
        /* Dense plaintext was already emitted above. Encrypted text is dense
         * under exactly one key; random data does not clear the 55% gate. */
        if (raw_print > (uint64_t)(n * 70 / 100)) continue;

        int kx1 = 0, kx2 = 0, ka1 = 0, ka2 = 0;
        best_keys(freq, n, 0, &kx1, &kx2);
        best_keys(freq, n, 1, &ka1, &ka2);

        int keys[4] = { kx1, kx2, ka1, ka2 };
        int modes[4] = { 0, 0, 1, 1 };
        for (int m = 0; m < 4 && lines < MAX_LINES; m++) {
            int key = keys[m];
            if (!key) continue;
            if (m == 1 && key == kx1) continue;
            if (m == 3 && key == ka1) continue;
            for (size_t j = 0; j < n; j++) {
                uint8_t c = dump[base + j];
                decoded[j] = (uint8_t)(modes[m] ? (uint8_t)(c - key) : (uint8_t)(c ^ key));
            }
            emit_strings(f, decoded, n, base, modes[m] ? "add" : "xor", key,
                         &lines, st);
        }
    }

    free(decoded);
    fprintf(f, "TOTAL %u\n", st->recovered_strings);
    fclose(f);
    return 0;
}
