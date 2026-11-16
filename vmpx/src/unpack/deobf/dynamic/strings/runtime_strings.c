/* runtime_strings.c - runtime string recovery from live capture buffers
 *
 * The input is bytes read from the running process, not a dump file or a
 * section table. Both single-byte ASCII and UTF-16LE are recovered, filtered
 * for plausibility by density (not by vowel ratio), and deduplicated by
 * content hash. All growth is bounded by the constants in the header.
 *
 * Every emitted record carries the provenance tag supplied by the caller and
 * an explicit truncation flag. Records that the policy or the ceilings drop
 * are counted in dyn_strings_stats_t instead of disappearing silently.
 */
#include "unpack/deobf/dynamic/strings/runtime_strings.h"
#include <windows.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct dyn_strings {
    FILE* f;
    uint64_t* seen;
    uint8_t* seen_origin;
    uint32_t count;
    dyn_strings_stats_t st;
};

static int printable_ascii(uint8_t c) {
    return (c >= 0x20 && c <= 0x7e) || c == '\t';
}

static const char* origin_name(dyn_string_origin_t origin) {
    switch (origin) {
    case DYN_STRING_ORIGIN_PREVIEW: return "preview";
    case DYN_STRING_ORIGIN_REREAD:  return "reread";
    default:                        return "unverified";
    }
}

/* Strip anything that could break the line format or forge a field. The
 * caller's tag is evidence, so a hostile or malformed one is neutralised
 * rather than trusted verbatim. */
static void source_tag(char* dst, size_t cap, const char* src) {
    size_t w = 0;
    if (cap == 0) return;
    if (src) {
        for (size_t r = 0; src[r] && w + 1 < cap; r++) {
            unsigned char c = (unsigned char)src[r];
            int keep = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9') || c == '_' || c == '.' ||
                       c == '-';
            dst[w++] = keep ? (char)c : '_';
        }
    }
    if (w == 0) {
        memcpy(dst, "mem", 3);
        w = 3;
    }
    dst[w] = 0;
}

/* Length and density policy.
 *
 * Removed deliberately: the previous vowel gate. It discarded real
 * identifiers ("vmp_xqzt", "bcdf") while admitting vowel-rich noise.
 * Retained: a per-encoding minimum length, at least one ASCII letter, and
 * alnum/symbol density checks that reject binary residue.
 *
 * Text reaching this function is ASCII by construction: the ASCII scanner
 * accepts only 0x20..0x7e plus tab, and the UTF-16 scanner accepts only
 * 0x20..0x7e code units before conversion. */
static int plausible(dyn_strings_t* s, const char* text, uint32_t n, int wide) {
    uint32_t alpha = 0, digits = 0, symbols = 0;
    uint32_t min_len = wide ? DYN_STRING_MIN_UTF16 : DYN_STRING_MIN_ASCII;

    if (n < min_len) {
        s->st.reject_short++;
        return 0;
    }
    if (n > DYN_STRING_MAX_CHARS) {
        s->st.reject_binary++;
        return 0;
    }
    for (uint32_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)text[i];
        if (isalpha(c)) {
            alpha++;
        } else if (isdigit(c)) {
            digits++;
        } else if (c == '\\' || c == '/' || c == ':' || c == '.' ||
                   c == '_' || c == '-' || c == ' ' || c == '@' ||
                   c == '\t') {
            /* separators do not count for or against density */
        } else {
            symbols++;
        }
    }
    if (alpha == 0) {
        s->st.reject_noalpha++;
        return 0;
    }
    if ((alpha + digits) * 2 < n) {
        s->st.reject_binary++;
        return 0;
    }
    if (symbols * 4 > n) {
        s->st.reject_binary++;
        return 0;
    }
    return 1;
}

static uint64_t hash64(const char* s, uint32_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (uint32_t i = 0; i < n; i++) {
        h ^= (unsigned char)s[i];
        h *= 1099511628211ULL;
    }
    return h ? h : 1;
}

/* 0 = inserted (new), 1 = duplicate, 2 = table saturated (unproven, caller
 * may emit). Saturation is counted, not silently reported as a duplicate. */
static int seen_probe(dyn_strings_t* s, uint64_t h, uint8_t origin) {
    uint32_t slot = (uint32_t)h & (DYN_STRING_SEEN_SLOTS - 1u);
    for (uint32_t i = 0; i < DYN_STRING_SEEN_SLOTS; i++) {
        uint32_t at = (slot + i) & (DYN_STRING_SEEN_SLOTS - 1u);
        if (!s->seen[at]) {
            s->seen[at] = h;
            s->seen_origin[at] = origin;
            return 0;
        }
        if (s->seen[at] == h) {
            s->st.dup++;
            if (s->seen_origin[at] != origin) {
                s->st.dup_origin++;
                s->st.origin_confirmed[origin]++;
            }
            return 1;
        }
    }
    s->st.table_full++;
    return 2;
}

static void escaped(FILE* f, const char* s, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') fputc('\\', f);
        /* Bytes >= 0x80 are valid UTF-8 only on the wide path, where they
         * come from WideCharToMultiByte. The ASCII path never produces them. */
        if (c >= 0x20 && c != 0x7f) fputc(c, f);
        else fputc('.', f);
    }
}

static void emit(dyn_strings_t* s, const char* text, uint32_t n, uint64_t off,
                 const char* source, int wide, uint32_t trunc,
                 dyn_string_origin_t origin) {
    if (!s || !s->f) return;
    if (!plausible(s, text, n, wide)) return;
    if (s->st.entries >= DYN_STRING_MAX_ENTRIES) {
        s->st.cap_entries++;
        return;
    }
    if (s->st.bytes_out + n > DYN_STRING_MAX_BYTES) {
        s->st.cap_bytes++;
        return;
    }

    uint64_t h = hash64(text, n);
    int seen = seen_probe(s, h, (uint8_t)origin);
    if (seen == 1) return;

    fprintf(s->f, "src=%s origin=%s off=0x%llX enc=%s len=%u trunc=%u text=\"",
            source ? source : "mem", origin_name(origin),
            (unsigned long long)off, wide ? "utf16le" : "ascii", n, trunc);
    escaped(s->f, text, n);
    fputs("\"\n", s->f);

    s->count++;
    s->st.entries++;
    s->st.bytes_out += n;
    s->st.origin_seen[origin]++;
    if (trunc) s->st.truncated++;
}

static void scan_ascii(dyn_strings_t* s, const uint8_t* p, uint32_t len,
                       uint64_t base, const char* source,
                       dyn_string_origin_t origin) {
    uint32_t i = 0;
    while (i < len) {
        if (!printable_ascii(p[i])) { i++; continue; }
        uint32_t start = i;
        while (i < len && printable_ascii(p[i])) i++;
        uint32_t n = i - start;
        uint32_t trunc = 0;
        if (n > DYN_STRING_MAX_CHARS) {
            n = DYN_STRING_MAX_CHARS;
            trunc = 1;
        }
        char tmp[DYN_STRING_MAX_CHARS + 1];
        memcpy(tmp, p + start, n);
        tmp[n] = 0;
        emit(s, tmp, n, base + start, source, 0, trunc, origin);
    }
}

static void scan_utf16(dyn_strings_t* s, const uint8_t* p, uint32_t len,
                       uint64_t base, const char* source,
                       dyn_string_origin_t origin) {
    for (uint32_t i = 0; i + 1 < len; i++) {
        /* Fast skip: the code unit must be printable ASCII followed by 0x00.
         * Surrogates and non-ASCII units never enter this path. */
        if (p[i + 1] != 0 || p[i] < 0x20 || p[i] > 0x7e) continue;

        uint32_t start = i;
        uint32_t chars = 0;
        while (i + 1 < len && p[i + 1] == 0 && p[i] >= 0x20 && p[i] <= 0x7e) {
            i += 2;
            chars++;
            if (chars >= DYN_STRING_MAX_CHARS) break;
        }
        if (chars == 0) continue;

        uint32_t trunc = 0;
        if (chars >= DYN_STRING_MAX_CHARS && i + 1 < len && p[i + 1] == 0 &&
            p[i] >= 0x20 && p[i] <= 0x7e)
            trunc = 1;

        wchar_t wbuf[DYN_STRING_MAX_CHARS + 1];
        for (uint32_t k = 0; k < chars; k++) wbuf[k] = (wchar_t)p[start + k * 2];
        wbuf[chars] = 0;

        char out[DYN_STRING_MAX_CHARS * 3 + 1];
        int n = WideCharToMultiByte(CP_UTF8, 0, wbuf, (int)chars, out,
                                    (int)sizeof(out) - 1, NULL, NULL);
        if (n <= 0) continue;
        out[n] = 0;
        emit(s, out, (uint32_t)n, base + start, source, 1, trunc, origin);
    }
}

dyn_strings_t* dyn_strings_open(const char* path) {
    if (!path) return NULL;
    dyn_strings_t* s = (dyn_strings_t*)calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->seen = (uint64_t*)calloc(DYN_STRING_SEEN_SLOTS, sizeof(uint64_t));
    s->seen_origin = (uint8_t*)calloc(DYN_STRING_SEEN_SLOTS, sizeof(uint8_t));
    if (!s->seen || !s->seen_origin) {
        free(s->seen);
        free(s->seen_origin);
        free(s);
        return NULL;
    }
    if (fopen_s(&s->f, path, "w") != 0 || !s->f) {
        free(s->seen);
        free(s->seen_origin);
        free(s);
        return NULL;
    }
    return s;
}

void dyn_strings_feed_ex(dyn_strings_t* s, const uint8_t* data, uint32_t len,
                         uint64_t base, const char* source,
                         dyn_string_origin_t origin) {
    if (!s) return;
    if (!data || !source) {
        s->st.reject_null++;
        return;
    }
    if (!len) {
        s->st.reject_empty++;
        return;
    }
    if (origin != DYN_STRING_ORIGIN_PREVIEW && origin != DYN_STRING_ORIGIN_REREAD &&
        origin != DYN_STRING_ORIGIN_UNKNOWN)
        origin = DYN_STRING_ORIGIN_UNKNOWN;

    char tag[16];
    source_tag(tag, sizeof(tag), source);

    s->st.feeds++;
    s->st.bytes_in += len;
    scan_ascii(s, data, len, base, tag, origin);
    scan_utf16(s, data, len, base, tag, origin);
}

void dyn_strings_feed(dyn_strings_t* s, const uint8_t* data, uint32_t len,
                      uint64_t base, const char* source) {
    dyn_strings_feed_ex(s, data, len, base, source, DYN_STRING_ORIGIN_UNKNOWN);
}

void dyn_strings_close(dyn_strings_t* s) {
    if (!s) return;
    if (s->f) fclose(s->f);
    free(s->seen);
    free(s->seen_origin);
    free(s);
}

uint32_t dyn_strings_count(const dyn_strings_t* s) {
    return s ? s->count : 0;
}

uint64_t dyn_strings_bytes(const dyn_strings_t* s) {
    return s ? s->st.bytes_out : 0;
}

int dyn_strings_get_stats(const dyn_strings_t* s, dyn_strings_stats_t* out) {
    if (!s || !out) return -1;
    *out = s->st;
    return 0;
}
