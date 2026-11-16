/* runtime_strings.h - dynamic string recovery from live memory buffers */
#pragma once

#include <stdint.h>

typedef struct dyn_strings dyn_strings_t;

/* Where the fed bytes came from. DYN_STRING_ORIGIN_UNKNOWN is what the
 * legacy dyn_strings_feed() reports because its signature carries no
 * validity information. Values do not depend on report.c's capture codes;
 * map those explicitly at the call site. */
typedef enum dyn_string_origin {
    DYN_STRING_ORIGIN_UNKNOWN = 0,
    DYN_STRING_ORIGIN_PREVIEW = 1,
    DYN_STRING_ORIGIN_REREAD  = 2
} dyn_string_origin_t;

/* Hard bounds. Every limit is a compile-time ceiling; nothing in the
 * extractor grows with input volume beyond these. */
#define DYN_STRING_MAX_CHARS    512u
#define DYN_STRING_MIN_ASCII      3u
#define DYN_STRING_MIN_UTF16      2u
#define DYN_STRING_MAX_ENTRIES 500000u
#define DYN_STRING_MAX_BYTES  (8u * 1024u * 1024u)
#define DYN_STRING_SEEN_SLOTS  131072u

/* Counters. All values are cumulative for the lifetime of the handle and
 * are written by dyn_strings_get_stats(). Rejected candidates are counted
 * per policy reason, so a silent filter is never silent in the report. */
typedef struct dyn_strings_stats {
    uint64_t feeds;          /* accepted feed calls */
    uint64_t bytes_in;       /* bytes scanned (both encodings) */
    uint64_t entries;        /* records written */
    uint64_t bytes_out;      /* text bytes written, excludes labels/escapes */
    uint64_t dup;            /* duplicate content dropped */
    uint64_t dup_origin;     /* duplicate seen under a different origin */
    uint64_t reject_null;    /* null handle, data, source, or path */
    uint64_t reject_empty;   /* len == 0 */
    uint64_t reject_short;   /* below the per-encoding minimum */
    uint64_t reject_noalpha; /* no ASCII letter in the run */
    uint64_t reject_binary;  /* alnum density or symbol density failed */
    uint64_t truncated;      /* emitted record was clipped at MAX_CHARS */
    uint64_t cap_entries;    /* record dropped: entry ceiling */
    uint64_t cap_bytes;      /* record dropped: byte ceiling */
    uint64_t table_full;     /* seen table saturated; record emitted unproven */
    uint64_t origin_seen[3];      /* emissions per origin */
    uint64_t origin_confirmed[3]; /* duplicate sightings per origin */
} dyn_strings_stats_t;

dyn_strings_t* dyn_strings_open(const char* path);
void dyn_strings_feed(dyn_strings_t* s, const uint8_t* data, uint32_t len,
                      uint64_t base, const char* source);
/* Same as dyn_strings_feed with an explicit provenance tag. */
void dyn_strings_feed_ex(dyn_strings_t* s, const uint8_t* data, uint32_t len,
                         uint64_t base, const char* source,
                         dyn_string_origin_t origin);
void dyn_strings_close(dyn_strings_t* s);
uint32_t dyn_strings_count(const dyn_strings_t* s);
uint64_t dyn_strings_bytes(const dyn_strings_t* s);
int dyn_strings_get_stats(const dyn_strings_t* s, dyn_strings_stats_t* out);
