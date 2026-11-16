/* pageepoch.h - bounded per-page identity epochs for a live target
 *
 * A page's identity is the tuple (state, protection, type, content CRC32).
 * The tracker keeps a fixed-capacity, address-sorted table of committed
 * readable pages and derives each page's identity from VirtualQueryEx region
 * properties plus a CRC32 over the live 4 KiB page. A page keeps its epoch
 * while the identity tuple is unchanged and advances to a fresh monotonic
 * epoch when any element changes, when the page first appears, or when its
 * bytes cannot be read. A failed read is never treated as "unchanged": the
 * page advances and the failure is counted.
 *
 * The table is bounded. Two caller arenas of `cap` entries can be supplied
 * with pageepoch_init_arena, or pageepoch_init allocates a fixed default. No
 * allocation happens after init, so a poll loop cannot grow the heap.
 */
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stddef.h>

#include "unpack/memory/region_map.h"
#include "unpack/memory/proc_reader.h"

#define PAGE_EPOCH_PAGE      0x1000u    /* 4 KiB identity unit */
#define PAGE_EPOCH_MAX_PAGES 262144u    /* 1 GiB of tracked pages */

typedef struct {
    uint64_t addr;        /* page-aligned base */
    uint32_t crc;         /* content CRC32 of the last good read */
    uint32_t protect;     /* region protection at last observation */
    uint32_t type;        /* MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE */
    uint32_t state;       /* MEM_COMMIT */
    uint32_t epoch;       /* monotonic identity epoch, 0 = never seen */
    uint8_t  present;     /* occupied by a committed readable region */
    uint8_t  failed;      /* last read failed; crc is stale */
    uint8_t  reserved[2];
} pageepoch_page_t;

typedef struct {
    pageepoch_page_t* cur;      /* sorted live table */
    pageepoch_page_t* scratch;  /* merge destination */
    uint32_t cap;
    uint32_t count;
    uint32_t next_epoch;        /* last epoch value handed out */
    uint32_t epochs_advanced;   /* total epoch bumps across all refreshes */
    uint32_t read_failures;     /* total failed page reads */
    uint32_t truncated;         /* enumeration reached the page cap */
    uint64_t refresh_seq;       /* completed refresh count */
    uint32_t owns;              /* 1 when this module allocated the tables */
    uint32_t reserved;
} pageepoch_t;

typedef struct {
    uint32_t pages_tracked;
    uint32_t epochs_advanced;
    uint32_t read_failures;
    uint32_t capacity;
    uint32_t truncated;
    uint64_t refresh_seq;
} pageepoch_stats_t;

int  pageepoch_init(pageepoch_t* pe, uint32_t cap);
int  pageepoch_init_arena(pageepoch_t* pe, pageepoch_page_t* cur,
                          pageepoch_page_t* scratch, uint32_t cap);
void pageepoch_close(pageepoch_t* pe);

/* Refresh the region map when proc is non-NULL, then re-derive page epochs
 * through rd. Returns 0 when the pass completed inside bounds, -1 on bad
 * arguments, a failed region refresh, or truncation (stats.truncated is set;
 * prior entries beyond the cap are preserved unchanged). */
int  pageepoch_refresh(pageepoch_t* pe, vmpx_region_map_t* regions,
                       HANDLE proc, vmpx_proc_reader_t* rd);

/* Current identity epoch for the page containing addr, or 0 when untracked. */
uint32_t pageepoch_of(const pageepoch_t* pe, uint64_t addr);

void pageepoch_stats(const pageepoch_t* pe, pageepoch_stats_t* out);
