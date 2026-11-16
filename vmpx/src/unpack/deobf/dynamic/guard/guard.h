/* guard.h - the single owner of the vectored exception handler and of the
 * guard-page rollback bookkeeping for the dynamic techniques.
 *
 * Before Phase 3, codecov, watch, and the OEP probes each installed their own
 * VEH and each managed its own page protection. That produced N dispatchers
 * racing on the same fault, N saved-protection tables, and no way to tell which
 * consumer owned a page. This registry owns the one VEH, routes a fault to the
 * one interested technique, and keeps the rollback data so a lease that expires
 * recomputes protection from live page state instead of restoring a value that
 * the target may have replaced.
 *
 * The fault path iterates a fixed array: no allocation, no lock, no syscall.
 * Registration and rollback happen off the fault path and take a spinlock.
 */
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdint.h>

#define GUARD_MAX_ENTRIES   64u    /* fixed slot count; exhaustion fails closed */
#define GUARD_MAX_PAGES     8192u  /* rollback records; exhaustion fails closed */
#define GUARD_ENTRY_PAGES   64u    /* inline page-list capacity per entry       */
#define GUARD_TECH_MAX      32u    /* technique name, truncated to fit          */
#define GUARD_PAGE          0x1000u

/* entry states. GUARD_ST_ARMED is published with a release store and read
 * without a lock by the dispatcher; every other field is written before it. */
#define GUARD_ST_FREE   0u
#define GUARD_ST_ARMED  1u

/* Owner 0 is reserved: it marks an unclaimed slot. */
#define GUARD_OWNER_NONE 0u

/* Routed exception classes. Anything else is an unknown fault and is returned
 * to the next handler untouched. */
#define GUARD_CODE_GUARD ((DWORD)0x80000001u) /* STATUS_GUARD_PAGE_VIOLATION */
#define GUARD_CODE_BP    ((DWORD)0x80000003u) /* STATUS_BREAKPOINT          */
#define GUARD_CODE_STEP  ((DWORD)0x80000004u) /* STATUS_SINGLE_STEP         */

/* A technique handler returns EXCEPTION_CONTINUE_EXECUTION to consume the
 * fault or EXCEPTION_CONTINUE_SEARCH to decline it. The dispatcher stops at the
 * first handler that does not decline, so one fault never has two consumers. */
typedef LONG (CALLBACK *guard_handler_fn)(uint32_t owner,
                                          EXCEPTION_POINTERS* ep, void* ctx);

typedef struct {
    const char*       technique;   /* copied; NULL is refused                     */
    uint32_t          owner;       /* 0 -> auto-assign; else must be unique        */
    guard_handler_fn  handler;     /* required                                    */
    void*             ctx;         /* opaque; stored verbatim                     */
    uint32_t          nesting;     /* max re-entrant depth; 0 -> 1                */
    uint32_t          lease_ms;    /* 0 -> no lease; else deadline ticks          */
    uint64_t          range_base;  /* optional address range [base, base+size)    */
    uint64_t          range_size;
} guard_spec_t;

/* Rollback record for one guarded page. `installed` is the protection guard
 * wrote (base | PAGE_GUARD); `original` is the value before that write. */
typedef struct {
    uint32_t      owner;
    uint32_t      page;        /* 4K-aligned page base               */
    uint32_t      installed;
    uint32_t      original;
    uint32_t      epoch;       /* page epoch at arm time             */
    volatile LONG live;        /* 1 = guard still applied here       */
} guard_page_rec_t;

/* Process-lifetime lifecycle. guard_init installs the one VEH; guard_shutdown
 * removes it and drops every entry and rollback record. Both are idempotent. */
int  guard_init(void);
void guard_shutdown(void);
int  guard_ready(void);

/* Claim a slot and publish it ARMED. Returns the owner id, or GUARD_OWNER_NONE
 * on refusal (no free slot, missing handler, or a duplicate explicit owner). */
uint32_t guard_register(const guard_spec_t* spec);
int  guard_set_range(uint32_t owner, uint64_t base, uint64_t size);
int  guard_add_pages(uint32_t owner, const uint32_t* pages, uint32_t count);
int  guard_release(uint32_t owner);

/* Rollback bookkeeping. guard_track_page is called by the arming technique
 * right after its VirtualProtect succeeds; guard_disarm restores tracking for
 * one owner, recomputing from live protection; guard_release drops the slot
 * after the same restore. */
int  guard_track_page(uint32_t owner, uint64_t page,
                      uint32_t installed, uint32_t original);
int  guard_untrack_page(uint32_t owner, uint64_t page);
int  guard_disarm(uint32_t owner);

/* Diagnostics: current global epoch, total routed faults, live-entry flag. */
uint32_t guard_epoch(void);
uint32_t guard_faults(void);
int  guard_owner_active(uint32_t owner);
