/* guard.c - one VEH, one dispatcher, one rollback table for the dynamic
 * techniques.
 *
 * Ownership: guard_init installs a single vectored exception handler with
 * AddVectoredExceptionHandler and guard_shutdown removes it. codecov, watch,
 * and the OEP probes register an entry with guard_register and stop calling
 * the VEH API themselves.
 *
 * Routing: the dispatcher matches the fault address against each ARMED entry,
 * skips entries whose lease has expired, and calls the first interested
 * handler. It returns EXCEPTION_CONTINUE_SEARCH for any fault no entry wants,
 * and it stops at the first handler that does not decline, so two entries can
 * never consume one fault.
 *
 * Constraint budget: the fault path touches only the fixed entry array. No
 * allocation, no lock, no system call. Allocation-free registration means the
 * caller's page list is copied into the entry's inline array; the registry
 * refuses rather than growing.
 */
#include "unpack/deobf/dynamic/guard/guard.h"
#include <string.h>

#ifndef STATUS_GUARD_PAGE_VIOLATION
#define STATUS_GUARD_PAGE_VIOLATION ((DWORD)0x80000001u)
#endif

typedef struct {
    volatile LONG   state;        /* GUARD_ST_FREE / GUARD_ST_ARMED  */
    uint32_t        owner;
    uint32_t        nesting;      /* max re-entrant depth            */
    uint32_t        lease_ms;
    uint32_t        deadline;     /* 0 -> no lease; else tick target */
    uint32_t        install_epoch;
    uint32_t        page_count;
    uint64_t        range_base;
    uint64_t        range_size;
    guard_handler_fn handler;
    void*           ctx;
    char            technique[GUARD_TECH_MAX];
    uint32_t        pages[GUARD_ENTRY_PAGES];
} guard_entry_t;

static guard_entry_t        g_entries[GUARD_MAX_ENTRIES];
static guard_page_rec_t     g_pages[GUARD_MAX_PAGES];
static PVOID                g_veh = NULL;
static volatile LONG        g_init = 0;
static volatile LONG        g_reg_lock = 0;
static volatile LONG        g_faults = 0;
static uint32_t             g_epoch = 0;
static uint32_t             g_owner_seq = 0;

/* Per-thread re-entrancy state. A handler that faults inside itself must not be
 * re-entered past its declared nesting depth. */
static __declspec(thread) uint32_t t_owner = GUARD_OWNER_NONE;
static __declspec(thread) uint32_t t_depth = 0;

/* ---- small helpers ---------------------------------------------------- */

static void lock_registry(void) {
    while (InterlockedCompareExchange(&g_reg_lock, 1, 0) != 0)
        YieldProcessor();
}

static void unlock_registry(void) {
    InterlockedExchange(&g_reg_lock, 0);
}

/* Wrap-safe "deadline reached" test. Both values are 32-bit tick counts; a
 * deadline more than 2^31 ticks away cannot be live by construction. */
static int lease_expired(const guard_entry_t* e) {
    if (!e->deadline) return 0;
    return (int32_t)((uint32_t)GetTickCount() - e->deadline) >= 0;
}

static int code_routable(DWORD code) {
    return code == GUARD_CODE_GUARD || code == GUARD_CODE_BP ||
           code == GUARD_CODE_STEP;
}

static uint32_t entry_index(uint32_t owner) {
    for (uint32_t i = 0; i < GUARD_MAX_ENTRIES; i++)
        if (g_entries[i].owner == owner &&
            InterlockedCompareExchange(&g_entries[i].state, 0, 0) != GUARD_ST_FREE)
            return i;
    return GUARD_MAX_ENTRIES;
}

static int page_seen(const guard_entry_t* e, uint32_t page) {
    for (uint32_t i = 0; i < e->page_count && i < GUARD_ENTRY_PAGES; i++)
        if (e->pages[i] == page) return 1;
    return 0;
}

/* An entry with neither a page list nor a range matches any routed fault. That
 * is what a debug-register or breakpoint technique wants: the trigger is the
 * exception class, not the address. */
static int entry_matches(const guard_entry_t* e, uint64_t fault) {
    if (e->page_count) {
        uint32_t page = (uint32_t)(fault & ~(uint64_t)(GUARD_PAGE - 1));
        return page_seen(e, page);
    }
    if (e->range_size) {
        uint64_t end = e->range_base + e->range_size;
        if (end < e->range_base) end = 0xFFFFFFFFFFFFFFFFull;
        return fault >= e->range_base && fault < end;
    }
    return 1;
}

/* ---- the single dispatcher ------------------------------------------- */

static LONG CALLBACK guard_dispatch(EXCEPTION_POINTERS* ep) {
    if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    if (InterlockedCompareExchange(&g_init, 0, 0) == 0)
        return EXCEPTION_CONTINUE_SEARCH;

    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (!code_routable(code)) return EXCEPTION_CONTINUE_SEARCH;

    /* Guard-page faults name the touched address in Information[1]. Breakpoint
     * and single-step name the instruction in ExceptionAddress. */
    uint64_t fault;
    if (code == GUARD_CODE_GUARD && ep->ExceptionRecord->NumberParameters >= 2)
        fault = (uint64_t)ep->ExceptionRecord->ExceptionInformation[1];
    else
        fault = (uint64_t)(uintptr_t)ep->ExceptionRecord->ExceptionAddress;

    for (uint32_t i = 0; i < GUARD_MAX_ENTRIES; i++) {
        guard_entry_t* e = &g_entries[i];
        if (e->state != GUARD_ST_ARMED) continue;
        if (!e->handler) continue;
        if (lease_expired(e)) continue;
        if (!entry_matches(e, fault)) continue;

        /* Refuse a re-entrant call that would exceed the declared depth. */
        if (t_owner == e->owner && t_depth >= e->nesting)
            continue;

        uint32_t prev_owner = t_owner;
        uint32_t prev_depth = t_depth;
        t_owner = e->owner;
        t_depth++;
        LONG r = e->handler(e->owner, ep, e->ctx);
        t_depth = prev_depth;
        t_owner = prev_owner;

        if (r != EXCEPTION_CONTINUE_SEARCH) {
            InterlockedIncrement(&g_faults);
            return r;               /* one consumer, then stop */
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* ---- lifecycle -------------------------------------------------------- */

int guard_init(void) {
    if (InterlockedCompareExchange(&g_init, 1, 0) != 0) return 0;
    g_veh = AddVectoredExceptionHandler(1, guard_dispatch);
    if (!g_veh) {
        InterlockedExchange(&g_init, 0);
        return -1;
    }
    return 0;
}

void guard_shutdown(void) {
    PVOID veh = g_veh;
    g_veh = NULL;
    if (InterlockedExchange(&g_init, 0) == 0 && !veh) return;

    lock_registry();
    for (uint32_t i = 0; i < GUARD_MAX_ENTRIES; i++) {
        if (InterlockedExchange(&g_entries[i].state, GUARD_ST_FREE) != GUARD_ST_FREE)
            g_entries[i].owner = GUARD_OWNER_NONE;
    }
    for (uint32_t i = 0; i < GUARD_MAX_PAGES; i++)
        InterlockedExchange(&g_pages[i].live, 0);
    unlock_registry();

    if (veh) RemoveVectoredExceptionHandler(veh);
}

int guard_ready(void) {
    return InterlockedCompareExchange(&g_init, 0, 0) != 0 && g_veh != NULL;
}

uint32_t guard_epoch(void) { return g_epoch; }
uint32_t guard_faults(void) { return (uint32_t)InterlockedCompareExchange(&g_faults, 0, 0); }

int guard_owner_active(uint32_t owner) {
    uint32_t idx = entry_index(owner);
    if (idx >= GUARD_MAX_ENTRIES) return 0;
    return !lease_expired(&g_entries[idx]);
}

/* ---- registration ----------------------------------------------------- */

uint32_t guard_register(const guard_spec_t* spec) {
    if (!spec || !spec->handler) return GUARD_OWNER_NONE;

    lock_registry();

    /* An explicit owner must be unique; owner 0 is auto-assigned. */
    uint32_t owner = spec->owner;
    if (owner == GUARD_OWNER_NONE) {
        owner = ++g_owner_seq;
        if (owner == GUARD_OWNER_NONE) owner = ++g_owner_seq;
    } else if (entry_index(owner) < GUARD_MAX_ENTRIES) {
        unlock_registry();
        return GUARD_OWNER_NONE;
    }

    uint32_t slot = GUARD_MAX_ENTRIES;
    for (uint32_t i = 0; i < GUARD_MAX_ENTRIES; i++) {
        if (g_entries[i].owner == GUARD_OWNER_NONE &&
            g_entries[i].state == GUARD_ST_FREE) {
            slot = i;
            break;
        }
    }
    if (slot >= GUARD_MAX_ENTRIES) {   /* fail closed on exhaustion */
        unlock_registry();
        return GUARD_OWNER_NONE;
    }

    guard_entry_t* e = &g_entries[slot];
    e->owner = owner;
    e->nesting = spec->nesting ? spec->nesting : 1;
    e->lease_ms = spec->lease_ms;
    e->deadline = spec->lease_ms ? (uint32_t)GetTickCount() + spec->lease_ms : 0;
    e->install_epoch = ++g_epoch;
    e->range_base = spec->range_base;
    e->range_size = spec->range_size;
    e->page_count = 0;
    e->handler = spec->handler;
    e->ctx = spec->ctx;
    memset(e->technique, 0, sizeof(e->technique));
    if (spec->technique) {
        strncpy_s(e->technique, sizeof(e->technique), spec->technique,
                  _TRUNCATE);
    }
    /* Publish the slot last so the dispatcher never sees a half-filled entry. */
    InterlockedExchange(&e->state, GUARD_ST_ARMED);

    unlock_registry();
    return owner;
}

int guard_set_range(uint32_t owner, uint64_t base, uint64_t size) {
    lock_registry();
    uint32_t idx = entry_index(owner);
    if (idx >= GUARD_MAX_ENTRIES) { unlock_registry(); return -1; }
    g_entries[idx].range_base = base;
    g_entries[idx].range_size = size;
    g_entries[idx].page_count = 0;
    unlock_registry();
    return 0;
}

int guard_add_pages(uint32_t owner, const uint32_t* pages, uint32_t count) {
    if (!pages || !count) return -1;
    lock_registry();
    uint32_t idx = entry_index(owner);
    if (idx >= GUARD_MAX_ENTRIES) { unlock_registry(); return -1; }
    guard_entry_t* e = &g_entries[idx];
    for (uint32_t i = 0; i < count; i++) {
        uint32_t page = pages[i] & ~(GUARD_PAGE - 1);
        if (!page) continue;
        if (e->page_count >= GUARD_ENTRY_PAGES) { unlock_registry(); return -1; }
        if (page_seen(e, page)) continue;
        e->pages[e->page_count++] = page;
    }
    /* A page list supersedes any range on the same entry. */
    e->range_base = 0;
    e->range_size = 0;
    unlock_registry();
    return 0;
}

/* ---- rollback bookkeeping --------------------------------------------- */

int guard_track_page(uint32_t owner, uint64_t page,
                     uint32_t installed, uint32_t original) {
    uint32_t base = (uint32_t)(page & ~(uint64_t)(GUARD_PAGE - 1));
    if (!base) return -1;

    lock_registry();
    uint32_t idx = entry_index(owner);
    if (idx >= GUARD_MAX_ENTRIES) { unlock_registry(); return -1; }

    uint32_t slot = GUARD_MAX_PAGES;
    for (uint32_t i = 0; i < GUARD_MAX_PAGES; i++) {
        if (g_pages[i].owner == owner && g_pages[i].page == base) {
            slot = i;                 /* refresh an existing record */
            break;
        }
        if (slot == GUARD_MAX_PAGES && g_pages[i].owner == GUARD_OWNER_NONE)
            slot = i;                 /* first free slot seen */
    }
    if (slot >= GUARD_MAX_PAGES) { unlock_registry(); return -1; }

    guard_page_rec_t* r = &g_pages[slot];
    r->owner = owner;
    r->page = base;
    r->installed = installed;
    r->original = original;
    r->epoch = ++g_epoch;
    InterlockedExchange(&r->live, 1);
    unlock_registry();
    return 0;
}

int guard_untrack_page(uint32_t owner, uint64_t page) {
    uint32_t base = (uint32_t)(page & ~(uint64_t)(GUARD_PAGE - 1));
    lock_registry();
    for (uint32_t i = 0; i < GUARD_MAX_PAGES; i++) {
        if (g_pages[i].owner == owner && g_pages[i].page == base) {
            InterlockedExchange(&g_pages[i].live, 0);
            g_pages[i].owner = GUARD_OWNER_NONE;
            unlock_registry();
            return 0;
        }
    }
    unlock_registry();
    return -1;
}

/* Restore one owner's guarded pages, called off the fault path. The saved
 * original is restored only when the live base protection still equals what
 * guard installed; if the target re-protected the page since (its epoch moved)
 * the saved value is stale and is discarded rather than written back. */
static uint32_t pages_restore(uint32_t owner) {
    uint32_t restored = 0;
    for (uint32_t i = 0; i < GUARD_MAX_PAGES; i++) {
        guard_page_rec_t* r = &g_pages[i];
        if (r->owner != owner) continue;
        if (InterlockedExchange(&r->live, 0) == 0) continue;

        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((LPCVOID)(uintptr_t)r->page, &mbi, sizeof(mbi)))
            continue;                 /* cannot read live state: leave it */

        DWORD live = mbi.Protect;
        if ((live & 0xFFu) != (r->installed & 0xFFu))
            continue;                 /* epoch moved; do not restore stale */

        DWORD old = 0;
        if (VirtualProtect((LPVOID)(uintptr_t)r->page, GUARD_PAGE,
                           r->original, &old))
            restored++;
    }
    return restored;
}

int guard_disarm(uint32_t owner) {
    lock_registry();
    uint32_t restored = pages_restore(owner);
    unlock_registry();
    return (int)restored;
}

int guard_release(uint32_t owner) {
    lock_registry();
    uint32_t idx = entry_index(owner);
    if (idx >= GUARD_MAX_ENTRIES) { unlock_registry(); return -1; }

    pages_restore(owner);
    InterlockedExchange(&g_entries[idx].state, GUARD_ST_FREE);
    g_entries[idx].owner = GUARD_OWNER_NONE;
    for (uint32_t i = 0; i < GUARD_MAX_PAGES; i++) {
        if (g_pages[i].owner == owner) {
            InterlockedExchange(&g_pages[i].live, 0);
            g_pages[i].owner = GUARD_OWNER_NONE;
        }
    }
    unlock_registry();
    return 0;
}
