/* trace.c - bounded instruction trace window with range prioritization
 *
 * What is functional in this build:
 *   - the window (100000 instructions / 250 ms, first cap wins),
 *   - the range-priority classifier that puts recently materialized executable
 *     ranges (tier 0) ahead of whole-image coverage (tier 1),
 *   - the fixed-size ring with explicit oldest-drop overflow accounting,
 *   - the stats record and truncation reporting,
 *   - a bounded hardware single-step self-test (trace_step_probe).
 *
 * What is a truthful stub in this build:
 *   - the self-driving stepping path that would feed trace_record() from target
 *     threads. It is not installed. A process-wide VEH single-step handler would
 *     collide with the guard single-step handler in oep.c and with the packer's
 *     own anti-debug, so trace_step_supported() returns 0 and window status
 *     carries VMPX_TRACE_STEP_NONE. Records are still accepted from any producer
 *     the caller wires (guard VEH, context sampler). The probe proves the
 *     mechanism works on a thread we own; it does not deliver target stepping.
 */
#include "unpack/deobf/dynamic/trace/trace.h"
#include "armor/stealth/stealth.h"
#include <stdlib.h>
#include <string.h>

static vmpx_trace_range_t g_ranges[VMPX_TRACE_MAX_RANGES];
static uint32_t g_range_n = 0;
static uint32_t g_hidden_dropped = 0;

static vmpx_trace_insn_t g_ring[VMPX_TRACE_RING];
static vmpx_trace_stats_t g_stats;
static volatile LONG g_running = 0;
static uint64_t g_seq = 0;

/* stepping self-test state */
static volatile LONG g_step_active = 0;
static volatile LONG g_step_tid = 0;
static volatile LONG g_step_count = 0;
static volatile LONG g_step_mechanism_ok = 0;
static PVOID g_step_veh = NULL;

/* --- bounded hardware single-step self-test ------------------------------ */

/* Only the probing thread is touched. Every other thread's single-step is
 * passed down the VEH chain, so the guard handler in oep.c still gets it. The
 * handler re-arms TF until the hard cap, then clears it, which makes the loop
 * finish in at most VMPX_TRACE_STEP_PROBE_MAX steps. */
static LONG CALLBACK trace_probe_veh(PEXCEPTION_POINTERS ep) {
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord)
        return EXCEPTION_CONTINUE_SEARCH;
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    if (!InterlockedCompareExchange(&g_step_active, 1, 1))
        return EXCEPTION_CONTINUE_SEARCH;
    if ((uint32_t)GetCurrentThreadId() != (uint32_t)InterlockedCompareExchange(&g_step_tid, 0, 0))
        return EXCEPTION_CONTINUE_SEARCH;

    LONG n = InterlockedIncrement(&g_step_count);
    if (n >= (LONG)VMPX_TRACE_STEP_PROBE_MAX) {
        ep->ContextRecord->EFlags &= ~0x100u;   /* clear TF: loop terminates */
    } else {
        ep->ContextRecord->EFlags |= 0x100u;    /* keep stepping             */
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

int trace_step_probe(void) {
    if (g_step_veh) return -1;
    g_step_count = 0;
    g_step_tid = (LONG)GetCurrentThreadId();
    InterlockedExchange(&g_step_active, 1);

    g_step_veh = AddVectoredExceptionHandler(1, trace_probe_veh);
    if (!g_step_veh) {
        InterlockedExchange(&g_step_active, 0);
        return VMPX_TRACE_ERR_UNSUPPORTED;
    }

    CONTEXT c;
    memset(&c, 0, sizeof(c));
    c.ContextFlags = CONTEXT_CONTROL;
    int fired = 0;
    if (GetThreadContext(GetCurrentThread(), &c)) {
        c.EFlags |= 0x100u;
        if (SetThreadContext(GetCurrentThread(), &c)) {
            /* Returning from SetThreadContext retires instructions with TF
             * armed; the handler above runs bounded times and clears TF. */
            volatile LONG spin = 0;
            while (InterlockedCompareExchange(&g_step_count, 0, 0) == 0 &&
                   spin < 1000000L)
                spin++;
            fired = 1;
        }
    }

    /* Defensive: if no trap ever arrived, TF may still be set on this thread. */
    if (GetThreadContext(GetCurrentThread(), &c)) {
        if (c.EFlags & 0x100u) {
            c.EFlags &= ~0x100u;
            SetThreadContext(GetCurrentThread(), &c);
        }
    }

    RemoveVectoredExceptionHandler(g_step_veh);
    g_step_veh = NULL;
    InterlockedExchange(&g_step_active, 0);

    LONG steps = InterlockedCompareExchange(&g_step_count, 0, 0);
    if (fired && steps > 0) InterlockedExchange(&g_step_mechanism_ok, 1);
    return (int)steps;
}

int trace_step_supported(void) {
    /* No safe per-target stepping path is delivered by this module. The probe
     * result is exposed separately; it does not enable target streaming. */
    return 0;
}

uint32_t trace_step_mode(void) { return VMPX_TRACE_STEP_NONE; }

const char* trace_step_reason(void) {
    if (InterlockedCompareExchange(&g_step_mechanism_ok, 0, 0))
        return "mechanism-proven-target-streaming-not-installed";
    return "no-safe-stepping-path";
}

/* --- range priority ------------------------------------------------------ */

static int range_cmp(const void* a, const void* b) {
    const vmpx_trace_range_t* x = (const vmpx_trace_range_t*)a;
    const vmpx_trace_range_t* y = (const vmpx_trace_range_t*)b;
    uint32_t tx = (x->flags & VMPX_TRACE_RANGE_RECENT) ? 0u : 1u;
    uint32_t ty = (y->flags & VMPX_TRACE_RANGE_RECENT) ? 0u : 1u;
    if (tx != ty) return tx < ty ? -1 : 1;
    if (x->materialized_tick != y->materialized_tick)
        return x->materialized_tick > y->materialized_tick ? -1 : 1;
    if (x->base != y->base) return x->base < y->base ? -1 : 1;
    if (x->id != y->id) return x->id < y->id ? -1 : 1;
    return 0;
}

static int range_admit(uint64_t base, uint64_t size) {
    if (!size) return 0;
    if (base + size < base) return 0;             /* wrap: refuse */
    if (stealth_hidden_region(base, size)) return 0;
    return 1;
}

int trace_set_ranges(const vmpx_trace_range_t* ranges, uint32_t count) {
    g_range_n = 0;
    g_hidden_dropped = 0;
    if (!ranges) return VMPX_TRACE_OK;
    if (count > VMPX_TRACE_MAX_RANGES) count = VMPX_TRACE_MAX_RANGES;
    for (uint32_t i = 0; i < count; i++) {
        if (!range_admit(ranges[i].base, ranges[i].size)) {
            g_hidden_dropped++;
            continue;
        }
        g_ranges[g_range_n++] = ranges[i];
    }
    qsort(g_ranges, g_range_n, sizeof(g_ranges[0]), range_cmp);
    g_stats.ranges = g_range_n;
    g_stats.hidden_dropped = g_hidden_dropped;
    return VMPX_TRACE_OK;
}

int trace_note_materialized(uint64_t base, uint64_t size, uint64_t tick) {
    if (!range_admit(base, size)) return VMPX_TRACE_ERR_ARG;
    for (uint32_t i = 0; i < g_range_n; i++) {
        if (g_ranges[i].base == base && g_ranges[i].size == size) {
            g_ranges[i].flags |= VMPX_TRACE_RANGE_RECENT;
            g_ranges[i].materialized_tick = tick;
            qsort(g_ranges, g_range_n, sizeof(g_ranges[0]), range_cmp);
            return VMPX_TRACE_OK;
        }
    }
    if (g_range_n >= VMPX_TRACE_MAX_RANGES) return VMPX_TRACE_ERR_ARG;
    g_ranges[g_range_n].base = base;
    g_ranges[g_range_n].size = size;
    g_ranges[g_range_n].materialized_tick = tick;
    g_ranges[g_range_n].id = g_range_n;
    g_ranges[g_range_n].flags = VMPX_TRACE_RANGE_RECENT;
    g_range_n++;
    qsort(g_ranges, g_range_n, sizeof(g_ranges[0]), range_cmp);
    g_stats.ranges = g_range_n;
    return VMPX_TRACE_OK;
}

uint32_t trace_classify(uint64_t ip) {
    for (uint32_t i = 0; i < g_range_n; i++) {
        uint64_t b = g_ranges[i].base;
        uint64_t e = b + g_ranges[i].size;
        if (e < b) e = 0xFFFFFFFFFFFFFFFFull;
        if (ip < b || ip >= e) continue;
        return (g_ranges[i].flags & VMPX_TRACE_RANGE_RECENT)
                   ? VMPX_TRACE_TIER_RECENT
                   : VMPX_TRACE_TIER_IMAGE;
    }
    return VMPX_TRACE_TIER_NONE;
}

static int have_recent(void) {
    for (uint32_t i = 0; i < g_range_n; i++)
        if (g_ranges[i].flags & VMPX_TRACE_RANGE_RECENT) return 1;
    return 0;
}

uint32_t trace_image_share(void) {
    if (!have_recent()) return VMPX_TRACE_MAX_INSNS;
    return VMPX_TRACE_MAX_INSNS / VMPX_TRACE_IMAGE_SHARE;
}

/* --- window bookkeeping -------------------------------------------------- */

void trace_reset(void) {
    g_range_n = 0;
    g_hidden_dropped = 0;
    g_seq = 0;
    InterlockedExchange(&g_running, 0);
    memset(&g_stats, 0, sizeof(g_stats));
    memset(g_ring, 0, sizeof(g_ring));
    g_stats.status = VMPX_TRACE_STATUS_IDLE;
    g_stats.step_mode = VMPX_TRACE_STEP_NONE;
}

int trace_elapsed_ms(void) {
    if (!g_stats.freq) return 0;
    LARGE_INTEGER now;
    if (!QueryPerformanceCounter(&now)) return 0;
    uint64_t d = (uint64_t)now.QuadPart - g_stats.start_tick;
    uint64_t ms = (d * 1000ull) / g_stats.freq;
    if (ms > 0x7FFFFFFFull) return 0x7FFFFFFF;
    return (int)ms;
}

static void refresh_elapsed(void) {
    LARGE_INTEGER now;
    if (g_stats.freq && QueryPerformanceCounter(&now))
        g_stats.elapsed_ticks = (uint64_t)now.QuadPart - g_stats.start_tick;
}

int trace_window_open(void) {
    if (!g_range_n) return VMPX_TRACE_ERR_ARG;

    LARGE_INTEGER f, t;
    if (!QueryPerformanceFrequency(&f) || f.QuadPart == 0)
        return VMPX_TRACE_ERR_UNSUPPORTED;
    if (!QueryPerformanceCounter(&t))
        return VMPX_TRACE_ERR_UNSUPPORTED;

    g_stats.start_tick = (uint64_t)t.QuadPart;
    g_stats.freq = (uint64_t)f.QuadPart;
    g_stats.instructions = 0;
    g_stats.elapsed_ticks = 0;
    g_stats.overflows = 0;
    g_stats.out_of_range = 0;
    g_stats.image_insns = 0;
    g_stats.ring_head = 0;
    g_stats.ring_tail = 0;
    g_stats.hidden_dropped = g_hidden_dropped;
    g_stats.ranges = g_range_n;
    g_stats.truncation = VMPX_TRACE_TRUNC_NONE;
    g_stats.step_mode = trace_step_mode();
    g_seq = 0;

    InterlockedExchange(&g_running, 1);
    g_stats.status = VMPX_TRACE_STATUS_RUNNING;

    /* Optional bounded mechanism self-test, opt-in so normal agent operation is
     * never perturbed. It never enables target streaming. */
    char gate[8] = { 0 };
    if (GetEnvironmentVariableA("VMPX_TRACE_PROBE", gate, sizeof(gate)) > 0 &&
        gate[0] == '1' &&
        !InterlockedCompareExchange(&g_step_mechanism_ok, 0, 0))
        (void)trace_step_probe();

    if (!trace_step_supported()) {
        g_stats.step_mode = VMPX_TRACE_STEP_NONE;
        return VMPX_TRACE_ERR_UNSUPPORTED;   /* window open, stepping unsupported */
    }
    return VMPX_TRACE_OK;
}

void trace_window_close(uint32_t reason) {
    if (!InterlockedCompareExchange(&g_running, 0, 0)) {
        if (g_stats.status != VMPX_TRACE_STATUS_IDLE)
            refresh_elapsed();
        if (g_stats.status == VMPX_TRACE_STATUS_RUNNING)
            g_stats.status = VMPX_TRACE_STATUS_DONE;
        return;
    }
    InterlockedExchange(&g_running, 0);
    refresh_elapsed();
    g_stats.status = VMPX_TRACE_STATUS_DONE;
    if (reason != VMPX_TRACE_TRUNC_NONE)
        g_stats.truncation = reason;
    g_stats.step_mode = trace_step_mode();
}

int trace_running(void) {
    return (int)InterlockedCompareExchange(&g_running, 0, 0);
}

int trace_tick(void) {
    if (!InterlockedCompareExchange(&g_running, 0, 0)) return 0;
    if (trace_elapsed_ms() >= (int)VMPX_TRACE_WINDOW_MS) {
        trace_window_close(VMPX_TRACE_TRUNC_TIME_CAP);
        return 0;
    }
    return 1;
}

/* --- record path (no allocation) ----------------------------------------- */

int trace_record(uint32_t tid, uint64_t ip, const uint8_t* bytes, uint32_t len) {
    if (!InterlockedCompareExchange(&g_running, 0, 0))
        return VMPX_TRACE_ERR_CLOSED;

    if (g_stats.instructions >= VMPX_TRACE_MAX_INSNS) {
        trace_window_close(VMPX_TRACE_TRUNC_INSN_CAP);
        return VMPX_TRACE_ERR_CLOSED;
    }
    if (trace_elapsed_ms() >= (int)VMPX_TRACE_WINDOW_MS) {
        trace_window_close(VMPX_TRACE_TRUNC_TIME_CAP);
        return VMPX_TRACE_ERR_CLOSED;
    }

    uint32_t tier = trace_classify(ip);
    if (tier == VMPX_TRACE_TIER_NONE) {
        g_stats.out_of_range++;
        return VMPX_TRACE_SKIPPED;
    }
    if (tier == VMPX_TRACE_TIER_IMAGE &&
        g_stats.image_insns >= trace_image_share()) {
        /* recent ranges own the budget; image coverage is capped silently */
        return VMPX_TRACE_SKIPPED;
    }

    LARGE_INTEGER now;
    uint64_t tick = 0;
    if (QueryPerformanceCounter(&now)) tick = (uint64_t)now.QuadPart;

    uint32_t n = len;
    if (n > VMPX_TRACE_PREVIEW) n = VMPX_TRACE_PREVIEW;

    vmpx_trace_insn_t* slot = &g_ring[g_stats.ring_head % VMPX_TRACE_RING];
    slot->seq = ++g_seq;
    slot->tick = tick;
    slot->ip = ip;
    slot->tid = tid;
    slot->len = (uint16_t)n;
    slot->tier = (uint16_t)tier;
    if (n && bytes) memcpy(slot->bytes, bytes, n);
    if (n < VMPX_TRACE_PREVIEW) memset(slot->bytes + n, 0, VMPX_TRACE_PREVIEW - n);

    g_stats.ring_head++;
    if (tier == VMPX_TRACE_TIER_IMAGE) g_stats.image_insns++;
    g_stats.instructions++;
    g_stats.elapsed_ticks = tick ? (tick - g_stats.start_tick) : g_stats.elapsed_ticks;

    if ((g_stats.ring_head - g_stats.ring_tail) > VMPX_TRACE_RING) {
        g_stats.ring_tail = g_stats.ring_head - VMPX_TRACE_RING;
        g_stats.overflows++;
        if (g_stats.truncation == VMPX_TRACE_TRUNC_NONE)
            g_stats.truncation = VMPX_TRACE_TRUNC_RING;
    }
    return VMPX_TRACE_RECORDED;
}

uint32_t trace_drain(vmpx_trace_insn_t* out, uint32_t max) {
    if (!out || !max) return 0;
    uint32_t avail = g_stats.ring_head - g_stats.ring_tail;
    if (avail > VMPX_TRACE_RING) avail = VMPX_TRACE_RING;
    if (avail > max) avail = max;
    for (uint32_t i = 0; i < avail; i++) {
        uint32_t idx = (g_stats.ring_tail + i) % VMPX_TRACE_RING;
        out[i] = g_ring[idx];
    }
    g_stats.ring_tail += avail;
    refresh_elapsed();
    return avail;
}

const vmpx_trace_stats_t* trace_stats(void) { return &g_stats; }

const char* trace_status_name(uint32_t status) {
    switch (status) {
    case VMPX_TRACE_STATUS_IDLE:        return "idle";
    case VMPX_TRACE_STATUS_READY:       return "ready";
    case VMPX_TRACE_STATUS_RUNNING:     return "running";
    case VMPX_TRACE_STATUS_DONE:        return "done";
    case VMPX_TRACE_STATUS_UNSUPPORTED: return "unsupported";
    default:                            return "unknown";
    }
}

const char* trace_truncation_name(uint32_t reason) {
    switch (reason) {
    case VMPX_TRACE_TRUNC_NONE:        return "none";
    case VMPX_TRACE_TRUNC_INSN_CAP:    return "insn-cap";
    case VMPX_TRACE_TRUNC_TIME_CAP:    return "time-cap";
    case VMPX_TRACE_TRUNC_RING:        return "ring-overflow";
    case VMPX_TRACE_TRUNC_RANGE:       return "range";
    case VMPX_TRACE_TRUNC_UNSUPPORTED: return "unsupported";
    default:                           return "unknown";
    }
}

const char* trace_step_name(uint32_t mode) {
    switch (mode) {
    case VMPX_TRACE_STEP_NONE: return "unsupported";
    case VMPX_TRACE_STEP_HW:   return "hardware-single-step";
    default:                   return "unknown";
    }
}
