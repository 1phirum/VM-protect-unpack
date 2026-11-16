/* baseline.c - low-perturbation baseline measurement and focused-window leases
 *
 * Two questions for the CLI: how fast is the target running with nothing
 * attached (baseline), and is a new intrusive observation still inside its
 * fixed budget? A window opens only when no other window is active, the
 * requested guard-page / probe / trace lease fits the budget, and the control
 * deadline has not elapsed. Closing releases the lease and records whether the
 * window completed or was cancelled. Report artifacts read the timing label so
 * a perturbed interval is never presented as baseline.
 *
 * No dynamic allocation: all state lives in vmpx_baseline_budget_t.
 */
#include "unpack/deobf/dynamic/baseline/baseline.h"
#include <string.h>

#define VMPX_BASE_SAMPLE_CAP 60000u

static uint64_t filetime_100ns(const FILETIME* ft) {
    return ((uint64_t)ft->dwHighDateTime << 32) | (uint64_t)ft->dwLowDateTime;
}

static uint64_t qpc_now(void) {
    LARGE_INTEGER v;
    v.QuadPart = 0;
    (void)QueryPerformanceCounter(&v);
    return (uint64_t)v.QuadPart;
}

static uint64_t qpc_freq(void) {
    LARGE_INTEGER f;
    f.QuadPart = 0;
    if (!QueryPerformanceFrequency(&f) || f.QuadPart <= 0) return 0;
    return (uint64_t)f.QuadPart;
}

static uint64_t cpu_now(HANDLE target, uint64_t fallback) {
    FILETIME create, exit, kernel, user;
    if (!target) return fallback;
    create.dwLowDateTime = 0; create.dwHighDateTime = 0;
    exit.dwLowDateTime = 0;   exit.dwHighDateTime = 0;
    kernel.dwLowDateTime = 0; kernel.dwHighDateTime = 0;
    user.dwLowDateTime = 0;   user.dwHighDateTime = 0;
    if (!GetProcessTimes(target, &create, &exit, &kernel, &user))
        return fallback;
    return filetime_100ns(&kernel) + filetime_100ns(&user);
}

static void copy_label(char* dst, size_t cap, const char* src) {
    size_t i = 0;
    if (!dst || cap == 0) return;
    dst[0] = 0;
    if (!src) return;
    while (i + 1 < cap && src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = 0;
}

void vmpx_baseline_defaults(vmpx_baseline_budget_t* b) {
    if (!b) return;
    memset(b, 0, sizeof(*b));
    b->limits.max_windows = VMPX_BASE_MAX_WINDOWS;
    b->limits.max_guard_pages = VMPX_BASE_MAX_GUARD_PAGES;
    b->limits.max_probe_ms = VMPX_BASE_MAX_PROBE_MS;
    b->limits.max_trace_instructions = VMPX_BASE_MAX_TRACE_INSTR;
    b->limits.control_deadline_ms = VMPX_BASE_CONTROL_DEADLINE_MS;
    b->phase = VMPX_BASE_PHASE_IDLE;
}

void vmpx_baseline_reset(vmpx_baseline_budget_t* b) {
    vmpx_baseline_limits_t keep;
    if (!b) return;
    keep = b->limits;
    memset(b, 0, sizeof(*b));
    if (keep.max_windows && keep.max_guard_pages && keep.max_probe_ms &&
        keep.max_trace_instructions && keep.control_deadline_ms) {
        b->limits = keep;
        b->phase = VMPX_BASE_PHASE_IDLE;
    } else {
        vmpx_baseline_defaults(b);
    }
}

int vmpx_baseline_configure(vmpx_baseline_budget_t* b, uint32_t max_windows,
                            uint32_t max_guard_pages, uint32_t max_probe_ms,
                            uint32_t max_trace_instructions) {
    if (!b) return -1;
    if (!max_windows || !max_guard_pages || !max_probe_ms ||
        !max_trace_instructions)
        return -1;
    b->limits.max_windows = max_windows;
    b->limits.max_guard_pages = max_guard_pages;
    b->limits.max_probe_ms = max_probe_ms;
    b->limits.max_trace_instructions = max_trace_instructions;
    if (!b->limits.control_deadline_ms)
        b->limits.control_deadline_ms = VMPX_BASE_CONTROL_DEADLINE_MS;
    return 0;
}

int vmpx_baseline_begin(vmpx_baseline_budget_t* b, HANDLE target) {
    if (!b) return -1;
    if (b->active || b->baseline_open) return -1;
    if (b->phase == VMPX_BASE_PHASE_FOCUSED) return -1;

    b->phase = VMPX_BASE_PHASE_BASELINE;
    b->baseline_open = 1;
    b->baseline_opened_ms = GetTickCount64();
    b->baseline_start_qpc = qpc_now();
    b->baseline_start_cpu = cpu_now(target, 0);
    b->baseline_last_cpu = b->baseline_start_cpu;
    memset(&b->baseline, 0, sizeof(b->baseline));
    return 0;
}

int vmpx_baseline_sample(vmpx_baseline_budget_t* b, HANDLE target) {
    if (!b || !b->baseline_open) return -1;
    if (GetTickCount64() - b->baseline_opened_ms >
        b->limits.control_deadline_ms)
        return -1; /* deadline: stop sampling, fail closed */
    b->baseline_last_cpu = cpu_now(target, b->baseline_last_cpu);
    b->baseline.samples++;
    return 0;
}

int vmpx_baseline_end(vmpx_baseline_budget_t* b, HANDLE target,
                      vmpx_baseline_sample_t* out) {
    vmpx_baseline_sample_t s;
    uint64_t q_end, cpu_end, freq, delta_q;
    if (!b || !b->baseline_open) return -1;

    q_end = qpc_now();
    cpu_end = cpu_now(target, b->baseline_last_cpu);
    b->baseline_last_cpu = cpu_end;

    memset(&s, 0, sizeof(s));
    s.start_qpc = b->baseline_start_qpc;
    s.end_qpc = q_end;
    s.start_cpu_100ns = b->baseline_start_cpu;
    s.cpu_100ns = (cpu_end >= b->baseline_start_cpu)
                      ? cpu_end - b->baseline_start_cpu
                      : 0;
    s.cpu_ms = s.cpu_100ns / 10000u;
    freq = qpc_freq();
    delta_q = (q_end >= b->baseline_start_qpc)
                  ? q_end - b->baseline_start_qpc
                  : 0;
    s.elapsed_ms = freq ? (delta_q * 1000u) / freq : 0;
    s.samples = b->baseline.samples;
    s.valid = b->baseline.samples ? 1u : 0u;

    b->baseline = s;
    b->baseline_open = 0;
    b->phase = VMPX_BASE_PHASE_IDLE;
    if (out) *out = s;
    return 0;
}

int vmpx_baseline_measure(vmpx_baseline_budget_t* b, HANDLE target,
                          vmpx_baseline_sample_t* out) {
    uint32_t cap;
    if (vmpx_baseline_begin(b, target) != 0) return -1;

    cap = b->limits.control_deadline_ms;
    if (cap == 0) cap = 1u;
    if (cap > VMPX_BASE_SAMPLE_CAP) cap = VMPX_BASE_SAMPLE_CAP;

    while (b->baseline.samples < cap) {
        if (vmpx_baseline_sample(b, target) != 0) break;
        if (GetTickCount64() - b->baseline_opened_ms >=
            b->limits.control_deadline_ms)
            break;
        Sleep(1);
    }
    return vmpx_baseline_end(b, target, out);
}

int vmpx_baseline_window_open(vmpx_baseline_budget_t* b, const char* label,
                              uint32_t guard_pages, uint32_t probe_ms,
                              uint32_t trace_instr) {
    uint64_t now;
    if (!b) return -1;
    now = GetTickCount64();

    if (b->active) { b->windows_refused++; return -1; }        /* overlap */
    if (b->baseline_open) { b->windows_refused++; return -1; }
    if (b->windows_opened >= b->limits.max_windows) {
        b->windows_refused++;
        return -1;
    }
    if (guard_pages > b->limits.max_guard_pages ||
        probe_ms > b->limits.max_probe_ms ||
        trace_instr > b->limits.max_trace_instructions) {
        b->windows_refused++;
        return -1;
    }
    if (b->control_epoch_set &&
        now - b->control_epoch_ms > b->limits.control_deadline_ms) {
        b->windows_refused++;
        return -1;
    }
    if (!b->control_epoch_set) {
        b->control_epoch_ms = now;
        b->control_epoch_set = 1;
    }

    b->active = 1;
    b->phase = VMPX_BASE_PHASE_FOCUSED;
    b->windows_opened++;
    b->lease_guard_pages = guard_pages;
    b->lease_probe_ms = probe_ms;
    b->lease_trace_instr = trace_instr;
    b->lease_opened_ms = now;
    copy_label(b->label, sizeof(b->label),
               label ? label : VMPX_BASE_LABEL_FOCUSED);
    return 0;
}

int vmpx_baseline_window_close(vmpx_baseline_budget_t* b, int completed) {
    if (!b || !b->active) return -1;
    b->active = 0;
    if (completed) b->windows_completed++;
    else b->windows_cancelled++;
    /* Release every modification the window declared. */
    b->lease_guard_pages = 0;
    b->lease_probe_ms = 0;
    b->lease_trace_instr = 0;
    b->lease_opened_ms = 0;
    b->phase = VMPX_BASE_PHASE_IDLE;
    copy_label(b->label, sizeof(b->label), "");
    return 0;
}

int vmpx_baseline_window_cancel(vmpx_baseline_budget_t* b) {
    return vmpx_baseline_window_close(b, 0);
}

uint32_t vmpx_baseline_window_active(const vmpx_baseline_budget_t* b) {
    return b ? b->active : 0u;
}

uint32_t vmpx_baseline_window_count(const vmpx_baseline_budget_t* b) {
    return b ? b->windows_opened : 0u;
}

const char* vmpx_baseline_window_label(const vmpx_baseline_budget_t* b) {
    if (!b || !b->label[0]) return VMPX_BASE_LABEL_BASELINE;
    return b->label;
}

int vmpx_baseline_timing_excluded(const vmpx_baseline_budget_t* b) {
    if (!b) return 0;
    return (b->active || b->windows_opened) ? 1 : 0;
}

const char* vmpx_baseline_timing_label(const vmpx_baseline_budget_t* b) {
    if (!b) return VMPX_BASE_LABEL_BASELINE;
    if (b->active && b->label[0]) return b->label;
    if (b->windows_opened) return VMPX_BASE_LABEL_FOCUSED;
    return VMPX_BASE_LABEL_BASELINE;
}
