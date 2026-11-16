/* baseline.h - low-perturbation baseline and focused-window arbitration
 *
 * The controller decides when intrusive observation (guard pages, timed
 * probes, instruction tracing) may touch the target. It measures a guard-free
 * baseline of the target's CPU time and elapsed wall time, leases a bounded
 * focused window to one caller at a time, and labels every focused interval
 * so a report artifact never presents perturbed timing as baseline.
 *
 * All state is fixed-size inside vmpx_baseline_budget_t. Opening, closing, and
 * canceling a window allocate nothing. Every path fails closed: a refused
 * window makes no modification, and a closed window releases its lease.
 */
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdint.h>
#include <stddef.h>

/* Budget defaults. max_guard_pages, max_probe_ms, and max_trace_instructions
 * mirror the profile observation limits; the controller is the enforcement
 * point for them at lease time. */
#define VMPX_BASE_MAX_WINDOWS         8u
#define VMPX_BASE_MAX_GUARD_PAGES     64u
#define VMPX_BASE_MAX_PROBE_MS        250u
#define VMPX_BASE_MAX_TRACE_INSTR     100000u
#define VMPX_BASE_CONTROL_DEADLINE_MS 2000u

#define VMPX_BASE_PHASE_IDLE     0u
#define VMPX_BASE_PHASE_BASELINE 1u
#define VMPX_BASE_PHASE_FOCUSED  2u

/* Timing labels a report artifact reads. A focused label means the interval
 * must not be quoted as baseline. */
#define VMPX_BASE_LABEL_BASELINE "baseline"
#define VMPX_BASE_LABEL_FOCUSED  "focused-window"
#define VMPX_BASE_LABEL_CAP      48u

typedef struct {
    uint32_t max_windows;
    uint32_t max_guard_pages;      /* per lease */
    uint32_t max_probe_ms;         /* per lease */
    uint32_t max_trace_instructions; /* per lease */
    uint32_t control_deadline_ms;  /* bound on the focused phase */
} vmpx_baseline_limits_t;

/* One completed baseline measurement. cpu fields are the target's kernel+user
 * time over the window; elapsed is wall time via QPC. */
typedef struct {
    uint64_t start_qpc;
    uint64_t end_qpc;
    uint64_t start_cpu_100ns;
    uint64_t cpu_100ns;
    uint64_t elapsed_ms;
    uint64_t cpu_ms;
    uint32_t samples;
    uint32_t valid;
} vmpx_baseline_sample_t;

typedef struct {
    vmpx_baseline_limits_t limits;

    /* baseline phase */
    uint32_t phase;               /* VMPX_BASE_PHASE_* */
    uint32_t baseline_open;
    uint64_t baseline_opened_ms;
    uint64_t baseline_start_qpc;
    uint64_t baseline_start_cpu;
    uint64_t baseline_last_cpu;
    vmpx_baseline_sample_t baseline;

    /* focused-window lease */
    uint32_t active;
    uint32_t windows_opened;
    uint32_t windows_completed;
    uint32_t windows_cancelled;
    uint32_t windows_refused;
    uint32_t lease_guard_pages;
    uint32_t lease_probe_ms;
    uint32_t lease_trace_instr;
    uint64_t lease_opened_ms;
    uint32_t control_epoch_set;
    uint64_t control_epoch_ms;
    char label[VMPX_BASE_LABEL_CAP];
} vmpx_baseline_budget_t;

void vmpx_baseline_defaults(vmpx_baseline_budget_t* b);
void vmpx_baseline_reset(vmpx_baseline_budget_t* b);
int  vmpx_baseline_configure(vmpx_baseline_budget_t* b, uint32_t max_windows,
                             uint32_t max_guard_pages, uint32_t max_probe_ms,
                             uint32_t max_trace_instructions);

/* Baseline phase. begin opens guard-free sampling, sample takes one bounded
 * reading, end finalizes into `out`. measure runs the whole bounded loop. */
int  vmpx_baseline_begin(vmpx_baseline_budget_t* b, HANDLE target);
int  vmpx_baseline_sample(vmpx_baseline_budget_t* b, HANDLE target);
int  vmpx_baseline_end(vmpx_baseline_budget_t* b, HANDLE target,
                       vmpx_baseline_sample_t* out);
int  vmpx_baseline_measure(vmpx_baseline_budget_t* b, HANDLE target,
                           vmpx_baseline_sample_t* out);

/* Focused window lifecycle: open(label) -> active -> close()/cancel().
 * Opening while another window is active, while a baseline is open, past the
 * window count, over a lease limit, or past the control deadline is refused
 * without side effects. Closing releases the lease and records completion. */
int  vmpx_baseline_window_open(vmpx_baseline_budget_t* b, const char* label,
                               uint32_t guard_pages, uint32_t probe_ms,
                               uint32_t trace_instr);
int  vmpx_baseline_window_close(vmpx_baseline_budget_t* b, int completed);
int  vmpx_baseline_window_cancel(vmpx_baseline_budget_t* b);

uint32_t vmpx_baseline_window_active(const vmpx_baseline_budget_t* b);
uint32_t vmpx_baseline_window_count(const vmpx_baseline_budget_t* b);
const char* vmpx_baseline_window_label(const vmpx_baseline_budget_t* b);
int  vmpx_baseline_timing_excluded(const vmpx_baseline_budget_t* b);
const char* vmpx_baseline_timing_label(const vmpx_baseline_budget_t* b);
