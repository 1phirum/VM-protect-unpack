/* trace.h - bounded instruction trace window
 *
 * A caller-supplied set of executable ranges is ranked so that ranges which
 * were *recently* made executable (freshly materialized decoder/VM handler
 * pages) are recorded ahead of whole-image coverage. Recording runs inside a
 * hard window: at most VMPX_TRACE_MAX_INSNS instructions or
 * VMPX_TRACE_WINDOW_MS milliseconds, whichever comes first, then the window
 * closes and reports the truncation reason. Records land in a fixed-size ring;
 * overflow drops the oldest record and bumps an explicit counter. No heap and
 * no allocation in the record path.
 *
 * The record path is producer-agnostic: a guard VEH, a context sampler, or a
 * single-step handler all feed trace_record(). This module owns the window,
 * the range priority, and the ring only. The self-driving stepping path is not
 * installed here (see trace_step_probe / trace_step_supported and the notes in
 * trace.c); trace_window_open() reports that honestly.
 */
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

#define VMPX_TRACE_MAX_INSNS      100000u   /* instruction cap per window     */
#define VMPX_TRACE_WINDOW_MS      250u      /* wall-clock cap per window      */
#define VMPX_TRACE_MAX_RANGES     16u       /* caller-supplied range slots    */
#define VMPX_TRACE_RING           4096u     /* fixed ring records             */
#define VMPX_TRACE_PREVIEW        16u       /* code bytes kept per record     */
#define VMPX_TRACE_STEP_PROBE_MAX 32u       /* hard bound on the probe loop   */
#define VMPX_TRACE_IMAGE_SHARE    4u        /* image tier gets 1/N of the cap */

/* range flags */
#define VMPX_TRACE_RANGE_RECENT   1u        /* materialized after capture start */

/* range priority tiers, lowest number wins the budget */
#define VMPX_TRACE_TIER_RECENT    0u
#define VMPX_TRACE_TIER_IMAGE     1u
#define VMPX_TRACE_TIER_NONE      2u        /* outside every supplied range    */

/* window status */
#define VMPX_TRACE_STATUS_IDLE        0u
#define VMPX_TRACE_STATUS_READY       1u
#define VMPX_TRACE_STATUS_RUNNING     2u
#define VMPX_TRACE_STATUS_DONE        3u
#define VMPX_TRACE_STATUS_UNSUPPORTED 4u

/* truncation reason, reported when the window closes */
#define VMPX_TRACE_TRUNC_NONE        0u
#define VMPX_TRACE_TRUNC_INSN_CAP    1u
#define VMPX_TRACE_TRUNC_TIME_CAP    2u
#define VMPX_TRACE_TRUNC_RING        3u
#define VMPX_TRACE_TRUNC_RANGE       4u
#define VMPX_TRACE_TRUNC_UNSUPPORTED 5u

/* stepping path state */
#define VMPX_TRACE_STEP_NONE 0u   /* no safe self-driving path installed */
#define VMPX_TRACE_STEP_HW   1u   /* bounded hardware single-step proven */

/* return codes */
#define VMPX_TRACE_OK              0
#define VMPX_TRACE_ERR_ARG        -1
#define VMPX_TRACE_ERR_UNSUPPORTED -2
#define VMPX_TRACE_ERR_CLOSED     -3

/* trace_record() result: 1 recorded, 0 skipped (ineligible), negative closed */
#define VMPX_TRACE_RECORDED 1
#define VMPX_TRACE_SKIPPED  0

typedef struct {
    uint64_t base;
    uint64_t size;
    uint64_t materialized_tick;   /* QPC when the range became executable   */
    uint32_t id;                  /* caller correlation, opaque to this module */
    uint32_t flags;               /* VMPX_TRACE_RANGE_RECENT                */
} vmpx_trace_range_t;

typedef struct {
    uint64_t seq;
    uint64_t tick;
    uint64_t ip;
    uint32_t tid;
    uint16_t len;
    uint16_t tier;
    uint8_t  bytes[VMPX_TRACE_PREVIEW];
} vmpx_trace_insn_t;

typedef struct {
    uint64_t instructions;   /* records accepted this window                */
    uint64_t elapsed_ticks;  /* QPC ticks since the window opened           */
    uint64_t start_tick;     /* QPC at open                                 */
    uint64_t freq;           /* QPC frequency                               */
    uint64_t overflows;      /* oldest records dropped by the ring          */
    uint64_t out_of_range;   /* IPs outside every supplied range            */
    uint64_t image_insns;    /* image-tier records accepted                 */
    uint32_t truncation;     /* VMPX_TRACE_TRUNC_*                          */
    uint32_t status;         /* VMPX_TRACE_STATUS_*                         */
    uint32_t step_mode;      /* VMPX_TRACE_STEP_*                           */
    uint32_t ranges;         /* ranges retained after filtering/sorting     */
    uint32_t ring_head;      /* monotonically increasing write cursor       */
    uint32_t ring_tail;      /* oldest retained record cursor               */
    uint32_t hidden_dropped; /* ranges rejected as agent/hidden memory      */
} vmpx_trace_stats_t;

void        trace_reset(void);
int         trace_set_ranges(const vmpx_trace_range_t* ranges, uint32_t count);
int         trace_note_materialized(uint64_t base, uint64_t size, uint64_t tick);
uint32_t    trace_classify(uint64_t ip);
uint32_t    trace_image_share(void);

/* Bounded hardware single-step self-test. Runs on the calling thread only and
 * is hard capped by VMPX_TRACE_STEP_PROBE_MAX, so it cannot loop. Returns the
 * number of single steps observed, or a negative error. It proves the
 * mechanism works; it does not deliver target-thread stepping. */
int         trace_step_probe(void);
int         trace_step_supported(void);   /* 1 only when a safe path is live */
uint32_t    trace_step_mode(void);
const char* trace_step_reason(void);      /* why stepping is unavailable      */

int         trace_window_open(void);
void        trace_window_close(uint32_t reason);
int         trace_running(void);
int         trace_tick(void);
int         trace_elapsed_ms(void);

int         trace_record(uint32_t tid, uint64_t ip, const uint8_t* bytes,
                         uint32_t len);
uint32_t    trace_drain(vmpx_trace_insn_t* out, uint32_t max);

const vmpx_trace_stats_t* trace_stats(void);
const char* trace_status_name(uint32_t status);
const char* trace_truncation_name(uint32_t reason);
const char* trace_step_name(uint32_t mode);
