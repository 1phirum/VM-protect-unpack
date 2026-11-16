/* result.c - status names, exit mapping and result initialization */
#include "unpack/result.h"
#include <string.h>

void vmpx_run_result_init(vmpx_run_result_t* r) {
    if (!r) return;
    memset(r, 0, sizeof(*r));
    r->status = VMPX_RUN_INTERNAL_ERROR;
}

const char* vmpx_run_status_name(vmpx_run_status_t s) {
    switch (s) {
    case VMPX_RUN_OK:                 return "ok";
    case VMPX_RUN_LAUNCHED:           return "launched";
    case VMPX_RUN_INVALID_ARG:        return "invalid-arg";
    case VMPX_RUN_CAPTURE_FAILED:     return "capture-failed";
    case VMPX_RUN_RESTORE_INCOMPLETE: return "restore-incomplete";
    case VMPX_RUN_TERMINAL_EXCEPTION: return "terminal-exception";
    case VMPX_RUN_PROCESS_EXITED:     return "process-exited";
    case VMPX_RUN_TIMEOUT:            return "timeout";
    case VMPX_RUN_UNSUPPORTED:        return "unsupported";
    case VMPX_RUN_INTERNAL_ERROR:     return "internal-error";
    }
    return "unknown";
}

int vmpx_run_status_exit(vmpx_run_status_t s) {
    switch (s) {
    case VMPX_RUN_OK:
    case VMPX_RUN_LAUNCHED:           return 0;
    case VMPX_RUN_INVALID_ARG:        return 2;
    case VMPX_RUN_CAPTURE_FAILED:     return 3;
    case VMPX_RUN_RESTORE_INCOMPLETE: return 4;
    case VMPX_RUN_TERMINAL_EXCEPTION: return 5;
    case VMPX_RUN_PROCESS_EXITED:     return 6;
    case VMPX_RUN_TIMEOUT:            return 7;
    case VMPX_RUN_UNSUPPORTED:        return 8;
    case VMPX_RUN_INTERNAL_ERROR:     return 9;
    }
    return 9;
}

int vmpx_run_result_incomplete(const vmpx_run_result_t* r) {
    if (!r) return 1;
    return !r->capture_complete || !r->restore_complete ||
           r->failed != 0 || r->pages_failed != 0;
}

/* One place decides whether an observed run passes. A terminal exception or
 * a diagnostic timeout always outranks a created process. */
vmpx_run_status_t vmpx_run_classify(int debug_observed,
                                    uint32_t terminal_exceptions,
                                    uint32_t timed_out,
                                    uint32_t process_exited) {
    if (!debug_observed) return VMPX_RUN_LAUNCHED;
    if (terminal_exceptions) return VMPX_RUN_TERMINAL_EXCEPTION;
    if (timed_out) return VMPX_RUN_TIMEOUT;
    if (process_exited) return VMPX_RUN_PROCESS_EXITED;
    return VMPX_RUN_OK;
}
