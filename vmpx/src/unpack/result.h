/* result.h - typed runtime outcomes shared by restore, run and validation
 *
 * A launch is not a pass. The status enum separates a completed restore from
 * an observed terminal exception, an exited process and a diagnostic timeout.
 * Commands map the status to a process exit code; nothing prints "ok" for a
 * path that only reached the loader.
 */
#pragma once

#include <stdint.h>

typedef enum {
    VMPX_RUN_OK = 0,                  /* requested observation completed */
    VMPX_RUN_LAUNCHED = 1,            /* restore applied; no observation asked */
    VMPX_RUN_INVALID_ARG = 2,
    VMPX_RUN_CAPTURE_FAILED = 3,
    VMPX_RUN_RESTORE_INCOMPLETE = 4,
    VMPX_RUN_TERMINAL_EXCEPTION = 5,
    VMPX_RUN_PROCESS_EXITED = 6,
    VMPX_RUN_TIMEOUT = 7,
    VMPX_RUN_UNSUPPORTED = 8,
    VMPX_RUN_INTERNAL_ERROR = 9
} vmpx_run_status_t;

typedef struct {
    vmpx_run_status_t status;
    uint32_t pid;
    uint32_t mapped;
    uint32_t failed;
    uint64_t pages_mapped;
    uint64_t pages_failed;
    uint32_t modules_child;
    uint32_t modules_snapshot;
    uint32_t capture_complete;
    uint32_t restore_complete;
    uint32_t terminal_exceptions;
    uint32_t translated_eips;
    uint32_t debug_assist;
    uint32_t process_exited;
    uint32_t timed_out;
    uint32_t exit_code;
} vmpx_run_result_t;

void        vmpx_run_result_init(vmpx_run_result_t* r);
const char* vmpx_run_status_name(vmpx_run_status_t s);
int         vmpx_run_status_exit(vmpx_run_status_t s);
int         vmpx_run_result_incomplete(const vmpx_run_result_t* r);
vmpx_run_status_t vmpx_run_classify(int debug_observed,
                                    uint32_t terminal_exceptions,
                                    uint32_t timed_out,
                                    uint32_t process_exited);
