/* result_test.c - result-layer gate tests; no target process is created */
#include "unpack/result.h"
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond) do {                                              \
    if (!(cond)) {                                                    \
        printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);         \
        failures++;                                                   \
    }                                                                 \
} while (0)

int main(void) {
    vmpx_run_result_t r;
    memset(&r, 0xA5, sizeof(r));
    vmpx_run_result_init(&r);
    CHECK(r.status == VMPX_RUN_INTERNAL_ERROR);
    CHECK(r.pid == 0);
    CHECK(r.terminal_exceptions == 0);
    CHECK(r.timed_out == 0);
    CHECK(r.capture_complete == 0);
    CHECK(r.restore_complete == 0);

    CHECK(vmpx_run_classify(1, 1, 0, 0) == VMPX_RUN_TERMINAL_EXCEPTION);
    CHECK(vmpx_run_classify(1, 1, 1, 1) == VMPX_RUN_TERMINAL_EXCEPTION);
    CHECK(vmpx_run_classify(1, 0, 1, 0) == VMPX_RUN_TIMEOUT);
    CHECK(vmpx_run_classify(1, 0, 0, 1) == VMPX_RUN_PROCESS_EXITED);
    CHECK(vmpx_run_classify(1, 0, 0, 0) == VMPX_RUN_OK);
    CHECK(vmpx_run_classify(0, 0, 0, 0) == VMPX_RUN_LAUNCHED);

    CHECK(vmpx_run_status_exit(VMPX_RUN_OK) == 0);
    CHECK(vmpx_run_status_exit(VMPX_RUN_LAUNCHED) == 0);
    CHECK(vmpx_run_status_exit(VMPX_RUN_INVALID_ARG) == 2);
    CHECK(vmpx_run_status_exit(VMPX_RUN_CAPTURE_FAILED) == 3);
    CHECK(vmpx_run_status_exit(VMPX_RUN_RESTORE_INCOMPLETE) == 4);
    CHECK(vmpx_run_status_exit(VMPX_RUN_TERMINAL_EXCEPTION) == 5);
    CHECK(vmpx_run_status_exit(VMPX_RUN_PROCESS_EXITED) == 6);
    CHECK(vmpx_run_status_exit(VMPX_RUN_TIMEOUT) == 7);
    CHECK(vmpx_run_status_exit(VMPX_RUN_UNSUPPORTED) == 8);
    CHECK(vmpx_run_status_exit(VMPX_RUN_INTERNAL_ERROR) == 9);

    r.failed = 1;
    CHECK(vmpx_run_result_incomplete(&r) == 1);
    r.failed = 0;
    r.pages_failed = 1;
    CHECK(vmpx_run_result_incomplete(&r) == 1);
    r.pages_failed = 0;
    CHECK(vmpx_run_result_incomplete(&r) == 1);
    r.capture_complete = 1;
    r.restore_complete = 1;
    CHECK(vmpx_run_result_incomplete(&r) == 0);
    r.restore_complete = 0;
    CHECK(vmpx_run_result_incomplete(&r) == 1);

    if (failures) {
        printf("result_test: %d failure(s)\n", failures);
        return 1;
    }
    printf("result_test: ok\n");
    return 0;
}
