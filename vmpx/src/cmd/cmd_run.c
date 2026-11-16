/* cmd_run.c - start a rebuilt PE with its original private context restored
 *
 * Exit codes follow unpack/result.h. A restore that reaches the loader is not
 * reported as an observation pass; a terminal exception or a diagnostic
 * timeout returns a non-zero code even when the child process was created.
 * A launch-only invocation remains exit 0 because launch was the requested
 * outcome, but its STATUS line carries the restore completeness explicitly.
 */
#include "vmpx.h"
#include "armor/elev.h"

static const char* completeness(const vmpx_run_result_t* r) {
    return vmpx_run_result_incomplete(r) ? "incomplete" : "complete";
}

static void print_run_failure(const vmpx_run_result_t* r,
                              vmpx_run_status_t status) {
    printf("STATUS run failed status=%s pid=%u capture=%u restore=%u "
           "mapped=%u failed=%u pages=%llu/%llu modules=%u/%u "
           "exceptions=%u translated=%u\n",
           vmpx_run_status_name(status), r->pid, r->capture_complete,
           r->restore_complete, r->mapped, r->failed,
           (unsigned long long)r->pages_mapped,
           (unsigned long long)(r->pages_mapped + r->pages_failed),
           r->modules_child, r->modules_snapshot,
           r->terminal_exceptions, r->translated_eips);
}

int cmd_run(int argc, char** argv) {
    const char* snap = arg_get(argc, argv, "--snap");
    const char* exe = arg_get(argc, argv, "--exe");
    if (!snap || !*snap || !exe || !*exe) {
        printf("[-] usage: vmpx run --snap <snapshot> --exe <rebuilt.exe> "
               "[--ctx <entry.ctx>] [--wait <ms>]\n");
        return vmpx_run_status_exit(VMPX_RUN_INVALID_ARG);
    }

    const char* wait = arg_get(argc, argv, "--wait");
    uint32_t ms = 0;
    if (arg_has(argc, argv, "--wait")) {
        char* end = NULL;
        unsigned long v = 0;
        if (!wait || !*wait) {
            printf("[-] usage: --wait expects milliseconds\n");
            return vmpx_run_status_exit(VMPX_RUN_INVALID_ARG);
        }
        v = strtoul(wait, &end, 0);
        if (end == wait || (end && *end) || v > 0x7FFFFFFFul) {
            printf("[-] usage: --wait expects milliseconds\n");
            return vmpx_run_status_exit(VMPX_RUN_INVALID_ARG);
        }
        ms = (uint32_t)v;
    }

    const char* ctx = arg_get(argc, argv, "--ctx");
    if (arg_has(argc, argv, "--ctx") && (!ctx || !*ctx)) {
        printf("[-] usage: --ctx expects a file path\n");
        return vmpx_run_status_exit(VMPX_RUN_INVALID_ARG);
    }

    if (!armor_is_elevated()) {
        printf("[-] run: elevation required to create the target process\n");
        printf("STATUS run failed status=unsupported pid=0 reason=elevation\n");
        return vmpx_run_status_exit(VMPX_RUN_UNSUPPORTED);
    }

    uint32_t pid = 0;
    vmpx_run_result_t r;
    int st = snap_restore_ex(exe, snap, ctx, &pid, &r);
    if (st != VMPX_RUN_OK && st != VMPX_RUN_LAUNCHED) {
        print_run_failure(&r, (vmpx_run_status_t)st);
        return vmpx_run_status_exit((vmpx_run_status_t)st);
    }

    if (wait && *wait) {
        HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                               FALSE, pid);
        if (!h) {
            printf("STATUS run failed status=%s pid=%u error=%lu "
                   "restore=%s\n",
                   vmpx_run_status_name(VMPX_RUN_INTERNAL_ERROR), pid,
                   GetLastError(), completeness(&r));
            return vmpx_run_status_exit(VMPX_RUN_INTERNAL_ERROR);
        }
        DWORD wr = WaitForSingleObject(h, ms ? ms : INFINITE);
        if (wr == WAIT_OBJECT_0) {
            DWORD code = 0;
            GetExitCodeProcess(h, &code);
            CloseHandle(h);
            printf("STATUS run exited pid=%u code=0x%08lX restore=%s\n", pid,
                   code, completeness(&r));
            return code == 0 ? 0
                             : vmpx_run_status_exit(VMPX_RUN_PROCESS_EXITED);
        }
        CloseHandle(h);
        printf("STATUS run alive pid=%u restore=%s\n", pid, completeness(&r));
        return 0;
    }

    if (st == VMPX_RUN_OK && vmpx_run_result_incomplete(&r)) {
        print_run_failure(&r, VMPX_RUN_RESTORE_INCOMPLETE);
        return vmpx_run_status_exit(VMPX_RUN_RESTORE_INCOMPLETE);
    }

    printf("STATUS run %s pid=%u restore=%s mapped=%u failed=%u "
           "pages=%llu/%llu\n",
           st == VMPX_RUN_OK ? "ok" : "launched", pid, completeness(&r),
           r.mapped, r.failed, (unsigned long long)r.pages_mapped,
           (unsigned long long)(r.pages_mapped + r.pages_failed));
    return 0;
}
