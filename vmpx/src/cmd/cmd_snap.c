/* cmd_snap.c - dump private VM context for the rebuilt bootstrap */
#include "vmpx.h"

int cmd_snap(int argc, char** argv) {
    const char* out = arg_get(argc, argv, "--out");
    int have_target = arg_get(argc, argv, "--pid") ||
                      arg_get(argc, argv, "--name") ||
                      arg_get(argc, argv, "--exe");
    if (!out || !have_target) {
        printf("[-] usage: vmpx snap [--pid N | --name exe | --exe path] "
               "--out <snapshot> [--lo 0xADDR] [--all-private]\n");
        return 2;
    }

    uint32_t pid = 0;
    if (resolve_pid(argc, argv, &pid) != 0)
        return vmpx_run_status_exit(VMPX_RUN_CAPTURE_FAILED);

    uint64_t lo = arg_num(argc, argv, "--lo", 0);
    if (arg_has(argc, argv, "--all-private")) lo = 1;

    if (snap_write(pid, lo, out) != 0) {
        printf("STATUS snap failed pid=%u out=%s status=capture-failed\n", pid,
               out);
        return vmpx_run_status_exit(VMPX_RUN_CAPTURE_FAILED);
    }
    printf("STATUS snap ok pid=%u out=%s\n", pid, out);
    return 0;
}
