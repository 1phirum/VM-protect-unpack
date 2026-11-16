/* cmd_modules.c - live module list */
#include "vmpx.h"

int cmd_modules(int argc, char** argv) {
    uint32_t pid = 0;
    if (resolve_pid(argc, argv, &pid) != 0) return 1;

    enable_debug_privilege();
    proc_list_modules(pid, arg_get(argc, argv, "--filter"));
    return 0;
}
