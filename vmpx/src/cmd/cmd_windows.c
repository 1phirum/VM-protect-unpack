/* cmd_windows.c - enumerate top-level windows owned by a process */
#include "vmpx.h"
#include "armor/winwait.h"

int cmd_windows(int argc, char** argv) {
    uint32_t pid = 0;
    if (resolve_pid(argc, argv, &pid) != 0) return 1;
    windump_for_pid(pid);
    return 0;
}
