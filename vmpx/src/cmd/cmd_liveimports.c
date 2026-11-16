/* cmd_liveimports.c - reconstruct the runtime import table of the main module */
#include "vmpx.h"

int cmd_liveimports(int argc, char** argv) {
    uint32_t pid = 0;
    if (resolve_pid(argc, argv, &pid) != 0) return 1;

    uint64_t base = 0;
    uint32_t size = 0;
    if (!proc_main_module(pid, &base, &size)) {
        printf("[-] main module not found in pid %u\n", pid);
        return 1;
    }
    printf("[*] pid %u  base 0x%llX\n", pid, (unsigned long long)base);

    enable_debug_privilege();
    return live_imports(pid, base, (int)arg_num(argc, argv, "--limit", 300)) == 0 ? 0 : 1;
}
