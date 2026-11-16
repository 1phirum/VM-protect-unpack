/* cmd_dump.c - dump the live image of the main module, with a meta sidecar */
#include "vmpx.h"

int cmd_dump(int argc, char** argv) {
    uint32_t pid = 0;
    if (resolve_pid(argc, argv, &pid) != 0) return 1;

    uint64_t base = 0;
    uint32_t size = 0;
    if (!proc_main_module(pid, &base, &size)) {
        printf("[-] main module not found in pid %u\n", pid);
        return 1;
    }
    printf("[*] pid %u  base 0x%llX  module size 0x%X\n",
           pid, (unsigned long long)base, size);

    char path[MAX_PATH];
    const char* out = arg_get(argc, argv, "--out");
    if (out) strncpy_s(path, sizeof(path), out, _TRUNCATE);
    else     sprintf_s(path, sizeof(path), "dump_%u.bin", pid);

    enable_debug_privilege();

    int sanity = image_sanity(pid, base, size);
    if (sanity != 0 && !arg_has(argc, argv, "--force")) {
        printf("[-] refusing to dump: image is not fully committed (use --force to override)\n");
        return 1;
    }

    uint64_t max_bytes = arg_num(argc, argv, "--max-mb", 600) << 20;
    vmpx_dump_meta_t meta;
    if (dump_image(pid, base, size, path, max_bytes, &meta) != 0) return 1;

    if (dump_meta_write(path, &meta) != 0) {
        printf("[-] dump written but meta sidecar failed: %s.meta\n", path);
        return 1;
    }
    printf("[+] meta: %s.meta\n", path);
    return 0;
}
