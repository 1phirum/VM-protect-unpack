/* cmd_poke.c - write bytes to remote memory */
#include "vmpx.h"

int cmd_poke(int argc, char** argv) {
    uint32_t pid = 0;
    if (resolve_pid(argc, argv, &pid) != 0) return 1;

    uint64_t addr = arg_num(argc, argv, "--addr", 0);
    const char* bytes = arg_get(argc, argv, "--bytes");
    if (!addr || !bytes) {
        printf("[-] usage: vmpx poke ... --addr 0xADDR --bytes \"90 90\"\n");
        return 2;
    }

    uint8_t data[256];
    size_t len = 0;
    if (parse_hex_bytes(bytes, data, sizeof(data), &len) != 0) {
        printf("[-] bad --bytes string\n");
        return 2;
    }

    enable_debug_privilege();

    uint8_t old[256];
    if (proc_read(pid, addr, old, len) == 0) {
        printf("[*] old:");
        for (size_t i = 0; i < len; i++) printf(" %02X", old[i]);
        printf("\n");
    }

    if (proc_write(pid, addr, data, len) != 0) {
        printf("[-] write failed (elevated?)\n");
        return 1;
    }
    printf("[+] wrote %zu bytes at 0x%llX\n", len, (unsigned long long)addr);
    return 0;
}
