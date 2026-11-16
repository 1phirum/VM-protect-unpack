/* cmd_peek.c - hex dump of remote memory */
#include "vmpx.h"

int cmd_peek(int argc, char** argv) {
    uint32_t pid = 0;
    if (resolve_pid(argc, argv, &pid) != 0) return 1;

    uint64_t addr = arg_num(argc, argv, "--addr", 0);
    if (!addr) {
        printf("[-] usage: vmpx peek ... --addr 0xADDR [--size N]\n");
        return 2;
    }
    size_t size = (size_t)arg_num(argc, argv, "--size", 64);

    uint8_t* buf = (uint8_t*)malloc(size);
    if (!buf) return 1;

    enable_debug_privilege();
    if (proc_read(pid, addr, buf, size) != 0) {
        printf("[-] read failed at 0x%llX (elevated?)\n", (unsigned long long)addr);
        free(buf);
        return 1;
    }

    for (size_t i = 0; i < size; i += 16) {
        printf("%08llX  ", (unsigned long long)(addr + i));
        for (size_t j = 0; j < 16 && i + j < size; j++) printf("%02X ", buf[i + j]);
        printf(" ");
        for (size_t j = 0; j < 16 && i + j < size; j++) {
            uint8_t c = buf[i + j];
            putchar(c >= 0x20 && c < 0x7F ? c : '.');
        }
        putchar('\n');
    }

    free(buf);
    return 0;
}
