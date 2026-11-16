#include <windows.h>
#include <stdint.h>

int main(void) {
    volatile uint8_t* p = (volatile uint8_t*)VirtualAlloc(
        NULL, 0x40000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) return 1;
    for (uint32_t n = 0; n < 1000000; n++) {
        uint32_t v = n * 2654435761u;
        for (uint32_t i = 0; i < 0x4000; i += 4096)
            p[i] = (uint8_t)(v >> (i & 7));
        p[0x1234] = (uint8_t)n;
        Sleep(50);
    }
    return 0;
}
