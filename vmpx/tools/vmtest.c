#include <windows.h>
#include <stdint.h>

int main(void) {
    uint8_t* p = (uint8_t*)VirtualAlloc(NULL, 0x1000,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
    if (!p) return 1;
    const uint8_t code[] = {
        0xB9, 0x00, 0x00, 0x00, 0x01, /* mov ecx, 0x01000000 */
        0x49,                         /* dec ecx */
        0x75, 0xFD,                   /* jnz $-1 */
        0xC3                          /* ret */
    };
    for (uint32_t i = 0; i < sizeof(code); i++) p[i] = code[i];
    typedef void (*fn_t)(void);
    fn_t fn = (fn_t)(void*)p;
    for (;;) {
        fn();
        Sleep(30);
    }
}
