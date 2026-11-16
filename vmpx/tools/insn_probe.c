/* insn_probe.c - dump kernel32 export prologues and follow simple thunks */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

static void dump(const char* mod, const char* name) {
    HMODULE h = GetModuleHandleA(mod);
    if (!h) h = LoadLibraryA(mod);
    unsigned char* p = (unsigned char*)GetProcAddress(h, name);
    if (!p) { printf("%s!%s = NULL\n", mod, name); return; }
    printf("%s!%s = %p :", mod, name, p);
    for (int i = 0; i < 16; i++) printf(" %02X", p[i]);
    printf("\n");

    for (int depth = 0; depth < 4; depth++) {
        if (p[0] == 0xE9) {
            int32_t rel = *(int32_t*)(p + 1);
            unsigned char* n = p + 5 + rel;
            printf("  E9 -> %p :", n);
            for (int i = 0; i < 12; i++) printf(" %02X", n[i]);
            printf("\n");
            p = n;
        } else if (p[0] == 0xEB) {
            int8_t rel = *(int8_t*)(p + 1);
            unsigned char* n = p + 2 + rel;
            printf("  EB -> %p :", n);
            for (int i = 0; i < 12; i++) printf(" %02X", n[i]);
            printf("\n");
            p = n;
        } else if (p[0] == 0xFF && p[1] == 0x25) {
            unsigned char* n = *(unsigned char**)(p + 2);
            printf("  FF25 -> %p :", n);
            for (int i = 0; i < 12; i++) printf(" %02X", n[i]);
            printf("\n");
            p = n;
        } else {
            break;
        }
    }
}

int main(void) {
    const char* names[] = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "OutputDebugStringW", "OutputDebugStringA",
        "GetTickCount", "GetTickCount64",
        "GetSystemTimeAsFileTime", "GetSystemTimePreciseAsFileTime",
        "GetLocalTime", "QueryPerformanceCounter"
    };
    for (int i = 0; i < (int)(sizeof(names)/sizeof(names[0])); i++)
        dump("kernel32.dll", names[i]);
    int* peb = (int*)__readfsdword(0x30);
    printf("BeingDebugged at %p = %d\n", (char*)peb + 2, *((unsigned char*)peb + 2));
    return 0;
}
