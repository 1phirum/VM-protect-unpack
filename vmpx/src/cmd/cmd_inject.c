/* cmd_inject.c - inject a DLL into a live process */
#include "vmpx.h"

int cmd_inject(int argc, char** argv) {
    const char* dll = arg_get(argc, argv, "--dll");
    if (!dll) {
        printf("[-] usage: vmpx inject [--pid N | --name exe] --dll <path>\n");
        return 2;
    }

    uint32_t pid = 0;
    if (resolve_pid(argc, argv, &pid) != 0) return 1;

    wchar_t wdll[520] = { 0 };
    if (!MultiByteToWideChar(CP_UTF8, 0, dll, -1, wdll, 520)) return 1;

    enable_debug_privilege();
    return inject_dll(pid, wdll) == 0 ? 0 : 1;
}
