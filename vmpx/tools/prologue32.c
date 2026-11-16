/* prologue32.c - dump export prologues from a 32-bit process */
#include <windows.h>
#include <stdio.h>

static void dump(const wchar_t* mod, const char* name) {
    HMODULE h = GetModuleHandleW(mod);
    if (!h) h = LoadLibraryW(mod);
    if (!h) { printf("%ls!%s: no module\n", mod, name); return; }
    unsigned char* p = (unsigned char*)GetProcAddress(h, name);
    if (!p) { printf("%ls!%s: no export\n", mod, name); return; }
    printf("%ls!%s %p:", mod, name, (void*)p);
    for (int i = 0; i < 16; i++) printf(" %02X", p[i]);
    printf("\n");
}

int main(void) {
    const wchar_t* mods[] = { L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll" };
    const char* names[] = {
        "NtQueryInformationProcess", "NtQuerySystemInformation",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "GetSystemTimeAsFileTime", "GetSystemTimePreciseAsFileTime",
        "GetTickCount", "GetTickCount64", "OutputDebugStringW",
        "OutputDebugStringA", "EnumWindows", "FindWindowW"
    };
    for (int m = 0; m < 3; m++)
        for (int n = 0; n < (int)(sizeof(names) / sizeof(names[0])); n++)
            dump(mods[m], names[n]);
    return 0;
}
