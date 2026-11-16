/* elev.c - integrity check and self-relaunch through UAC (L1) */
#include "vmpx.h"
#include "armor/elev.h"
#include <shellapi.h>

int armor_is_elevated(void) {
    HANDLE tok = NULL;
    TOKEN_ELEVATION el;
    DWORD sz = 0;
    int r = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return 0;
    if (GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &sz))
        r = el.TokenIsElevated ? 1 : 0;
    CloseHandle(tok);
    return r;
}

int armor_relaunch_elevated(void) {
    wchar_t exe[MAX_PATH] = { 0 };
    if (!GetModuleFileNameW(NULL, exe, MAX_PATH)) return -1;

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return -1;

    wchar_t params[4096] = { 0 };
    for (int i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"--elevated") == 0) continue;
        if (params[0]) wcscat_s(params, 4096, L" ");
        wcscat_s(params, 4096, L"\"");
        wcscat_s(params, 4096, argv[i]);
        wcscat_s(params, 4096, L"\"");
    }
    if (params[0]) wcscat_s(params, 4096, L" ");
    wcscat_s(params, 4096, L"--elevated");

    SHELLEXECUTEINFOW sei;
    memset(&sei, 0, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = exe;
    sei.lpParameters = params;
    sei.nShow = SW_SHOWNORMAL;

    BOOL ok = ShellExecuteExW(&sei);
    LocalFree(argv);
    if (!ok) {
        printf("[-] elevation refused or failed (%lu)\n", GetLastError());
        return -1;
    }
    if (sei.hProcess) CloseHandle(sei.hProcess);
    return 0;
}
