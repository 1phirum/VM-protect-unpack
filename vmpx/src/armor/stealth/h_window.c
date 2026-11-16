/* h_window.c - debugger window discovery filtering */
#include "armor/stealth/stealth.h"
#include <string.h>

typedef BOOL (WINAPI* enumw_t)(WNDENUMPROC, LPARAM);
typedef HWND (WINAPI* findw_t)(LPCWSTR, LPCWSTR);
typedef HWND (WINAPI* findexw_t)(HWND, HWND, LPCWSTR, LPCWSTR);
typedef HWND (WINAPI* finda_t)(LPCSTR, LPCSTR);
typedef HWND (WINAPI* findexa_t)(HWND, HWND, LPCSTR, LPCSTR);

static int wci_equal(const wchar_t* a, const wchar_t* b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        wchar_t ca = *a++, cb = *b++;
        if (ca >= L'A' && ca <= L'Z') ca = (wchar_t)(ca - L'A' + L'a');
        if (cb >= L'A' && cb <= L'Z') cb = (wchar_t)(cb - L'A' + L'b');
        if (ca != cb) return 0;
    }
    return *a == 0 && *b == 0;
}

static int wci_find(const wchar_t* hay, const wchar_t* needle) {
    if (!hay || !needle || !*needle) return 0;
    size_t nl = wcslen(needle);
    for (const wchar_t* p = hay; *p; p++) {
        size_t i = 0;
        while (i < nl && p[i]) {
            wchar_t a = p[i], b = needle[i];
            if (a >= L'A' && a <= L'Z') a = (wchar_t)(a - L'A' + L'a');
            if (b >= L'A' && b <= L'Z') b = (wchar_t)(b - L'A' + L'a');
            if (a != b) break;
            i++;
        }
        if (i == nl) return 1;
    }
    return 0;
}

int stealth_window_is_debugger(const wchar_t* cls, const wchar_t* title) {
    static const wchar_t* classes[] = {
        L"WinDbgFrameClass", L"TWinDbgFrame", L"OllyDbg", L"IDAFrame",
        L"x64dbg", L"x32dbg", L"x96dbg", L"Frida", L"ImmunityDebugger"
    };
    static const wchar_t* titles[] = {
        L"windbg", L"cdb", L"x64dbg", L"x32dbg", L"x96dbg", L"ollydbg",
        L"immunity debugger", L"ida pro", L"ida - ", L"ida 64", L"idaq",
        L"ghidra", L"dnspy", L"process hacker", L"process explorer",
        L"process monitor", L"system informer", L"cheat engine", L"frida",
        L"scylla", L"lordpe", L"pe-bear", L"pestudio", L"cff explorer",
        L"hxd", L"010 editor", L"hex workshop"
    };

    if (cls) {
        for (size_t i = 0; i < sizeof(classes) / sizeof(classes[0]); i++)
            if (wci_equal(cls, classes[i])) return 1;
    }
    if (title) {
        for (size_t i = 0; i < sizeof(titles) / sizeof(titles[0]); i++)
            if (wci_find(title, titles[i])) return 1;
    }
    return 0;
}

static int hwnd_is_debugger(HWND hwnd) {
    wchar_t cls[128] = { 0 };
    wchar_t title[256] = { 0 };
    GetClassNameW(hwnd, cls, 128);
    GetWindowTextW(hwnd, title, 256);
    return stealth_window_is_debugger(cls, title);
}

typedef struct {
    WNDENUMPROC proc;
    LPARAM      lparam;
} enum_ctx_t;

static __declspec(thread) enum_ctx_t g_enum_ctx[8];
static __declspec(thread) int g_enum_depth;

static BOOL CALLBACK enum_filter(HWND hwnd, LPARAM lparam) {
    enum_ctx_t* ctx = (enum_ctx_t*)(uintptr_t)lparam;
    if (!ctx || !ctx->proc) return FALSE;
    if (hwnd_is_debugger(hwnd)) return TRUE;
    return ctx->proc(hwnd, ctx->lparam);
}

BOOL WINAPI stealth_h_enumw(WNDENUMPROC proc, LPARAM lparam) {
    enumw_t orig = (enumw_t)stealth_trampoline(ST_HK_ENUMW);
    if (!orig) return FALSE;
    if (!proc) return orig(proc, lparam);

    int depth = g_enum_depth;
    if (depth < 0 || depth >= 8) return orig(proc, lparam);

    g_enum_ctx[depth].proc = proc;
    g_enum_ctx[depth].lparam = lparam;
    g_enum_depth = depth + 1;
    BOOL r = orig(enum_filter, (LPARAM)&g_enum_ctx[depth]);
    g_enum_depth = depth;
    return r;
}

HWND WINAPI stealth_h_findw(LPCWSTR cls, LPCWSTR title) {
    findw_t orig = (findw_t)stealth_trampoline(ST_HK_FINDW);
    if (!orig) return NULL;
    if (stealth_window_is_debugger(cls, title)) return NULL;
    HWND h = orig(cls, title);
    if (h && hwnd_is_debugger(h)) return NULL;
    return h;
}

HWND WINAPI stealth_h_findexw(HWND parent, HWND after, LPCWSTR cls,
                              LPCWSTR title) {
    findexw_t orig = (findexw_t)stealth_trampoline(ST_HK_FINDEXW);
    if (!orig) return NULL;
    if (stealth_window_is_debugger(cls, title)) return NULL;
    HWND h = orig(parent, after, cls, title);
    if (h && hwnd_is_debugger(h)) return NULL;
    return h;
}

HWND WINAPI stealth_h_finda(LPCSTR cls, LPCSTR title) {
    finda_t orig = (finda_t)stealth_trampoline(ST_HK_FINDA);
    if (!orig) return NULL;
    HWND h = orig(cls, title);
    if (h && hwnd_is_debugger(h)) return NULL;
    return h;
}

HWND WINAPI stealth_h_findexa(HWND parent, HWND after, LPCSTR cls,
                              LPCSTR title) {
    findexa_t orig = (findexa_t)stealth_trampoline(ST_HK_FINDEXA);
    if (!orig) return NULL;
    HWND h = orig(parent, after, cls, title);
    if (h && hwnd_is_debugger(h)) return NULL;
    return h;
}
