/* winwait.c - wait for a top-level window with a real title (L1)
 *
 * A null class matches any visible top-level window with a nonempty title.
 * Utility windows (TPUtilWindow, GDI+ hook windows, empty-title TApplication)
 * appear first and are not evidence that the unpacked UI is up.
 */
#include "armor/winwait.h"
#include <stdio.h>

typedef struct {
    DWORD   pid;
    const wchar_t* cls;
    int     count;
    HWND    first;
    wchar_t title[256];
} winfind_t;

static BOOL CALLBACK enum_win(HWND h, LPARAM lp) {
    winfind_t* w = (winfind_t*)lp;
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    if (pid != w->pid) return TRUE;

    wchar_t cls[128] = { 0 };
    wchar_t title[256] = { 0 };
    GetClassNameW(h, cls, 128);
    GetWindowTextW(h, title, 256);
    if (!cls[0] || !title[0] || !IsWindowVisible(h)) return TRUE;
    if (w->cls && _wcsicmp(cls, w->cls) != 0) return TRUE;

    if (!w->first) {
        w->first = h;
        wcsncpy_s(w->title, 256, title, _TRUNCATE);
    }
    w->count++;
    return TRUE;
}

int winwait_for_class(DWORD pid, const wchar_t* cls, int timeout_ms,
                      HWND* hwnd_out, wchar_t* title, size_t title_cap,
                      int* count_out) {
    winfind_t wf;
    memset(&wf, 0, sizeof(wf));
    wf.pid = pid;
    wf.cls = cls;

    int waited = 0;
    while (waited < timeout_ms) {
        wf.count = 0;
        wf.first = NULL;
        wf.title[0] = 0;
        EnumWindows(enum_win, (LPARAM)&wf);
        if (wf.count > 0) {
            if (hwnd_out) *hwnd_out = wf.first;
            if (title && title_cap)
                wcsncpy_s(title, title_cap, wf.title, _TRUNCATE);
            if (count_out) *count_out = wf.count;
            return 1;
        }
        Sleep(250);
        waited += 250;
    }

    if (hwnd_out) *hwnd_out = NULL;
    if (title && title_cap) title[0] = 0;
    if (count_out) *count_out = 0;
    return 0;
}

typedef struct {
    DWORD pid;
    int   count;
} windump_t;

static BOOL CALLBACK enum_dump(HWND h, LPARAM lp) {
    windump_t* w = (windump_t*)lp;
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    if (pid != w->pid) return TRUE;

    wchar_t cls[128] = { 0 };
    wchar_t title[256] = { 0 };
    GetClassNameW(h, cls, 128);
    GetWindowTextW(h, title, 256);
    printf("    hwnd=0x%llX visible=%d class=\"%ls\" title=\"%ls\"\n",
           (unsigned long long)(uintptr_t)h, IsWindowVisible(h) ? 1 : 0, cls, title);
    w->count++;
    return TRUE;
}

void windump_for_pid(DWORD pid) {
    windump_t w;
    w.pid = pid;
    w.count = 0;
    printf("[*] top-level windows for pid %lu:\n", pid);
    EnumWindows(enum_dump, (LPARAM)&w);
    printf("[*] %d window(s)\n", w.count);
}
