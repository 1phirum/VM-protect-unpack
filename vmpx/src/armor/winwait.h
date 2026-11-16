/* armor/winwait.h - wait for a top-level window class with a real title (L1) */
#pragma once

#include <windows.h>
#include <stddef.h>

int winwait_for_class(DWORD pid, const wchar_t* cls, int timeout_ms,
                      HWND* hwnd_out, wchar_t* title, size_t title_cap,
                      int* count_out);
void windump_for_pid(DWORD pid);
