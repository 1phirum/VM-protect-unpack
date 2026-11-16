/* h_debug.c - Win32 debugger probes and debug-output suppression */
#include "armor/stealth/stealth.h"

typedef BOOL (WINAPI* isdbg_t)(void);
typedef BOOL (WINAPI* crdbg_t)(HANDLE, PBOOL);
typedef void (WINAPI* ods_t)(LPCWSTR);

BOOL WINAPI stealth_h_isdbg(void) {
    return FALSE;
}

BOOL WINAPI stealth_h_crdbg(HANDLE proc, PBOOL present) {
    (void)proc;
    if (present) *present = FALSE;
    return TRUE;
}

void WINAPI stealth_h_odsw(LPCWSTR text) {
    (void)text;
}

void WINAPI stealth_h_odsa(LPCSTR text) {
    (void)text;
}
