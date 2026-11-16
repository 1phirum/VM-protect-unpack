/* h_time.c - timing virtualization while a debugger is attached
 *
 * A debugger pause shows up as a multi-second jump in QPC, tick count, or
 * file time.  Each clock keeps its own last-real/virtual pair and caps the
 * advance at one millisecond while the process is under a debugger.  Normal
 * polling intervals (sub-millisecond) pass through unchanged.
 */
#include "armor/stealth/stealth.h"

#define ST_ACCESS_DENIED ((LONG)0xC0000022L)
#define TICK_CAP_MS      1ull
#define TIME_CAP_100NS   10000ull              /* 1 ms */

typedef LONG (NTAPI* ntqpc_t)(PLARGE_INTEGER, PLARGE_INTEGER);
typedef LONG (NTAPI* ntqst_t)(PLARGE_INTEGER);

LONG NTAPI stealth_h_qpc(PLARGE_INTEGER counter, PLARGE_INTEGER freq) {
    ntqpc_t orig = (ntqpc_t)stealth_trampoline(ST_HK_QPC);
    if (!orig) return ST_ACCESS_DENIED;

    LARGE_INTEGER real, f;
    memset(&f, 0, sizeof(f));
    LONG st = orig(&real, &f);
    if (freq) *freq = f;
    if (st != 0 || !counter) return st;

    if (!stealth_under_debugger()) {
        *counter = real;
        return 0;
    }

    static int init;
    static LARGE_INTEGER last, virt;
    if (!init) {
        last = real;
        virt = real;
        init = 1;
    }

    LONGLONG delta = real.QuadPart - last.QuadPart;
    LONGLONG cap = f.QuadPart / 1000;          /* 1 ms in QPC units */
    if (cap < 1) cap = 1;
    if (delta < 0) delta = 0;
    if (delta > cap) delta = cap;
    virt.QuadPart += delta;
    last = real;
    *counter = virt;
    return 0;
}

LONG NTAPI stealth_h_qst(PLARGE_INTEGER now) {
    ntqst_t orig = (ntqst_t)stealth_trampoline(ST_HK_QST);
    if (!orig) return ST_ACCESS_DENIED;

    LARGE_INTEGER real;
    LONG st = orig(&real);
    if (st != 0 || !now) return st;

    if (!stealth_under_debugger()) {
        *now = real;
        return 0;
    }

    static int init;
    static LARGE_INTEGER last, virt;
    if (!init) {
        last = real;
        virt = real;
        init = 1;
    }

    LONGLONG delta = real.QuadPart - last.QuadPart;
    if (delta < 0) delta = 0;
    if (delta > (LONGLONG)TIME_CAP_100NS) delta = (LONGLONG)TIME_CAP_100NS;
    virt.QuadPart += delta;
    last = real;
    *now = virt;
    return 0;
}

typedef DWORD (WINAPI* tick_t)(void);
typedef ULONGLONG (WINAPI* tick64_t)(void);
typedef void (WINAPI* gstaft_t)(LPFILETIME);
typedef void (WINAPI* gstpft_t)(LPFILETIME);

static uint64_t filetime_to_u64(const FILETIME* ft) {
    return ((uint64_t)ft->dwHighDateTime << 32) | ft->dwLowDateTime;
}

static void u64_to_filetime(uint64_t v, FILETIME* ft) {
    ft->dwLowDateTime = (DWORD)v;
    ft->dwHighDateTime = (DWORD)(v >> 32);
}

static uint64_t virtual_filetime(const FILETIME* real, int* init,
                                 uint64_t* last, uint64_t* virt) {
    uint64_t r = filetime_to_u64(real);
    if (!*init) {
        *last = r;
        *virt = r;
        *init = 1;
    }
    uint64_t delta = r - *last;
    if (r < *last) delta = 0;
    if (delta > TIME_CAP_100NS) delta = TIME_CAP_100NS;
    *virt += delta;
    *last = r;
    return *virt;
}

DWORD WINAPI stealth_h_tick(void) {
    tick_t orig = (tick_t)stealth_trampoline(ST_HK_TICK);
    if (!orig) return 0;
    DWORD real = orig();
    if (!stealth_under_debugger()) return real;

    static int init;
    static uint64_t last, virt;
    if (!init) {
        last = real;
        virt = real;
        init = 1;
    }
    uint64_t delta = (uint32_t)(real - (DWORD)last);
    if (delta > TICK_CAP_MS) delta = TICK_CAP_MS;
    virt += delta;
    last = real;
    return (DWORD)virt;
}

ULONGLONG WINAPI stealth_h_tick64(void) {
    tick64_t orig = (tick64_t)stealth_trampoline(ST_HK_TICK64);
    if (!orig) return 0;
    ULONGLONG real = orig();
    if (!stealth_under_debugger()) return real;

    static int init;
    static uint64_t last, virt;
    if (!init) {
        last = real;
        virt = real;
        init = 1;
    }
    uint64_t delta = real - last;
    if (delta > TICK_CAP_MS) delta = TICK_CAP_MS;
    virt += delta;
    last = real;
    return virt;
}

void WINAPI stealth_h_gstaft(LPFILETIME out) {
    gstaft_t orig = (gstaft_t)stealth_trampoline(ST_HK_GSTAFT);
    if (!orig) return;

    static int init;
    static uint64_t last, virt;
    if (!stealth_under_debugger()) {
        orig(out);
        return;
    }
    FILETIME real;
    orig(&real);
    if (!out) return;
    u64_to_filetime(virtual_filetime(&real, &init, &last, &virt), out);
}

void WINAPI stealth_h_gstpft(LPFILETIME out) {
    gstpft_t orig = (gstpft_t)stealth_trampoline(ST_HK_GSTPFT);
    if (!orig) return;

    static int init;
    static uint64_t last, virt;
    if (!stealth_under_debugger()) {
        orig(out);
        return;
    }
    FILETIME real;
    orig(&real);
    if (!out) return;
    u64_to_filetime(virtual_filetime(&real, &init, &last, &virt), out);
}
