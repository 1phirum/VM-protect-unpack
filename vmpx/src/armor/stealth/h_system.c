/* h_system.c - system information filtering
 *
 * NtQuerySystemInformation is a common detection surface:
 *   - SystemProcessInformation: the target looks for debugger/tool processes,
 *     and for its own parent.
 *   - SystemModuleInformation: the target looks for injected DLLs.
 *   - SystemKernelDebuggerInformation: the target asks whether a kernel
 *     debugger is present.
 *
 * Entries are removed in place by splicing the NEXT_ENTRY chain.  The caller's
 * buffer is the only allocation involved and no length is ever grown.
 */
#include "armor/stealth/stealth.h"
#include <string.h>

#define ST_INFO_LEN_MISMATCH ((LONG)0xC0000004L)
#define ST_DEBUGGER_INACTIVE ((LONG)0xC0000354L)

#define QSI_PROCESS_INFO   5
#define QSI_MODULE_INFO    11
#define QSI_KD_DEBUGGER    35
#define QSI_EXT_PROCESS    57

typedef LONG (NTAPI* ntqsi_t)(ULONG, PVOID, ULONG, PULONG);

/* Offsets are shared for the leading fields on x86 and x64 because the
 * LARGE_INTEGER members align the ImageName at 0x38 in both layouts. */
#define SPI_NEXT        0x00
#define SPI_NAME_LEN    0x38
#define SPI_NAME_BUF    (sizeof(void*) == 8 ? 0x40 : 0x3C)
#define SPI_PID         (sizeof(void*) == 8 ? 0x58 : 0x44)
#define SPI_PPID        (sizeof(void*) == 8 ? 0x60 : 0x48)
#define SPI_MIN_SIZE    0x68

static int ci_equal(const char* a, const char* b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        char ca = *a++, cb = *b++;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
    }
    return *a == 0 && *b == 0;
}

static const char* base_name(const char* path) {
    const char* out = path;
    for (const char* p = path; p && *p; p++) {
        if (*p == '\\' || *p == '/') out = p + 1;
    }
    return out;
}

static int is_hidden_process_name(const char* path) {
    static const char* names[] = {
        "vmpx.exe", "vmpxagent.dll",
        "cdb.exe", "windbg.exe", "windbgx.exe",
        "x64dbg.exe", "x32dbg.exe", "x96dbg.exe",
        "ollydbg.exe", "immunitydebugger.exe",
        "ida.exe", "ida64.exe", "idaq.exe", "idaq64.exe",
        "ghidra.exe", "ghidrarun.exe", "dnspy.exe",
        "procexp.exe", "procexp64.exe", "procmon.exe", "procmon64.exe",
        "processhacker.exe", "systeminformer.exe",
        "cheatengine.exe", "cheatengine-x86_64.exe",
        "frida.exe", "frida-server.exe", "frida-helper.exe",
        "scylla.exe", "lordpe.exe", "pestudio.exe", "cffexplorer.exe",
        "hxd.exe", "010editor.exe", "pe-bear.exe"
    };
    const char* leaf = base_name(path);
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if (ci_equal(leaf, names[i])) return 1;
    return 0;
}

static int should_hide_process(const uint8_t* e) {
    uint32_t pid = *(const uint32_t*)(e + SPI_PID);
    if (!pid || pid == GetCurrentProcessId()) return 0;
    if (stealth_hidden_pid(pid)) return 1;
    if (pid == stealth_tool_pid()) return 1;

    uint16_t len = *(const uint16_t*)(e + SPI_NAME_LEN);
    const wchar_t* name = *(const wchar_t* const*)(e + SPI_NAME_BUF);
    if (!name || len < 2) return 0;

    char ansi[96];
    int n = WideCharToMultiByte(CP_ACP, 0, name, len / 2, ansi,
                                (int)sizeof(ansi) - 1, NULL, NULL);
    if (n <= 0) return 0;
    ansi[n] = 0;
    return is_hidden_process_name(ansi);
}

static void filter_process_list(PVOID info, ULONG len, PULONG ret,
                                uint32_t self_pid, uint32_t parent_pid) {
    if (!info || len < SPI_MIN_SIZE) return;

    uint8_t* base = (uint8_t*)info;
    ULONG used = ret && *ret ? *ret : len;
    if (used > len) used = len;

    uint8_t* prev = NULL;
    uint8_t* cur = base;

    while ((ULONG)(cur - base) + SPI_MIN_SIZE <= used) {
        uint8_t* e = cur;
        ULONG next = *(ULONG*)(e + SPI_NEXT);
        ULONG remain = used - (ULONG)(cur - base);

        if (self_pid && *(uint32_t*)(e + SPI_PID) == self_pid && parent_pid)
            *(uint32_t*)(e + SPI_PPID) = parent_pid;

        if (should_hide_process(e)) {
            if (next == 0) {
                if (prev) *(ULONG*)(prev + SPI_NEXT) = 0;
                if (ret) *ret = (ULONG)(cur - base);
                return;
            }
            if (next >= remain) break;
            memmove(cur, cur + next, remain - next);
            used -= next;
            if (ret) *ret = used;
            continue;
        }

        if (next == 0 || next >= remain) break;
        prev = cur;
        cur += next;
    }
}

static int module_is_agent(const uint8_t* mod, int is64) {
    /* FullPathName follows four USHORTs after the fixed fields:
     * x86 0x1C, x64 0x30. The path is a NUL-terminated ANSI string. */
    const char* name = (const char*)(mod + (is64 ? 0x30 : 0x1C));
    for (int i = 0; i < 256 && name[i]; i++) {
        if ((name[i] == 'v' || name[i] == 'V') &&
            _strnicmp(name + i, "vmpx", 4) == 0)
            return 1;
    }
    return 0;
}

static void filter_module_list(PVOID info, ULONG len, PULONG ret) {
    if (!info || len < sizeof(ULONG)) return;

    int is64 = (sizeof(void*) == 8);
    ULONG hdr = is64 ? 8u : 4u;
    ULONG mod_size = is64 ? 0x130u : 0x11Cu;
    if (len < hdr + mod_size) return;

    uint32_t* count = (uint32_t*)info;
    uint8_t* first = (uint8_t*)info + hdr;
    uint32_t n = *count;
    if (n == 0) return;
    if ((ULONG)(hdr + n * mod_size) > len) n = (len - hdr) / mod_size;

    uint32_t out = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint8_t* mod = first + (size_t)i * mod_size;
        if (module_is_agent(mod, is64)) continue;
        if (out != i) memmove(first + (size_t)out * mod_size, mod, mod_size);
        out++;
    }
    if (out != n) {
        *count = out;
        if (ret) *ret = hdr + out * mod_size;
    }
}

LONG NTAPI stealth_h_qsi(ULONG cls, PVOID info, ULONG len, PULONG ret) {
    ntqsi_t orig = (ntqsi_t)stealth_trampoline(ST_HK_QSI);
    if (!orig) return ST_DEBUGGER_INACTIVE;

    if (cls == QSI_KD_DEBUGGER) {
        if (!info || len < 2) {
            if (ret) *ret = 2;
            return ST_INFO_LEN_MISMATCH;
        }
        uint8_t* kd = (uint8_t*)info;
        kd[0] = 0;                                  /* DebuggerEnabled */
        kd[1] = 1;                                  /* DebuggerNotPresent */
        if (ret) *ret = 2;
        return 0;
    }

    LONG st = orig(cls, info, len, ret);
    if (st != 0 || !info || !len) return st;

    if (cls == QSI_PROCESS_INFO || cls == QSI_EXT_PROCESS) {
        uint32_t self = GetCurrentProcessId();
        filter_process_list(info, len, ret, self, stealth_parent());
    } else if (cls == QSI_MODULE_INFO) {
        filter_module_list(info, len, ret);
    }
    return st;
}

LONG NTAPI stealth_h_sdc(ULONG cmd, PVOID in, ULONG in_len, PVOID out,
                         ULONG out_len, PULONG ret) {
    (void)cmd; (void)in; (void)in_len; (void)out; (void)out_len; (void)ret;
    return ST_DEBUGGER_INACTIVE;
}
