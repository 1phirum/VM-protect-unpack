#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "inspection.h"
#include "vmpx.h"
#include "unpack/hook/watch.h"

static int fail(vp_error* e, const wchar_t* msg)
{
    if (e)
    {
        e->code = GetLastError();
        swprintf(e->message, 512, L"%ls (error %lu)", msg, e->code);
    }
    return -1;
}
static void hex(wchar_t* out, uint64_t n)
{
    swprintf(out, 64, L"0x%08llX", (unsigned long long)n);
}
int vp_processes(vp_row_fn rows, void* ctx, vp_error* e)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W p;
    size_t count = 0;
    if (snap == INVALID_HANDLE_VALUE)
    {
        return fail(e, L"Process snapshot failed");
    }
    p.dwSize = sizeof(p);
    if (Process32FirstW(snap, &p))
    {
        do
        {
            wchar_t pid[64], arch[64] = L"Unavailable", path[32768] = L"";
            const wchar_t* cells[4];
            HANDLE proc;
            DWORD n = 32768;
            BOOL wow = FALSE;
            if (!p.th32ProcessID)
            {
                continue;
            }
            swprintf(pid, 64, L"%lu", p.th32ProcessID);
            proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.th32ProcessID);
            if (proc)
            {
                if (IsWow64Process(proc, &wow))
                {
                    wcscpy(arch, wow ? L"x86" : sizeof(void*) == 8 ? L"x64" : L"x86");
                }
                QueryFullProcessImageNameW(proc, 0, path, &n);
                CloseHandle(proc);
            }
            cells[0] = p.szExeFile;
            cells[1] = pid;
            cells[2] = arch;
            cells[3] = path;
            rows(ctx, cells, 4);
            count++;
        } while (count < 65536 && Process32NextW(snap, &p));
    }
    CloseHandle(snap);
    return 0;
}
typedef struct
{
    uint32_t pid;
    vp_row_fn rows;
    void* ctx;
} window_context;
static BOOL CALLBACK window_row(HWND hwnd, LPARAM param)
{
    window_context* c = (window_context*)param;
    DWORD pid;
    wchar_t title[512], cls[256], handle[64];
    const wchar_t* row[5];
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != c->pid)
    {
        return TRUE;
    }
    GetWindowTextW(hwnd, title, 512);
    GetClassNameW(hwnd, cls, 256);
    hex(handle, (uint64_t)(uintptr_t)hwnd);
    row[0] = handle;
    row[1] = title;
    row[2] = cls;
    row[3] = IsWindowVisible(hwnd) ? L"Yes" : L"No";
    row[4] = IsWindowEnabled(hwnd) ? L"Enabled" : L"Disabled";
    c->rows(c->ctx, row, 5);
    return TRUE;
}
static int inspect_modules(uint32_t pid, vp_row_fn rows, void* ctx, vp_error* e)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    MODULEENTRY32W m;
    size_t count = 0;
    if (snap == INVALID_HANDLE_VALUE)
    {
        return fail(e, L"Module snapshot failed");
    }
    m.dwSize = sizeof(m);
    if (Module32FirstW(snap, &m))
    {
        do
        {
            wchar_t base[64], size[64];
            const wchar_t* row[4];
            hex(base, (uint64_t)(uintptr_t)m.modBaseAddr);
            swprintf(size, 64, L"%lu", m.modBaseSize);
            row[0] = m.szModule;
            row[1] = base;
            row[2] = size;
            row[3] = m.szExePath;
            rows(ctx, row, 4);
            count++;
        } while (count < 8192 && Module32NextW(snap, &m));
    }
    CloseHandle(snap);
    return 0;
}

static int inspect_memory(uint32_t pid, vp_row_fn rows, void* ctx, vp_error* e)
{
    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    uint64_t addr = 0;
    size_t count = 0;
    if (!proc)
    {
        return fail(e, L"Cannot query memory map");
    }
    while (addr < 0x80000000ull && count < 65536)
    {
        MEMORY_BASIC_INFORMATION mbi;
        wchar_t base[64], end[64], size[64], protect[64];
        const wchar_t* row[6];
        if (!VirtualQueryEx(proc, (LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi)))
        {
            break;
        }
        uint64_t b = (uint64_t)(uintptr_t)mbi.BaseAddress, n = (uint64_t)mbi.RegionSize;
        if (!n || b + n <= addr)
        {
            break;
        }
        if (mbi.State != MEM_FREE)
        {
            hex(base, b);
            hex(end, b + n);
            swprintf(size, 64, L"%llu", (unsigned long long)n);
            hex(protect, mbi.Protect);
            row[0] = base;
            row[1] = end;
            row[2] = size;
            row[3] = mbi.State == MEM_COMMIT ? L"Committed" : L"Reserved";
            row[4] = mbi.Type == MEM_IMAGE     ? L"Image"
                     : mbi.Type == MEM_PRIVATE ? L"Private"
                                               : L"Mapped";
            row[5] = protect;
            rows(ctx, row, 6);
        }
        addr = b + n;
        count++;
    }
    CloseHandle(proc);
    return 0;
}

static int inspect_windows(uint32_t pid, vp_row_fn rows, void* ctx, vp_error* e)
{
    (void)e;
    window_context c = {pid, rows, ctx};
    EnumWindows(window_row, (LPARAM)&c);
    return 0;
}

static int inspect_agent(uint32_t pid, vp_row_fn rows, void* ctx, vp_error* e)
{
    wchar_t name[64];
    swprintf(name, 64, L"Local\\VMPX_AGENT_%u", pid);
    HANDLE map = OpenFileMappingW(FILE_MAP_READ, FALSE, name);
    if (!map)
    {
        return fail(e, L"Agent status unavailable");
    }
    const vmpx_agent_status_t* st =
        (const vmpx_agent_status_t*)MapViewOfFile(map, FILE_MAP_READ, 0, 0, sizeof(*st));
    if (!st)
    {
        CloseHandle(map);
        return fail(e, L"Cannot map agent status");
    }
    if (st->magic != VMPX_AGENT_STATUS_MAGIC || st->version != VMPX_AGENT_STATUS_VERSION)
    {
        UnmapViewOfFile(st);
        CloseHandle(map);
        SetLastError(ERROR_REVISION_MISMATCH);
        return fail(e, L"Agent status version mismatch");
    }
    const wchar_t* names[] = {L"PID",
                              L"Agent base",
                              L"Hooks applied",
                              L"Hooks failed",
                              L"Stealth applied",
                              L"Stealth failed",
                              L"Debugger indicator"};
    uint32_t vals[] = {st->pid,        st->agent_base,   st->hooks_ok,      st->hooks_fail,
                       st->stealth_ok, st->stealth_fail, st->under_debugger};
    size_t i;
    for (i = 0; i < 7; i++)
    {
        wchar_t value[64];
        const wchar_t* row[2];
        if (i == 1)
        {
            hex(value, vals[i]);
        }
        else
        {
            swprintf(value, 64, L"%u", vals[i]);
        }
        row[0] = names[i];
        row[1] = value;
        rows(ctx, row, 2);
    }
    UnmapViewOfFile(st);
    CloseHandle(map);
    return 0;
}

int vp_process_inspect(uint32_t pid, int view, vp_row_fn rows, void* ctx, vp_error* e)
{
    if (!pid || !rows)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return fail(e, L"Invalid process query");
    }
    switch (view)
    {
    case 1:
        return inspect_modules(pid, rows, ctx, e);
    case 2:
        return inspect_memory(pid, rows, ctx, e);
    case 3:
        return inspect_windows(pid, rows, ctx, e);
    case 4:
        return inspect_agent(pid, rows, ctx, e);
    default:
        SetLastError(ERROR_INVALID_PARAMETER);
        return fail(e, L"Unknown inspection view");
    }
}

int vp_read(uint32_t pid, uint64_t address, void* bytes, size_t size, size_t* got, vp_error* e)
{
    if (!got || !bytes || !pid)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return fail(e, L"Invalid memory query");
    }
    *got = 0;
    if (!size || size > 1048576 || address > UINTPTR_MAX || size > UINTPTR_MAX - address)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return fail(e, L"Invalid read range");
    }
    HANDLE proc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc)
    {
        return fail(e, L"Cannot open process for read");
    }
    SIZE_T n = 0;
    BOOL ok = ReadProcessMemory(proc, (LPCVOID)(uintptr_t)address, bytes, size, &n);
    DWORD code = GetLastError();
    CloseHandle(proc);
    *got = n;
    if (!ok)
    {
        SetLastError(code);
        return fail(e, n ? L"Partial memory read" : L"Memory read failed");
    }
    return 0;
}
int vp_stop_watch(uint32_t pid, vp_error* e)
{
    wchar_t name[128];
    swprintf(name, 128, L"Local\\VMPX_WATCH_%u", pid);
    HANDLE map = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
    if (!map)
    {
        return fail(e, L"Watch mapping unavailable");
    }
    vmpx_watch_ctl_t* ctl =
        (vmpx_watch_ctl_t*)MapViewOfFile(map, FILE_MAP_ALL_ACCESS, 0, 0, VMPX_WATCH_MAP_SIZE);
    if (!ctl)
    {
        CloseHandle(map);
        return fail(e, L"Cannot map watch control");
    }
    if (ctl->magic != VMPX_WATCH_MAGIC || ctl->version != VMPX_WATCH_VERSION)
    {
        UnmapViewOfFile(ctl);
        CloseHandle(map);
        return fail(e, L"Invalid watch control version");
    }
    ctl->active = 0;
    UnmapViewOfFile(ctl);
    CloseHandle(map);
    return 0;
}
