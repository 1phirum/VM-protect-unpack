/* parent.c - PROC_THREAD_ATTRIBUTE_PARENT_PROCESS launch and hint mapping */
#include "vmpx.h"
#include "armor/parent.h"

#define PARENT_HINT_MAGIC 0x48505856u   /* "VXPH" */

typedef struct {
    ULONG magic;
    ULONG parent;
    ULONG tool;
} parent_hint_t;

static int spawn_plain(const wchar_t* exe, const wchar_t* dir,
                       PROCESS_INFORMATION* pi) {
    STARTUPINFOW si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    return CreateProcessW(exe, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL,
                          dir && dir[0] ? dir : NULL, &si, pi) ? 0 : -1;
}

/* The shell window belongs to the interactive explorer for this session.
 * Falling back to the first explorer.exe keeps the old behavior on systems
 * without a shell window (service sessions, alternate desktops). */
static uint32_t find_explorer(void) {
    HWND shell = GetShellWindow();
    if (shell) {
        DWORD pid = 0;
        GetWindowThreadProcessId(shell, &pid);
        if (pid) return pid;
    }
    uint32_t pid = 0;
    return proc_find_by_name(L"explorer.exe", &pid) ? pid : 0;
}

int armor_spawn_parented(const wchar_t* exe, const wchar_t* dir,
                         PROCESS_INFORMATION* pi, uint32_t* parent_pid) {
    if (!exe || !pi) return -1;
    if (parent_pid) *parent_pid = 0;

    uint32_t explorer = find_explorer();
    if (!explorer) {
        if (getenv("VMPX_PARENT_DEBUG"))
            printf("[*] parent: explorer not found\n");
        return spawn_plain(exe, dir, pi);
    }

    HANDLE ph = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, explorer);
    if (!ph) {
        if (getenv("VMPX_PARENT_DEBUG"))
            printf("[*] parent: OpenProcess(%lu) failed: %lu\n",
                   explorer, GetLastError());
        if (parent_pid) *parent_pid = explorer;   /* hint-only fallback */
        return spawn_plain(exe, dir, pi);
    }

    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
    LPPROC_THREAD_ATTRIBUTE_LIST attrs =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_size);
    int ok = attrs &&
             InitializeProcThreadAttributeList(attrs, 1, 0, &attr_size) &&
             UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                       &ph, sizeof(ph), NULL, NULL);
    if (!ok) {
        if (attrs) {
            DeleteProcThreadAttributeList(attrs);
            HeapFree(GetProcessHeap(), 0, attrs);
        }
        CloseHandle(ph);
        return spawn_plain(exe, dir, pi);
    }

    STARTUPINFOEXW si;
    memset(&si, 0, sizeof(si));
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = attrs;

    BOOL created = CreateProcessW(exe, NULL, NULL, NULL, FALSE,
                                  EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
                                  NULL, dir && dir[0] ? dir : NULL,
                                  &si.StartupInfo, pi);

    DeleteProcThreadAttributeList(attrs);
    HeapFree(GetProcessHeap(), 0, attrs);
    CloseHandle(ph);

    if (!created) {
        if (getenv("VMPX_PARENT_DEBUG"))
            printf("[*] parent: CreateProcess(attribute) failed: %lu\n",
                   GetLastError());
        if (parent_pid) *parent_pid = explorer;   /* hint-only fallback */
        return spawn_plain(exe, dir, pi);
    }
    if (parent_pid) *parent_pid = explorer;
    if (getenv("VMPX_PARENT_DEBUG"))
        printf("[*] parent: spoofed to %lu\n", explorer);
    return 0;
}

int armor_hint_open(uint32_t target_pid, uint32_t parent_pid, uint32_t tool_pid,
                    armor_hint_t* hint) {
    if (!hint) return -1;
    hint->map = NULL;
    hint->view = NULL;

    wchar_t name[64];
    swprintf_s(name, 64, L"Local\\VMPX_PARENT_%u", target_pid);

    HANDLE map = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                    0, sizeof(parent_hint_t), name);
    if (!map) return -1;

    parent_hint_t* p = (parent_hint_t*)MapViewOfFile(map, FILE_MAP_WRITE, 0, 0,
                                                     sizeof(parent_hint_t));
    if (!p) {
        CloseHandle(map);
        return -1;
    }
    p->magic = PARENT_HINT_MAGIC;
    p->parent = parent_pid;
    p->tool = tool_pid;

    hint->map = map;
    hint->view = p;
    return 0;
}

void armor_hint_close(armor_hint_t* hint) {
    if (!hint) return;
    if (hint->view) UnmapViewOfFile(hint->view);
    if (hint->map) CloseHandle(hint->map);
    hint->view = NULL;
    hint->map = NULL;
}
