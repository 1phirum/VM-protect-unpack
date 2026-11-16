/* peb_modules.c - read the x86 PEB loader list without Toolhelp
 *
 * Toolhelp can return ERROR_PARTIAL_COPY for a freshly created suspended
 * process. CreateProcess already gives us a handle; walking
 * PEB->Ldr->InLoadOrderModuleList is deterministic and uses only
 * ReadProcessMemory, so it works before the first thread ever runs.
 */
#include "unpack/memory/peb_modules.h"
#include "util/str.h"
#include <string.h>

typedef struct {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} pbi_t;

typedef LONG (NTAPI* ntqip_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static int read_mem(HANDLE proc, uint32_t addr, void* buf, size_t len) {
    if (!proc || !addr || !buf || !len) return -1;
    SIZE_T got = 0;
    if (!ReadProcessMemory(proc, (LPCVOID)(uintptr_t)addr, buf, len, &got) ||
        got != len)
        return -1;
    return 0;
}

static int read_u32(HANDLE proc, uint32_t addr, uint32_t* v) {
    return read_mem(proc, addr, v, sizeof(*v));
}

int vmpx_peb_modules(HANDLE proc, uint32_t pid, proc_mod_t* out, int cap) {
    if (!proc || !pid || !out || cap <= 0) return 0;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    ntqip_t ntqip = ntdll ?
        (ntqip_t)GetProcAddress(ntdll, "NtQueryInformationProcess") : NULL;
    if (!ntqip) return 0;

    pbi_t pbi;
    memset(&pbi, 0, sizeof(pbi));
    ULONG ret = 0;
    if (ntqip(proc, 0 /* ProcessBasicInformation */, &pbi, sizeof(pbi), &ret) != 0)
        return 0;
    uint32_t peb = (uint32_t)(uintptr_t)pbi.PebBaseAddress;
    if (!peb) return 0;

    uint32_t ldr = 0;
    if (read_u32(proc, peb + 0x0C, &ldr) != 0 || !ldr) return 0;

    uint32_t head = ldr + 0x0C;             /* InLoadOrderModuleList */
    uint32_t first = 0;
    if (read_u32(proc, head, &first) != 0 || !first || first == head) return 0;

    int n = 0;
    uint32_t node = first;
    for (int i = 0; i < 4096 && n < cap; i++) {
        if (!node || node == head || node >= 0x80000000u) break;

        uint32_t next = 0, dll_base = 0, image_size = 0;
        if (read_u32(proc, node, &next) != 0) break;
        if (read_u32(proc, node + 0x18, &dll_base) != 0) break;
        if (read_u32(proc, node + 0x20, &image_size) != 0) break;

        uint16_t name_len = 0;
        uint32_t name_buf = 0;
        if (read_mem(proc, node + 0x2C, &name_len, sizeof(name_len)) == 0 &&
            read_u32(proc, node + 0x30, &name_buf) == 0 &&
            name_len && name_buf && name_len < 0x1000) {
            uint16_t copy = name_len;
            if (copy > 126) copy = 126;
            if (read_mem(proc, name_buf, out[n].name, copy) == 0) {
                out[n].name[copy / 2] = 0;
                out[n].name[63] = 0;
                out[n].base = dll_base;
                out[n].size = image_size;
                if (dll_base && image_size) n++;
            }
        }

        if (!next || next == node) break;
        node = next;
    }
    return n;
}
