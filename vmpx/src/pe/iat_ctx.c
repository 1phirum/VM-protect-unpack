/* iat_ctx.c - process handle, module ranges, import directory, export caches (L1) */
#include "pe/iat_ctx.h"
#include "pe/hdr.h"
#include "util/str.h"
#include <string.h>

int iat_ctx_read(void* user, uint64_t addr, void* buf, size_t len) {
    iat_ctx_t* c = (iat_ctx_t*)user;
    if (!c || !c->proc || !buf || !len) return -1;
    SIZE_T got = 0;
    BOOL ok = ReadProcessMemory(c->proc, (LPCVOID)(uintptr_t)addr, buf, len, &got);
    return (ok && got == len) ? 0 : -1;
}

int iat_ctx_open(iat_ctx_t* c, uint32_t pid, uint64_t base,
                 const uint8_t* file_hdr, uint64_t file_size) {
    if (!c) return -1;
    memset(c, 0, sizeof(*c));
    c->pid = pid;
    c->base = base;
    c->proc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!c->proc) return -1;

    c->nmods = proc_modules_snapshot(pid, c->mods, IAT_MAX_MODULES);
    if (c->nmods < 0) c->nmods = 0;

    if (file_hdr) {
        pehdr_t h;
        if (pehdr_parse(file_hdr, file_size, &h) == 0) {
            c->is64 = pehdr_is_64(&h);
            c->imp_rva = pehdr_dir_rva(&h, PEHDR_DIR_IMPORT);
            c->imp_size = pehdr_dir_size(&h, PEHDR_DIR_IMPORT);
        }
    }
    if (!c->imp_rva) {
        uint8_t hdr[0x1000];
        if (iat_ctx_read(c, base, hdr, sizeof(hdr)) == 0) {
            pehdr_t h;
            if (pehdr_parse(hdr, sizeof(hdr), &h) == 0) {
                c->is64 = pehdr_is_64(&h);
                c->imp_rva = pehdr_dir_rva(&h, PEHDR_DIR_IMPORT);
                c->imp_size = pehdr_dir_size(&h, PEHDR_DIR_IMPORT);
            }
        }
    }
    return 0;
}

void iat_ctx_close(iat_ctx_t* c) {
    if (!c) return;
    for (int i = 0; i < c->nmods && i < IAT_MAX_MODULES; i++)
        live_exports_free(&c->exp[i]);
    if (c->proc) CloseHandle(c->proc);
    memset(c, 0, sizeof(*c));
}

int iat_ctx_module(iat_ctx_t* c, uint64_t addr) {
    if (!c) return -1;
    for (int i = 0; i < c->nmods; i++) {
        if (addr >= c->mods[i].base && addr < c->mods[i].base + c->mods[i].size)
            return i;
    }
    return -1;
}

int iat_ctx_resolve(iat_ctx_t* c, uint64_t addr, char* mod, size_t mod_cap,
                    char* name, size_t name_cap, uint16_t* ordinal,
                    int* by_ordinal) {
    int idx = iat_ctx_module(c, addr);
    if (idx < 0) return -1;

    if (mod && mod_cap)
        str_narrow_leaf(c->mods[idx].name, mod, mod_cap);

    if (live_exports_build(iat_ctx_read, c, c->mods[idx].base, &c->exp[idx]) < 0)
        return -1;

    uint64_t delta = addr - c->mods[idx].base;
    if (delta > 0xFFFFFFFFull) return -1;
    return live_exports_lookup(&c->exp[idx], (uint32_t)delta, name, name_cap,
                               ordinal, by_ordinal);
}
