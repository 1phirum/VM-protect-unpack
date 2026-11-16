/* cmd_memmap.c - enumerate committed regions of a live process */
#include "vmpx.h"

static void prot_str(uint32_t p, char* out, size_t cap) {
    char b[8] = { 0 };
    size_t n = 0;
    if (p & PAGE_READONLY) b[n++] = 'R';
    if (p & PAGE_READWRITE) { if (n < 2) b[n++] = 'R'; b[n++] = 'W'; }
    if (p & PAGE_WRITECOPY) { b[n++] = 'C'; }
    if (p & PAGE_EXECUTE) b[n++] = 'X';
    if (p & PAGE_EXECUTE_READ) { b[n++] = 'R'; b[n++] = 'X'; }
    if (p & PAGE_EXECUTE_READWRITE) { b[n++] = 'R'; b[n++] = 'W'; b[n++] = 'X'; }
    if (p & PAGE_EXECUTE_WRITECOPY) { b[n++] = 'C'; b[n++] = 'X'; }
    if (p & PAGE_GUARD) b[n++] = 'G';
    if ((p & 0xFF) == PAGE_NOACCESS) { b[0] = '-'; b[1] = 0; n = 1; }
    if (!n) { b[0] = '?'; b[1] = 0; n = 1; }
    b[n] = 0;
    strncpy_s(out, cap, b, _TRUNCATE);
}

static const char* state_str(uint32_t s) {
    switch (s) {
    case MEM_COMMIT:  return "CMIT";
    case MEM_RESERVE: return "RSVD";
    case MEM_FREE:    return "FREE";
    default:          return "????";
    }
}

static const char* type_str(uint32_t t) {
    switch (t) {
    case MEM_IMAGE:   return "IMG";
    case MEM_MAPPED:  return "MAP";
    case MEM_PRIVATE: return "PRV";
    default:          return "---";
    }
}

int cmd_memmap(int argc, char** argv) {
    uint32_t pid = 0;
    if (resolve_pid(argc, argv, &pid) != 0) return 1;

    uint64_t near_addr = arg_num(argc, argv, "--near", 0);
    uint64_t radius = arg_num(argc, argv, "--radius", 0);
    uint64_t lo = 0, hi = 0x80000000ull;
    if (near_addr) {
        if (!radius) radius = 0x2000000ull;
        lo = near_addr > radius ? near_addr - radius : 0;
        hi = near_addr + radius;
        if (hi > 0x80000000ull) hi = 0x80000000ull;
    }

    int all = arg_has(argc, argv, "--all");
    int private_only = arg_has(argc, argv, "--private") || !near_addr;
    uint64_t min_kb = arg_num(argc, argv, "--min-kb", near_addr ? 0 : 64);
    uint64_t min_size = min_kb << 10;

    vmpx_mem_region_t* regions = NULL;
    size_t count = 0;
    if (proc_mem_snapshot(pid, lo, hi, &regions, &count) != 0) {
        printf("[-] memmap: snapshot failed for pid %u (elevation?)\n", pid);
        return 1;
    }

    printf("[*] pid %u range 0x%llX-0x%llX  %zu region(s)\n",
           pid, (unsigned long long)lo, (unsigned long long)hi, count);
    printf("  %-10s %-10s %-10s %-6s %-4s\n", "base", "end", "size", "state", "prot");

    uint64_t priv_committed = 0, img_committed = 0, map_committed = 0;
    int shown = 0;
    for (size_t i = 0; i < count; i++) {
        const vmpx_mem_region_t* r = &regions[i];
        if (r->state == MEM_COMMIT) {
            if (r->type == MEM_PRIVATE) priv_committed += r->size;
            else if (r->type == MEM_IMAGE) img_committed += r->size;
            else if (r->type == MEM_MAPPED) map_committed += r->size;
        }
        if (!all && r->state != MEM_COMMIT) continue;
        if (private_only && r->type != MEM_PRIVATE) continue;
        if (r->size < min_size) continue;

        char prot[10];
        prot_str(r->protect, prot, sizeof(prot));
        printf("  %08llX   %08llX   %8lluK  %-4s   %-4s  %s\n",
               (unsigned long long)r->base,
               (unsigned long long)(r->base + r->size),
               (unsigned long long)(r->size >> 10),
               state_str(r->state), type_str(r->type), prot);
        shown++;
    }

    printf("[*] shown=%d private=%lluMB image=%lluMB mapped=%lluMB\n",
           shown,
           (unsigned long long)(priv_committed >> 20),
           (unsigned long long)(img_committed >> 20),
           (unsigned long long)(map_committed >> 20));
    proc_mem_free(regions);
    return 0;
}
