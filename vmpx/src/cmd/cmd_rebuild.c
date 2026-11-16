/* cmd_rebuild.c - live dump + recovered IAT -> runnable PE (stage B)
 *
 * Defaults come from the dump sidecar (<live>.meta): pid, image base, image
 * size. The original file is still required for headers VMProtect wipes in
 * memory, so --file (or --exe / $VMPX_TARGET) must resolve to the source PE.
 */
#include "vmpx.h"
#include "pe/hdr.h"
#include "util/str.h"
#include <string.h>

static int source_path(int argc, char** argv, char* out, size_t cap) {
    const char* file = arg_get(argc, argv, "--file");
    if (file) {
        strncpy_s(out, cap, file, _TRUNCATE);
        return 0;
    }
    wchar_t wide[MAX_PATH * 2] = { 0 };
    if (resolve_target(arg_get(argc, argv, "--exe"), wide, MAX_PATH * 2) != 0)
        return -1;
    return str_narrow(wide, out, cap);
}

int cmd_rebuild(int argc, char** argv) {
    const char* live = arg_get(argc, argv, "--live");
    const char* out = arg_get(argc, argv, "--out");
    if (!live || !out) {
        printf("[-] usage: vmpx rebuild --live <dump> --out <pe> [--file <original.exe>] "
               "[--pid N | --name exe] [--base 0xADDR] [--entry 0xRVA] [--cast]\n");
        return 2;
    }

    vmpx_dump_meta_t meta;
    int have_meta = (dump_meta_read(live, &meta) == 0);
    if (have_meta)
        printf("[*] meta: pid=%u base=0x%llX image=0x%llX dump=0x%llX\n",
               meta.pid, (unsigned long long)meta.base,
               (unsigned long long)meta.image_size, (unsigned long long)meta.dump_size);
    else
        printf("[!] no readable meta sidecar for %s\n", live);

    uint32_t pid = 0;
    int have_pid = 0;
    if (arg_get(argc, argv, "--pid") || arg_get(argc, argv, "--name")) {
        if (resolve_pid(argc, argv, &pid) != 0) return 1;
        have_pid = 1;
    } else if (have_meta && meta.pid && proc_alive(meta.pid)) {
        pid = meta.pid;
        have_pid = 1;
    }
    if (!have_pid) {
        printf("[-] rebuild needs the live process: pass --pid N, --name exe, "
               "or dump while it is running (meta pid)\n");
        return 1;
    }

    char src[MAX_PATH * 2] = { 0 };
    if (source_path(argc, argv, src, sizeof(src)) != 0) {
        printf("[-] original file not resolved: pass --file <original.exe>\n");
        return 1;
    }

    pe_t pe;
    if (pe_load(src, &pe) != 0) return 1;

    uint64_t base = arg_num(argc, argv, "--base", 0);
    if (!base && have_meta) base = meta.base;
    if (!base) {
        uint32_t mod_size = 0;
        if (!proc_main_module(pid, &base, &mod_size)) {
            printf("[-] cannot resolve main module base for pid %u\n", pid);
            pe_free(&pe);
            return 1;
        }
    }
    printf("[*] live pid=%u base=0x%llX source=%s\n",
           pid, (unsigned long long)base, src);

    iat_table_t tab;
    if (iat_table_init(&tab, IAT_MAX_FUNCS) != 0) {
        printf("[-] out of memory for import table\n");
        pe_free(&pe);
        return 1;
    }

    int n = iat_from_live(pid, base, pe.data, pe.size, &tab);
    printf("[*] descriptor pass: modules=%u funcs=%u unresolved=%u\n",
           tab.nmods, tab.nfuncs, iat_table_unresolved(&tab));

    int need_cast = (n <= 0) || iat_table_unresolved(&tab) != 0 ||
                    arg_has(argc, argv, "--cast");
    if (need_cast) {
        int blocks = iat_cast(pid, base, pe.data, pe.size, &tab);
        printf("[*] cast pass: +%d block(s), modules=%u funcs=%u unresolved=%u\n",
               blocks > 0 ? blocks : 0, tab.nmods, tab.nfuncs,
               iat_table_unresolved(&tab));
    }

    if (tab.nmods == 0 || tab.nfuncs == 0) {
        printf("[-] no imports recovered\n");
        iat_table_free(&tab);
        pe_free(&pe);
        return 1;
    }
    if (iat_table_unresolved(&tab) != 0) {
        printf("[-] %u slot(s) still unresolved; rebuild would misbind the IAT\n",
               iat_table_unresolved(&tab));
        iat_table_free(&tab);
        pe_free(&pe);
        return 1;
    }

    uint32_t entry = (uint32_t)arg_num(argc, argv, "--entry", 0);
    int clean_data = arg_has(argc, argv, "--clean-data") ? 1 : 0;
    if (entry) printf("[*] entry override: RVA 0x%X\n", entry);
    if (clean_data) printf("[*] clean data: writable sections restored from file\n");

    int rc = pe_rebuild(pe.data, pe.size, base, entry, clean_data, live, out, &tab);
    if (rc == 0)
        printf("STATUS rebuild ok %s modules=%u funcs=%u\n", out, tab.nmods, tab.nfuncs);
    else
        printf("STATUS rebuild fail %s\n", out);

    iat_table_free(&tab);
    pe_free(&pe);
    return rc == 0 ? 0 : 1;
}
