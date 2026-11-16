/* deobf_run.c - offline deobfuscation over read-only file mappings
 *
 * The analyzer works on a 490 MB dump and an optional 224 MB original. Loading
 * both into heap would commit ~714 MB in a 32-bit process and invite allocator
 * fragmentation. Services map both files read-only and operate in place.
 */
#include "vmpx.h"
#include "unpack/deobf/deobf.h"
#include "unpack/memory/mapfile.h"
#include <stdio.h>
#include <string.h>

static void ensure_dir(const char* dir) {
    if (dir && *dir) CreateDirectoryA(dir, NULL);
}

int deobf_run(const char* dump_path, const char* file_path, const char* out_dir,
              int scan_strings) {
    if (!dump_path || !out_dir) return -1;
    ensure_dir(out_dir);

    vmpx_file_map_t dump_map;
    if (vmpx_file_map_open(dump_path, &dump_map) != 0) {
        printf("[-] deobf: cannot map %s\n", dump_path);
        return -1;
    }
    const uint8_t* dump = dump_map.data;
    uint64_t dlen = dump_map.size;

    vmpx_file_map_t file_map;
    memset(&file_map, 0, sizeof(file_map));
    file_map.file = INVALID_HANDLE_VALUE;
    int have_file = 0;
    if (file_path && *file_path) {
        if (vmpx_file_map_open(file_path, &file_map) == 0) {
            have_file = 1;
        } else {
            printf("[!] deobf: cannot map original %s; diff skipped\n", file_path);
        }
    }

    deobf_stats_t st;
    memset(&st, 0, sizeof(st));
    char path[MAX_PATH * 2];

    _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\entropy.txt", out_dir);
    if (deobf_entropy(dump, dlen, path, &st) != 0)
        printf("[!] deobf: entropy report failed\n");

    if (have_file) {
        _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\diff.txt", out_dir);
        if (deobf_diff(file_map.data, file_map.size, dump, dlen, path, &st) != 0)
            printf("[!] deobf: diff report failed\n");
    }

    _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\carved", out_dir);
    if (deobf_carve(dump, dlen, path, &st) != 0)
        printf("[!] deobf: carve failed\n");

    if (scan_strings) {
        _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\strings.txt", out_dir);
        if (deobf_strings(dump, dlen, path, &st) != 0)
            printf("[!] deobf: string recovery failed\n");
    }

    _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\report.txt", out_dir);
    FILE* r = NULL;
    if (fopen_s(&r, path, "w") == 0 && r) {
        fprintf(r, "VMPX deobfuscation report\n");
        fprintf(r, "dump=%s size=0x%llX\n", dump_path,
                (unsigned long long)dlen);
        fprintf(r, "file=%s size=0x%llX\n", have_file ? file_path : "(none)",
                (unsigned long long)(have_file ? file_map.size : 0));
        fprintf(r, "sections=%u high_entropy_ranges=%u changed_sections=%u\n",
                st.sections, st.high_entropy_ranges, st.changed_sections);
        fprintf(r, "carved_images=%u recovered_strings=%u pages_scanned=%u\n",
                st.carved_images, st.recovered_strings, st.pages_scanned);
        fclose(r);
    }

    printf("[+] deobf: sections=%u high_entropy=%u changed=%u carved=%u "
           "strings=%u pages=%u -> %s\n",
           st.sections, st.high_entropy_ranges, st.changed_sections,
           st.carved_images, st.recovered_strings, st.pages_scanned, out_dir);

    if (have_file) vmpx_file_map_close(&file_map);
    vmpx_file_map_close(&dump_map);
    return 0;
}
