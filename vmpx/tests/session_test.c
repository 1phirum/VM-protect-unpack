/* session_test.c - identity, generations, lifecycle and manifest emission */
#include "unpack/deobf/dynamic/session/session.h"
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond) do {                                              \
    if (!(cond)) {                                                    \
        printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);         \
        failures++;                                                   \
    }                                                                 \
} while (0)

static int file_contains(const char* path, const char* needle) {
    FILE* f = NULL;
    if (fopen_s(&f, path, "rb") != 0 || !f) return 0;
    char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    return strstr(buf, needle) != NULL;
}

int main(void) {
    char id_a[VMPX_SESSION_ID_CAP], id_b[VMPX_SESSION_ID_CAP];
    char id_c[VMPX_SESSION_ID_CAP];
    CHECK(vmpx_session_make_id(42, 100, 7, id_a, sizeof(id_a)) == 0);
    CHECK(vmpx_session_make_id(42, 101, 7, id_b, sizeof(id_b)) == 0);
    CHECK(vmpx_session_make_id(42, 100, 8, id_c, sizeof(id_c)) == 0);
    CHECK(strcmp(id_a, id_b) != 0);
    CHECK(strcmp(id_a, id_c) != 0);
    CHECK(vmpx_session_make_id(42, 100, 7, id_a, 8) != 0);

    const char* out = "tests\\_session_out";
    vmpx_session_t s;
    char err[256];
    CHECK(vmpx_session_open(0, out, &s, err, sizeof(err)) != 0);
    CHECK(vmpx_session_open(GetCurrentProcessId(), out, &s, err,
                            sizeof(err)) == 0);
    CHECK(s.proc != NULL);
    CHECK(s.state == VMPX_SESSION_IDENTIFIED);
    CHECK(s.id.pid == GetCurrentProcessId());
    CHECK(s.id.id[0] != 0 && s.id.create_time != 0 && s.id.nonce != 0);
    CHECK(s.id.image_base != 0 && s.id.image_size != 0);
    CHECK(s.id.image_path[0] != 0);
    CHECK(s.module_count > 0);
    CHECK(s.regions.count > 0);

    const vmpx_session_module_t* main_mod = vmpx_session_module_at(
        &s, s.id.image_base);
    CHECK(main_mod != NULL && main_mod->base == s.id.image_base);
    uint32_t main_gen = main_mod ? main_mod->generation : 0;
    CHECK(vmpx_session_module_by_name(&s, "session_test.exe") != NULL);

    CHECK(vmpx_session_refresh_modules(&s) == 0);
    main_mod = vmpx_session_module_at(&s, s.id.image_base);
    CHECK(main_mod && main_mod->generation == main_gen);
    CHECK(vmpx_session_refresh_regions(&s) == 0);
    CHECK(vmpx_region_map_valid_span(&s.regions, s.id.image_base) > 0);

    CHECK(vmpx_session_enter(&s, VMPX_SESSION_BASELINING, err,
                             sizeof(err)) == 0);
    CHECK(vmpx_session_enter(&s, VMPX_SESSION_OBSERVING, err,
                             sizeof(err)) == 0);
    CHECK(vmpx_session_enter(&s, VMPX_SESSION_FOCUSED_CAPTURE, err,
                             sizeof(err)) == 0);
    CHECK(vmpx_session_enter(&s, VMPX_SESSION_OBSERVING, err,
                             sizeof(err)) == 0);
    CHECK(vmpx_session_enter(&s, VMPX_SESSION_RECONSTRUCTING, err,
                             sizeof(err)) == 0);
    CHECK(vmpx_session_enter(&s, VMPX_SESSION_VALIDATING, err,
                             sizeof(err)) == 0);
    CHECK(vmpx_session_enter(&s, VMPX_SESSION_COMPLETED, err,
                             sizeof(err)) == 0);
    CHECK(vmpx_session_enter(&s, VMPX_SESSION_STOPPING, err,
                             sizeof(err)) == 0);
    CHECK(vmpx_session_enter(&s, VMPX_SESSION_STOPPED, err,
                             sizeof(err)) == 0);
    CHECK(vmpx_session_enter(&s, VMPX_SESSION_OBSERVING, err,
                             sizeof(err)) != 0);

    vmpx_profile_t p;
    vmpx_profile_defaults(&p);
    CHECK(vmpx_session_write_manifest(&s, &p, err, sizeof(err)) == 0);
    CHECK(s.writes == 1);
    CHECK(file_contains("tests\\_session_out\\session\\manifest.json",
                        "\"state\": \"stopped\""));
    CHECK(file_contains("tests\\_session_out\\session\\manifest.json",
                        s.id.id));
    CHECK(file_contains("tests\\_session_out\\session\\capabilities.json",
                        "\"codecov\""));
    CHECK(file_contains("tests\\_session_out\\session\\modules.jsonl",
                        "session_test.exe"));
    CHECK(file_contains("tests\\_session_out\\session\\regions.jsonl",
                        "\"generation\""));
    CHECK(file_contains("tests\\_session_out\\session\\profile.effective.json",
                        "\"host_budget_mib\": 256"));

    vmpx_session_close(&s);
    CHECK(s.proc == NULL && s.scratch == NULL);

    const char* files[] = {
        "tests\\_session_out\\session\\manifest.json",
        "tests\\_session_out\\session\\capabilities.json",
        "tests\\_session_out\\session\\modules.jsonl",
        "tests\\_session_out\\session\\regions.jsonl",
        "tests\\_session_out\\session\\profile.effective.json",
    };
    for (int i = 0; i < 5; i++) remove(files[i]);
    RemoveDirectoryA("tests\\_session_out\\session");
    RemoveDirectoryA("tests\\_session_out");

    if (failures) {
        printf("session_test: %d failure(s)\n", failures);
        return 1;
    }
    printf("session_test: ok\n");
    return 0;
}
