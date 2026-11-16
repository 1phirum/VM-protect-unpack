/* profile_test.c - defaults, strict parsing, bounds and effective round-trip */
#include "unpack/deobf/dynamic/profile/profile.h"
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond) do {                                              \
    if (!(cond)) {                                                    \
        printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);         \
        failures++;                                                   \
    }                                                                 \
} while (0)

static int write_text(const char* path, const char* text) {
    FILE* f = NULL;
    if (fopen_s(&f, path, "wb") != 0 || !f) return -1;
    size_t n = strlen(text);
    int ok = fwrite(text, 1, n, f) == n;
    fclose(f);
    return ok ? 0 : -1;
}

static void expect_bad(const char* path, const char* text) {
    CHECK(write_text(path, text) == 0);
    vmpx_profile_t p;
    char err[256];
    CHECK(vmpx_profile_load(path, &p, err, sizeof(err)) != 0);
    CHECK(err[0] != 0);
}

int main(void) {
    vmpx_profile_t p;
    char err[256];

    vmpx_profile_defaults(&p);
    CHECK(p.schema_version == 1);
    CHECK(strcmp(p.architecture, "auto") == 0);
    CHECK(p.host_budget_mib == 256 && p.read_chunk_kib == 1024);
    CHECK(vmpx_profile_validate(&p, err, sizeof(err)) == 0);

    const char* good = "tests\\_profile_good.json";
    CHECK(write_text(good,
        "{\n"
        "  \"schema_version\": 1,\n"
        "  \"architecture\": \"x86\",\n"
        "  \"discovery\": {\"image\":\"main\",\"regions\":\"all\","
        "\"entry_policy\":\"captured\"},\n"
        "  \"observation\": {\"backend\":\"guard-page\","
        "\"baseline_required\":false,\"max_guard_pages\":32,"
        "\"max_probe_ms\":100,\"max_trace_instructions\":5000},\n"
        "  \"memory\": {\"host_budget_mib\":128,\"agent_budget_mib\":16,"
        "\"read_chunk_kib\":64},\n"
        "  \"reconstruction\": {\"prefer_loader_initialization\":false,"
        "\"allow_checkpoint_diagnostics\":true,"
        "\"require_dependency_preflight\":false},\n"
        "  \"validation\": {\"feature_inventory\":\"flows.json\","
        "\"fresh_process_required\":false,"
        "\"diagnostic_repair_allowed_for_pass\":true}\n"
        "}\n") == 0);
    CHECK(vmpx_profile_load(good, &p, err, sizeof(err)) == 0);
    CHECK(strcmp(p.architecture, "x86") == 0);
    CHECK(strcmp(p.discovery_regions, "all") == 0);
    CHECK(strcmp(p.observation_backend, "guard-page") == 0);
    CHECK(p.baseline_required == 0 && p.max_guard_pages == 32);
    CHECK(p.host_budget_mib == 128 && p.read_chunk_kib == 64);
    CHECK(p.prefer_loader_initialization == 0);
    CHECK(p.diagnostic_repair_allowed_for_pass == 1);
    CHECK(p.loaded_from_file == 1);
    CHECK(strcmp(p.source_path, good) == 0);

    const char* eff = "tests\\_profile_effective.json";
    CHECK(vmpx_profile_write(eff, &p) == 0);
    vmpx_profile_t q;
    CHECK(vmpx_profile_load(eff, &q, err, sizeof(err)) == 0);
    CHECK(strcmp(q.architecture, "x86") == 0);
    CHECK(q.host_budget_mib == 128 && q.read_chunk_kib == 64);
    CHECK(q.fresh_process_required == 0);
    CHECK(q.max_trace_instructions == 5000);

    expect_bad("tests\\_profile_bad.json", "{}");
    expect_bad("tests\\_profile_bad.json", "{\"schema_version\":2}");
    expect_bad("tests\\_profile_bad.json",
               "{\"schema_version\":1,\"architecture\":\"x64\"}");
    expect_bad("tests\\_profile_bad.json",
               "{\"schema_version\":1,\"observation\":{\"max_guard_pages\":0}}");
    expect_bad("tests\\_profile_bad.json",
               "{\"schema_version\":1,\"memory\":{\"host_budget_mib\":16,"
               "\"read_chunk_kib\":16384}}");
    expect_bad("tests\\_profile_bad.json",
               "{\"schema_version\":1,\"memory\":{\"host_budget_mib\":\"big\"}}");
    expect_bad("tests\\_profile_bad.json",
               "{\"schema_version\":1,\"schema_version\":1}");
    expect_bad("tests\\_profile_bad.json",
               "{\"schema_version\":1} trailing");
    expect_bad("tests\\_profile_bad.json",
               "{\"schema_version\":1,\"observation\":{\"backend\":\"nope\"}}");

    vmpx_profile_t missing;
    CHECK(vmpx_profile_load("tests\\_profile_missing.json", &missing, err,
                            sizeof(err)) != 0);
    CHECK(err[0] != 0);

    remove(good);
    remove(eff);
    remove("tests\\_profile_bad.json");
    if (failures) {
        printf("profile_test: %d failure(s)\n", failures);
        return 1;
    }
    printf("profile_test: ok\n");
    return 0;
}
