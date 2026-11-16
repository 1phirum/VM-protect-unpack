/* profile.c - defaults, strict known-field parsing, effective JSON emission */
#include "unpack/deobf/dynamic/profile/profile.h"
#include "util/json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PROFILE_MAX_BYTES (1u << 20)

static int copy_str(char* dst, size_t cap, const char* src, size_t len,
                    const char* name, char* err, size_t err_cap) {
    if (len >= cap) {
        _snprintf_s(err, err_cap, _TRUNCATE, "profile: %s is too long", name);
        return -1;
    }
    memcpy(dst, src, len);
    dst[len] = 0;
    return 0;
}

void vmpx_profile_defaults(vmpx_profile_t* p) {
    if (!p) return;
    memset(p, 0, sizeof(*p));
    p->schema_version = 1;
    _snprintf_s(p->architecture, sizeof(p->architecture), _TRUNCATE, "auto");
    _snprintf_s(p->discovery_image, sizeof(p->discovery_image), _TRUNCATE,
                "main");
    _snprintf_s(p->discovery_regions, sizeof(p->discovery_regions), _TRUNCATE,
                "materialized-and-executed");
    _snprintf_s(p->discovery_entry_policy, sizeof(p->discovery_entry_policy),
                _TRUNCATE, "evidence-candidates");
    _snprintf_s(p->observation_backend, sizeof(p->observation_backend),
                _TRUNCATE, "auto");
    p->baseline_required = 1;
    p->max_guard_pages = 64;
    p->max_probe_ms = 250;
    p->max_trace_instructions = 100000;
    p->host_budget_mib = 256;
    p->agent_budget_mib = 32;
    p->read_chunk_kib = 1024;
    p->prefer_loader_initialization = 1;
    p->allow_checkpoint_diagnostics = 0;
    p->require_dependency_preflight = 1;
    p->fresh_process_required = 1;
    p->diagnostic_repair_allowed_for_pass = 0;
}

static int one_of(const char* s, const char* const* values, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (strcmp(s, values[i]) == 0) return 1;
    return 0;
}

static int read_str(const json_value_t* root, const char* path, char* out,
                    size_t cap, char* err, size_t err_cap) {
    const json_value_t* v = json_get(root, path);
    if (!v) return 0;
    const char* s = json_string(v);
    if (!s) {
        _snprintf_s(err, err_cap, _TRUNCATE,
                    "profile: %s must be a string", path);
        return -1;
    }
    return copy_str(out, cap, s, strlen(s), path, err, err_cap);
}

static int read_u32(const json_value_t* root, const char* path, uint32_t min,
                    uint32_t max, uint32_t* out, char* err, size_t err_cap) {
    const json_value_t* v = json_get(root, path);
    if (!v) return 0;
    int64_t n = 0;
    if (json_int(v, &n) != 0 || n < (int64_t)min || n > (int64_t)max) {
        _snprintf_s(err, err_cap, _TRUNCATE,
                    "profile: %s must be an integer in [%u, %u]", path, min,
                    max);
        return -1;
    }
    *out = (uint32_t)n;
    return 0;
}

static int read_bool(const json_value_t* root, const char* path,
                     uint32_t* out, char* err, size_t err_cap) {
    const json_value_t* v = json_get(root, path);
    if (!v) return 0;
    int b = 0;
    if (json_bool(v, &b) != 0) {
        _snprintf_s(err, err_cap, _TRUNCATE,
                    "profile: %s must be a boolean", path);
        return -1;
    }
    *out = b ? 1u : 0u;
    return 0;
}

static int valid_enum(const char* s, const char* what,
                      const char* const* values, size_t n, char* err,
                      size_t err_cap) {
    if (!one_of(s, values, n)) {
        _snprintf_s(err, err_cap, _TRUNCATE, "profile: invalid %s", what);
        return -1;
    }
    return 0;
}

int vmpx_profile_validate(const vmpx_profile_t* p, char* err, size_t err_cap) {
    char dummy[1];
    if (!err || !err_cap) {
        err = dummy;
        err_cap = 1;
    }
    err[0] = 0;
    if (!p) return -1;
    if (p->schema_version != 1) {
        _snprintf_s(err, err_cap, _TRUNCATE,
                    "profile: unsupported schema_version %u",
                    p->schema_version);
        return -1;
    }

    static const char* const arch[] = { "auto", "x86" };
    static const char* const image[] = { "main" };
    static const char* const regions[] = {
        "all", "materialized", "materialized-and-executed"
    };
    static const char* const entry[] = {
        "evidence-candidates", "first-executable", "captured"
    };
    static const char* const backend[] = {
        "auto", "sampling", "guard-page", "trace"
    };

    if (valid_enum(p->architecture, "architecture", arch, 2, err, err_cap) ||
        valid_enum(p->discovery_image, "discovery.image", image, 1, err,
                   err_cap) ||
        valid_enum(p->discovery_regions, "discovery.regions", regions, 3, err,
                   err_cap) ||
        valid_enum(p->discovery_entry_policy, "discovery.entry_policy", entry,
                   3, err, err_cap) ||
        valid_enum(p->observation_backend, "observation.backend", backend, 4,
                   err, err_cap))
        return -1;

    if (p->max_guard_pages < 1 || p->max_guard_pages > 65536 ||
        p->max_probe_ms < 1 || p->max_probe_ms > 60000 ||
        p->max_trace_instructions < 1 ||
        p->max_trace_instructions > 10000000) {
        _snprintf_s(err, err_cap, _TRUNCATE,
                    "profile: observation limit out of range");
        return -1;
    }
    if (p->host_budget_mib < 16 || p->host_budget_mib > 4096 ||
        p->agent_budget_mib < 1 || p->agent_budget_mib > 1024 ||
        p->read_chunk_kib < 4 || p->read_chunk_kib > 16384) {
        _snprintf_s(err, err_cap, _TRUNCATE,
                    "profile: memory limit out of range");
        return -1;
    }
    if (p->read_chunk_kib > p->host_budget_mib * 512u) {
        _snprintf_s(err, err_cap, _TRUNCATE,
                    "profile: read_chunk_kib exceeds half the host budget");
        return -1;
    }
    if (p->baseline_required > 1 || p->prefer_loader_initialization > 1 ||
        p->allow_checkpoint_diagnostics > 1 ||
        p->require_dependency_preflight > 1 ||
        p->fresh_process_required > 1 ||
        p->diagnostic_repair_allowed_for_pass > 1) {
        _snprintf_s(err, err_cap, _TRUNCATE,
                    "profile: boolean field out of range");
        return -1;
    }
    if (strlen(p->validation_feature_inventory) >=
        sizeof(p->validation_feature_inventory)) {
        _snprintf_s(err, err_cap, _TRUNCATE,
                    "profile: feature inventory path is too long");
        return -1;
    }
    return 0;
}

int vmpx_profile_load(const char* path, vmpx_profile_t* p, char* err,
                      size_t err_cap) {
    char dummy[1];
    if (!err || !err_cap) {
        err = dummy;
        err_cap = 1;
    }
    err[0] = 0;
    if (!path || !p) return -1;

    FILE* f = NULL;
    if (fopen_s(&f, path, "rb") != 0 || !f) {
        _snprintf_s(err, err_cap, _TRUNCATE, "profile: cannot open %s", path);
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        _snprintf_s(err, err_cap, _TRUNCATE, "profile: cannot seek %s", path);
        return -1;
    }
    long sz = ftell(f);
    if (sz < 0 || (unsigned long)sz > PROFILE_MAX_BYTES) {
        fclose(f);
        _snprintf_s(err, err_cap, _TRUNCATE, "profile: %s is too large", path);
        return -1;
    }
    rewind(f);
    char* text = (char*)malloc((size_t)sz + 1);
    if (!text) {
        fclose(f);
        _snprintf_s(err, err_cap, _TRUNCATE, "profile: out of memory");
        return -1;
    }
    size_t got = fread(text, 1, (size_t)sz, f);
    fclose(f);
    text[got] = 0;
    if (got != (size_t)sz) {
        free(text);
        _snprintf_s(err, err_cap, _TRUNCATE, "profile: short read on %s", path);
        return -1;
    }

    json_value_t* root = NULL;
    if (json_parse(text, got, &root, err, err_cap) != 0) {
        free(text);
        return -1;
    }
    free(text);
    if (!root || json_kind(root) != JSON_OBJECT) {
        json_free(root);
        _snprintf_s(err, err_cap, _TRUNCATE,
                    "profile: root must be an object");
        return -1;
    }
    if (!json_get(root, "schema_version")) {
        json_free(root);
        _snprintf_s(err, err_cap, _TRUNCATE,
                    "profile: schema_version is required");
        return -1;
    }

    vmpx_profile_defaults(p);
    _snprintf_s(p->source_path, sizeof(p->source_path), _TRUNCATE, "%s", path);
    p->loaded_from_file = 1;

    int bad =
        read_u32(root, "schema_version", 1, 1, &p->schema_version, err,
                 err_cap) ||
        read_str(root, "architecture", p->architecture,
                 sizeof(p->architecture), err, err_cap) ||
        read_str(root, "discovery.image", p->discovery_image,
                 sizeof(p->discovery_image), err, err_cap) ||
        read_str(root, "discovery.regions", p->discovery_regions,
                 sizeof(p->discovery_regions), err, err_cap) ||
        read_str(root, "discovery.entry_policy", p->discovery_entry_policy,
                 sizeof(p->discovery_entry_policy), err, err_cap) ||
        read_str(root, "observation.backend", p->observation_backend,
                 sizeof(p->observation_backend), err, err_cap) ||
        read_bool(root, "observation.baseline_required",
                  &p->baseline_required, err, err_cap) ||
        read_u32(root, "observation.max_guard_pages", 1, 65536,
                 &p->max_guard_pages, err, err_cap) ||
        read_u32(root, "observation.max_probe_ms", 1, 60000,
                 &p->max_probe_ms, err, err_cap) ||
        read_u32(root, "observation.max_trace_instructions", 1, 10000000,
                 &p->max_trace_instructions, err, err_cap) ||
        read_u32(root, "memory.host_budget_mib", 16, 4096,
                 &p->host_budget_mib, err, err_cap) ||
        read_u32(root, "memory.agent_budget_mib", 1, 1024,
                 &p->agent_budget_mib, err, err_cap) ||
        read_u32(root, "memory.read_chunk_kib", 4, 16384,
                 &p->read_chunk_kib, err, err_cap) ||
        read_bool(root, "reconstruction.prefer_loader_initialization",
                  &p->prefer_loader_initialization, err, err_cap) ||
        read_bool(root, "reconstruction.allow_checkpoint_diagnostics",
                  &p->allow_checkpoint_diagnostics, err, err_cap) ||
        read_bool(root, "reconstruction.require_dependency_preflight",
                  &p->require_dependency_preflight, err, err_cap) ||
        read_str(root, "validation.feature_inventory",
                 p->validation_feature_inventory,
                 sizeof(p->validation_feature_inventory), err, err_cap) ||
        read_bool(root, "validation.fresh_process_required",
                  &p->fresh_process_required, err, err_cap) ||
        read_bool(root, "validation.diagnostic_repair_allowed_for_pass",
                  &p->diagnostic_repair_allowed_for_pass, err, err_cap);

    json_free(root);
    if (bad) return -1;
    if (vmpx_profile_validate(p, err, err_cap) != 0) return -1;
    return 0;
}

int vmpx_profile_write(const char* path, const vmpx_profile_t* p) {
    if (!path || !p) return -1;
    FILE* f = NULL;
    if (fopen_s(&f, path, "wb") != 0 || !f) return -1;

    fprintf(f, "{\n  \"schema_version\": %u,\n  \"architecture\": ",
            p->schema_version);
    json_write_string(f, p->architecture);
    fprintf(f, ",\n  \"discovery\": {\n    \"image\": ");
    json_write_string(f, p->discovery_image);
    fprintf(f, ",\n    \"regions\": ");
    json_write_string(f, p->discovery_regions);
    fprintf(f, ",\n    \"entry_policy\": ");
    json_write_string(f, p->discovery_entry_policy);
    fprintf(f, "\n  },\n  \"observation\": {\n    \"backend\": ");
    json_write_string(f, p->observation_backend);
    fprintf(f, ",\n    \"baseline_required\": %s",
            p->baseline_required ? "true" : "false");
    fprintf(f, ",\n    \"max_guard_pages\": %u", p->max_guard_pages);
    fprintf(f, ",\n    \"max_probe_ms\": %u", p->max_probe_ms);
    fprintf(f, ",\n    \"max_trace_instructions\": %u",
            p->max_trace_instructions);
    fprintf(f, "\n  },\n  \"memory\": {\n    \"host_budget_mib\": %u",
            p->host_budget_mib);
    fprintf(f, ",\n    \"agent_budget_mib\": %u", p->agent_budget_mib);
    fprintf(f, ",\n    \"read_chunk_kib\": %u", p->read_chunk_kib);
    fprintf(f, "\n  },\n  \"reconstruction\": {\n"
               "    \"prefer_loader_initialization\": %s",
            p->prefer_loader_initialization ? "true" : "false");
    fprintf(f, ",\n    \"allow_checkpoint_diagnostics\": %s",
            p->allow_checkpoint_diagnostics ? "true" : "false");
    fprintf(f, ",\n    \"require_dependency_preflight\": %s",
            p->require_dependency_preflight ? "true" : "false");
    fprintf(f, "\n  },\n  \"validation\": {\n    \"feature_inventory\": ");
    json_write_string(f, p->validation_feature_inventory);
    fprintf(f, ",\n    \"fresh_process_required\": %s",
            p->fresh_process_required ? "true" : "false");
    fprintf(f, ",\n    \"diagnostic_repair_allowed_for_pass\": %s",
            p->diagnostic_repair_allowed_for_pass ? "true" : "false");
    fprintf(f, "\n  },\n  \"source_path\": ");
    json_write_string(f, p->source_path);
    fprintf(f, ",\n  \"loaded_from_file\": %s\n}\n",
            p->loaded_from_file ? "true" : "false");

    int bad = ferror(f);
    if (fclose(f) != 0) bad = 1;
    return bad ? -1 : 0;
}
