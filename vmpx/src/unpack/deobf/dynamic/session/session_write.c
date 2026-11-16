/* session_write.c - manifest, effective profile, capability list, JSONL maps */
#include "unpack/deobf/dynamic/session/session.h"
#include "util/json.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static void set_err(char* err, size_t cap, const char* fmt, ...) {
    if (!err || !cap) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf_s(err, cap, _TRUNCATE, fmt, ap);
    va_end(ap);
}

static int session_dir(const vmpx_session_t* s, char* dir, size_t cap,
                       char* err, size_t err_cap) {
    if (CreateDirectoryA(s->out_dir, NULL) == 0 &&
        GetLastError() != ERROR_ALREADY_EXISTS) {
        set_err(err, err_cap, "session: cannot create %s (%lu)", s->out_dir,
                GetLastError());
        return -1;
    }
    _snprintf_s(dir, cap, _TRUNCATE, "%s\\session", s->out_dir);
    if (CreateDirectoryA(dir, NULL) == 0 &&
        GetLastError() != ERROR_ALREADY_EXISTS) {
        set_err(err, err_cap, "session: cannot create %s (%lu)", dir,
                GetLastError());
        return -1;
    }
    return 0;
}

static int write_capabilities(const char* dir, char* err, size_t err_cap) {
    char path[VMPX_SESSION_PATH_CAP * 2];
    _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\capabilities.json", dir);
    FILE* f = NULL;
    if (fopen_s(&f, path, "wb") != 0 || !f) {
        set_err(err, err_cap, "session: cannot write %s", path);
        return -1;
    }
    fputs("{\n  \"schema_version\": 1,\n  \"capabilities\": [\n", f);
    static const char* const names[] = {
        "control", "memdelta", "codecov", "threadctx", "vmtrans", "strings"
    };
    static const char* const kinds[] = {
        "control-ring", "page-hash-delta", "guard-page-first-exec",
        "thread-context-sample", "private-exec-classification",
        "runtime-string-recovery"
    };
    for (uint32_t i = 0; i < 6; i++) {
        fprintf(f, "    {\"name\":");
        json_write_string(f, names[i]);
        fputs(",\"available\":true,\"evidence\":", f);
        json_write_string(f, kinds[i]);
        fprintf(f, "}%s\n", i + 1 < 6 ? "," : "");
    }
    fputs("  ]\n}\n", f);
    int bad = ferror(f);
    if (fclose(f) != 0) bad = 1;
    if (bad) set_err(err, err_cap, "session: write failed for %s", path);
    return bad ? -1 : 0;
}

int vmpx_session_write_modules(vmpx_session_t* s, char* err, size_t err_cap) {
    if (!s) return -1;
    char dir[VMPX_SESSION_PATH_CAP * 2];
    if (session_dir(s, dir, sizeof(dir), err, err_cap) != 0) return -1;
    char path[VMPX_SESSION_PATH_CAP * 3];
    _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\modules.jsonl", dir);
    FILE* f = NULL;
    if (fopen_s(&f, path, "wb") != 0 || !f) {
        set_err(err, err_cap, "session: cannot write %s", path);
        return -1;
    }
    for (uint32_t i = 0; i < s->module_count; i++) {
        const vmpx_session_module_t* m = &s->modules[i];
        fputs("{\"name\":", f);
        json_write_string(f, m->name);
        fputs(",\"path\":", f);
        json_write_string(f, m->path);
        fprintf(f, ",\"base\":%llu,\"size\":%u,\"generation\":%u,"
                   "\"present\":%s}\n",
                (unsigned long long)m->base, m->size, m->generation,
                m->present ? "true" : "false");
    }
    int bad = ferror(f);
    if (fclose(f) != 0) bad = 1;
    if (bad) set_err(err, err_cap, "session: write failed for %s", path);
    return bad ? -1 : 0;
}

int vmpx_session_write_regions(vmpx_session_t* s, char* err, size_t err_cap) {
    if (!s) return -1;
    char dir[VMPX_SESSION_PATH_CAP * 2];
    if (session_dir(s, dir, sizeof(dir), err, err_cap) != 0) return -1;
    char path[VMPX_SESSION_PATH_CAP * 3];
    _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\regions.jsonl", dir);
    FILE* f = NULL;
    if (fopen_s(&f, path, "wb") != 0 || !f) {
        set_err(err, err_cap, "session: cannot write %s", path);
        return -1;
    }
    for (uint32_t i = 0; i < s->regions.count; i++) {
        const vmpx_region_t* r = &s->regions.v[i];
        fprintf(f, "{\"base\":%llu,\"size\":%llu,\"state\":%u,"
                   "\"protect\":%u,\"type\":%u,\"generation\":%u,"
                   "\"present\":%s}\n",
                (unsigned long long)r->base, (unsigned long long)r->size,
                r->state, r->protect, r->type, r->generation,
                r->present ? "true" : "false");
    }
    int bad = ferror(f);
    if (fclose(f) != 0) bad = 1;
    if (bad) set_err(err, err_cap, "session: write failed for %s", path);
    return bad ? -1 : 0;
}

int vmpx_session_write_manifest(vmpx_session_t* s, const vmpx_profile_t* p,
                                char* err, size_t err_cap) {
    if (!s) return -1;
    char dir[VMPX_SESSION_PATH_CAP * 2];
    if (session_dir(s, dir, sizeof(dir), err, err_cap) != 0) return -1;

    char eff[VMPX_SESSION_PATH_CAP * 3];
    _snprintf_s(eff, sizeof(eff), _TRUNCATE, "%s\\profile.effective.json", dir);
    if (p && vmpx_profile_write(eff, p) != 0) {
        set_err(err, err_cap, "session: cannot write %s", eff);
        return -1;
    }
    if (write_capabilities(dir, err, err_cap) != 0) return -1;
    if (vmpx_session_write_modules(s, err, err_cap) != 0) return -1;
    if (vmpx_session_write_regions(s, err, err_cap) != 0) return -1;

    char path[VMPX_SESSION_PATH_CAP * 3];
    _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\manifest.json", dir);
    FILE* f = NULL;
    if (fopen_s(&f, path, "wb") != 0 || !f) {
        set_err(err, err_cap, "session: cannot write %s", path);
        return -1;
    }
    fputs("{\n  \"schema_version\": 1,\n  \"identity\": {\n    \"id\": ", f);
    json_write_string(f, s->id.id);
    fprintf(f, ",\n    \"pid\": %u,\n    \"create_time\": %llu,\n"
               "    \"nonce\": %llu,\n    \"image_base\": %llu,\n"
               "    \"image_size\": %u,\n    \"image_path\": ",
            s->id.pid, (unsigned long long)s->id.create_time,
            (unsigned long long)s->id.nonce,
            (unsigned long long)s->id.image_base, s->id.image_size);
    json_write_string(f, s->id.image_path);
    fputs("\n  },\n  \"state\": ", f);
    json_write_string(f, vmpx_session_state_name(s->state));
    fprintf(f, ",\n  \"modules\": %u,\n  \"regions\": %u,\n"
               "  \"writes\": %u,\n  \"profile_source\": ",
            s->module_count, s->regions.count, s->writes + 1u);
    json_write_string(f, p ? p->source_path : "");
    fputs(",\n  \"effective_profile\": \"session/profile.effective.json\",\n"
          "  \"capabilities\": \"session/capabilities.json\",\n"
          "  \"modules_file\": \"session/modules.jsonl\",\n"
          "  \"regions_file\": \"session/regions.jsonl\"\n}\n", f);
    int bad = ferror(f);
    if (fclose(f) != 0) bad = 1;
    if (bad) set_err(err, err_cap, "session: write failed for %s", path);
    if (!bad) s->writes++;
    return bad ? -1 : 0;
}
