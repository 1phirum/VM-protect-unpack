/* json_access.c - free, typed access, dotted paths, string emission */
#include "util/json_int.h"
#include <stdlib.h>
#include <string.h>

void json_free(json_value_t* v) {
    if (!v) return;
    switch (v->type) {
    case JSON_STRING:
        free(v->u.string.ptr);
        break;
    case JSON_ARRAY:
        for (size_t i = 0; i < v->u.array.count; i++)
            json_free(v->u.array.items[i]);
        free(v->u.array.items);
        break;
    case JSON_OBJECT:
        for (size_t i = 0; i < v->u.object.count; i++) {
            free(v->u.object.keys[i]);
            json_free(v->u.object.values[i]);
        }
        free(v->u.object.keys);
        free(v->u.object.values);
        break;
    default:
        break;
    }
    free(v);
}

json_type_t json_kind(const json_value_t* v) {
    return v ? v->type : JSON_NULL;
}

static const json_value_t* obj_find(const json_value_t* v, const char* key,
                                    size_t len) {
    for (size_t i = 0; i < v->u.object.count; i++) {
        const char* k = v->u.object.keys[i];
        if (strlen(k) == len && memcmp(k, key, len) == 0)
            return v->u.object.values[i];
    }
    return NULL;
}

const json_value_t* json_get(const json_value_t* root, const char* path) {
    if (!root || !path) return NULL;
    if (!*path) return root;
    const json_value_t* cur = root;
    const char* p = path;
    while (*p) {
        const char* dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        if (!len) return NULL;
        if (cur->type == JSON_OBJECT) {
            cur = obj_find(cur, p, len);
        } else if (cur->type == JSON_ARRAY) {
            size_t index = 0;
            for (size_t i = 0; i < len; i++) {
                if (p[i] < '0' || p[i] > '9') return NULL;
                if (index > ((size_t)-1 - (size_t)(p[i] - '0')) / 10)
                    return NULL;
                index = index * 10 + (size_t)(p[i] - '0');
            }
            if (index >= cur->u.array.count) return NULL;
            cur = cur->u.array.items[index];
        } else {
            return NULL;
        }
        if (!cur) return NULL;
        if (!dot) break;
        p = dot + 1;
    }
    return cur;
}

const char* json_string(const json_value_t* v) {
    return (v && v->type == JSON_STRING) ? v->u.string.ptr : NULL;
}

size_t json_string_len(const json_value_t* v) {
    return (v && v->type == JSON_STRING) ? v->u.string.len : 0;
}

int json_int(const json_value_t* v, int64_t* out) {
    if (!v || !out || v->type != JSON_NUMBER) return -1;
    if (v->u.number.is_int) {
        *out = v->u.number.i;
        return 0;
    }
    double d = v->u.number.d;
    if (d < -9223372036854775808.0 || d >= 9223372036854775808.0) return -1;
    int64_t x = (int64_t)d;
    if ((double)x != d) return -1;
    *out = x;
    return 0;
}

int json_bool(const json_value_t* v, int* out) {
    if (!v || !out || v->type != JSON_BOOL) return -1;
    *out = v->u.boolean;
    return 0;
}

size_t json_count(const json_value_t* v) {
    if (!v) return 0;
    if (v->type == JSON_ARRAY) return v->u.array.count;
    if (v->type == JSON_OBJECT) return v->u.object.count;
    return 0;
}

const json_value_t* json_at(const json_value_t* v, size_t index) {
    if (!v) return NULL;
    if (v->type == JSON_ARRAY)
        return index < v->u.array.count ? v->u.array.items[index] : NULL;
    if (v->type == JSON_OBJECT)
        return index < v->u.object.count ? v->u.object.values[index] : NULL;
    return NULL;
}

const char* json_key(const json_value_t* v, size_t index) {
    if (!v || v->type != JSON_OBJECT || index >= v->u.object.count) return NULL;
    return v->u.object.keys[index];
}

int json_write_string(FILE* f, const char* s) {
    if (!f || !s) return -1;
    if (fputc('"', f) == EOF) return -1;
    for (const unsigned char* p = (const unsigned char*)s; *p; p++) {
        unsigned char c = *p;
        if (c == '"' || c == '\\') {
            if (fputc('\\', f) == EOF || fputc(c, f) == EOF) return -1;
        } else if (c < 0x20) {
            if (fprintf(f, "\\u%04X", (unsigned)c) < 0) return -1;
        } else {
            if (fputc(c, f) == EOF) return -1;
        }
    }
    return fputc('"', f) == EOF ? -1 : 0;
}
