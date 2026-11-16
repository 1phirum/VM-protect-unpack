/* json_parse.c - recursive descent with explicit depth and node ceilings */
#include "util/json_int.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define JSON_MAX_DEPTH 32
#define JSON_MAX_NODES 8192
#define JSON_MAX_MEMBERS 4096

typedef struct {
    const char* s;
    size_t n;
    size_t i;
    uint32_t nodes;
    int failed;
    char* err;
    size_t err_cap;
} parser_t;

static void fail(parser_t* p, const char* msg) {
    if (p->failed) return;
    p->failed = 1;
    if (p->err && p->err_cap)
        _snprintf_s(p->err, p->err_cap, _TRUNCATE, "json: %s at byte %zu", msg,
                    p->i);
}

static void skip_ws(parser_t* p) {
    while (p->i < p->n) {
        char c = p->s[p->i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') p->i++;
        else break;
    }
}

static json_value_t* new_value(parser_t* p, json_type_t type) {
    if (p->nodes >= JSON_MAX_NODES) {
        fail(p, "node limit");
        return NULL;
    }
    json_value_t* v = (json_value_t*)calloc(1, sizeof(*v));
    if (!v) {
        fail(p, "out of memory");
        return NULL;
    }
    v->type = type;
    p->nodes++;
    return v;
}

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int read_hex4(parser_t* p, uint32_t* out) {
    if (p->i + 4 > p->n) return -1;
    uint32_t v = 0;
    for (int k = 0; k < 4; k++) {
        int d = hex_digit(p->s[p->i + k]);
        if (d < 0) return -1;
        v = (v << 4) | (uint32_t)d;
    }
    p->i += 4;
    *out = v;
    return 0;
}

static int utf8_put(char* buf, size_t cap, size_t* o, uint32_t cp) {
    if (cp == 0) return -1;
    if (cp < 0x80) {
        if (*o + 1 > cap) return -1;
        buf[(*o)++] = (char)cp;
    } else if (cp < 0x800) {
        if (*o + 2 > cap) return -1;
        buf[(*o)++] = (char)(0xC0 | (cp >> 6));
        buf[(*o)++] = (char)(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        if (*o + 3 > cap) return -1;
        buf[(*o)++] = (char)(0xE0 | (cp >> 12));
        buf[(*o)++] = (char)(0x80 | ((cp >> 6) & 0x3F));
        buf[(*o)++] = (char)(0x80 | (cp & 0x3F));
    } else {
        if (*o + 4 > cap) return -1;
        buf[(*o)++] = (char)(0xF0 | (cp >> 18));
        buf[(*o)++] = (char)(0x80 | ((cp >> 12) & 0x3F));
        buf[(*o)++] = (char)(0x80 | ((cp >> 6) & 0x3F));
        buf[(*o)++] = (char)(0x80 | (cp & 0x3F));
    }
    return 0;
}

static char* parse_string_raw(parser_t* p, size_t* out_len) {
    if (p->i >= p->n || p->s[p->i] != '"') {
        fail(p, "expected string");
        return NULL;
    }
    p->i++;
    size_t cap = p->n - p->i;
    char* buf = (char*)malloc(cap + 1);
    if (!buf) {
        fail(p, "out of memory");
        return NULL;
    }
    size_t o = 0;
    while (p->i < p->n) {
        unsigned char c = (unsigned char)p->s[p->i++];
        if (c == '"') {
            buf[o] = 0;
            *out_len = o;
            return buf;
        }
        if (c < 0x20) {
            fail(p, "control character in string");
            free(buf);
            return NULL;
        }
        if (c != '\\') {
            buf[o++] = (char)c;
            continue;
        }
        if (p->i >= p->n) {
            fail(p, "truncated escape");
            free(buf);
            return NULL;
        }
        char e = p->s[p->i++];
        if (e == '"' || e == '\\' || e == '/') buf[o++] = e;
        else if (e == 'b') buf[o++] = '\b';
        else if (e == 'f') buf[o++] = '\f';
        else if (e == 'n') buf[o++] = '\n';
        else if (e == 'r') buf[o++] = '\r';
        else if (e == 't') buf[o++] = '\t';
        else if (e == 'u') {
            uint32_t cp = 0;
            if (read_hex4(p, &cp) != 0) {
                fail(p, "bad unicode escape");
                free(buf);
                return NULL;
            }
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                if (p->i + 2 > p->n || p->s[p->i] != '\\' ||
                    p->s[p->i + 1] != 'u') {
                    fail(p, "missing low surrogate");
                    free(buf);
                    return NULL;
                }
                p->i += 2;
                uint32_t lo = 0;
                if (read_hex4(p, &lo) != 0 || lo < 0xDC00 || lo > 0xDFFF) {
                    fail(p, "bad low surrogate");
                    free(buf);
                    return NULL;
                }
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                fail(p, "unpaired low surrogate");
                free(buf);
                return NULL;
            }
            if (utf8_put(buf, cap, &o, cp) != 0) {
                fail(p, "unsupported unicode code point");
                free(buf);
                return NULL;
            }
        } else {
            fail(p, "unknown escape");
            free(buf);
            return NULL;
        }
    }
    fail(p, "unterminated string");
    free(buf);
    return NULL;
}

static int obj_add(parser_t* p, json_value_t* v, char* key, json_value_t* val) {
    if (v->u.object.count >= JSON_MAX_MEMBERS) {
        fail(p, "object member limit");
        return -1;
    }
    for (size_t i = 0; i < v->u.object.count; i++) {
        if (strcmp(v->u.object.keys[i], key) == 0) {
            fail(p, "duplicate object key");
            return -1;
        }
    }
    if (v->u.object.count == v->u.object.cap) {
        size_t cap = v->u.object.cap ? v->u.object.cap * 2 : 8;
        char** keys = (char**)realloc(v->u.object.keys, cap * sizeof(*keys));
        if (!keys) {
            fail(p, "out of memory");
            return -1;
        }
        v->u.object.keys = keys;
        json_value_t** vals = (json_value_t**)realloc(
            v->u.object.values, cap * sizeof(*vals));
        if (!vals) {
            fail(p, "out of memory");
            return -1;
        }
        v->u.object.values = vals;
        v->u.object.cap = cap;
    }
    v->u.object.keys[v->u.object.count] = key;
    v->u.object.values[v->u.object.count] = val;
    v->u.object.count++;
    return 0;
}

static int arr_add(parser_t* p, json_value_t* v, json_value_t* item) {
    if (v->u.array.count >= JSON_MAX_MEMBERS) {
        fail(p, "array member limit");
        return -1;
    }
    if (v->u.array.count == v->u.array.cap) {
        size_t cap = v->u.array.cap ? v->u.array.cap * 2 : 8;
        json_value_t** items = (json_value_t**)realloc(
            v->u.array.items, cap * sizeof(*items));
        if (!items) {
            fail(p, "out of memory");
            return -1;
        }
        v->u.array.items = items;
        v->u.array.cap = cap;
    }
    v->u.array.items[v->u.array.count++] = item;
    return 0;
}

static int parse_value(parser_t* p, json_value_t** out, int depth);

static int parse_object(parser_t* p, json_value_t** out, int depth) {
    if (depth > JSON_MAX_DEPTH) {
        fail(p, "depth limit");
        return -1;
    }
    json_value_t* v = new_value(p, JSON_OBJECT);
    if (!v) return -1;
    p->i++; /* { */
    skip_ws(p);
    if (p->i < p->n && p->s[p->i] == '}') {
        p->i++;
        *out = v;
        return 0;
    }
    for (;;) {
        skip_ws(p);
        size_t klen = 0;
        char* key = parse_string_raw(p, &klen);
        if (!key) {
            json_free(v);
            return -1;
        }
        (void)klen;
        skip_ws(p);
        if (p->i >= p->n || p->s[p->i] != ':') {
            fail(p, "expected ':'");
            free(key);
            json_free(v);
            return -1;
        }
        p->i++;
        json_value_t* val = NULL;
        if (parse_value(p, &val, depth + 1) != 0) {
            free(key);
            json_free(v);
            return -1;
        }
        if (obj_add(p, v, key, val) != 0) {
            free(key);
            json_free(val);
            json_free(v);
            return -1;
        }
        skip_ws(p);
        if (p->i < p->n && p->s[p->i] == ',') {
            p->i++;
            continue;
        }
        if (p->i < p->n && p->s[p->i] == '}') {
            p->i++;
            *out = v;
            return 0;
        }
        fail(p, "expected ',' or '}'");
        json_free(v);
        return -1;
    }
}

static int parse_array(parser_t* p, json_value_t** out, int depth) {
    if (depth > JSON_MAX_DEPTH) {
        fail(p, "depth limit");
        return -1;
    }
    json_value_t* v = new_value(p, JSON_ARRAY);
    if (!v) return -1;
    p->i++; /* [ */
    skip_ws(p);
    if (p->i < p->n && p->s[p->i] == ']') {
        p->i++;
        *out = v;
        return 0;
    }
    for (;;) {
        json_value_t* item = NULL;
        if (parse_value(p, &item, depth + 1) != 0) {
            json_free(v);
            return -1;
        }
        if (arr_add(p, v, item) != 0) {
            json_free(item);
            json_free(v);
            return -1;
        }
        skip_ws(p);
        if (p->i < p->n && p->s[p->i] == ',') {
            p->i++;
            continue;
        }
        if (p->i < p->n && p->s[p->i] == ']') {
            p->i++;
            *out = v;
            return 0;
        }
        fail(p, "expected ',' or ']'");
        json_free(v);
        return -1;
    }
}

static int parse_number(parser_t* p, json_value_t** out) {
    size_t start = p->i;
    int is_int = 1;
    if (p->s[p->i] == '-') p->i++;
    if (p->i >= p->n) {
        fail(p, "truncated number");
        return -1;
    }
    if (p->s[p->i] == '0') {
        p->i++;
        if (p->i < p->n && p->s[p->i] >= '0' && p->s[p->i] <= '9') {
            fail(p, "leading zero");
            return -1;
        }
    } else if (p->s[p->i] >= '1' && p->s[p->i] <= '9') {
        while (p->i < p->n && p->s[p->i] >= '0' && p->s[p->i] <= '9') p->i++;
    } else {
        fail(p, "bad number");
        return -1;
    }
    if (p->i < p->n && p->s[p->i] == '.') {
        is_int = 0;
        p->i++;
        if (p->i >= p->n || p->s[p->i] < '0' || p->s[p->i] > '9') {
            fail(p, "bad fraction");
            return -1;
        }
        while (p->i < p->n && p->s[p->i] >= '0' && p->s[p->i] <= '9') p->i++;
    }
    if (p->i < p->n && (p->s[p->i] == 'e' || p->s[p->i] == 'E')) {
        is_int = 0;
        p->i++;
        if (p->i < p->n && (p->s[p->i] == '+' || p->s[p->i] == '-')) p->i++;
        if (p->i >= p->n || p->s[p->i] < '0' || p->s[p->i] > '9') {
            fail(p, "bad exponent");
            return -1;
        }
        while (p->i < p->n && p->s[p->i] >= '0' && p->s[p->i] <= '9') p->i++;
    }

    size_t len = p->i - start;
    if (!len || len >= 64) {
        fail(p, "number too long");
        return -1;
    }
    char tmp[64];
    memcpy(tmp, p->s + start, len);
    tmp[len] = 0;
    json_value_t* v = new_value(p, JSON_NUMBER);
    if (!v) return -1;
    if (is_int) {
        errno = 0;
        long long x = _strtoi64(tmp, NULL, 10);
        if (errno == ERANGE) {
            v->u.number.is_int = 0;
            v->u.number.d = strtod(tmp, NULL);
        } else {
            v->u.number.is_int = 1;
            v->u.number.i = (int64_t)x;
            v->u.number.d = (double)x;
        }
    } else {
        v->u.number.is_int = 0;
        v->u.number.d = strtod(tmp, NULL);
    }
    *out = v;
    return 0;
}

static int parse_literal(parser_t* p, const char* lit, json_type_t type,
                         int boolean, json_value_t** out) {
    size_t len = strlen(lit);
    if (p->i + len > p->n || memcmp(p->s + p->i, lit, len) != 0) {
        fail(p, "bad literal");
        return -1;
    }
    p->i += len;
    json_value_t* v = new_value(p, type);
    if (!v) return -1;
    v->u.boolean = boolean;
    *out = v;
    return 0;
}

static int parse_value(parser_t* p, json_value_t** out, int depth) {
    skip_ws(p);
    if (p->i >= p->n) {
        fail(p, "unexpected end");
        return -1;
    }
    char c = p->s[p->i];
    if (c == '{') return parse_object(p, out, depth);
    if (c == '[') return parse_array(p, out, depth);
    if (c == '"') {
        size_t len = 0;
        char* s = parse_string_raw(p, &len);
        if (!s) return -1;
        json_value_t* v = new_value(p, JSON_STRING);
        if (!v) {
            free(s);
            return -1;
        }
        v->u.string.ptr = s;
        v->u.string.len = len;
        *out = v;
        return 0;
    }
    if (c == 't') return parse_literal(p, "true", JSON_BOOL, 1, out);
    if (c == 'f') return parse_literal(p, "false", JSON_BOOL, 0, out);
    if (c == 'n') return parse_literal(p, "null", JSON_NULL, 0, out);
    if (c == '-' || (c >= '0' && c <= '9')) return parse_number(p, out);
    fail(p, "unknown value");
    return -1;
}

int json_parse(const char* text, size_t len, json_value_t** out, char* err,
               size_t err_cap) {
    if (out) *out = NULL;
    if (err && err_cap) err[0] = 0;
    if (!text || !out) return -1;
    if (len == (size_t)-1) len = strlen(text);
    parser_t p;
    memset(&p, 0, sizeof(p));
    p.s = text;
    p.n = len;
    p.err = err;
    p.err_cap = err_cap;

    json_value_t* v = NULL;
    if (parse_value(&p, &v, 0) != 0) {
        json_free(v);
        if (err && err_cap && !err[0])
            _snprintf_s(err, err_cap, _TRUNCATE, "json: parse failed");
        return -1;
    }
    skip_ws(&p);
    if (p.i != p.n) {
        fail(&p, "trailing data");
        json_free(v);
        return -1;
    }
    *out = v;
    return 0;
}
