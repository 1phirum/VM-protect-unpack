/* json.h - bounded JSON parser and path access for profiles and manifests
 *
 * Supported: null, bool, number, string, array, object. Depth is capped at 32
 * and the tree at 8192 values. Duplicate object keys, trailing bytes, control
 * characters in strings, and embedded U+0000 are rejected. Object keys are
 * NUL-terminated; json_get() treats '.' as a path separator and a decimal
 * segment as an array index, so keys containing dots are not addressable.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef enum {
    JSON_NULL = 0,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type_t;

typedef struct json_value json_value_t;

int   json_parse(const char* text, size_t len, json_value_t** out,
                 char* err, size_t err_cap);
void  json_free(json_value_t* v);

json_type_t json_kind(const json_value_t* v);
const json_value_t* json_get(const json_value_t* root, const char* path);
const char* json_string(const json_value_t* v);
size_t      json_string_len(const json_value_t* v);
int         json_int(const json_value_t* v, int64_t* out);
int         json_bool(const json_value_t* v, int* out);
size_t      json_count(const json_value_t* v);
const json_value_t* json_at(const json_value_t* v, size_t index);
const char* json_key(const json_value_t* v, size_t index);

int   json_write_string(FILE* f, const char* s);
