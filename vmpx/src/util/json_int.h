/* json_int.h - private JSON tree layout */
#pragma once

#include "util/json.h"

struct json_value {
    json_type_t type;
    union {
        int boolean;
        struct {
            double d;
            int64_t i;
            int is_int;
        } number;
        struct {
            char* ptr;
            size_t len;
        } string;
        struct {
            json_value_t** items;
            size_t count;
            size_t cap;
        } array;
        struct {
            char** keys;
            json_value_t** values;
            size_t count;
            size_t cap;
        } object;
    } u;
};
