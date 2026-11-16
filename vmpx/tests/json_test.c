/* json_test.c - parser, path access, rejection and string emission */
#include "util/json.h"
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond) do {                                              \
    if (!(cond)) {                                                    \
        printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);         \
        failures++;                                                   \
    }                                                                 \
} while (0)

static void expect_fail(const char* text) {
    json_value_t* v = NULL;
    char err[256];
    CHECK(json_parse(text, strlen(text), &v, err, sizeof(err)) != 0);
    CHECK(v == NULL);
    CHECK(err[0] != 0);
    json_free(v);
}

int main(void) {
    const char* text =
        "{\"schema_version\":1,\"arch\":\"x86\",\"nested\":{\"a\":true,"
        "\"b\":[1,2,3]},\"s\":\"a\\\"b\\n\\u0041\",\"emoji\":\"\\uD83D\\uDE00\"}";
    json_value_t* root = NULL;
    char err[256];
    CHECK(json_parse(text, strlen(text), &root, err, sizeof(err)) == 0);
    CHECK(root && json_kind(root) == JSON_OBJECT);
    CHECK(json_count(root) == 5);

    int64_t n = 0;
    CHECK(json_int(json_get(root, "schema_version"), &n) == 0 && n == 1);
    CHECK(strcmp(json_string(json_get(root, "arch")), "x86") == 0);
    int b = 0;
    CHECK(json_bool(json_get(root, "nested.a"), &b) == 0 && b == 1);
    CHECK(json_count(json_get(root, "nested.b")) == 3);
    CHECK(json_int(json_at(json_get(root, "nested.b"), 2), &n) == 0 && n == 3);
    CHECK(json_at(json_get(root, "nested.b"), 3) == NULL);
    CHECK(json_get(root, "nested.b.1") != NULL);
    CHECK(json_get(root, "nested.b.4") == NULL);
    CHECK(json_get(root, "nested.missing") == NULL);

    const char* s = json_string(json_get(root, "s"));
    CHECK(s && strcmp(s, "a\"b\nA") == 0);
    CHECK(json_string_len(json_get(root, "emoji")) == 4);
    CHECK(json_string(json_get(root, "missing")) == NULL);

    CHECK(json_int(json_get(root, "arch"), &n) != 0);
    CHECK(json_bool(json_get(root, "schema_version"), &b) != 0);

    expect_fail("{\"a\":1,\"a\":2}");
    expect_fail("{\"a\":1} trailing");
    expect_fail("{\"a\":01}");
    expect_fail("{\"a\":1,}");
    expect_fail("[1,2,]");
    expect_fail("{\"a\":\"\\u0000\"}");
    expect_fail("{\"a\":\"\\uD800\"}");
    expect_fail("{\"a\":\"\\q\"}");
    expect_fail("{\"a\":1} // comment");
    expect_fail("[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]");

    json_value_t* big = NULL;
    const char* big_text = "{\"x\":9223372036854775808}";
    CHECK(json_parse(big_text, strlen(big_text), &big, err,
                     sizeof(err)) == 0);
    CHECK(json_int(json_get(big, "x"), &n) != 0);
    json_free(big);

    json_free(root);
    if (failures) {
        printf("json_test: %d failure(s)\n", failures);
        return 1;
    }
    printf("json_test: ok\n");
    return 0;
}
