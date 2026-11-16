/* str.h - narrow/wide conversion and leaf-name helpers (L0) */
#pragma once

#include <stddef.h>
#include <wchar.h>

int         str_i_contains(const char* hay, const char* needle);
const wchar_t* str_wide_leaf(const wchar_t* path);
int         str_widen(const char* src, wchar_t* out, size_t cap);
int         str_narrow(const wchar_t* src, char* out, size_t cap);
int         str_narrow_leaf(const wchar_t* src, char* out, size_t cap);
