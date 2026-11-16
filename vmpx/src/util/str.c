/* str.c - narrow/wide conversion and leaf-name helpers (L0) */
#include "util/str.h"
#include <windows.h>
#include <ctype.h>
#include <string.h>

int str_i_contains(const char* hay, const char* needle) {
    if (!hay || !needle || !*needle) return 1;
    size_t n = strlen(needle);
    for (const char* p = hay; *p; p++) {
        size_t i = 0;
        while (i < n && p[i] &&
               tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i]))
            i++;
        if (i == n) return 1;
    }
    return 0;
}

const wchar_t* str_wide_leaf(const wchar_t* path) {
    if (!path) return L"";
    const wchar_t* slash = wcsrchr(path, L'\\');
    return slash ? slash + 1 : path;
}

int str_widen(const char* src, wchar_t* out, size_t cap) {
    if (!src || !*src || !out || cap == 0) return -1;
    if (!(size_t)MultiByteToWideChar(CP_UTF8, 0, src, -1, out, (int)cap)) return -1;
    return 0;
}

int str_narrow(const wchar_t* src, char* out, size_t cap) {
    if (!src || !out || cap == 0) return -1;
    out[0] = 0;
    if (!(size_t)WideCharToMultiByte(CP_UTF8, 0, src, -1, out, (int)cap, NULL, NULL))
        return -1;
    return 0;
}

int str_narrow_leaf(const wchar_t* src, char* out, size_t cap) {
    if (!src || !out || cap == 0) return -1;
    return str_narrow(str_wide_leaf(src), out, cap);
}
