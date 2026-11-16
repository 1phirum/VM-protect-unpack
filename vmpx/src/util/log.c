/* log.c - allocation-free line logging used by the in-process agent (L0) */
#include "util/log.h"
#include <string.h>

HANDLE log_open_append_next_to(HMODULE self, const wchar_t* relpath) {
    wchar_t path[MAX_PATH] = { 0 };
    if (!GetModuleFileNameW(self, path, MAX_PATH)) return NULL;
    wchar_t* slash = wcsrchr(path, L'\\');
    if (!slash || !relpath) return NULL;
    slash[1] = 0;
    if (wcslen(path) + wcslen(relpath) + 1 >= MAX_PATH) return NULL;
    wcscat_s(path, MAX_PATH, relpath);
    return CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

void log_text(HANDLE h, const char* text) {
    if (!h || h == INVALID_HANDLE_VALUE || !text) return;
    DWORD wrote = 0;
    WriteFile(h, text, (DWORD)strlen(text), &wrote, NULL);
}

static void append_hex(uint32_t v, char* out) {
    static const char* digits = "0123456789ABCDEF";
    for (int i = 0; i < 8; i++) out[i] = digits[(v >> (28 - i * 4)) & 0xF];
}

void log_hex(HANDLE h, const char* prefix, uint32_t a, uint32_t b) {
    if (!h || h == INVALID_HANDLE_VALUE || !prefix) return;
    char line[192];
    size_t n = 0;
    while (prefix[n] && n < sizeof(line) - 24) {
        line[n] = prefix[n];
        n++;
    }
    line[n++] = ' ';
    append_hex(a, line + n);
    n += 8;
    line[n++] = ' ';
    append_hex(b, line + n);
    n += 8;
    line[n++] = '\n';
    DWORD wrote = 0;
    WriteFile(h, line, (DWORD)n, &wrote, NULL);
}
