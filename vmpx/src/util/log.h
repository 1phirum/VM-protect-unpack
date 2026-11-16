/* log.h - allocation-free line logging used by the in-process agent (L0) */
#pragma once

#include <windows.h>
#include <stdint.h>

HANDLE log_open_append_next_to(HMODULE self, const wchar_t* relpath);
void   log_text(HANDLE h, const char* text);
void   log_hex(HANDLE h, const char* prefix, uint32_t a, uint32_t b);
