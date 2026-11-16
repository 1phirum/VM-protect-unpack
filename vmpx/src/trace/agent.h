/* trace/agent.h - in-process bootstrap pieces (L1) */
#pragma once

#include <windows.h>
#include <stdint.h>

unsigned trace_clean_peb(void);
int      trace_unlink_self(HMODULE self);
void     trace_publish_status(uint32_t pid, uint32_t peb, int hidden,
                              int hooks, int fail, uint32_t parent,
                              uint32_t tool, int under_debug);
void     trace_set_hidden(uint32_t pid, int hidden);
HANDLE   trace_log_open(HMODULE self, const wchar_t* relpath);
