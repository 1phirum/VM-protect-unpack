/* armor/anti/anti.h - in-process anti-debug neutralization internals (L1) */
#pragma once

#include <windows.h>
#include <stdint.h>

#define ANTI_HOOK_COUNT 8

enum {
    ANTI_HK_QIP = 0,
    ANTI_HK_QSI,
    ANTI_HK_SIT,
    ANTI_HK_GCT,
    ANTI_HK_SCT,
    ANTI_HK_QVM,
    ANTI_HK_PVM,
    ANTI_HK_QPC
};

/* loader-free ntdll resolution */
uint8_t* anti_find_ntdll(void);
void*    anti_export_by_name(uint8_t* base, const char* name);

/* patch one stub, copy its head into an executable thunk */
int anti_hook_patch(void* target, void* handler, void** thunk_out);

/* install table and status */
int         anti_install(void);
int         anti_hook_count(void);
int         anti_hook_fail_count(void);
const char* anti_hook_name(int index);
void*       anti_thunk(int index);
