/* peb_modules.h - module enumeration through the target's PEB loader list */
#pragma once

#include "vmpx.h"
#include <windows.h>

int vmpx_peb_modules(HANDLE proc, uint32_t pid, proc_mod_t* out, int cap);
