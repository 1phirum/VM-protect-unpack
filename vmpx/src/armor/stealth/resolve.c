/* resolve.c - module/export resolution (L1)
 *
 * State (agent image bounds, parent/tool identity, hidden regions) lives in
 * state.c. This file only turns names into addresses.
 */
#include "armor/stealth/stealth.h"

uint8_t* stealth_module_base(const wchar_t* name) {
    HMODULE h = GetModuleHandleW(name);
    return (uint8_t*)h;
}

void* stealth_export(const wchar_t* module, const char* name) {
    HMODULE h = GetModuleHandleW(module);
    if (!h) return NULL;
    return (void*)GetProcAddress(h, name);
}
