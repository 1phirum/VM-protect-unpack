/* hook.c - one relative-jump inline hook with a copied-stub thunk (L1)
 *
 * The thunk copies 48 bytes of the original ntdll stub, not just the five that
 * are overwritten: NtQueryInformationProcess on Windows 11 carries a longer
 * syscall stub with a self-relative call and a fallback branch inside the first
 * 41 bytes. A 16-byte copy would execute zero padding when called through.
 */
#include "armor/anti/anti.h"

#define THUNK_HEAD_COPY 48
#define THUNK_ALLOC     96

int anti_hook_patch(void* target, void* handler, void** thunk_out) {
    if (!target || !handler || !thunk_out) return -1;
    *thunk_out = NULL;

    uint8_t* fn = (uint8_t*)target;
    if (fn[0] != 0xB8) return -1;                  /* not a mov eax,ssn stub */

    void* thunk = VirtualAlloc(NULL, THUNK_ALLOC, MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    if (!thunk) return -1;
    memcpy(thunk, fn, THUNK_HEAD_COPY);
    *thunk_out = thunk;                            /* live before the patch */

    DWORD old = 0;
    if (!VirtualProtect(fn, 8, PAGE_EXECUTE_READWRITE, &old)) {
        VirtualFree(thunk, 0, MEM_RELEASE);
        *thunk_out = NULL;
        return -1;
    }

    intptr_t delta = (intptr_t)handler - (intptr_t)(fn + 5);
    if (delta < INT32_MIN || delta > INT32_MAX) {
        VirtualProtect(fn, 8, old, &old);
        VirtualFree(thunk, 0, MEM_RELEASE);
        *thunk_out = NULL;
        return -1;
    }
    int32_t rel = (int32_t)delta;
    fn[0] = 0xE9;
    *(int32_t*)(fn + 1) = rel;
    FlushInstructionCache(GetCurrentProcess(), fn, 5);

    DWORD tmp = 0;
    VirtualProtect(fn, 8, old, &tmp);
    return 0;
}
