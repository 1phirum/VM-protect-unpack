/* h_thread.c - debug-register masking and invisible thread creation */
#include "armor/stealth/stealth.h"

#define ST_ACCESS_DENIED ((LONG)0xC0000022L)

typedef LONG (NTAPI* ntgct_t)(HANDLE, PCONTEXT);
typedef LONG (NTAPI* ntsct_t)(HANDLE, PCONTEXT);
typedef LONG (NTAPI* ntsit_t)(HANDLE, ULONG, PVOID, ULONG);
typedef LONG (NTAPI* ntqit_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI* ntcte_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
                              PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004UL

LONG NTAPI stealth_h_gct(HANDLE thread, PCONTEXT ctx) {
    ntgct_t orig = (ntgct_t)stealth_trampoline(ST_HK_GCT);
    if (!orig) return ST_ACCESS_DENIED;

    LONG st = orig(thread, ctx);
    if (st == 0 && ctx && (ctx->ContextFlags & CONTEXT_DEBUG_REGISTERS)) {
        ctx->Dr0 = 0;
        ctx->Dr1 = 0;
        ctx->Dr2 = 0;
        ctx->Dr3 = 0;
        ctx->Dr6 = 0;
        ctx->Dr7 = 0;
    }
    return st;
}

LONG NTAPI stealth_h_sct(HANDLE thread, PCONTEXT ctx) {
    ntsct_t orig = (ntsct_t)stealth_trampoline(ST_HK_SCT);
    if (!orig) return ST_ACCESS_DENIED;
    /* The target may set its own debug registers.  Leaving the write intact
     * keeps its internal state consistent; the read side is masked above. */
    return orig(thread, ctx);
}

LONG NTAPI stealth_h_sit(HANDLE thread, ULONG cls, PVOID info, ULONG len) {
    ntsit_t orig = (ntsit_t)stealth_trampoline(ST_HK_SIT);
    if (!orig) return ST_ACCESS_DENIED;
    /* ThreadHideFromDebugger must reach the kernel so target threads vanish
     * from a debugger's thread list.  Everything else passes untouched. */
    return orig(thread, cls, info, len);
}

LONG NTAPI stealth_h_qit(HANDLE thread, ULONG cls, PVOID info, ULONG len,
                         PULONG ret) {
    ntqit_t orig = (ntqit_t)stealth_trampoline(ST_HK_QIT);
    if (!orig) return ST_ACCESS_DENIED;
    return orig(thread, cls, info, len, ret);
}

LONG NTAPI stealth_h_ctex(PHANDLE th, ACCESS_MASK access, POBJECT_ATTRIBUTES oa,
                          HANDLE proc, PVOID start, PVOID arg, ULONG flags,
                          SIZE_T zero, SIZE_T stack, SIZE_T max_stack,
                          PVOID attr) {
    ntcte_t orig = (ntcte_t)stealth_trampoline(ST_HK_CTX);
    if (!orig) return ST_ACCESS_DENIED;

    ULONG hidden_flags = flags | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
    LONG st = orig(th, access, oa, proc, start, arg, hidden_flags, zero,
                   stack, max_stack, attr);
    if (st < 0 && !(flags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER))
        st = orig(th, access, oa, proc, start, arg, flags, zero,
                  stack, max_stack, attr);
    return st;
}
