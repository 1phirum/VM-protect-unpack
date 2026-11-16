/* handlers.c - neutralization handlers behind the ntdll hooks (L1) */
#include "armor/anti/anti.h"

#define VMPX_STATUS_PORT_NOT_SET ((LONG)0xC0000353L)

#define CLS_PROCESS_DEBUG_PORT       7
#define CLS_PROCESS_DEBUG_OBJECT     0x1E
#define CLS_PROCESS_DEBUG_FLAGS      0x1F
#define CLS_SYSTEM_KD_DEBUGGER       0x23
#define CLS_THREAD_HIDE_FROM_DEBUG   0x11

typedef LONG (NTAPI* ntqip_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI* ntqsi_t)(ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI* ntsit_t)(HANDLE, ULONG, PVOID, ULONG);
typedef LONG (NTAPI* ntgct_t)(HANDLE, PCONTEXT);
typedef LONG (NTAPI* ntsct_t)(HANDLE, PCONTEXT);
typedef LONG (NTAPI* ntqvm_t)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
typedef LONG (NTAPI* ntpvm_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef LONG (NTAPI* ntqpc_t)(PLARGE_INTEGER, PLARGE_INTEGER);

typedef struct {
    BOOLEAN DebuggerEnabled;
    BOOLEAN DebuggerNotPresent;
} kdinfo_t;

LONG NTAPI anti_h_qip(HANDLE proc, ULONG cls, PVOID info, ULONG len, PULONG ret) {
    ntqip_t orig = (ntqip_t)anti_thunk(ANTI_HK_QIP);
    switch (cls) {
    case CLS_PROCESS_DEBUG_PORT:
        if (info && len >= sizeof(ULONG)) *(ULONG*)info = 0;
        if (ret) *ret = sizeof(ULONG);
        return 0;
    case CLS_PROCESS_DEBUG_OBJECT:
        if (info && len >= sizeof(ULONG)) *(ULONG*)info = 0;
        if (ret) *ret = sizeof(ULONG);
        return VMPX_STATUS_PORT_NOT_SET;
    case CLS_PROCESS_DEBUG_FLAGS:
        if (info && len >= sizeof(ULONG)) *(ULONG*)info = 1;
        if (ret) *ret = sizeof(ULONG);
        return 0;
    default:
        return orig ? orig(proc, cls, info, len, ret) : VMPX_STATUS_PORT_NOT_SET;
    }
}

LONG NTAPI anti_h_qsi(ULONG cls, PVOID info, ULONG len, PULONG ret) {
    ntqsi_t orig = (ntqsi_t)anti_thunk(ANTI_HK_QSI);
    if (cls == CLS_SYSTEM_KD_DEBUGGER) {
        if (info && len >= sizeof(kdinfo_t)) {
            kdinfo_t* kd = (kdinfo_t*)info;
            kd->DebuggerEnabled = FALSE;
            kd->DebuggerNotPresent = TRUE;
        }
        if (ret) *ret = sizeof(kdinfo_t);
        return 0;
    }
    return orig ? orig(cls, info, len, ret) : VMPX_STATUS_PORT_NOT_SET;
}

LONG NTAPI anti_h_sit(HANDLE thread, ULONG cls, PVOID info, ULONG len) {
    ntsit_t orig = (ntsit_t)anti_thunk(ANTI_HK_SIT);
    if (cls == CLS_THREAD_HIDE_FROM_DEBUG) return 0;
    return orig ? orig(thread, cls, info, len) : VMPX_STATUS_PORT_NOT_SET;
}

LONG NTAPI anti_h_gct(HANDLE thread, PCONTEXT ctx) {
    ntgct_t orig = (ntgct_t)anti_thunk(ANTI_HK_GCT);
    if (!orig) return VMPX_STATUS_PORT_NOT_SET;
    LONG st = orig(thread, ctx);
    if (st == 0 && ctx && (ctx->ContextFlags & CONTEXT_DEBUG_REGISTERS)) {
        ctx->Dr0 = ctx->Dr1 = ctx->Dr2 = ctx->Dr3 = 0;
        ctx->Dr6 = ctx->Dr7 = 0;
    }
    return st;
}

LONG NTAPI anti_h_sct(HANDLE thread, PCONTEXT ctx) {
    ntsct_t orig = (ntsct_t)anti_thunk(ANTI_HK_SCT);
    if (!orig) return VMPX_STATUS_PORT_NOT_SET;
    if (!ctx) return orig(thread, ctx);
    CONTEXT local = *ctx;
    if (local.ContextFlags & CONTEXT_DEBUG_REGISTERS) {
        local.Dr0 = local.Dr1 = local.Dr2 = local.Dr3 = 0;
        local.Dr6 = local.Dr7 = 0;
    }
    return orig(thread, &local);
}

LONG NTAPI anti_h_qvm(HANDLE proc, PVOID addr, ULONG cls, PVOID info,
                      SIZE_T len, PSIZE_T ret) {
    ntqvm_t orig = (ntqvm_t)anti_thunk(ANTI_HK_QVM);
    return orig ? orig(proc, addr, cls, info, len, ret) : VMPX_STATUS_PORT_NOT_SET;
}

LONG NTAPI anti_h_pvm(HANDLE proc, PVOID* addr, PSIZE_T size, ULONG prot, PULONG old) {
    ntpvm_t orig = (ntpvm_t)anti_thunk(ANTI_HK_PVM);
    return orig ? orig(proc, addr, size, prot, old) : VMPX_STATUS_PORT_NOT_SET;
}

LONG NTAPI anti_h_qpc(PLARGE_INTEGER counter, PLARGE_INTEGER freq) {
    ntqpc_t orig = (ntqpc_t)anti_thunk(ANTI_HK_QPC);
    return orig ? orig(counter, freq) : VMPX_STATUS_PORT_NOT_SET;
}
