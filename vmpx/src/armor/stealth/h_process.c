/* h_process.c - process/thread information filters */
#include "armor/stealth/stealth.h"

#define ST_PORT_NOT_SET       ((LONG)0xC0000353L)
#define ST_INFO_LEN_MISMATCH  ((LONG)0xC0000004L)

typedef LONG (NTAPI* ntqip_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef struct {
    LONG     ExitStatus;
    uint32_t PebBaseAddress;
    uint32_t AffinityMask;
    LONG     BasePriority;
    uint32_t UniqueProcessId;
    uint32_t InheritedFromUniqueProcessId;
} pbi32_t;

static LONG write_ulong(PVOID info, ULONG len, PULONG ret, ULONG v) {
    if (ret) *ret = sizeof(ULONG);
    if (!info || len < sizeof(ULONG)) return ST_INFO_LEN_MISMATCH;
    *(ULONG*)info = v;
    return 0;
}

LONG NTAPI stealth_h_qip(HANDLE proc, ULONG cls, PVOID info, ULONG len, PULONG ret) {
    ntqip_t orig = (ntqip_t)stealth_trampoline(ST_HK_QIP);
    if (!orig) return ST_PORT_NOT_SET;

    switch (cls) {
    case 0: {                                  /* ProcessBasicInformation */
        LONG st = orig(proc, cls, info, len, ret);
        if (st == 0 && info && len >= sizeof(pbi32_t) && stealth_parent())
            ((pbi32_t*)info)->InheritedFromUniqueProcessId = stealth_parent();
        return st;
    }
    case 7:                                    /* ProcessDebugPort */
        return write_ulong(info, len, ret, 0);
    case 0x1D:                                 /* ProcessBreakOnTermination */
        return write_ulong(info, len, ret, 0);
    case 0x1E:                                 /* ProcessDebugObjectHandle */
        if (info && len >= sizeof(ULONG)) *(ULONG*)info = 0;
        if (ret) *ret = sizeof(ULONG);
        return ST_PORT_NOT_SET;
    case 0x1F:                                 /* ProcessDebugFlags */
        return write_ulong(info, len, ret, 1);
    default:
        return orig(proc, cls, info, len, ret);
    }
}


