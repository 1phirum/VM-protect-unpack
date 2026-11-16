/* hook.c - instruction-safe inline hook engine (L1)
 *
 * The engine copies whole prologue instructions, not a fixed byte count. That
 * keeps the trampoline valid on ntdll syscall stubs (mov eax,ssn), hotpatch
 * prologues (mov edi,edi; push ebp; mov ebp,esp), and forwarder exports.
 * Relative branches in the copied head are rejected rather than relocated:
 * every hooked function here has a straight-line prologue.
 */
#include "armor/stealth/stealth.h"

static int modrm_len(const uint8_t* p) {
    int i = 0;
    uint8_t m = p[i++];
    int mod = m >> 6;
    int rm = m & 7;
    if (mod == 3) return i;
    if (rm == 4) {
        uint8_t sib = p[i++];
        if (mod == 0 && (sib & 7) == 5) i += 4;
    } else if (mod == 0 && rm == 5) {
        i += 4;
    }
    if (mod == 1) i += 1;
    else if (mod == 2) i += 4;
    return i;
}

/* Length of one x86 instruction, or -1. Covers the prologue grammar used by
 * ntdll, kernel32 and user32 stubs; unknown opcodes abort the hook instead of
 * guessing. */
static int insn_len(const uint8_t* p) {
    int i = 0;
    while (i < 4) {
        uint8_t b = p[i];
        if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65 || b == 0x66 || b == 0x67) { i++; continue; }
        break;
    }

    uint8_t op = p[i++];
    if (op >= 0x50 && op <= 0x5F) return i;
    if (op == 0x90 || op == 0xCC || op == 0xC3 || op == 0xCB ||
        op == 0xC9 || op == 0xF4 || op == 0xF5 || op == 0xFC || op == 0xFD ||
        op == 0xF8 || op == 0xF9 || op == 0x9C || op == 0x9D) return i;
    if (op >= 0xB0 && op <= 0xB7) return i + 1;
    if (op >= 0xB8 && op <= 0xBF) return i + 4;
    if (op == 0x6A) return i + 1;
    if (op == 0x68) return i + 4;
    if (op == 0xE8 || op == 0xE9) return i + 4;
    if (op == 0xEB || (op >= 0x70 && op <= 0x7F) ||
        op == 0xE0 || op == 0xE1 || op == 0xE2 || op == 0xE3) return i + 1;
    if (op == 0xA8) return i + 1;
    if (op == 0xA9) return i + 4;
    if (op >= 0xA0 && op <= 0xA3) return i + 4;
    if (op == 0xC2 || op == 0xCA) return i + 2;
    if (op == 0xCD) return i + 1;
    if (op == 0x0F) {
        uint8_t op2 = p[i++];
        if (op2 >= 0x80 && op2 <= 0x8F) return i + 4;
        if (op2 == 0x05 || op2 == 0x34 || op2 == 0x35) return i;
        if (op2 == 0x0B || op2 == 0xA2 || op2 == 0x31 || op2 == 0x30 ||
            op2 == 0x1F || op2 == 0x18 || op2 == 0x19 || op2 == 0x1A ||
            op2 == 0x1B || op2 == 0xAF || op2 == 0xA3 || op2 == 0xAB ||
            op2 == 0xB3 || op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE ||
            op2 == 0xBF || op2 == 0xBC || op2 == 0xBD || op2 == 0x40 ||
            op2 == 0x41 || op2 == 0x42 || op2 == 0x43 || op2 == 0x44 ||
            op2 == 0x45 || op2 == 0x46 || op2 == 0x47 || op2 == 0x48 ||
            op2 == 0x49 || op2 == 0x4A || op2 == 0x4B || op2 == 0x4C ||
            op2 == 0x4D || op2 == 0x4E || op2 == 0x4F)
            return i + modrm_len(p + i);
        return -1;
    }
    if (op == 0xFF) return i + modrm_len(p + i);
    if (op == 0x80 || op == 0x83) return i + modrm_len(p + i) + 1;
    if (op == 0x81 || op == 0xC7) return i + modrm_len(p + i) + 4;
    if (op == 0xC6) return i + modrm_len(p + i) + 1;
    if (op == 0x69) return i + modrm_len(p + i) + 4;
    if (op == 0x6B) return i + modrm_len(p + i) + 1;
    if (op == 0xF6) {
        int m = modrm_len(p + i);
        uint8_t mrm = p[i];
        return i + m + (((mrm >> 3) & 7) <= 1 ? 1 : 0);
    }
    if (op == 0xF7) {
        int m = modrm_len(p + i);
        uint8_t mrm = p[i];
        return i + m + (((mrm >> 3) & 7) <= 1 ? 4 : 0);
    }

    static const uint8_t modrm_ops[] = {
        0x01, 0x03, 0x09, 0x0B, 0x11, 0x13, 0x19, 0x1B, 0x21, 0x23, 0x29,
        0x2B, 0x31, 0x33, 0x39, 0x3B, 0x63, 0x84, 0x85, 0x86, 0x87, 0x88,
        0x89, 0x8A, 0x8B, 0x8D, 0x8F
    };
    for (size_t k = 0; k < sizeof(modrm_ops); k++)
        if (op == modrm_ops[k]) return i + modrm_len(p + i);

    return -1;
}

static int is_rel_branch(const uint8_t* p) {
    if (p[0] == 0xE8 || p[0] == 0xE9 || p[0] == 0xEB) return 1;
    if (p[0] >= 0x70 && p[0] <= 0x7F) return 1;
    if (p[0] == 0x0F && p[1] >= 0x80 && p[1] <= 0x8F) return 1;
    return 0;
}

static int prologue_len(const uint8_t* p) {
    int i = 0;
    while (i < 12) {
        if (is_rel_branch(p + i)) return -1;
        int n = insn_len(p + i);
        if (n <= 0) return -1;
        i += n;
        if (i >= 5) return i;
    }
    return -1;
}

static uint8_t* follow_thunk(uint8_t* fn) {
    for (int depth = 0; depth < 4; depth++) {
        if (fn[0] == 0xE9) {
            int32_t rel = *(int32_t*)(fn + 1);
            fn = fn + 5 + rel;
        } else if (fn[0] == 0xEB) {
            int8_t rel = *(int8_t*)(fn + 1);
            fn = fn + 2 + rel;
        } else if (fn[0] == 0xFF && fn[1] == 0x25) {
            /* x86: FF 25 imm32 is jmp dword ptr [imm32]. The immediate is
             * the IAT slot address; the call target lives at that slot. */
            uint32_t slot = *(uint32_t*)(fn + 2);
            fn = *(uint8_t**)(uintptr_t)slot;
        } else {
            break;
        }
    }
    return fn;
}

int stealth_hook_install(stealth_hook_t* hook, const wchar_t* module,
                         const char* name, void* handler, const char* label) {
    if (!hook || !module || !name || !handler) return -1;
    memset(hook, 0, sizeof(*hook));
    hook->label = label;

    uint8_t* fn = (uint8_t*)stealth_export(module, name);
    if (!fn) return -1;
    fn = follow_thunk(fn);

    int len = prologue_len(fn);
    if (len < 5 || len > 16) return -1;

    uint8_t* thunk = (uint8_t*)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE,
                                            PAGE_EXECUTE_READWRITE);
    if (!thunk) return -1;

    memcpy(thunk, fn, (size_t)len);
    intptr_t back = (intptr_t)(fn + len) - (intptr_t)(thunk + len + 5);
    if (back < INT32_MIN || back > INT32_MAX) {
        VirtualFree(thunk, 0, MEM_RELEASE);
        return -1;
    }
    thunk[len] = 0xE9;
    *(int32_t*)(thunk + len + 1) = (int32_t)back;

    DWORD old = 0;
    if (!VirtualProtect(thunk, 64, PAGE_EXECUTE_READ, &old)) {
        VirtualFree(thunk, 0, MEM_RELEASE);
        return -1;
    }

    if (!VirtualProtect(fn, (SIZE_T)len, PAGE_EXECUTE_READWRITE, &old)) {
        VirtualFree(thunk, 0, MEM_RELEASE);
        return -1;
    }

    intptr_t delta = (intptr_t)handler - (intptr_t)(fn + 5);
    if (delta < INT32_MIN || delta > INT32_MAX) {
        DWORD tmp = 0;
        VirtualProtect(fn, (SIZE_T)len, old, &tmp);
        VirtualFree(thunk, 0, MEM_RELEASE);
        return -1;
    }

    memcpy(hook->original, fn, (size_t)len);
    hook->target = fn;
    hook->trampoline = thunk;
    hook->copy_len = (uint32_t)len;
    hook->patch_len = (uint32_t)len;

    memset(fn, 0x90, (size_t)len);
    fn[0] = 0xE9;
    *(int32_t*)(fn + 1) = (int32_t)delta;
    FlushInstructionCache(GetCurrentProcess(), fn, (SIZE_T)len);

    DWORD tmp = 0;
    VirtualProtect(fn, (SIZE_T)len, old, &tmp);
    hook->active = 1;
    return 0;
}
