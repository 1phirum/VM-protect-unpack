/* debug.c - first-chance tracing for a restored child */
#include "unpack/snapshot/snapshot_int.h"

int snap_debug_enabled(void) {
    char buf[8];
    size_t n = 0;
    if (getenv_s(&n, buf, sizeof(buf), "VMPX_RUN_DEBUG") != 0 || n == 0) return 0;
    return buf[0] != '0';
}

static void print_protect(HANDLE proc, uint32_t addr, const char* what) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(proc, (LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi)) == 0) {
        printf("[dbg] %s=0x%08lX unmapped\n", what, (unsigned long)addr);
        return;
    }
    printf("[dbg] %s=0x%08lX base=0x%08lX size=0x%08lX protect=0x%lX state=0x%lX\n",
           what, (unsigned long)addr,
           (unsigned long)(uintptr_t)mbi.BaseAddress,
           (unsigned long)mbi.RegionSize,
           (unsigned long)mbi.Protect, (unsigned long)mbi.State);
}

/* A protected image can decrypt its dispatch stubs after the entry point and
 * carry absolute addresses captured from the original process. If the child
 * loaded the same module at a different base, translate the stale execute
 * target to the child's copy of that module. */
static uint32_t translate_eip(HANDLE proc, uint32_t eip,
                              const uint32_t* orig_base,
                              const uint32_t* orig_size,
                              const uint32_t* child_base,
                              uint32_t module_count) {
    printf("[dbg] translate eip=0x%08lX modules=%lu\n",
           (unsigned long)eip, (unsigned long)module_count);
    for (uint32_t i = 0; i < module_count; i++) {
        if (!orig_size[i]) continue;
        if (eip < orig_base[i] || eip >= orig_base[i] + orig_size[i])
            continue;
        uint32_t child = child_base[i];
        printf("[dbg] translate match orig=0x%08lX size=0x%08lX "
               "child=0x%08lX\n",
               (unsigned long)orig_base[i], (unsigned long)orig_size[i],
               (unsigned long)child);
        if (!child || child == orig_base[i]) return 0;
        uint32_t t = child + (eip - orig_base[i]);
        MEMORY_BASIC_INFORMATION mbi;
        memset(&mbi, 0, sizeof(mbi));
        if (!VirtualQueryEx(proc, (LPCVOID)(uintptr_t)t, &mbi, sizeof(mbi))) {
            printf("[dbg] translate query failed %lu\n", GetLastError());
            return 0;
        }
        printf("[dbg] translate target=0x%08lX state=0x%lX prot=0x%lX\n",
               (unsigned long)t, (unsigned long)mbi.State,
               (unsigned long)mbi.Protect);
        if (mbi.State != MEM_COMMIT) return 0;
        DWORD p = mbi.Protect & 0xFF;
        if (p != PAGE_EXECUTE && p != PAGE_EXECUTE_READ &&
            p != PAGE_EXECUTE_READWRITE && p != PAGE_EXECUTE_WRITECOPY)
            return 0;
        return t;
    }
    return 0;
}

/* The target keeps a valid SEH chain, so the interesting event is the first
 * execute fault: the CPU jumped to an address that is not backed by an image.
 * Capture the exact register file and stack, then stop before WER folds it
 * into a second-chance dump. */
void snap_debug_run(uint32_t pid, HANDLE proc, const uint32_t* orig_base,
                    const uint32_t* orig_size, const uint32_t* child_base,
                    uint32_t module_count, vmpx_run_result_t* result) {
    if (result) {
        result->pid = pid;
        result->debug_assist = 1;
    }
    uint64_t start = GetTickCount64();
    uint32_t avs = 0;
    for (;;) {
        if (GetTickCount64() - start > 30000) {
            printf("[dbg] timeout; stopping process\n");
            if (result) result->timed_out = 1;
            TerminateProcess(proc, 0xDEAD);
            break;
        }
        DEBUG_EVENT de;
        if (!WaitForDebugEvent(&de, 250)) continue;

        DWORD cont = DBG_CONTINUE;
        if (de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            if (de.u.CreateProcessInfo.hFile)
                CloseHandle(de.u.CreateProcessInfo.hFile);
        } else if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            EXCEPTION_DEBUG_INFO* x = &de.u.Exception;
            DWORD code = x->ExceptionRecord.ExceptionCode;
            uint32_t addr = (uint32_t)(uintptr_t)x->ExceptionRecord.ExceptionAddress;
            if (code == EXCEPTION_BREAKPOINT) {
                cont = DBG_CONTINUE;
            } else {
                HANDLE th = OpenThread(THREAD_GET_CONTEXT |
                                           THREAD_SET_CONTEXT |
                                           THREAD_QUERY_INFORMATION,
                                       FALSE, de.dwThreadId);
                CONTEXT ctx;
                memset(&ctx, 0, sizeof(ctx));
                ctx.ContextFlags = CONTEXT_FULL;
                int have = th && GetThreadContext(th, &ctx);
                printf("[dbg] exception code=0x%08lX first=%d addr=0x%08lX tid=%lu\n",
                       (unsigned long)code, x->dwFirstChance ? 1 : 0,
                       (unsigned long)addr, (unsigned long)de.dwThreadId);
                if (code == EXCEPTION_ACCESS_VIOLATION) {
                    avs++;
                    printf("[dbg] av op=%llu target=0x%08llX\n",
                           (unsigned long long)x->ExceptionRecord.ExceptionInformation[0],
                           (unsigned long long)x->ExceptionRecord.ExceptionInformation[1]);
                    print_protect(proc, addr, "eip");
                    print_protect(proc,
                                  (uint32_t)x->ExceptionRecord.ExceptionInformation[1],
                                  "target");
                }
                if (have) {
                    printf("[dbg] eip=%08lX esp=%08lX ebp=%08lX eax=%08lX "
                           "ebx=%08lX ecx=%08lX edx=%08lX esi=%08lX edi=%08lX\n",
                           (unsigned long)ctx.Eip, (unsigned long)ctx.Esp,
                           (unsigned long)ctx.Ebp, (unsigned long)ctx.Eax,
                           (unsigned long)ctx.Ebx, (unsigned long)ctx.Ecx,
                           (unsigned long)ctx.Edx, (unsigned long)ctx.Esi,
                           (unsigned long)ctx.Edi);
                    uint8_t bytes[32];
                    SIZE_T got = 0;
                    if (ReadProcessMemory(proc, (LPCVOID)(uintptr_t)ctx.Eip,
                                          bytes, sizeof(bytes), &got) && got) {
                        printf("[dbg] code:");
                        for (SIZE_T i = 0; i < got; i++) printf(" %02X", bytes[i]);
                        printf("\n");
                    }
                    uint32_t st[256];
                    got = 0;
                    if (ReadProcessMemory(proc, (LPCVOID)(uintptr_t)ctx.Esp,
                                          st, sizeof(st), &got) && got) {
                        printf("[dbg] stack:");
                        for (SIZE_T i = 0; i < got / 4; i++) {
                            if ((i % 8) == 0) printf("\n[dbg]  %08lX:",
                                                     (unsigned long)(ctx.Esp + i * 4));
                            printf(" %08lX", (unsigned long)st[i]);
                        }
                        printf("\n");
                    }
                    uint32_t frame = ctx.Ebp;
                    printf("[dbg] ebp chain:");
                    for (int i = 0; i < 16 && frame >= 0x1000 &&
                                    frame < 0x7FFE0000; i++) {
                        uint32_t pair[2];
                        SIZE_T g = 0;
                        if (!ReadProcessMemory(proc, (LPCVOID)(uintptr_t)frame,
                                               pair, sizeof(pair), &g) ||
                            g != sizeof(pair))
                            break;
                        printf("\n[dbg]  #%d ebp=%08lX ret=%08lX", i,
                               (unsigned long)frame, (unsigned long)pair[1]);
                        if (pair[0] <= frame) break;
                        frame = pair[0];
                    }
                    printf("\n");
                }
                int execute_av = code == EXCEPTION_ACCESS_VIOLATION &&
                                 x->ExceptionRecord.ExceptionInformation[0] == 8;
                if (execute_av && have) {
                    uint32_t t = translate_eip(proc, addr, orig_base,
                                               orig_size, child_base,
                                               module_count);
                    if (t) {
                        ctx.Eip = t;
                        if (SetThreadContext(th, &ctx)) {
                            printf("[dbg] translated stale eip 0x%08lX -> "
                                   "0x%08lX\n",
                                   (unsigned long)addr, (unsigned long)t);
                            if (result) result->translated_eips++;
                            if (th) CloseHandle(th);
                            avs = 0;
                            ContinueDebugEvent(pid, de.dwThreadId,
                                               DBG_CONTINUE);
                            continue;
                        }
                    }
                }
                if (th) CloseHandle(th);

                if (execute_av || !x->dwFirstChance || avs >= 32) {
                    printf("[dbg] stopping on terminal exception\n");
                    if (result) result->terminal_exceptions++;
                    cont = DBG_EXCEPTION_NOT_HANDLED;
                    ContinueDebugEvent(pid, de.dwThreadId, cont);
                    TerminateProcess(proc, 0xDEAD);
                    break;
                }
                cont = DBG_EXCEPTION_NOT_HANDLED;
            }
        } else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            printf("[dbg] process exit code=0x%08lX\n",
                   (unsigned long)de.u.ExitProcess.dwExitCode);
            if (result) {
                result->process_exited = 1;
                result->exit_code = de.u.ExitProcess.dwExitCode;
            }
            break;
        }
        ContinueDebugEvent(pid, de.dwThreadId, cont);
    }
    DebugActiveProcessStop(pid);
}
