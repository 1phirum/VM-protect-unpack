/* cmd_oepcap.c - launch a target under a hardware execution breakpoint and
 * snapshot the exact state at the unpacked entry point. */
#include "vmpx.h"
#include "unpack/result.h"
#include "pe/hdr.h"
#include "util/str.h"
#include "armor/parent.h"
#include "unpack/deobf/dynamic/oep/oep.h"
#include "unpack/deobf/dynamic/control/control.h"
#include <tlhelp32.h>

/* Helper failures are mapped here, once, at the command boundary. A failed
 * resolution, injection or capture is never reported as ok, and the exit code
 * names the class: a missing target is validation, no OEP candidate is
 * unsupported, a target that is already gone is a process exit, everything
 * else is a capture failure. */
static int oepcap_fail(const char* reason, uint32_t pid, const char* mode) {
    vmpx_run_status_t st = VMPX_RUN_CAPTURE_FAILED;
    if (!strcmp(reason, "target") || !strcmp(reason, "target-path") ||
        !strcmp(reason, "usage"))
        st = VMPX_RUN_INVALID_ARG;
    else if (!strcmp(reason, "no-oep"))
        st = VMPX_RUN_UNSUPPORTED;
    else if (!strcmp(reason, "process-not-found"))
        st = VMPX_RUN_PROCESS_EXITED;
    printf("STATUS oepcap failed status=%s pid=%u mode=%s reason=%s\n",
           vmpx_run_status_name(st), pid,
           mode ? mode : "-", reason);
    return vmpx_run_status_exit(st);
}

static int agent_path(wchar_t* out, size_t cap) {
    return agent_materialize(NULL, out, cap);
}

static int read_pe(const char* path, pehdr_t* h, uint8_t* buf, size_t cap) {
    FILE* f = NULL;
    if (fopen_s(&f, path, "rb") != 0 || !f) return -1;
    size_t got = fread(buf, 1, cap, f);
    fclose(f);
    if (!got) return -1;
    return pehdr_parse(buf, got, h);
}

static uint32_t find_oep(const char* exe, uint64_t* image_base,
                         uint32_t* image_size) {
    uint8_t buf[0x1000];
    pehdr_t h;
    if (read_pe(exe, &h, buf, sizeof(buf)) != 0) return 0;
    if (image_base) *image_base = h.image_base;
    if (image_size) *image_size = h.size_image;
    return h.entry;
}

/* The first executable section is the unpacked application code for a
 * protected PE whose later executable sections are the packer stubs. */
static int first_exec_section(const char* exe, uint32_t* out_va,
                              uint32_t* out_size) {
    FILE* f = NULL;
    if (fopen_s(&f, exe, "rb") != 0 || !f) return -1;
    uint8_t buf[0x1000];
    size_t got = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    if (got < 0x40) return -1;
    uint32_t e_lfanew = 0;
    memcpy(&e_lfanew, buf + 0x3C, 4);
    if (e_lfanew + 0x18 > got) return -1;
    uint32_t sig = 0;
    memcpy(&sig, buf + e_lfanew, 4);
    if (sig != 0x00004550u) return -1;
    uint16_t nsec = 0, opt = 0;
    memcpy(&nsec, buf + e_lfanew + 6, 2);
    memcpy(&opt, buf + e_lfanew + 20, 2);
    size_t off = (size_t)e_lfanew + 24 + opt;
    for (uint16_t i = 0; i < nsec; i++, off += 40) {
        if (off + 40 > got) break;
        uint32_t vs = 0, va = 0, ch = 0;
        memcpy(&vs, buf + off + 8, 4);
        memcpy(&va, buf + off + 12, 4);
        memcpy(&ch, buf + off + 36, 4);
        if (!vs || !(ch & 0x20000000u)) continue;
        if (out_va) *out_va = va;
        if (out_size) *out_size = vs;
        return 0;
    }
    return -1;
}

static void suspend_others(uint32_t pid, DWORD except_tid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid || te.th32ThreadID == except_tid)
                continue;
            HANDLE th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (th) {
                SuspendThread(th);
                CloseHandle(th);
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

static int wait_oep(uint32_t pid, uint32_t oep_va, CONTEXT* out, int timeout_ms) {
    uint64_t start = GetTickCount64();
    for (;;) {
        if (GetTickCount64() - start > (uint64_t)timeout_ms) {
            printf("[-] oepcap: timeout waiting for 0x%08lX\n", (unsigned long)oep_va);
            return -1;
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
            if (code == EXCEPTION_SINGLE_STEP && addr == oep_va) {
                HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                                       FALSE, de.dwThreadId);
                int ok = 0;
                if (th) {
                    memset(out, 0, sizeof(*out));
                    out->ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
                    ok = GetThreadContext(th, out) != 0;
                    CloseHandle(th);
                }
                if (!ok) {
                    printf("[-] oepcap: cannot read entry context\n");
                    TerminateProcess(de.u.CreateProcessInfo.hProcess, 0xDEAD);
                    return -1;
                }
                printf("[+] oepcap: hit 0x%08lX tid=%lu\n",
                       (unsigned long)addr, (unsigned long)de.dwThreadId);
                return (int)de.dwThreadId;
            }
            if (code == EXCEPTION_BREAKPOINT) {
                cont = DBG_CONTINUE;
            } else {
                cont = DBG_EXCEPTION_NOT_HANDLED;
            }
        } else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            printf("[-] oepcap: process exited code=0x%08lX\n",
                   (unsigned long)de.u.ExitProcess.dwExitCode);
            return -1;
        }
        ContinueDebugEvent(pid, de.dwThreadId, cont);
    }
}

static uintptr_t export_offset(const wchar_t* dll, const char* name) {
    HMODULE h = LoadLibraryExW(dll, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!h) {
        printf("[-] oepcap: cannot map agent locally (%lu)\n", GetLastError());
        return 0;
    }
    FARPROC p = GetProcAddress(h, name);
    uintptr_t off = p ? (uintptr_t)p - (uintptr_t)h : 0;
    FreeLibrary(h);
    return off;
}

static int remote_call(HANDLE proc, uintptr_t fn, uint32_t arg, DWORD* code) {
    HANDLE th = CreateRemoteThread(proc, NULL, 0,
                                   (LPTHREAD_START_ROUTINE)fn,
                                   (LPVOID)(uintptr_t)arg, 0, NULL);
    if (!th) {
        printf("[-] oepcap: CreateRemoteThread failed (%lu)\n", GetLastError());
        return -1;
    }
    DWORD w = WaitForSingleObject(th, 20000);
    DWORD c = 0;
    GetExitCodeThread(th, &c);
    CloseHandle(th);
    if (w != WAIT_OBJECT_0) {
        printf("[-] oepcap: remote arm timed out\n");
        return -1;
    }
    if (code) *code = c;
    return 0;
}

static int write_oep_ctx(const char* out, const vmpx_oep_ctx_t* c) {
    char path[MAX_PATH * 2];
    _snprintf_s(path, sizeof(path), _TRUNCATE, "%s.ctx", out);
    FILE* f = NULL;
    if (fopen_s(&f, path, "w") != 0 || !f) {
        printf("[-] oepcap: context write failed (%lu)\n", GetLastError());
        return -1;
    }
    fprintf(f, "pid=%u\n", c->pid);
    fprintf(f, "oep=0x%08lX\n", (unsigned long)c->oep_va);
    fprintf(f, "tid=%u\n", c->tid);
    fprintf(f, "eip=0x%08lX\nesp=0x%08lX\nebp=0x%08lX\n",
            (unsigned long)c->eip, (unsigned long)c->esp,
            (unsigned long)c->ebp);
    fprintf(f, "eax=0x%08lX\nebx=0x%08lX\necx=0x%08lX\nedx=0x%08lX\n",
            (unsigned long)c->eax, (unsigned long)c->ebx,
            (unsigned long)c->ecx, (unsigned long)c->edx);
    fprintf(f, "esi=0x%08lX\nedi=0x%08lX\neflags=0x%08lX\n",
            (unsigned long)c->esi, (unsigned long)c->edi,
            (unsigned long)c->eflags);
    fclose(f);
    printf("[+] oepcap: context -> %s\n", path);
    return 0;
}

static int oepcap_armored(const wchar_t* target, const char* out,
                          uint32_t oep_va, uint64_t lo, int timeout_ms,
                          uint32_t* pid_out, int* ctx_ok) {
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    uint32_t parent_pid = 0;
    if (armor_spawn_parented(target, NULL, &pi, &parent_pid) != 0) {
        printf("[-] oepcap: armored CreateProcess failed (%lu)\n", GetLastError());
        return 1;
    }
    if (pid_out) *pid_out = pi.dwProcessId;

    wchar_t agent[MAX_PATH] = { 0 };
    if (agent_path(agent, MAX_PATH) != 0) {
        printf("[-] oepcap: agent path unresolved\n");
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    armor_hint_t hint;
    memset(&hint, 0, sizeof(hint));
    armor_hint_open(pi.dwProcessId, parent_pid, GetCurrentProcessId(), &hint);
    uintptr_t remote_base = 0;
    if (inject_dll_base(pi.dwProcessId, agent, &remote_base) != 0) {
        printf("[-] oepcap: agent injection failed\n");
        armor_hint_close(&hint);
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    armor_hint_close(&hint);

    uintptr_t off = export_offset(agent, "AgentArmOep");
    if (!off || !remote_base) {
        printf("[-] oepcap: AgentArmOep not found (off=0x%llX base=0x%llX)\n",
               (unsigned long long)off, (unsigned long long)remote_base);
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    HANDLE proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                              PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                              PROCESS_VM_READ, FALSE, pi.dwProcessId);
    if (!proc) {
        printf("[-] oepcap: OpenProcess failed (%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    DWORD arm_code = 0;
    if (remote_call(proc, remote_base + off, oep_va, &arm_code) != 0 ||
        arm_code != 1) {
        printf("[-] oepcap: AgentArmOep returned 0x%lX\n", (unsigned long)arm_code);
        CloseHandle(proc);
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    printf("[*] oepcap: pid=%u oep=0x%08lX armored arm=%lu\n",
           pi.dwProcessId, (unsigned long)oep_va, (unsigned long)arm_code);

    wchar_t evt_name[96];
    wchar_t map_name[96];
    swprintf_s(evt_name, 96, L"Local\\VMPX_OEP_EVT_%u", pi.dwProcessId);
    swprintf_s(map_name, 96, L"Local\\VMPX_OEP_CTX_%u", pi.dwProcessId);
    HANDLE evt = OpenEventW(SYNCHRONIZE, FALSE, evt_name);
    HANDLE map = OpenFileMappingW(FILE_MAP_READ, FALSE, map_name);
    if (!evt || !map) {
        printf("[-] oepcap: cannot open agent signals (%lu)\n", GetLastError());
        if (evt) CloseHandle(evt);
        if (map) CloseHandle(map);
        CloseHandle(proc);
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    ResumeThread(pi.hThread);

    DWORD wr = WaitForSingleObject(evt, (DWORD)timeout_ms);
    if (wr != WAIT_OBJECT_0) {
        DWORD exit_code = 0;
        GetExitCodeProcess(pi.hProcess, &exit_code);
        printf("[-] oepcap: no entry hit (wait=%lu exit=0x%lX)\n",
               (unsigned long)wr, (unsigned long)exit_code);
        CloseHandle(map);
        CloseHandle(evt);
        CloseHandle(proc);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    vmpx_oep_ctx_t* view =
        (vmpx_oep_ctx_t*)MapViewOfFile(map, FILE_MAP_READ, 0, 0, sizeof(*view));
    vmpx_oep_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (view) {
        memcpy(&ctx, view, sizeof(ctx));
        UnmapViewOfFile(view);
    }
    if (ctx.magic != VMPX_OEP_MAGIC || !ctx.hit) {
        printf("[-] oepcap: entry context mapping invalid\n");
        CloseHandle(map);
        CloseHandle(evt);
        CloseHandle(proc);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    printf("[+] oepcap: hit 0x%08lX tid=%u eip=%08lX esp=%08lX ebp=%08lX "
           "eax=%08lX ebx=%08lX ecx=%08lX edx=%08lX esi=%08lX edi=%08lX\n",
           (unsigned long)ctx.oep_va, ctx.tid,
           (unsigned long)ctx.eip, (unsigned long)ctx.esp,
           (unsigned long)ctx.ebp, (unsigned long)ctx.eax,
           (unsigned long)ctx.ebx, (unsigned long)ctx.ecx,
           (unsigned long)ctx.edx, (unsigned long)ctx.esi,
           (unsigned long)ctx.edi);

    suspend_others(pi.dwProcessId, 0);

    if (snap_write(pi.dwProcessId, lo, out) != 0) {
        printf("[-] oepcap: snapshot failed\n");
        CloseHandle(map);
        CloseHandle(evt);
        CloseHandle(proc);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }
    int ctx_rc = write_oep_ctx(out, &ctx);
    if (ctx_ok) *ctx_ok = ctx_rc == 0;

    CloseHandle(map);
    CloseHandle(evt);
    CloseHandle(proc);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

/* Sampler-based entry capture. The agent's thread sampler runs from load,
 * records the first instruction executed in the application code section, and
 * parks that thread. Nothing is written to the target, no debug register is
 * set, and no page protection is changed, so the packer's anti-debug checks
 * do not fire. */
static int oepcap_sample(const wchar_t* target, const char* out,
                         uint64_t lo, int timeout_ms, const char* img,
                         uint64_t image_base, uint32_t image_size,
                         uint32_t* pid_out, int* ctx_ok) {
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    uint32_t parent_pid = 0;

    SetEnvironmentVariableW(L"VMPX_DYN_BOOT", L"2");
    SetEnvironmentVariableW(L"VMPX_DYN_THREAD_MS", L"1");

    if (armor_spawn_parented(target, NULL, &pi, &parent_pid) != 0) {
        printf("[-] oepcap: armored CreateProcess failed (%lu)\n", GetLastError());
        return 1;
    }
    if (pid_out) *pid_out = pi.dwProcessId;

    wchar_t agent[MAX_PATH] = { 0 };
    if (agent_path(agent, MAX_PATH) != 0) {
        printf("[-] oepcap: agent path unresolved\n");
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    armor_hint_t hint;
    memset(&hint, 0, sizeof(hint));
    armor_hint_open(pi.dwProcessId, parent_pid, GetCurrentProcessId(), &hint);
    if (inject_dll(pi.dwProcessId, agent) != 0) {
        printf("[-] oepcap: agent injection failed\n");
        armor_hint_close(&hint);
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    armor_hint_close(&hint);

    wchar_t map_name[96];
    swprintf_s(map_name, 96, L"Local\\VMPX_DYN_%u", pi.dwProcessId);
    HANDLE map = NULL;
    vmpx_dyn_ctl_t* ctl = NULL;
    for (int i = 0; i < 400; i++) {
        map = OpenFileMappingW(FILE_MAP_READ, FALSE, map_name);
        if (map) {
            ctl = (vmpx_dyn_ctl_t*)MapViewOfFile(map, FILE_MAP_READ, 0, 0,
                                                  sizeof(*ctl));
            if (ctl) break;
            CloseHandle(map);
            map = NULL;
        }
        Sleep(10);
    }
    if (!ctl) {
        printf("[-] oepcap: control mapping not found\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    printf("[*] oepcap: pid=%u sample app=[0x%08llX..0x%08llX)\n",
           pi.dwProcessId, (unsigned long long)ctl->app_lo,
           (unsigned long long)ctl->app_hi);

    /* Drain the CreateProcess suspension. */
    for (int i = 0; i < 4; i++) {
        DWORD prev = ResumeThread(pi.hThread);
        if (prev == 0 || prev == (DWORD)-1) break;
    }

    uint64_t start = GetTickCount64();
    vmpx_dyn_entry_t e;
    memset(&e, 0, sizeof(e));
    int got = 0;
    for (;;) {
        if (ctl->entry.ready) {
            MemoryBarrier();
            memcpy(&e, (const void*)&ctl->entry, sizeof(e));
            got = 1;
            break;
        }
        DWORD exit_code = 0;
        if (GetExitCodeProcess(pi.hProcess, &exit_code) &&
            exit_code != STILL_ACTIVE) {
            printf("[-] oepcap: process exited code=0x%lX\n",
                   (unsigned long)exit_code);
            break;
        }
        if (GetTickCount64() - start > (uint64_t)timeout_ms) {
            printf("[-] oepcap: no app instruction seen in %d ms (samples=%lu)\n",
                   timeout_ms, (unsigned long)ctl->thread_samples);
            break;
        }
        Sleep(2);
    }

    if (!got) {
        UnmapViewOfFile(ctl);
        CloseHandle(map);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    printf("[+] oepcap: entry eip=%08lX tid=%u esp=%08lX ebp=%08lX eax=%08lX "
           "ebx=%08lX ecx=%08lX edx=%08lX esi=%08lX edi=%08lX\n",
           (unsigned long)e.eip, e.tid, (unsigned long)e.esp,
           (unsigned long)e.ebp, (unsigned long)e.eax, (unsigned long)e.ebx,
           (unsigned long)e.ecx, (unsigned long)e.edx, (unsigned long)e.esi,
           (unsigned long)e.edi);

    vmpx_oep_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.magic = VMPX_OEP_MAGIC;
    ctx.version = VMPX_OEP_VERSION;
    ctx.pid = pi.dwProcessId;
    ctx.hit = 1;
    ctx.oep_va = (uint32_t)e.eip;
    ctx.tid = e.tid;
    ctx.eip = (uint32_t)e.eip;
    ctx.esp = (uint32_t)e.esp;
    ctx.ebp = (uint32_t)e.ebp;
    ctx.eax = e.eax;
    ctx.ebx = e.ebx;
    ctx.ecx = e.ecx;
    ctx.edx = e.edx;
    ctx.esi = e.esi;
    ctx.edi = e.edi;
    ctx.eflags = e.eflags;

    suspend_others(pi.dwProcessId, 0);

    if (img && *img) {
        vmpx_dump_meta_t meta;
        memset(&meta, 0, sizeof(meta));
        if (dump_image(pi.dwProcessId, image_base, image_size, img, 0,
                       &meta) != 0) {
            printf("[-] oepcap: entry image dump failed\n");
        } else {
            printf("[+] oepcap: image -> %s (base=0x%llX size=0x%llX)\n",
                   img, (unsigned long long)meta.base,
                   (unsigned long long)meta.image_size);
        }
    }

    if (snap_write(pi.dwProcessId, lo, out) != 0) {
        printf("[-] oepcap: snapshot failed\n");
        UnmapViewOfFile(ctl);
        CloseHandle(map);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }
    int ctx_rc = write_oep_ctx(out, &ctx);
    if (ctx_ok) *ctx_ok = ctx_rc == 0;

    char spath[MAX_PATH * 2];
    _snprintf_s(spath, sizeof(spath), _TRUNCATE, "%s.stack", out);
    FILE* sf = NULL;
    if (fopen_s(&sf, spath, "w") == 0 && sf) {
        fprintf(sf, "eip=0x%08lX esp=0x%08lX ebp=0x%08lX\n",
                (unsigned long)e.eip, (unsigned long)e.esp,
                (unsigned long)e.ebp);
        uint32_t n = e.stack_dwords;
        if (n > 64u) n = 64u;
        for (uint32_t i = 0; i < n; i++)
            fprintf(sf, "[%02lu] 0x%08lX\n", (unsigned long)i,
                    (unsigned long)e.stack[i]);
        fclose(sf);
        printf("[+] oepcap: stack -> %s\n", spath);
    }

    UnmapViewOfFile(ctl);
    CloseHandle(map);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

int cmd_oepcap(int argc, char** argv) {
    const char* exe = arg_get(argc, argv, "--exe");
    const char* out = arg_get(argc, argv, "--out");
    if (!exe || !out) {
        printf("[-] usage: vmpx oepcap --exe <target.exe> --out <snapshot> "
               "[--img <image.bin>] [--lo 0x10000] [--timeout-ms N] [--oep-rva 0xRVA] [--armored] [--delay-ms N] [--sw] [--hook] [--guard] [--guard-size N] [--sample]\n");
        printf("STATUS oepcap failed status=%s pid=0 mode=- reason=usage\n",
               vmpx_run_status_name(VMPX_RUN_INVALID_ARG));
        return vmpx_run_status_exit(VMPX_RUN_INVALID_ARG);
    }

    int use_guard = arg_has(argc, argv, "--guard");
    int use_sample = arg_has(argc, argv, "--sample");
    int use_armored = arg_has(argc, argv, "--armored");
    const char* mode_name = use_sample ? "sample"
                          : use_armored ? (use_guard ? "guard"
                                          : (arg_has(argc, argv, "--sw") ? "sw"
                                          : (arg_has(argc, argv, "--hook") ? "hook"
                                          : "dr")))
                          : "debug";

    wchar_t target[MAX_PATH * 2] = { 0 };
    if (resolve_target(exe, target, MAX_PATH * 2) != 0)
        return oepcap_fail("target", 0, mode_name);

    char narrow[MAX_PATH * 2] = { 0 };
    if (str_narrow(target, narrow, sizeof(narrow)) != 0) {
        printf("[-] oepcap: cannot narrow target path\n");
        return oepcap_fail("target-path", 0, mode_name);
    }

    uint64_t image_base = 0;
    uint32_t image_size = 0;
    uint32_t entry = find_oep(narrow, &image_base, &image_size);
    const char* oep_arg = arg_get(argc, argv, "--oep-rva");
    uint32_t guard_size = (uint32_t)arg_num(argc, argv, "--guard-size", 0);
    uint32_t oep_rva = oep_arg ? (uint32_t)arg_num(argc, argv, "--oep-rva", 0)
                               : entry;
    if (use_guard) {
        uint32_t sec_va = 0, sec_size = 0;
        if (first_exec_section(narrow, &sec_va, &sec_size) == 0) {
            if (!oep_arg) oep_rva = sec_va;
            if (!guard_size) guard_size = sec_size;
        }
    }
    if (!oep_rva) {
        printf("[-] oepcap: no OEP candidate; pass --oep-rva or --guard\n");
        return oepcap_fail("no-oep", 0, mode_name);
    }
    uint32_t oep_va = (uint32_t)image_base + oep_rva;
    uint64_t lo = arg_num(argc, argv, "--lo", 0x10000);
    int timeout_ms = (int)arg_num(argc, argv, "--timeout-ms", 60000);

    if (use_sample) {
        uint32_t pid = 0;
        int ctx_ok = -1;
        int rc = oepcap_sample(target, out, lo, timeout_ms,
                               arg_get(argc, argv, "--img"),
                               image_base, image_size, &pid, &ctx_ok);
        if (rc != 0) return oepcap_fail("capture", pid, mode_name);
        printf("STATUS oepcap ok pid=%u mode=%s out=%s ctx=%s\n", pid,
               mode_name, out, ctx_ok == 0 ? "written" : "missing");
        return 0;
    }

    if (use_armored) {
        uint64_t delay = arg_num(argc, argv, "--delay-ms", 0);
        wchar_t d[32];
        swprintf_s(d, 32, L"%llu", (unsigned long long)delay);
        SetEnvironmentVariableW(L"VMPX_OEP_DELAY", d);
        const wchar_t* mode = use_guard ? L"guard"
                              : (arg_has(argc, argv, "--sw") ? L"sw"
                              : (arg_has(argc, argv, "--hook") ? L"hook" : L"dr"));
        SetEnvironmentVariableW(L"VMPX_OEP_MODE", mode);
        SetEnvironmentVariableW(L"VMPX_OEP_LOG", L"1");
        if (use_guard) {
            wchar_t gs[32];
            swprintf_s(gs, 32, L"%u", guard_size);
            SetEnvironmentVariableW(L"VMPX_OEP_GUARD", gs);
        }
        uint32_t pid = 0;
        int ctx_ok = -1;
        int rc = oepcap_armored(target, out, oep_va, lo, timeout_ms, &pid,
                                &ctx_ok);
        SetEnvironmentVariableW(L"VMPX_OEP_DELAY", NULL);
        SetEnvironmentVariableW(L"VMPX_OEP_MODE", NULL);
        SetEnvironmentVariableW(L"VMPX_OEP_LOG", NULL);
        SetEnvironmentVariableW(L"VMPX_OEP_GUARD", NULL);
        if (rc != 0) return oepcap_fail("capture", pid, mode_name);
        printf("STATUS oepcap ok pid=%u mode=%s out=%s oep=0x%08lX ctx=%s\n",
               pid, mode_name, out, (unsigned long)oep_va,
               ctx_ok == 0 ? "written" : "missing");
        return 0;
    }

    wchar_t cmdline[MAX_PATH * 4];
    _snwprintf_s(cmdline, MAX_PATH * 4, _TRUNCATE, L"\"%ls\"", target);

    int armored = use_armored;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    if (armored) {
        uint32_t parent_pid = 0;
        if (armor_spawn_parented(target, NULL, &pi, &parent_pid) != 0) {
            printf("[-] oepcap: armored CreateProcess failed (%lu)\n", GetLastError());
            return oepcap_fail("create-process", 0, mode_name);
        }
        wchar_t agent[MAX_PATH] = { 0 };
        if (agent_path(agent, MAX_PATH) != 0) {
            printf("[-] oepcap: agent path unresolved\n");
            TerminateProcess(pi.hProcess, 1);
            return oepcap_fail("agent-path", pi.dwProcessId, mode_name);
        }
        armor_hint_t hint;
        memset(&hint, 0, sizeof(hint));
        armor_hint_open(pi.dwProcessId, parent_pid, GetCurrentProcessId(), &hint);
        if (inject_dll(pi.dwProcessId, agent) != 0) {
            printf("[-] oepcap: agent injection failed\n");
            armor_hint_close(&hint);
            TerminateProcess(pi.hProcess, 1);
            return oepcap_fail("injection", pi.dwProcessId, mode_name);
        }
        armor_hint_close(&hint);
    } else if (!CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
                               DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED,
                               NULL, NULL, &si, &pi)) {
        printf("[-] oepcap: CreateProcess failed (%lu)\n", GetLastError());
        return oepcap_fail("create-process", 0, mode_name);
    }

    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[-] oepcap: GetThreadContext failed (%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return oepcap_fail("thread-context", pi.dwProcessId, mode_name);
    }
    ctx.Dr0 = oep_va;
    ctx.Dr7 = (ctx.Dr7 & ~0x000F0003u) | 0x1u;
    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("[-] oepcap: SetThreadContext failed (%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return oepcap_fail("thread-context", pi.dwProcessId, mode_name);
    }
    printf("[*] oepcap: pid=%u base=0x%08llX oep=0x%08lX rva=0x%08lX%s\n",
           pi.dwProcessId, (unsigned long long)image_base,
           (unsigned long)oep_va, (unsigned long)oep_rva,
           armored ? " armored" : "");

    if (armored) {
        if (!DebugActiveProcess(pi.dwProcessId)) {
            printf("[-] oepcap: DebugActiveProcess failed (%lu)\n", GetLastError());
            TerminateProcess(pi.hProcess, 1);
            return oepcap_fail("debug-attach", pi.dwProcessId, mode_name);
        }
        DebugSetProcessKillOnExit(FALSE);
    }

    /* CreateProcess suspension plus DebugActiveProcess can leave a thread
     * suspended more than once. Drain the count; stop at zero. */
    for (int i = 0; i < 8; i++) {
        DWORD prev = ResumeThread(pi.hThread);
        if (prev == 0 || prev == (DWORD)-1) break;
    }

    CONTEXT hit;
    int tid = wait_oep(pi.dwProcessId, oep_va, &hit, timeout_ms);
    if (tid < 0) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return oepcap_fail("no-entry-hit", pi.dwProcessId, mode_name);
    }

    suspend_others(pi.dwProcessId, (DWORD)tid);

    if (snap_write(pi.dwProcessId, lo, out) != 0) {
        printf("[-] oepcap: snapshot failed\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return oepcap_fail("snapshot", pi.dwProcessId, mode_name);
    }

    char ctx_path[MAX_PATH * 2];
    _snprintf_s(ctx_path, sizeof(ctx_path), _TRUNCATE, "%s.ctx", out);
    FILE* f = NULL;
    int ctx_written = 0;
    if (fopen_s(&f, ctx_path, "w") == 0 && f) {
        fprintf(f, "pid=%u\n", pi.dwProcessId);
        fprintf(f, "oep=0x%08lX\n", (unsigned long)oep_va);
        fprintf(f, "eip=0x%08lX\nesp=0x%08lX\nebp=0x%08lX\n",
                (unsigned long)hit.Eip, (unsigned long)hit.Esp,
                (unsigned long)hit.Ebp);
        fprintf(f, "eax=0x%08lX\nebx=0x%08lX\necx=0x%08lX\nedx=0x%08lX\n",
                (unsigned long)hit.Eax, (unsigned long)hit.Ebx,
                (unsigned long)hit.Ecx, (unsigned long)hit.Edx);
        fprintf(f, "esi=0x%08lX\nedi=0x%08lX\neflags=0x%08lX\n",
                (unsigned long)hit.Esi, (unsigned long)hit.Edi,
                (unsigned long)hit.EFlags);
        fprintf(f, "dr0=0x%08lX\ndr7=0x%08lX\n",
                (unsigned long)hit.Dr0, (unsigned long)hit.Dr7);
        fclose(f);
        ctx_written = 1;
        printf("[+] oepcap: context -> %s\n", ctx_path);
    } else {
        printf("[-] oepcap: context write failed (%lu)\n", GetLastError());
    }

    printf("[+] oepcap: eip=%08lX esp=%08lX ebp=%08lX eax=%08lX "
           "ebx=%08lX ecx=%08lX edx=%08lX esi=%08lX edi=%08lX\n",
           (unsigned long)hit.Eip, (unsigned long)hit.Esp,
           (unsigned long)hit.Ebp, (unsigned long)hit.Eax,
           (unsigned long)hit.Ebx, (unsigned long)hit.Ecx,
           (unsigned long)hit.Edx, (unsigned long)hit.Esi,
           (unsigned long)hit.Edi);

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    printf("STATUS oepcap ok pid=%u mode=%s out=%s oep=0x%08lX ctx=%s\n",
           pi.dwProcessId, mode_name, out, (unsigned long)oep_va,
           ctx_written ? "written" : "missing");
    return 0;
}
