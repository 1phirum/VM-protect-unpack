/* cmd_oep.c - sample a live target's threads and locate candidate OEP frames
 *
 * The target is unpacked by the time its main window exists. The main thread
 * is inside the application message loop; its EBP chain still contains the
 * frame that called the entry routine, and the stack still contains return
 * addresses into the unpacked image. Each candidate return address is mapped
 * back to the nearest push ebp / mov ebp,esp prologue so an entry-point
 * override can be tested.
 */
#include "vmpx.h"
#include "unpack/result.h"
#include "armor/winwait.h"
#include <tlhelp32.h>

#define MAX_CAND 64

typedef struct {
    uint32_t rva[MAX_CAND];
    uint32_t ret[MAX_CAND];
    int      n;
} cands_t;

static int in_mod(uint32_t v, uint64_t base, uint32_t size) {
    return v >= base && v < base + size;
}

static void add_cand(cands_t* c, uint32_t rva, uint32_t ret) {
    for (int i = 0; i < c->n; i++)
        if (c->rva[i] == rva) return;
    if (c->n >= MAX_CAND) return;
    c->rva[c->n] = rva;
    c->ret[c->n] = ret;
    c->n++;
}

static uint32_t nearest_prologue(HANDLE hp, uint64_t base, uint32_t size,
                                 uint32_t ret) {
    if (!in_mod(ret, base, size)) return 0;
    uint32_t lo = ret > 0x1000 ? ret - 0x1000 : (uint32_t)base;
    if (lo < base) lo = (uint32_t)base;
    uint8_t buf[0x1000];
    SIZE_T got = 0;
    if (!ReadProcessMemory(hp, (LPCVOID)(uintptr_t)lo, buf, sizeof(buf), &got))
        return 0;
    for (int i = (int)got - 3; i >= 0; i--) {
        if (buf[i] == 0x55 && buf[i + 1] == 0x8B && buf[i + 2] == 0xEC)
            return lo + (uint32_t)i;
    }
    return 0;
}

static uint32_t entry_rva(HANDLE hp, uint64_t base) {
    IMAGE_DOS_HEADER dos;
    SIZE_T got = 0;
    if (!ReadProcessMemory(hp, (LPCVOID)(uintptr_t)base, &dos, sizeof(dos),
                           &got) || got != sizeof(dos))
        return 0;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS32 nt;
    if (!ReadProcessMemory(hp, (LPCVOID)(uintptr_t)(base + dos.e_lfanew),
                           &nt, sizeof(nt), &got) || got != sizeof(nt))
        return 0;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return 0;
    return nt.OptionalHeader.AddressOfEntryPoint;
}

static void sample_thread(HANDLE hp, uint32_t pid, DWORD tid,
                          uint64_t base, uint32_t size, cands_t* cands,
                          FILE* out) {
    (void)pid;
    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                           THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!th) return;

    SuspendThread(th);
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    if (GetThreadContext(th, &ctx)) {
        fprintf(out, "THREAD tid=%lu eip=%08lX%s esp=%08lX ebp=%08lX\n",
                tid, (unsigned long)ctx.Eip,
                in_mod(ctx.Eip, base, size) ? " (image)" : "",
                (unsigned long)ctx.Esp, (unsigned long)ctx.Ebp);

        uint8_t stack[0x2000];
        SIZE_T got = 0;
        if (ReadProcessMemory(hp, (LPCVOID)(uintptr_t)ctx.Esp, stack,
                              sizeof(stack), &got)) {
            for (SIZE_T i = 0; i + 4 <= got; i += 4) {
                uint32_t v = *(uint32_t*)(stack + i);
                if (!in_mod(v, base, size)) continue;
                uint32_t rva = v - (uint32_t)base;
                uint32_t cand = nearest_prologue(hp, base, size, v);
                fprintf(out, "  STACK +%03lX ret=%08lX rva=%08lX cand=%08lX\n",
                        (unsigned long)i, (unsigned long)v,
                        (unsigned long)rva, (unsigned long)(cand ? cand - (uint32_t)base : 0));
                if (cand) add_cand(cands, cand - (uint32_t)base, v);
            }
        }

        /* EBP chain: [ebp] = saved ebp, [ebp+4] = return address. */
        uint32_t ebp = ctx.Ebp;
        for (int depth = 0; depth < 64; depth++) {
            uint32_t frame[2] = { 0, 0 };
            SIZE_T r = 0;
            if (!ReadProcessMemory(hp, (LPCVOID)(uintptr_t)ebp, frame,
                                   sizeof(frame), &r) || r != sizeof(frame))
                break;
            if (in_mod(frame[1], base, size)) {
                uint32_t cand = nearest_prologue(hp, base, size, frame[1]);
                fprintf(out, "  FRAME depth=%d ebp=%08lX ret=%08lX rva=%08lX cand=%08lX\n",
                        depth, (unsigned long)ebp, (unsigned long)frame[1],
                        (unsigned long)(frame[1] - (uint32_t)base),
                        (unsigned long)(cand ? cand - (uint32_t)base : 0));
                if (cand) add_cand(cands, cand - (uint32_t)base, frame[1]);
            }
            if (frame[0] <= ebp || frame[0] - ebp > 0x100000) break;
            ebp = frame[0];
        }
    }
    ResumeThread(th);
    CloseHandle(th);
}

/* Helper failures are mapped here, once, at the command boundary. A failed
 * resolution, injection or capture is never reported as ok, and the exit code
 * names the class: a missing target or usage error is a validation failure, a
 * target that is already gone is a process exit, everything else is a capture
 * failure. */
static int oep_fail(const char* reason, uint32_t pid) {
    vmpx_run_status_t st = VMPX_RUN_CAPTURE_FAILED;
    if (!strcmp(reason, "target") || !strcmp(reason, "usage"))
        st = VMPX_RUN_INVALID_ARG;
    else if (!strcmp(reason, "process-not-found"))
        st = VMPX_RUN_PROCESS_EXITED;
    printf("STATUS oep failed status=%s pid=%u reason=%s\n",
           vmpx_run_status_name(st), pid, reason);
    return vmpx_run_status_exit(st);
}

int cmd_oep(int argc, char** argv) {
    const char* out_path = arg_get(argc, argv, "--out");
    int wait_ms = (int)arg_num(argc, argv, "--wait-ms", 0);
    int launch = arg_has(argc, argv, "--launch") ? 1 : 0;

    uint32_t pid = 0;
    if (launch) {
        wchar_t target[MAX_PATH * 2] = { 0 };
        if (resolve_target(arg_get(argc, argv, "--exe"), target, MAX_PATH * 2) != 0)
            return oep_fail("target", 0);
        if (launch_armored(target, 1, 180000) != 0) {
            printf("[-] launch failed\n");
            return oep_fail("launch", 0);
        }
        const wchar_t* leaf = wcsrchr(target, L'\\');
        if (!proc_find_by_name(leaf ? leaf + 1 : target, &pid)) {
            printf("[-] launched process not found\n");
            return oep_fail("process-not-found", 0);
        }
    } else if (resolve_pid(argc, argv, &pid) != 0) {
        return oep_fail("process-not-found", 0);
    }

    if (wait_ms > 0) {
        HWND hwnd = NULL;
        wchar_t title[256] = { 0 };
        int count = 0;
        winwait_for_class(pid, NULL, wait_ms, &hwnd, title, 256, &count);
    }

    proc_mod_t mods[256];
    int nmods = proc_modules_snapshot(pid, mods, 256);
    if (nmods <= 0) {
        printf("[-] no module snapshot for pid %u\n", pid);
        return oep_fail("module-snapshot", pid);
    }
    uint64_t base = mods[0].base;
    uint32_t size = mods[0].size;
    printf("[*] main module: %ls base=%08llX size=%08X\n",
           mods[0].name, (unsigned long long)base, size);

    HANDLE hp = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hp) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        return oep_fail("open-process", pid);
    }

    FILE* out = stdout;
    const char* out_name = "-";
    if (out_path) {
        if (fopen_s(&out, out_path, "w") != 0 || !out) {
            printf("[-] cannot open %s for writing\n", out_path);
            CloseHandle(hp);
            return oep_fail("out-open", pid);
        }
        out_name = out_path;
    }

    fprintf(out, "MODULE pid=%u base=%08lX size=%08lX entry=%08lX\n",
            pid, (unsigned long)base, (unsigned long)size,
            (unsigned long)(base ? entry_rva(hp, base) : 0));

    cands_t cands;
    memset(&cands, 0, sizeof(cands));

    int thread_snap = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) {
            thread_snap = 1;
            do {
                if (te.th32OwnerProcessID == pid)
                    sample_thread(hp, pid, te.th32ThreadID, base, size, &cands, out);
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }

    fprintf(out, "CANDIDATES %d\n", cands.n);
    for (int i = 0; i < cands.n; i++)
        fprintf(out, "  CAND rva=%08lX ret=%08lX\n",
                (unsigned long)cands.rva[i], (unsigned long)cands.ret[i]);

    const char* fail = NULL;
    if (!thread_snap) fail = "thread-snapshot";
    else if (!cands.n) fail = "no-candidates";

    if (out != stdout) fclose(out);
    CloseHandle(hp);

    if (fail) return oep_fail(fail, pid);

    printf("STATUS oep ok pid=%u candidates=%d out=%s\n", pid, cands.n,
           out_name);
    return 0;
}
