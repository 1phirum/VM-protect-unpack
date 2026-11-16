/* restore.c - orchestrate snapshot restoration into a suspended child
 *
 * Input loading, page mapping, module rebasing, context application and TLS
 * repair live in separate translation units. This file owns only the order of
 * operations and the typed result. A path that reaches the end of a diagnostic
 * window with a terminal exception never reports a successful run.
 */
#include "unpack/snapshot/restore_int.h"

typedef struct {
    PROCESS_INFORMATION pi;
    HANDLE proc;
    int child_created;
    int proc_opened;
    uint32_t* child_base;
    uint32_t* orig_base;
    uint32_t* orig_size;
    uint16_t* owner;
} restore_child_t;

static void child_close(restore_child_t* c, int terminate) {
    if (!c) return;
    if (terminate && c->child_created && c->pi.hProcess)
        TerminateProcess(c->pi.hProcess, 1);
    if (c->proc_opened && c->proc) CloseHandle(c->proc);
    if (c->child_created) {
        if (c->pi.hThread) CloseHandle(c->pi.hThread);
        if (c->pi.hProcess) CloseHandle(c->pi.hProcess);
    }
    free(c->child_base);
    free(c->orig_base);
    free(c->orig_size);
    free(c->owner);
    memset(c, 0, sizeof(*c));
}

static int restore_fail(vmpx_run_result_t* result, vmpx_run_status_t status) {
    if (result) result->status = status;
    return -1;
}

/* The main image base is the child module whose name matches the rebuilt exe.
 * The rebuilt header's preferred base is the fallback: the Stage B image is a
 * fixed-base build, but load order and renamed copies are not assumptions. */
static uint32_t child_main_base(const char* exe, const proc_mod_t* child,
                                int nchild, uint64_t fallback) {
    if (exe && *exe) {
        const char* base = exe;
        for (const char* p = exe; *p; p++)
            if (*p == '\\' || *p == '/') base = p + 1;
        uint32_t found = restore_find_child_base(base, child, nchild);
        if (found) return found;
    }
    return (uint32_t)fallback;
}

static int child_modules(HANDLE proc, DWORD pid, proc_mod_t* out, int cap,
                         int* toolhelp, int* enum_rc, int* peb_rc) {
    int n = proc_modules_snapshot(pid, out, cap);
    *toolhelp = n;
    *enum_rc = 0;
    *peb_rc = 0;
    if (n <= 0) {
        n = restore_enum_child_modules(proc, out, cap);
        *enum_rc = n;
    }
    if (n <= 0) {
        n = vmpx_peb_modules(proc, pid, out, cap);
        *peb_rc = n;
    }
    return n;
}

static int snap_restore_impl(const char* exe, const char* snap_path,
                             const char* ctx_path, uint32_t* pid_out,
                             vmpx_run_result_t* result) {
    if (result) vmpx_run_result_init(result);
    if (!exe || !snap_path || !pid_out)
        return restore_fail(result, VMPX_RUN_INVALID_ARG);

    restore_input_t in;
    if (restore_input_open(snap_path, &in) != 0)
        return restore_fail(result, VMPX_RUN_CAPTURE_FAILED);
    if (result) result->capture_complete = 1;

    restore_pe_t pe;
    if (restore_pe_info(exe, &pe) != 0 || !pe.image_base || !pe.entry) {
        printf("[-] run: rebuilt PE header is not usable\n");
        restore_input_close(&in);
        return restore_fail(result, VMPX_RUN_CAPTURE_FAILED);
    }

    wchar_t exe_w[MAX_PATH * 2];
    if (str_widen(exe, exe_w, MAX_PATH * 2) != 0) {
        restore_input_close(&in);
        return restore_fail(result, VMPX_RUN_INVALID_ARG);
    }

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    if (!CreateProcessW(exe_w, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED,
                        NULL, NULL, &si, &pi)) {
        printf("[-] run: CreateProcess failed (%lu)\n", GetLastError());
        restore_input_close(&in);
        return restore_fail(result, VMPX_RUN_RESTORE_INCOMPLETE);
    }

    restore_child_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.pi = pi;
    ch.child_created = 1;
    if (result) result->pid = pi.dwProcessId;

    proc_mod_t child[VMPX_SNAP_MAX_MODULES];
    int n_th = 0, n_enum = 0, n_peb = 0;
    int nchild = child_modules(pi.hProcess, pi.dwProcessId, child,
                               VMPX_SNAP_MAX_MODULES, &n_th, &n_enum, &n_peb);
    if (nchild <= 0)
        printf("[!] run: child loader list is empty before first resume; "
               "module rebasing skipped (toolhelp=%d enum=%d peb=%d)\n",
               n_th, n_enum, n_peb);

    /* The child's main image base can differ from the rebuilt header's
     * preferred base, so discover it before the entry gate is written. */
    uint32_t main_child = child_main_base(exe, child, nchild, pe.image_base);

    uint32_t nmods = in.h.module_count ? in.h.module_count : 1;
    ch.child_base = (uint32_t*)calloc(nmods, sizeof(*ch.child_base));
    ch.orig_base = (uint32_t*)calloc(nmods, sizeof(*ch.orig_base));
    ch.orig_size = (uint32_t*)calloc(nmods, sizeof(*ch.orig_size));
    ch.owner = (uint16_t*)malloc(0x100000 * sizeof(*ch.owner));
    if (!ch.child_base || !ch.orig_base || !ch.orig_size || !ch.owner) {
        printf("[-] run: out of memory for restore maps\n");
        child_close(&ch, 1);
        restore_input_close(&in);
        return restore_fail(result, VMPX_RUN_INTERNAL_ERROR);
    }

    ch.proc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                          PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                          FALSE, pi.dwProcessId);
    if (!ch.proc) {
        printf("[-] run: OpenProcess child failed (%lu)\n", GetLastError());
        child_close(&ch, 1);
        restore_input_close(&in);
        return restore_fail(result, VMPX_RUN_RESTORE_INCOMPLETE);
    }
    ch.proc_opened = 1;

    entry_ctx_t ec;
    memset(&ec, 0, sizeof(ec));
    int have_ctx = 0;
    int restore_ok = 1;
    if (ctx_path && *ctx_path) {
        if (restore_read_entry_ctx(ctx_path, &ec) != 0) {
            printf("[-] run: cannot read entry context %s "
                   "(eip, esp and pid required)\n", ctx_path);
            child_close(&ch, 1);
            restore_input_close(&in);
            return restore_fail(result, VMPX_RUN_INVALID_ARG);
        }
        have_ctx = 1;
    }
    uint32_t entry_va = main_child + pe.entry;
    uint32_t stack_base = 0, stack_limit = 0;
    if (have_ctx) {
        if (restore_stack_bounds(&in, ec.esp, &stack_base, &stack_limit) != 0) {
            printf("[!] run: esp=0x%08lX is not in a captured region; "
                   "stack bounds synthesized\n", (unsigned long)ec.esp);
            restore_ok = 0;
        }
        if (restore_write_entry_gate(ch.proc, entry_va) != 0) {
            printf("[-] run: entry gate write failed at 0x%08lX\n",
                   (unsigned long)entry_va);
            child_close(&ch, 1);
            restore_input_close(&in);
            return restore_fail(result, VMPX_RUN_RESTORE_INCOMPLETE);
        }
        printf("[*] run: entry gate 0x%08lX ctx eip=0x%08lX esp=0x%08lX "
               "stack=0x%08lX..0x%08lX\n",
               entry_va, ec.eip, ec.esp, stack_limit, stack_base);
    }

    map_state_t ms;
    memset(&ms, 0, sizeof(ms));
    ms.proc = ch.proc;
    ms.in = &in;
    ms.child_base = ch.child_base;
    ms.orig_base = ch.orig_base;
    ms.orig_size = ch.orig_size;
    ms.owner = ch.owner;
    ms.child = child;
    ms.nchild = nchild;
    ms.main_base = main_child;

    uint32_t orig_teb = 0, orig_peb = 0;
    const uint8_t* teb_data = NULL;
    const uint8_t* tls_block = NULL;
    uint32_t child_image_base = main_child;
    uint32_t child_tls_index_va =
        pe.has_tls ? child_image_base + pe.tls_index_rva : 0;

    if (have_ctx) {
        teb_data = restore_find_teb_data(&in, ec.pid, &orig_teb);
        if (orig_teb)
            orig_peb = restore_peek_dword(&in, orig_teb + 0x30);
        if (!teb_data) {
            printf("[!] run: captured TEB page absent; thread identity is "
                   "not restored\n");
            restore_ok = 0;
        }
        if (teb_data && pe.has_tls) {
            uint32_t orig_tls_array = *(const uint32_t*)(teb_data + 0x2C);
            uint32_t orig_index_va =
                (uint32_t)in.h.image_base + pe.tls_index_rva;
            uint32_t tls_index = restore_peek_dword(&in, orig_index_va);
            if (tls_index < 64 && orig_tls_array) {
                uint32_t orig_block = restore_peek_dword(
                    &in, orig_tls_array + tls_index * 4);
                if (orig_block)
                    tls_block = restore_peek_ptr(&in, orig_block, 0x1000);
            }
            if (!tls_block) {
                printf("[!] run: captured TLS block unavailable; TLS state "
                       "is not relocated\n");
                restore_ok = 0;
            }
        } else if (teb_data && !pe.has_tls) {
            printf("[!] run: rebuilt image has no TLS directory; "
                   "TLS restore skipped\n");
            restore_ok = 0;
        }
        printf("[*] run: captured teb=0x%08lX peb=0x%08lX%s\n",
               (unsigned long)orig_teb, (unsigned long)orig_peb,
               teb_data ? "" : " (teb page absent)");
    }

    uint32_t child_pid = pi.dwProcessId;
    int dbg = 0;
    if (!have_ctx) {
        if (nchild <= 0) {
            /* The earlier warning already named the cause; record it as a
             * degraded restore so the summary cannot read as clean. */
            restore_ok = 0;
        }
        dbg = snap_debug_enabled();
        if (dbg) {
            if (!DebugActiveProcess(child_pid)) {
                printf("[!] run: DebugActiveProcess failed (%lu)\n",
                       (unsigned long)GetLastError());
                dbg = 0;
            } else {
                DebugSetProcessKillOnExit(FALSE);
                printf("[+] run: debugger attached before first resume\n");
            }
        }
        restore_map_payload(&ms);
        if (restore_rebase_image_pointers(&ms) != 0) {
            printf("[!] run: image pointer rebase incomplete\n");
            restore_ok = 0;
        }
        ResumeThread(pi.hThread);
    } else {
        const char* premap = getenv("VMPX_PREMAP");
        if (premap && *premap && *premap != '0') {
            uint8_t* skip = (uint8_t*)calloc(in.h.region_count, 1);
            if (skip) {
                for (uint32_t i = 0; i < in.h.region_count; i++) {
                    uint64_t rb = in.rd[i].base;
                    uint64_t re = rb + in.rd[i].size;
                    /* Only pre-map the low private heap before the loader.
                     * Image range and high private pages are mapped after the
                     * gate so the loader's mappings are not overwritten. */
                    if (rb >= in.h.image_base) skip[i] = 1;
                    if (ec.esp >= rb && ec.esp < re) skip[i] = 1;
                    if (orig_teb && rb < (uint64_t)orig_teb + 0x1000 &&
                        (uint64_t)orig_teb < re) skip[i] = 1;
                    if (orig_peb && rb < (uint64_t)orig_peb + 0x1000 &&
                        (uint64_t)orig_peb < re) skip[i] = 1;
                }
                printf("[*] run: pre-map phase 1 (heap and data)\n");
                restore_map_payload_filtered(&ms, skip, 0);
                free(skip);
                /* A phase-one region may overlap the entry page; re-arm the
                 * self-loop after the data is in place. */
                if (restore_write_entry_gate(ch.proc, entry_va) != 0) {
                    printf("[-] run: entry gate rewrite failed at 0x%08lX\n",
                           (unsigned long)entry_va);
                    child_close(&ch, 1);
                    restore_input_close(&in);
                    return restore_fail(result, VMPX_RUN_RESTORE_INCOMPLETE);
                }
            }
        }
        ResumeThread(pi.hThread);
        if (restore_wait_entry_gate(pi.hThread, entry_va, 30000) == 0) {
            /* The loader is complete; no thread is using the child's stack,
             * heap, PEB or TEB. Re-query the module list and map the original
             * process state over the loader's. */
            n_th = 0;
            n_enum = 0;
            n_peb = 0;
            nchild = child_modules(pi.hProcess, pi.dwProcessId, child,
                                   VMPX_SNAP_MAX_MODULES, &n_th, &n_enum,
                                   &n_peb);
            printf("[*] run: loader complete, child modules=%d\n", nchild);
            if (nchild <= 0) {
                printf("[-] run: child module list unavailable after the "
                       "loader; no base for the captured state\n");
                child_close(&ch, 1);
                restore_input_close(&in);
                return restore_fail(result, VMPX_RUN_RESTORE_INCOMPLETE);
            }
            for (int j = 0; j < nchild; j++) {
                char mn[128];
                str_narrow(child[j].name, mn, sizeof(mn));
                printf("[*] run: child[%d] %s 0x%08llX +0x%llX\n", j, mn,
                       (unsigned long long)child[j].base,
                       (unsigned long long)child[j].size);
            }
            ms.child = child;
            ms.nchild = nchild;
            ms.main_base =
                child_main_base(exe, child, nchild, pe.image_base);
            restore_map_payload(&ms);
            if (restore_rebase_image_pointers(&ms) != 0) {
                printf("[!] run: image pointer rebase incomplete\n");
                restore_ok = 0;
            }
            child_image_base = ms.main_base;
            child_tls_index_va =
                pe.has_tls ? child_image_base + pe.tls_index_rva : 0;
            if (restore_apply_entry_ctx(ch.proc, pi.hThread, &ec, stack_base,
                                        stack_limit, teb_data, orig_teb,
                                        child_tls_index_va, tls_block) != 0) {
                printf("[-] run: entry context apply failed; terminating the "
                       "child\n");
                child_close(&ch, 1);
                restore_input_close(&in);
                return restore_fail(result, VMPX_RUN_RESTORE_INCOMPLETE);
            }
            dbg = snap_debug_enabled();
            if (dbg) {
                if (!DebugActiveProcess(child_pid)) {
                    printf("[!] run: DebugActiveProcess failed (%lu)\n",
                           (unsigned long)GetLastError());
                    dbg = 0;
                } else {
                    DebugSetProcessKillOnExit(FALSE);
                    printf("[+] run: debugger attached after context apply\n");
                }
            }
            ResumeThread(pi.hThread);
        } else {
            printf("[!] run: entry gate not reached at 0x%08lX\n", entry_va);
            child_close(&ch, 1);
            restore_input_close(&in);
            return restore_fail(result, VMPX_RUN_RESTORE_INCOMPLETE);
        }
    }

    if (dbg)
        snap_debug_run(child_pid, ch.proc, ms.orig_base, ms.orig_size,
                       ms.child_base, in.h.module_count, result);

    if (result) {
        result->pid = child_pid;
        result->mapped = ms.mapped;
        result->failed = ms.failed;
        result->pages_mapped = ms.pages_mapped;
        result->pages_failed = ms.pages_failed;
        result->modules_child = nchild > 0 ? (uint32_t)nchild : 0;
        result->modules_snapshot = in.h.module_count;
        result->restore_complete =
            (restore_ok && ms.failed == 0 && ms.pages_failed == 0) ? 1 : 0;
        result->status = vmpx_run_classify(
            dbg, result->terminal_exceptions, result->timed_out,
            result->process_exited);
        /* A requested restore that did not apply cleanly cannot report a
         * launch or an observation pass; a worse observation outcome stands. */
        if (have_ctx && !result->restore_complete &&
            (result->status == VMPX_RUN_OK ||
             result->status == VMPX_RUN_LAUNCHED))
            result->status = VMPX_RUN_RESTORE_INCOMPLETE;
    }

    vmpx_run_status_t summary =
        result ? result->status : VMPX_RUN_INTERNAL_ERROR;
    printf("[%c] run: pid=%u mapped=%u failed=%u pages=%llu/%llu "
           "modules=%d snapshot_modules=%u status=%s\n",
           ((summary == VMPX_RUN_OK || summary == VMPX_RUN_LAUNCHED) &&
            (!result || result->restore_complete)) ? '+' : '!',
           child_pid, ms.mapped, ms.failed,
           (unsigned long long)ms.pages_mapped,
           (unsigned long long)(ms.pages_mapped + ms.pages_failed),
           nchild, in.h.module_count, vmpx_run_status_name(summary));

    child_close(&ch, 0);
    restore_input_close(&in);

    *pid_out = child_pid;
    return (result && result->status != VMPX_RUN_OK &&
            result->status != VMPX_RUN_LAUNCHED) ? -1 : 0;
}

int snap_restore_ex(const char* exe, const char* snap_path, const char* ctx_path,
                    uint32_t* pid_out, vmpx_run_result_t* result) {
    vmpx_run_result_t local;
    if (!result) result = &local;
    vmpx_run_result_init(result);
    int rc = snap_restore_impl(exe, snap_path, ctx_path, pid_out, result);
    if (rc != 0 && (result->status == VMPX_RUN_OK ||
                    result->status == VMPX_RUN_LAUNCHED))
        result->status = VMPX_RUN_INTERNAL_ERROR;
    return (int)result->status;
}

int snap_restore(const char* exe, const char* snap_path, uint32_t* pid_out) {
    vmpx_run_result_t r;
    int st = snap_restore_ex(exe, snap_path, NULL, pid_out, &r);
    return st == VMPX_RUN_OK || st == VMPX_RUN_LAUNCHED ? 0 : -1;
}

int snap_restore_ctx(const char* exe, const char* snap_path,
                     const char* ctx_path, uint32_t* pid_out) {
    vmpx_run_result_t r;
    int st = snap_restore_ex(exe, snap_path, ctx_path, pid_out, &r);
    return st == VMPX_RUN_OK || st == VMPX_RUN_LAUNCHED ? 0 : -1;
}
