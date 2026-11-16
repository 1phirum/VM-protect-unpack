/* agent.c - in-process bootstrap: identity, PEB clean, stealth hooks, status
 *
 * Built as x86 DLL, injected while the target is suspended. Hooks install
 * synchronously in DLL_PROCESS_ATTACH so they are live before the first TLS
 * callback. The loader unlink is deferred: LoadLibrary is still walking the
 * loader lists inside DllMain, and removing the entry there fails the load.
 */
#include "vmpx.h"
#include "trace/agent.h"
#include "armor/stealth/stealth.h"
#include "unpack/hook/watch.h"
#include "unpack/deobf/dynamic/control/control.h"
#include "unpack/deobf/dynamic/oep/oep.h"
#include "util/log.h"

#define AGENT_ARTIFACTS L"artifacts\\agent.log"

static HMODULE g_self = NULL;
static HANDLE  g_log = NULL;
static DWORD   g_pid = 0;

static DWORD WINAPI hide_worker(LPVOID param) {
    (void)param;
    Sleep(200);                                /* LoadLibrary must finish first */
    int hidden = trace_unlink_self(g_self);
    trace_set_hidden(g_pid, hidden);

    if (g_log) {
        log_text(g_log, hidden ? "[agent] loader unlink: ok\n"
                               : "[agent] loader unlink: entry not found\n");
        log_text(g_log, hidden ? "[agent] hidden=1\n" : "[agent] hidden=0\n");
        log_text(g_log, hidden ? "[agent] status ok\n" : "[agent] status visible\n");
        CloseHandle(g_log);
        g_log = NULL;
    }
    return 0;
}

BOOL WINAPI DllMain(HMODULE self, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) return TRUE;

    g_self = self;
    DisableThreadLibraryCalls(self);

    g_log = trace_log_open(self, AGENT_ARTIFACTS);   /* before unlink */
    g_pid = GetCurrentProcessId();

    stealth_set_self(self);
    stealth_init_identity();                     /* parent/tool/debugger state */
    unsigned peb = trace_clean_peb();

    int hooks = stealth_install();
    int fail = stealth_hook_fail_count();
    uint32_t parent = stealth_parent();
    uint32_t tool = stealth_tool_pid();
    int under = stealth_under_debugger();

    trace_publish_status(g_pid, peb, 0, hooks, fail, parent, tool, under);
    watch_init(self);
    dyn_control_init(self);
    dyn_memdelta_start(self);
    dyn_codecov_start();
    dyn_threadctx_start();

    if (g_log) {
        log_hex(g_log, "[agent] attach pid=", g_pid, (uint32_t)(uintptr_t)g_self);
        log_hex(g_log, "[agent] peb=", peb, 0);
        log_text(g_log, "[agent] peb clean: BeingDebugged=0 NtGlobalFlag=0\n");
        log_hex(g_log, "[agent] hooks ok=", (uint32_t)hooks, (uint32_t)fail);
        log_hex(g_log, "[agent] parent=", parent, tool);
        log_hex(g_log, "[agent] under_debugger=", (uint32_t)under, 0);
    }

    HANDLE th = CreateThread(NULL, 0, hide_worker, NULL, 0, NULL);
    if (th) {
        CloseHandle(th);
    } else {
        int hidden = trace_unlink_self(g_self);
        trace_set_hidden(g_pid, hidden);
        if (g_log) CloseHandle(g_log);
        g_log = NULL;
    }
    return TRUE;
}

__declspec(dllexport) unsigned AgentPing(void) {
    return 0x56504D58u;                        /* "VPMX" */
}

__declspec(dllexport) int AgentArmOep(unsigned oep_va) {
    return dyn_oep_arm((uint32_t)oep_va);
}
