/* logfile.c - agent log handle next to the injected DLL (L1) */
#include "trace/agent.h"
#include "util/log.h"

HANDLE trace_log_open(HMODULE self, const wchar_t* relpath) {
    return log_open_append_next_to(self, relpath);
}
