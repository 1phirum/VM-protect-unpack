/* session_bridge.c - open, fail, or finish a report session exactly once */
#include "unpack/deobf/dynamic/session/session_bridge.h"
#include <string.h>

int vmpx_dyn_session_start(vmpx_dyn_session_t* d, uint32_t pid,
                           const char* out_dir, const vmpx_profile_t* p,
                           char* err, size_t err_cap) {
    if (!d || !p || !out_dir) return -1;
    memset(d, 0, sizeof(*d));
    d->profile = *p;
    if (vmpx_session_open(pid, out_dir, &d->session, err, err_cap) != 0)
        return -1;
    d->opened = 1;
    if (vmpx_session_enter(&d->session, VMPX_SESSION_BASELINING, err,
                           err_cap) != 0) {
        vmpx_session_close(&d->session);
        d->opened = 0;
        return -1;
    }
    return 0;
}

static void refresh_quiet(vmpx_session_t* s) {
    vmpx_session_refresh_modules(s);
    vmpx_session_refresh_regions(s);
}

int vmpx_dyn_session_fail(vmpx_dyn_session_t* d, char* err, size_t err_cap) {
    if (!d || !d->opened) return 0;
    char local[256];
    char* e = err ? err : local;
    size_t cap = err ? err_cap : sizeof(local);
    vmpx_session_enter(&d->session, VMPX_SESSION_FAILED, e, cap);
    vmpx_session_enter(&d->session, VMPX_SESSION_STOPPING, e, cap);
    refresh_quiet(&d->session);
    int rc = vmpx_session_write_manifest(&d->session, &d->profile, e, cap);
    vmpx_session_close(&d->session);
    d->opened = 0;
    return rc;
}

int vmpx_dyn_session_finish(vmpx_dyn_session_t* d, char* err, size_t err_cap) {
    if (!d || !d->opened) return 0;
    char local[256];
    char* e = err ? err : local;
    size_t cap = err ? err_cap : sizeof(local);
    vmpx_session_enter(&d->session, VMPX_SESSION_STOPPING, e, cap);
    vmpx_session_enter(&d->session, VMPX_SESSION_STOPPED, e, cap);
    refresh_quiet(&d->session);
    int rc = vmpx_session_write_manifest(&d->session, &d->profile, e, cap);
    vmpx_session_close(&d->session);
    d->opened = 0;
    return rc;
}

void vmpx_dyn_session_close(vmpx_dyn_session_t* d) {
    if (!d) return;
    if (d->opened) {
        vmpx_session_close(&d->session);
        d->opened = 0;
    }
}
