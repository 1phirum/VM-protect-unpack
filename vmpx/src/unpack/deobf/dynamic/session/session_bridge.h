/* session_bridge.h - one lifecycle owner for the dynamic report command */
#pragma once

#include "unpack/deobf/dynamic/profile/profile.h"
#include "unpack/deobf/dynamic/session/session.h"

typedef struct {
    vmpx_session_t session;
    vmpx_profile_t profile;
    int opened;
} vmpx_dyn_session_t;

int  vmpx_dyn_session_start(vmpx_dyn_session_t* d, uint32_t pid,
                            const char* out_dir, const vmpx_profile_t* p,
                            char* err, size_t err_cap);
int  vmpx_dyn_session_fail(vmpx_dyn_session_t* d, char* err, size_t err_cap);
int  vmpx_dyn_session_finish(vmpx_dyn_session_t* d, char* err, size_t err_cap);
void vmpx_dyn_session_close(vmpx_dyn_session_t* d);
