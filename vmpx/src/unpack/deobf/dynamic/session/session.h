/* session.h - target identity, lifecycle, module/region generations, manifest */
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>
#include <stdint.h>

#include "unpack/deobf/dynamic/profile/profile.h"
#include "unpack/memory/region_map.h"

#define VMPX_SESSION_MAX_MODULES 512
#define VMPX_SESSION_ID_CAP 128
#define VMPX_SESSION_PATH_CAP 512

typedef enum {
    VMPX_SESSION_CREATED = 0,
    VMPX_SESSION_IDENTIFIED,
    VMPX_SESSION_BASELINING,
    VMPX_SESSION_OBSERVING,
    VMPX_SESSION_FOCUSED_CAPTURE,
    VMPX_SESSION_CHECKPOINTING,
    VMPX_SESSION_RECONSTRUCTING,
    VMPX_SESSION_VALIDATING,
    VMPX_SESSION_COMPLETED,
    VMPX_SESSION_STOPPING,
    VMPX_SESSION_STOPPED,
    VMPX_SESSION_FAILED
} vmpx_session_state_t;

typedef struct {
    char id[VMPX_SESSION_ID_CAP];
    uint32_t pid;
    uint64_t create_time;
    uint64_t nonce;
    uint64_t image_base;
    uint32_t image_size;
    char image_path[VMPX_SESSION_PATH_CAP];
} vmpx_session_identity_t;

typedef struct {
    char name[64];
    char path[VMPX_SESSION_PATH_CAP];
    uint64_t base;
    uint32_t size;
    uint32_t generation;
    uint32_t present;
    uint32_t seen;
} vmpx_session_module_t;

typedef struct {
    vmpx_session_identity_t id;
    vmpx_session_state_t state;
    HANDLE proc;
    vmpx_region_map_t regions;
    vmpx_session_module_t modules[VMPX_SESSION_MAX_MODULES];
    vmpx_session_module_t* scratch;
    uint32_t module_count;
    uint32_t next_module_generation;
    char out_dir[VMPX_SESSION_PATH_CAP];
    uint32_t writes;
} vmpx_session_t;

int  vmpx_session_make_id(uint32_t pid, uint64_t create_time, uint64_t nonce,
                          char* out, size_t cap);
int  vmpx_session_open(uint32_t pid, const char* out_dir, vmpx_session_t* s,
                       char* err, size_t err_cap);
void vmpx_session_close(vmpx_session_t* s);
const char* vmpx_session_state_name(vmpx_session_state_t state);
int  vmpx_session_enter(vmpx_session_t* s, vmpx_session_state_t next,
                        char* err, size_t err_cap);
int  vmpx_session_refresh_modules(vmpx_session_t* s);
int  vmpx_session_refresh_regions(vmpx_session_t* s);
const vmpx_session_module_t* vmpx_session_module_by_name(
    const vmpx_session_t* s, const char* name);
const vmpx_session_module_t* vmpx_session_module_at(const vmpx_session_t* s,
                                                    uint64_t addr);
int  vmpx_session_write_manifest(vmpx_session_t* s, const vmpx_profile_t* p,
                                 char* err, size_t err_cap);
int  vmpx_session_write_modules(vmpx_session_t* s, char* err, size_t err_cap);
int  vmpx_session_write_regions(vmpx_session_t* s, char* err, size_t err_cap);
