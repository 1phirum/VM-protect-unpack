/* profile.h - effective dynamic-session profile and bounds validation
 *
 * The profile is generic. It contains no target path, class name, module name,
 * or address. Target selectors belong to a workflow and are resolved against
 * the live generation.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#define VMPX_PROFILE_PATH 260

typedef struct {
    uint32_t schema_version;
    char architecture[16];

    char discovery_image[16];
    char discovery_regions[40];
    char discovery_entry_policy[40];

    char observation_backend[16];
    uint32_t baseline_required;
    uint32_t max_guard_pages;
    uint32_t max_probe_ms;
    uint32_t max_trace_instructions;

    uint32_t host_budget_mib;
    uint32_t agent_budget_mib;
    uint32_t read_chunk_kib;

    uint32_t prefer_loader_initialization;
    uint32_t allow_checkpoint_diagnostics;
    uint32_t require_dependency_preflight;

    char validation_feature_inventory[VMPX_PROFILE_PATH];
    uint32_t fresh_process_required;
    uint32_t diagnostic_repair_allowed_for_pass;

    char source_path[VMPX_PROFILE_PATH];
    uint32_t loaded_from_file;
} vmpx_profile_t;

void vmpx_profile_defaults(vmpx_profile_t* p);
int  vmpx_profile_validate(const vmpx_profile_t* p, char* err, size_t err_cap);
int  vmpx_profile_load(const char* path, vmpx_profile_t* p, char* err,
                       size_t err_cap);
int  vmpx_profile_write(const char* path, const vmpx_profile_t* p);
