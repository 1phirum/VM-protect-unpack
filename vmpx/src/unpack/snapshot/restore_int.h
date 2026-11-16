/* restore_int.h - private contracts for snapshot restoration
 *
 * These types are deliberately not in vmpx.h. Restore orchestration, snapshot
 * loading, page mapping, module rebasing, thread context and TLS each have a
 * narrow interface; commands see only snap_restore_ex and its typed result.
 */
#pragma once

#include "unpack/snapshot/snapshot_int.h"
#include "pe/hdr.h"

typedef struct {
    uint32_t eip, esp, ebp;
    uint32_t eax, ebx, ecx, edx, esi, edi, eflags;
    uint32_t tid, pid;
} entry_ctx_t;

typedef struct {
    FILE* f;
    vmpx_snap_hdr_t h;
    vmpx_snap_region_t* rd;
    vmpx_snap_module_t* md;
    uint64_t* roff;
    uint8_t* all;
    uint8_t* region_ok;
    uint8_t* bmap;
    uint64_t data_total;
} restore_input_t;

typedef struct {
    uint64_t image_base;
    uint32_t entry;
    uint32_t tls_index_rva;
    uint32_t has_tls;
} restore_pe_t;

typedef struct {
    HANDLE proc;
    const restore_input_t* in;
    uint32_t* child_base;
    uint32_t* orig_base;
    uint32_t* orig_size;
    uint16_t* owner;
    const proc_mod_t* child;
    int nchild;
    uint32_t main_base;   /* child base of the rebuilt main image, 0 if unknown */
    uint32_t mapped;
    uint32_t failed;
    uint64_t pages_mapped;
    uint64_t pages_failed;
} map_state_t;

/* restore_input.c */
int  restore_input_open(const char* snap_path, restore_input_t* in);
void restore_input_close(restore_input_t* in);
int  restore_read_entry_ctx(const char* path, entry_ctx_t* c);
int  restore_pe_info(const char* exe, restore_pe_t* out);
uint32_t restore_peek_dword(const restore_input_t* in, uint32_t va);
const uint8_t* restore_peek_ptr(const restore_input_t* in, uint32_t va,
                                uint32_t size);
const uint8_t* restore_find_teb_data(const restore_input_t* in, uint32_t pid,
                                     uint32_t* va_out);
int  restore_stack_bounds(const restore_input_t* in, uint32_t esp,
                          uint32_t* base, uint32_t* limit);

/* restore_context.c */
int  restore_write_entry_gate(HANDLE proc, uint32_t va);
int  restore_wait_entry_gate(HANDLE thread, uint32_t va, int timeout_ms);
int  restore_apply_entry_ctx(HANDLE proc, HANDLE thread, const entry_ctx_t* ec,
                             uint32_t stack_base, uint32_t stack_limit,
                             const uint8_t* teb_data, uint32_t orig_teb,
                             uint32_t child_tls_index_va,
                             const uint8_t* tls_block);

/* restore_modules.c */
int  restore_enum_child_modules(HANDLE proc, proc_mod_t* out, int cap);
uint32_t restore_find_child_base(const char* name, const proc_mod_t* child,
                                 int nchild);
int  restore_rebase_image_pointers(map_state_t* m);

/* restore_map.c */
int  restore_page_is_free(HANDLE proc, uint32_t va);
int  restore_page_is_child_image(HANDLE proc, uint64_t page, uint64_t main_base);
void restore_map_payload(map_state_t* m);
void restore_map_payload_filtered(map_state_t* m, const uint8_t* skip,
                                  int rebase);

/* restore_tls.c */
int  restore_tls_index(HANDLE proc, uint32_t index_va, uint32_t* index_out);
void restore_fix_tls_exception(HANDLE proc, uint32_t teb, uint32_t index_va);
int  restore_relocate_tls_block(HANDLE proc, uint32_t child_tls_array,
                                uint32_t index_va, const uint8_t* block);
