/* vmpx.h - shared types, command interface, utility prototypes (C11) */
#pragma once

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif

#include <windows.h>
#include <wchar.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unpack/result.h"

typedef struct {
    HANDLE          file;
    HANDLE          map;
    const uint8_t*  data;
    uint64_t        size;
} pe_t;

/* ---- agent status block (stage A), published as Local\VMPX_AGENT_<pid> ---- */
#define VMPX_AGENT_STATUS_MAGIC   0x53415856u   /* "VXAS" */
#define VMPX_AGENT_STATUS_VERSION 2u
#define VMPX_AGENT_MAX_HOOKS      32
#define VMPX_AGENT_MAX_STEALTH    32

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t pid;
    uint32_t hooks_ok;
    uint32_t hooks_fail;
    uint32_t stealth_ok;
    uint32_t stealth_fail;
    uint32_t hidden;
    uint32_t peb;
    uint32_t parent_pid;
    uint32_t tool_pid;
    uint32_t under_debugger;
    uint32_t flags;
    uint32_t agent_base;
    uint32_t reserved;
    char     hooks[VMPX_AGENT_MAX_HOOKS][32];
    char     stealth[VMPX_AGENT_MAX_STEALTH][32];
} vmpx_agent_status_t;

/* ---- artifact types (fixed at M2, see docs/formats.md) ---- */

/* one dispatch observation, fixed 96 bytes, written by the agent */
typedef struct {
    uint64_t seq;
    uint32_t eip;
    uint32_t handler;
    uint32_t fetch_ea;
    uint32_t opcode;
    uint32_t regs[9];      /* eax..edi, esp, ebp */
    uint32_t eflags;
    uint32_t mem_ea;
    uint32_t mem_val;
    uint32_t pad[6];       /* explicit, no struct-layout reliance */
} dispatch_rec_t;

/* synthesized handler effect */
typedef struct {
    uint8_t  kind;         /* MOV ADD SUB XOR AND OR SHL SHR SAR ROL ROR
                              MUL IMUL DIV LOAD STORE CMP JCC JMP CALL RET
                              PUSHF POPF NOP VMEXIT UNKNOWN */
    int8_t   dst, src1, src2;   /* vreg indices, -1 = immediate/native */
    uint32_t imm;
    uint8_t  size;         /* 1,2,4 */
    uint8_t  flags_mask;
    int8_t   mem_base, mem_index;
    uint8_t  mem_scale;
    int32_t  mem_disp;
} effect_t;

/* handler database entry (one line in .vmh) */
typedef struct {
    uint32_t addr;
    uint16_t len;
    uint8_t  bytes[96];
    effect_t effect;
    uint32_t samples;
    uint32_t conflicts;
} handler_t;

/* VM bytecode instruction */
typedef struct {
    uint32_t ea;
    uint8_t  opcode;
    uint32_t handler;
    uint8_t  noperand;
    uint8_t  operand[8];
} vminst_t;

/* SSA IR node */
typedef struct irnode {
    uint32_t id;
    uint8_t  op;
    uint8_t  width;
    uint32_t imm;
    struct irnode* a;
    struct irnode* b;
    struct irnode* c;
    uint32_t flags_use;
    uint32_t ea_hint;
} irnode_t;

/* VM basic block */
typedef struct {
    uint32_t id, ea;
    uint32_t entry_vmregs;
    vminst_t* insns; uint32_t ninsn;
    uint32_t succ[2]; uint8_t nsucc;
    uint8_t  term;
} vmblock_t;

/* pe */
int      pe_load(const char* path, pe_t* pe);
void     pe_free(pe_t* pe);
int      pe_info(const pe_t* pe);
int      pe_imports(const pe_t* pe, int limit);
uint32_t pe_entry_rva(const pe_t* pe);
uint32_t pe_size_of_image(const pe_t* pe);
uint64_t pe_image_base(const pe_t* pe);

/* proc */
typedef struct {
    wchar_t  name[64];
    uint64_t base;
    uint32_t size;
} proc_mod_t;

int      proc_find_by_name(const wchar_t* exe, uint32_t* pid_out);
int      proc_alive(uint32_t pid);
void     proc_list_modules(uint32_t pid, const char* filter);
int      proc_modules_snapshot(uint32_t pid, proc_mod_t* out, int cap);
int      proc_module_base(uint32_t pid, const wchar_t* name, uint64_t* base, uint32_t* size);
int      proc_main_module(uint32_t pid, uint64_t* base, uint32_t* size);
int      proc_read(uint32_t pid, uint64_t addr, void* buf, size_t len);
int      proc_write(uint32_t pid, uint64_t addr, const void* buf, size_t len);

typedef struct {
    uint64_t base;
    uint64_t size;
    uint32_t state;
    uint32_t protect;
    uint32_t type;
} vmpx_mem_region_t;

int      proc_mem_snapshot(uint32_t pid, uint64_t lo, uint64_t hi,
                           vmpx_mem_region_t** out, size_t* count);
void     proc_mem_free(vmpx_mem_region_t* regions);

/* armor */
int      launch_armored(const wchar_t* exe, int armor, int wait_ms);
int      launch_armored_ex(const wchar_t* exe, int armor, int wait_ms,
                           const wchar_t* window_class);
int      anti_install(void);
int      anti_hook_count(void);
int      anti_hook_fail_count(void);
const char* anti_hook_name(int index);

/* inject */
int      inject_dll(uint32_t pid, const wchar_t* dll);
int      inject_dll_base(uint32_t pid, const wchar_t* dll, uintptr_t* base_out);
int      module_present(uint32_t pid, const wchar_t* name);

/* unpack */
#define VMPX_DUMP_MAGIC   0x4D445856u   /* "VXDM" */
#define VMPX_DUMP_VERSION 1u

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t pid;
    uint32_t module_size;
    uint64_t base;
    uint64_t dump_size;
    uint64_t image_size;
} vmpx_dump_meta_t;

int      dump_image(uint32_t pid, uint64_t base, uint32_t size, const char* out,
                    uint64_t max_bytes, vmpx_dump_meta_t* meta);
int      live_imports(uint32_t pid, uint64_t base, int limit);
int      image_sanity(uint32_t pid, uint64_t base, uint32_t size);
int      dump_meta_write(const char* dump_path, const vmpx_dump_meta_t* meta);
int      dump_meta_read(const char* dump_path, vmpx_dump_meta_t* meta);

/* private-region snapshot (rebuild bootstrap) */
#define VMPX_SNAP_MAGIC   0x4E535856u   /* "VXSN" */
#define VMPX_SNAP_VERSION 2u
#define VMPX_SNAP_MAX_REGIONS 8192
#define VMPX_SNAP_MAX_MODULES 512
#define VMPX_SNAP_REG_ZERO 1u            /* region read failed; payload is zero-filled */

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t region_count;
    uint32_t module_count;
    uint64_t image_base;
    uint64_t image_size;
    uint64_t data_offset;
} vmpx_snap_hdr_t;

typedef struct {
    uint64_t base;
    uint64_t size;
    uint32_t protect;
    uint32_t type;
    uint32_t crc32;
    uint32_t flags;
} vmpx_snap_region_t;

typedef struct {
    uint32_t base;
    uint32_t size;
    char     name[64];
} vmpx_snap_module_t;
#pragma pack(pop)

int      snap_write(uint32_t pid, uint64_t min_base, const char* out);
int      snap_restore(const char* exe, const char* snap_path, uint32_t* pid_out);
int      snap_restore_ctx(const char* exe, const char* snap_path,
                          const char* ctx_path, uint32_t* pid_out);
int      snap_restore_ex(const char* exe, const char* snap_path,
                         const char* ctx_path, uint32_t* pid_out,
                         vmpx_run_result_t* result);

/* iat / rebuild (stage B) */
#define IAT_MAX_MODULES 256
#define IAT_MAX_FUNCS   65536

typedef struct {
    char     name[96];
    uint16_t ordinal;
    uint8_t  by_ordinal;
    uint8_t  resolved;
} iat_func_t;

typedef struct {
    char     dll[64];
    uint32_t first_thunk;    /* live IAT RVA */
    uint32_t count;
    uint32_t first_func;     /* index into iat_table_t.funcs */
} iat_mod_t;

typedef struct {
    uint32_t    nmods;
    uint32_t    nfuncs;
    iat_mod_t   mods[IAT_MAX_MODULES];
    iat_func_t* funcs;
    uint32_t    funcs_cap;
} iat_table_t;

int      iat_table_init(iat_table_t* tab, uint32_t func_cap);
void     iat_table_reset(iat_table_t* tab);
void     iat_table_free(iat_table_t* tab);
uint32_t iat_table_unresolved(const iat_table_t* tab);

int iat_from_live(uint32_t pid, uint64_t base, const uint8_t* file_hdr,
                  uint64_t file_size, iat_table_t* tab);
int iat_cast(uint32_t pid, uint64_t base, const uint8_t* file_hdr,
             uint64_t file_size, iat_table_t* tab);
int pe_rebuild(const uint8_t* file_hdr, uint64_t file_size, uint64_t live_base,
               uint32_t entry_rva, int clean_data, const char* dump_path,
               const char* out_path, const iat_table_t* tab);

/* util */
void     enable_debug_privilege(void);
int      parse_hex_bytes(const char* s, uint8_t* out, size_t cap, size_t* outlen);
const char* arg_get(int argc, char** argv, const char* key);
int      arg_has(int argc, char** argv, const char* key);
uint64_t arg_num(int argc, char** argv, const char* key, uint64_t dflt);
int      resolve_target(const char* override_path, wchar_t* out, size_t cap);
int      resolve_pid(int argc, char** argv, uint32_t* pid_out);

/* commands - one verb per file, main.c only dispatches */
int cmd_info(int argc, char** argv);
int cmd_imports(int argc, char** argv);
int cmd_launch(int argc, char** argv);
int cmd_modules(int argc, char** argv);
int cmd_inject(int argc, char** argv);
int cmd_dump(int argc, char** argv);
int cmd_liveimports(int argc, char** argv);
int cmd_peek(int argc, char** argv);
int cmd_poke(int argc, char** argv);
int cmd_agentstatus(int argc, char** argv);
int cmd_rebuild(int argc, char** argv);
int cmd_windows(int argc, char** argv);
int cmd_memmap(int argc, char** argv);
int cmd_oep(int argc, char** argv);
int cmd_oepcap(int argc, char** argv);
int cmd_snap(int argc, char** argv);
int cmd_run(int argc, char** argv);
int cmd_deobf(int argc, char** argv);
int cmd_watch(int argc, char** argv);
