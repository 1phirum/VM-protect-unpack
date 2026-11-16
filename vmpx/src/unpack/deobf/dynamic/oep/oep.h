/* oep.h - in-process entry-point capture without a debug object
 *
 * The target is started suspended, the agent is injected, and the agent places
 * a guard page on the unpacked entry page. The first fetch of the entry address
 * publishes the exact register file through a named mapping and parks the
 * thread. The parent snapshots the live process while it is parked, so no
 * debugger is attached and no debug object exists for the packer to find.
 */
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

#define VMPX_OEP_MAGIC   0x50454F56u   /* "VOEP" little-endian */
#define VMPX_OEP_VERSION 1u

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t pid;
    volatile uint32_t hit;
    uint32_t oep_va;
    uint32_t page_base;
    uint32_t page_prot;
    uint32_t tid;
    uint32_t eip;
    uint32_t esp;
    uint32_t ebp;
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t esi;
    uint32_t edi;
    uint32_t eflags;
    uint32_t dr0;
    uint32_t dr7;
    uint32_t reserved[8];
} vmpx_oep_ctx_t;

int dyn_oep_arm(uint32_t oep_va);
