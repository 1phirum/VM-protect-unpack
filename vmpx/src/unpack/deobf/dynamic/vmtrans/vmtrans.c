/* vmtrans.c - classify runtime EIP transitions into private executable code
 *
 * VMProtect alternates between image code and private executable pages that
 * hold decoded handlers and bytecode. The thread sampler calls this observer
 * when a thread's EIP changes; transitions into or out of private executable
 * memory are published as VM events with the complete thread snapshot.
 */
#include "unpack/deobf/dynamic/control/control.h"
#include "unpack/deobf/dynamic/vmtrans/vmtrans.h"

#define VM_MAX_THREADS 512u

typedef struct {
    uint32_t tid;
    uint32_t last_eip;
    uint8_t  last_private;
    uint8_t  last_image;
    uint8_t  used;
} vm_thread_t;

static vm_thread_t g_vm[VM_MAX_THREADS];

static vm_thread_t* vm_state(uint32_t tid) {
    for (uint32_t i = 0; i < VM_MAX_THREADS; i++) {
        if (g_vm[i].used && g_vm[i].tid == tid) return &g_vm[i];
    }
    for (uint32_t i = 0; i < VM_MAX_THREADS; i++) {
        if (!g_vm[i].used) {
            g_vm[i].used = 1;
            g_vm[i].tid = tid;
            return &g_vm[i];
        }
    }
    return NULL;
}

void vmtrans_track(uint32_t tid, uint32_t eip, uint32_t esp,
                   int private_exec, int in_image,
                   const uint8_t* data, uint32_t len) {
    vmpx_dyn_ctl_t* ctl = dyn_control_get();
    if (!ctl || !ctl->active || !(ctl->mode & VMPX_DYN_MODE_THREAD))
        return;

    vm_thread_t* st = vm_state(tid);
    if (!st) return;

    uint8_t priv = private_exec ? 1u : 0u;
    uint8_t img = in_image ? 1u : 0u;
    if (priv == st->last_private &&
        (st->last_eip != 0 || !priv)) {
        st->last_eip = eip;
        st->last_image = img;
        return;
    }

    uint32_t flags = VMPX_DYN_F_VM;
    if (priv && !st->last_private) flags |= VMPX_DYN_F_VM_ENTER;
    if (!priv && st->last_private) flags |= VMPX_DYN_F_VM_LEAVE;
    if (priv) flags |= VMPX_DYN_F_VM_PRIVATE;
    if (img) flags |= VMPX_DYN_F_VM_IMAGE;

    dyn_event_publish(VMPX_DYN_EV_VM, flags, eip, 1, eip, esp, 0,
                      data, len, tid, ((uint32_t)st->last_private << 8) | priv);

    st->last_eip = eip;
    st->last_private = priv;
    st->last_image = img;
}
