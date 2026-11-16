/* rebase.c - relocate absolute pointers found in restored private pages */
#include "unpack/snapshot/snapshot_int.h"

void snap_rebase_payload(uint8_t* all, const uint64_t* roff,
                         const vmpx_snap_region_t* rd, uint32_t region_count,
                         const uint16_t* owner,
                         const uint32_t* child_base,
                         const uint32_t* orig_base,
                         const uint32_t* orig_size) {
    if (!all || !roff || !rd || !owner || !child_base ||
        !orig_base || !orig_size)
        return;

    /* Only touch values that fall inside a module recorded in the snapshot.
     * Equal bases mean the child mapped the module where the target did and
     * the original bytes are already correct. */
    for (uint32_t i = 0; i < region_count; i++) {
        for (size_t off = 0; off + 4 <= (size_t)rd[i].size; off += 4) {
            uint32_t v;
            memcpy(&v, all + roff[i] + off, 4);
            uint32_t pg = v >> 12;
            if (pg >= 0x100000) continue;
            uint16_t idx = owner[pg];
            if (idx == 0xFFFFu || !child_base[idx]) continue;
            if (child_base[idx] == orig_base[idx]) continue;
            if (v < orig_base[idx] || v >= orig_base[idx] + orig_size[idx])
                continue;
            v = child_base[idx] + (v - orig_base[idx]);
            memcpy(all + roff[i] + off, &v, 4);
        }
    }
}
