/* peb.c - PEB sanitize and loader-list unlink (L1)
 *
 * x86 PEB offsets: BeingDebugged 0x02, Ldr 0x0C, NtGlobalFlag 0x68. Heap flags
 * are left alone: the segment heap on modern Windows does not share the legacy
 * layout, and a wrong write there costs more than the check it defeats.
 */
#include "trace/agent.h"
#include <intrin.h>

typedef struct LIST {
    struct LIST* flink;
    struct LIST* blink;
} LIST;

unsigned trace_clean_peb(void) {
    BYTE* peb = (BYTE*)__readfsdword(0x30);
    if (!peb) return 0;
    peb[0x02] = 0;
    *(DWORD*)(peb + 0x68) = 0;
    return (unsigned)(uintptr_t)peb;
}

int trace_unlink_self(HMODULE self) {
    BYTE* peb = (BYTE*)__readfsdword(0x30);
    if (!peb) return 0;
    BYTE* ldr = *(BYTE**)(peb + 0x0C);
    if (!ldr) return 0;

    LIST* head = (LIST*)(ldr + 0x0C);          /* InLoadOrderModuleList */
    LIST* it = head->flink;
    while (it != head) {
        BYTE* entry = (BYTE*)it;               /* link is at entry+0 */
        if (*(HMODULE*)(entry + 0x18) == self) {
            LIST* links[3] = {
                (LIST*)(entry + 0x00),
                (LIST*)(entry + 0x08),
                (LIST*)(entry + 0x10)
            };
            for (int i = 0; i < 3; i++) {
                links[i]->blink->flink = links[i]->flink;
                links[i]->flink->blink = links[i]->blink;
                links[i]->flink = links[i];
                links[i]->blink = links[i];
            }
            return 1;
        }
        it = it->flink;
    }
    return 0;
}
