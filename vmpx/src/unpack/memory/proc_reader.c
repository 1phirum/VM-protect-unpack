/* proc_reader.c - one process handle, bounded chunks, explicit partial result
 *
 * On failure the caller must use out->read, not len. Bytes past out->read are
 * not written by this function. valid_span describes the readable extent from
 * addr at the time of the call; zero means the first page is not readable.
 */
#include "unpack/memory/proc_reader.h"
#include <string.h>

#define VMPX_READ_CHUNK (1u << 20)

int vmpx_proc_reader_open(vmpx_proc_reader_t* r, uint32_t pid) {
    if (!r || !pid) return -1;
    memset(r, 0, sizeof(*r));
    r->read_chunk = VMPX_READ_CHUNK;
    r->proc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE,
                          pid);
    if (!r->proc) {
        r->proc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
                              FALSE, pid);
    }
    if (!r->proc) return -1;
    r->pid = pid;
    return 0;
}

static uint64_t readable_span(HANDLE proc, uint64_t addr) {
    MEMORY_BASIC_INFORMATION mbi;
    memset(&mbi, 0, sizeof(mbi));
    if (!VirtualQueryEx(proc, (LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi)))
        return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    uint32_t p = mbi.Protect;
    if (p & PAGE_GUARD) return 0;
    switch (p & 0xFFu) {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        break;
    default:
        return 0;
    }
    uint64_t base = (uint64_t)(uintptr_t)mbi.BaseAddress;
    uint64_t end = base + (uint64_t)mbi.RegionSize;
    if (end < base || addr >= end) return 0;
    return end - addr;
}

int vmpx_proc_reader_read_ex(vmpx_proc_reader_t* r, uint64_t addr, void* buf,
                             size_t len, vmpx_read_result_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!r || !r->proc || !buf || !len) return -1;
    if (out) {
        out->addr = addr;
        out->requested = len;
        out->valid_span = readable_span(r->proc, addr);
    }

    uint8_t* p = (uint8_t*)buf;
    size_t left = len;
    uint64_t at = addr;
    uint64_t done = 0;
    while (left) {
        uint64_t span = readable_span(r->proc, at);
        if (!span) {
            if (out) {
                out->error = ERROR_NOACCESS;
                out->read = done;
                out->partial = done != 0 && done < len;
            }
            r->failed_reads++;
            return -1;
        }
        uint64_t chunk = r->read_chunk ? r->read_chunk : VMPX_READ_CHUNK;
        if (chunk > span) chunk = span;
        if (left < chunk) chunk = left;
        SIZE_T got = 0;
        BOOL ok = ReadProcessMemory(r->proc, (LPCVOID)(uintptr_t)at, p,
                                    (SIZE_T)chunk, &got);
        if (!ok || !got) {
            if (out) {
                out->error = ok ? ERROR_PARTIAL_COPY : GetLastError();
                out->read = done;
                out->partial = done != 0 && done < len;
            }
            r->failed_reads++;
            return -1;
        }
        p += got;
        at += got;
        done += got;
        left -= got;
        if (got < chunk) {
            if (out) {
                out->error = ERROR_PARTIAL_COPY;
                out->read = done;
                out->partial = done < len;
            }
            r->failed_reads++;
            return -1;
        }
    }

    r->total_read += done;
    if (out) out->read = done;
    return 0;
}

int vmpx_proc_reader_read(vmpx_proc_reader_t* r, uint64_t addr, void* buf,
                          size_t len) {
    vmpx_read_result_t rr;
    return vmpx_proc_reader_read_ex(r, addr, buf, len, &rr);
}

void vmpx_proc_reader_close(vmpx_proc_reader_t* r) {
    if (!r) return;
    if (r->proc) CloseHandle(r->proc);
    memset(r, 0, sizeof(*r));
}
