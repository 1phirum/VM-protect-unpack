/* dump.c - streamed live image dump (L2)
 *
 * A mapped 490 MB image used to be copied into a 490 MB heap buffer before it
 * hit disk. This path keeps peak commit at 4 MB: one process handle feeds a
 * bounded chunk buffer, and a buffered writer flushes it to the target file.
 * Unreadable chunks are zero-filled and counted; the output is always exactly
 * the requested image size.
 */
#include "vmpx.h"
#include "unpack/mempe.h"
#include "unpack/memory/file_writer.h"
#include "unpack/memory/proc_reader.h"
#include <stdlib.h>
#include <string.h>

int dump_image(uint32_t pid, uint64_t base, uint32_t size, const char* out,
               uint64_t max_bytes, vmpx_dump_meta_t* meta) {
    mempe_t m;
    if (mempe_read(pid, base, &m) != 0) {
        printf("[-] no PE header at 0x%llX\n", (unsigned long long)base);
        return -1;
    }
    if (!base) {
        printf("[-] image base is zero\n");
        return -1;
    }

    uint64_t dump_size = size ? size : m.size_image;
    if (!dump_size) dump_size = m.size_image;
    if (!dump_size) {
        printf("[-] image size unknown\n");
        return -1;
    }
    if (max_bytes && dump_size > max_bytes) {
        printf("[!] image is %llu MB, capping to %llu MB\n",
               (unsigned long long)(dump_size >> 20),
               (unsigned long long)(max_bytes >> 20));
        dump_size = max_bytes;
    }

    vmpx_writer_t writer;
    if (vmpx_writer_open(&writer, out, 4u << 20) != 0) {
        printf("[-] cannot create %s\n", out);
        return -1;
    }
    vmpx_proc_reader_t reader;
    if (vmpx_proc_reader_open(&reader, pid) != 0) {
        printf("[-] OpenProcess failed (%lu)\n", GetLastError());
        vmpx_writer_close(&writer);
        DeleteFileA(out);
        return -1;
    }

    const uint64_t chunk = 4u << 20;
    uint8_t* buf = (uint8_t*)malloc((size_t)chunk);
    if (!buf) {
        vmpx_proc_reader_close(&reader);
        vmpx_writer_close(&writer);
        DeleteFileA(out);
        return -1;
    }

    uint64_t done = 0;
    uint64_t failures = 0;
    int ok = 1;
    while (done < dump_size) {
        uint64_t left = dump_size - done;
        size_t want = (size_t)(left > chunk ? chunk : left);
        if (vmpx_proc_reader_read(&reader, base + done, buf, want) != 0) {
            failures++;
            printf("[!] read failed at +0x%llX, zero-filling 0x%zX bytes\n",
                   (unsigned long long)done, want);
            memset(buf, 0, want);
        }
        if (vmpx_writer_write(&writer, buf, want) != 0) {
            ok = 0;
            break;
        }
        done += want;
        if ((done & 0x3FFFFFF) == 0)
            printf("[*] %llu / %llu MB\n",
                   (unsigned long long)(done >> 20),
                   (unsigned long long)(dump_size >> 20));
    }

    free(buf);
    vmpx_proc_reader_close(&reader);
    if (vmpx_writer_close(&writer) != 0) ok = 0;
    if (!ok) {
        DeleteFileA(out);
        printf("[-] write failed for %s\n", out);
        return -1;
    }

    if (meta) {
        memset(meta, 0, sizeof(*meta));
        meta->magic = VMPX_DUMP_MAGIC;
        meta->version = VMPX_DUMP_VERSION;
        meta->pid = pid;
        meta->module_size = size;
        meta->base = base;
        meta->dump_size = dump_size;
        meta->image_size = m.size_image;
    }

    printf("[+] dumped %llu bytes to %s (read failures: %llu)\n",
           (unsigned long long)dump_size, out, (unsigned long long)failures);
    return 0;
}
