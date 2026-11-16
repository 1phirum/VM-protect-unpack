/* restore_input_test.c - snapshot input, TEB lookup and PE TLS discovery
 *
 * No target process is created. The test writes a minimal packed snapshot,
 * verifies CRC handling and bounds, then checks that the rebuilt image's TLS
 * index is discovered from its PE TLS directory rather than a literal.
 */
#include "unpack/snapshot/restore_int.h"

static int failures = 0;

#define CHECK(cond) do {                                              \
    if (!(cond)) {                                                    \
        printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);         \
        failures++;                                                   \
    }                                                                 \
} while (0)

static int write_snap(const char* path, uint64_t base, uint32_t size,
                      const uint8_t* payload, int bad_crc) {
    vmpx_snap_hdr_t h;
    memset(&h, 0, sizeof(h));
    h.magic = VMPX_SNAP_MAGIC;
    h.version = VMPX_SNAP_VERSION;
    h.region_count = 1;
    h.module_count = 0;
    h.data_offset = sizeof(h) + sizeof(vmpx_snap_region_t);

    vmpx_snap_region_t r;
    memset(&r, 0, sizeof(r));
    r.base = base;
    r.size = size;
    r.protect = PAGE_READWRITE;
    r.type = MEM_PRIVATE;
    r.crc32 = vmpx_crc32(payload, size) ^ (bad_crc ? 1u : 0u);

    FILE* f = NULL;
    if (fopen_s(&f, path, "wb") != 0 || !f) return -1;
    int ok = fwrite(&h, sizeof(h), 1, f) == 1 &&
             fwrite(&r, sizeof(r), 1, f) == 1 &&
             (size == 0 || fwrite(payload, size, 1, f) == 1);
    fclose(f);
    return ok ? 0 : -1;
}

int main(int argc, char** argv) {
    const char* snap = "tests\\_restore_input_tmp.vxsn";
    const char* ctx = "tests\\_restore_ctx_tmp.txt";
    remove(snap);
    remove(ctx);

    restore_input_t in;
    memset(&in, 0, sizeof(in));
    CHECK(restore_input_open("tests\\_missing.vxsn", &in) != 0);

    uint8_t payload[0x4000];
    memset(payload, 0, sizeof(payload));
    payload[0] = 0x11;
    payload[1] = 0x22;
    payload[2] = 0x33;
    payload[3] = 0x44;
    uint32_t teb = 0x23000;
    uint32_t pid = 0x1234;
    memcpy(payload + 0x3018, &teb, 4);
    memcpy(payload + 0x3020, &pid, 4);

    CHECK(write_snap(snap, 0x20000, 0x4000, payload, 0) == 0);
    CHECK(restore_input_open(snap, &in) == 0);
    CHECK(in.h.region_count == 1);
    CHECK(in.h.module_count == 0);
    CHECK(restore_peek_dword(&in, 0x20000) == 0x44332211u);
    CHECK(restore_peek_ptr(&in, 0x23FFC, 4) != NULL);
    CHECK(restore_peek_ptr(&in, 0x23FFF, 4) == NULL);
    CHECK(restore_peek_dword(&in, 0x23FFE) == 0);

    uint32_t teb_va = 0;
    const uint8_t* page = restore_find_teb_data(&in, pid, &teb_va);
    CHECK(page != NULL);
    CHECK(teb_va == teb);
    CHECK(restore_find_teb_data(&in, pid + 1, NULL) == NULL);

    uint32_t sb = 0, sl = 0;
    CHECK(restore_stack_bounds(&in, 0x21000, &sb, &sl) == 0);
    CHECK(sb == 0x24000 && sl == 0x20000);
    restore_input_close(&in);

    CHECK(write_snap(snap, 0x20000, 0x4000, payload, 1) == 0);
    CHECK(restore_input_open(snap, &in) != 0);

    CHECK(write_snap(snap, 0x20000, 0, payload, 0) == 0);
    CHECK(restore_input_open(snap, &in) != 0);

    FILE* f = NULL;
    if (fopen_s(&f, ctx, "w") == 0 && f) {
        fprintf(f, "eip=0x401000\nesp=0x20FF0\npid=1234\ntid=5678\n");
        fclose(f);
    }
    entry_ctx_t ec;
    CHECK(restore_read_entry_ctx(ctx, &ec) == 0);
    CHECK(ec.eip == 0x401000u);
    CHECK(ec.esp == 0x20FF0u);
    CHECK(ec.pid == 1234u);
    CHECK(ec.tid == 5678u);

    if (argc > 1) {
        restore_pe_t pe;
        CHECK(restore_pe_info(argv[1], &pe) == 0);
        CHECK(pe.image_base == 0x400000u);
        CHECK(pe.has_tls == 1);
        CHECK(pe.tls_index_rva == 0x14AFC3Cu);
    }

    remove(snap);
    remove(ctx);
    if (failures) {
        printf("restore_input_test: %d failure(s)\n", failures);
        return 1;
    }
    printf("restore_input_test: ok\n");
    return 0;
}
