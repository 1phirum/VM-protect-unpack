/* report.c - drive live collectors and write technique-separated artifacts */
#include "vmpx.h"
#include "unpack/deobf/dynamic/control/control.h"
#include "unpack/deobf/dynamic/control/codec.h"
#include "unpack/deobf/dynamic/report/report.h"
#include "unpack/deobf/dynamic/report/loss_ledger.h"
#include "unpack/deobf/dynamic/session/session_bridge.h"
#include "unpack/deobf/dynamic/strings/runtime_strings.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CAPTURE_BYTES (256ull << 20)

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t page_size;
    uint32_t reserved;
} capture_hdr_t;

typedef struct {
    uint64_t addr;
    uint64_t seq;
    uint32_t size;
    uint32_t len;
    uint32_t crc32;
    uint32_t hash_algo;
    uint32_t flags;
    uint32_t event_type;
    uint32_t validity;
    uint32_t page_epoch;
} capture_rec_t;
#pragma pack(pop)

#define VMPX_CAP_PREVIEW_ONLY 1u
#define VMPX_CAP_LATER_REREAD 2u

typedef struct {
    FILE* events;
    FILE* pages;
    FILE* capture;
    FILE* exec;
    FILE* thread;
    FILE* vm;
    FILE* api;
    FILE* loss;
    dyn_strings_t* strings;
    uint64_t captured;
    uint64_t max_capture;
    uint32_t max_events;
    uint32_t events_seen;
    uint32_t reset_pre;   /* events drained before the reset zeroed the counter */
    uint32_t by_type[10];
    uint32_t by_algo[3];
    vmpx_loss_ledger_t ledge;
    uint32_t mem_records;
    uint32_t exec_records;
    uint32_t thread_records;
    uint32_t vm_records;
    uint32_t api_records;
    uint32_t read_fail;
    uint32_t shard_stalled[VMPX_DYN_MAX_PRODUCERS];
    uint32_t shard_invalid[VMPX_DYN_MAX_PRODUCERS];
    uint32_t stall_noted_seq[VMPX_DYN_MAX_PRODUCERS];
    uint32_t last_ack[VMPX_DYN_MAX_PRODUCERS];
} report_ctx_t;

static HANDLE g_proc = NULL;

static void ensure_dir(const char* path) {
    if (path && *path) CreateDirectoryA(path, NULL);
}

static void make_path(char* out, size_t cap, const char* dir, const char* name) {
    _snprintf_s(out, cap, _TRUNCATE, "%s\\%s", dir, name);
}

static FILE* open_w(const char* dir, const char* name) {
    char path[MAX_PATH * 2];
    make_path(path, sizeof(path), dir, name);
    FILE* f = NULL;
    fopen_s(&f, path, "wb");
    return f;
}

static int read_live(uint64_t addr, void* buf, uint32_t len) {
    if (!g_proc || !buf || !len) return -1;
    SIZE_T got = 0;
    BOOL ok = ReadProcessMemory(g_proc, (LPCVOID)(uintptr_t)addr, buf,
                                (SIZE_T)len, &got);
    return (ok && got == len) ? 0 : -1;
}

static const char* ev_name(uint32_t type) {
    switch (type) {
    case VMPX_DYN_EV_MEM:     return "mem";
    case VMPX_DYN_EV_EXEC:    return "exec";
    case VMPX_DYN_EV_THREAD:  return "thread";
    case VMPX_DYN_EV_WRITE:   return "write";
    case VMPX_DYN_EV_PROTECT: return "protect";
    case VMPX_DYN_EV_MARK:    return "mark";
    case VMPX_DYN_EV_ERROR:   return "error";
    case VMPX_DYN_EV_VM:      return "vm";
    case VMPX_DYN_EV_FREE:    return "free";
    default:                  return "event";
    }
}

static const char* mem_type(uint32_t type) {
    if (type == MEM_IMAGE) return "image";
    if (type == MEM_MAPPED) return "mapped";
    if (type == MEM_PRIVATE) return "private";
    return "unknown";
}

static void write_event_line(report_ctx_t* c, const vmpx_dyn_event_t* e) {
    if (!c->events) return;
    fprintf(c->events,
            "seq=%llu tid=%u type=%s addr=0x%llX size=0x%llX "
            "eip=0x%llX esp=0x%llX crc=0x%08X flags=0x%X len=%u aux=0x%X\n",
            (unsigned long long)e->seq, e->tid, ev_name(e->type),
            (unsigned long long)e->addr, (unsigned long long)e->size,
            (unsigned long long)e->eip, (unsigned long long)e->esp,
            e->crc32, e->flags, e->len, e->aux);
}

static void emit_bytes_ex(report_ctx_t* c, const vmpx_dyn_event_t* e,
                          const uint8_t* data, uint32_t len, const char* source,
                          dyn_string_origin_t origin) {
    if (!c->strings || !data || !len) return;
    dyn_strings_feed_ex(c->strings, data, len, e->addr, source, origin);
}

static void emit_bytes(report_ctx_t* c, const vmpx_dyn_event_t* e,
                       const uint8_t* data, uint32_t len, const char* source) {
    emit_bytes_ex(c, e, data, len, source, DYN_STRING_ORIGIN_UNKNOWN);
}

static const char* validity_name(uint32_t valid) {
    if (valid == VMPX_CAP_PREVIEW_ONLY) return "preview_only";
    if (valid == VMPX_CAP_LATER_REREAD) return "later_reread";
    return "unknown";
}

static void write_capture(report_ctx_t* c, const vmpx_dyn_event_t* e,
                          const uint8_t* data, uint32_t len,
                          uint32_t validity) {
    if (!c->capture || !data || !len) return;
    if (c->captured + len > c->max_capture) return;

    capture_rec_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.addr = e->addr;
    rec.seq = e->seq;
    rec.size = (uint32_t)e->size;
    rec.len = len;
    rec.crc32 = e->crc32;
    rec.flags = e->flags;
    rec.event_type = e->type;
    rec.validity = validity;
    rec.hash_algo = e->hash_algo;
    rec.page_epoch = e->page_epoch;
    fwrite(&rec, sizeof(rec), 1, c->capture);
    fwrite(data, 1, len, c->capture);
    c->captured += len;
    c->mem_records++;
}

static void process_mem(report_ctx_t* c, const vmpx_dyn_event_t* e,
                        const char* source) {
    uint32_t want = (uint32_t)e->size;
    if (want > VMPX_DYN_PAGE) want = VMPX_DYN_PAGE;
    if (want == 0) want = e->len;
    if (want > VMPX_DYN_PAGE) want = VMPX_DYN_PAGE;

    uint8_t page[VMPX_DYN_PAGE];
    const uint8_t* data = e->data;
    uint32_t len = e->len;
    uint32_t validity = e->len ? VMPX_CAP_PREVIEW_ONLY : 0;

    /* The producer preview belongs to the event epoch. A host reread is a
     * later observation and is labeled as such; it is never substituted
     * silently for the bytes the producer saw. */
    if (want && read_live(e->addr, page, want) == 0) {
        data = page;
        len = want;
        validity = VMPX_CAP_LATER_REREAD;
    } else if (want) {
        c->read_fail++;
    }

    if (c->pages) {
        fprintf(c->pages,
                "seq=%llu addr=0x%llX size=0x%llX type=%s crc=0x%08X "
                "flags=0x%X validity=%s hash_algo=%u page_epoch=%u\n",
                (unsigned long long)e->seq, (unsigned long long)e->addr,
                (unsigned long long)e->size, mem_type(e->aux), e->crc32,
                e->flags, validity_name(validity), e->hash_algo,
                e->page_epoch);
    }
    write_capture(c, e, data, len, validity);
    dyn_string_origin_t origin = DYN_STRING_ORIGIN_UNKNOWN;
    if (validity == VMPX_CAP_PREVIEW_ONLY) origin = DYN_STRING_ORIGIN_PREVIEW;
    else if (validity == VMPX_CAP_LATER_REREAD) origin = DYN_STRING_ORIGIN_REREAD;
    emit_bytes_ex(c, e, data, len, source, origin);
}

static void process_event(report_ctx_t* c, const vmpx_dyn_event_t* e) {
    if (e->type < 10) c->by_type[e->type]++;
    if (e->hash_algo < 3) c->by_algo[e->hash_algo]++;
    write_event_line(c, e);

    switch (e->type) {
    case VMPX_DYN_EV_MEM:
        process_mem(c, e, "mem");
        break;
    case VMPX_DYN_EV_WRITE:
        process_mem(c, e, "write");
        c->api_records++;
        if (c->api)
            fprintf(c->api, "%llu,write,0x%llX,0x%llX,0x%X,0x%X\n",
                    (unsigned long long)e->seq, (unsigned long long)e->addr,
                    (unsigned long long)e->size, e->aux, e->aux2);
        break;
    case VMPX_DYN_EV_PROTECT:
        c->api_records++;
        if (c->api)
            fprintf(c->api, "%llu,protect,0x%llX,0x%llX,0x%X,0x%X\n",
                    (unsigned long long)e->seq, (unsigned long long)e->addr,
                    (unsigned long long)e->size, e->aux, e->aux2);
        break;
    case VMPX_DYN_EV_EXEC:
        if (c->exec) {
            fprintf(c->exec, "%llu,%u,0x%llX,0x%llX,0x%X\n",
                    (unsigned long long)e->seq, e->tid,
                    (unsigned long long)e->eip,
                    (unsigned long long)e->esp, e->flags);
        }
        c->exec_records++;
        emit_bytes(c, e, e->data, e->len, "exec");
        break;
    case VMPX_DYN_EV_THREAD: {
        c->thread_records++;
        if (c->thread) {
            uint32_t code0 = 0, code1 = 0, stack0 = 0;
            if (e->len >= 8) memcpy(&code0, e->data, 4);
            if (e->len >= 12) memcpy(&code1, e->data + 4, 4);
            if (e->len >= 32 + 36 + 4) memcpy(&stack0, e->data + 32 + 36, 4);
            fprintf(c->thread,
                    "%llu,%u,0x%llX,0x%llX,0x%08X,0x%08X,0x%08X,0x%X,0x%X\n",
                    (unsigned long long)e->seq, e->aux,
                    (unsigned long long)e->eip, (unsigned long long)e->esp,
                    code0, code1, stack0, e->flags, e->aux2);
        }
        emit_bytes(c, e, e->data, e->len, "thread");
        break;
    }
    case VMPX_DYN_EV_VM: {
        c->vm_records++;
        if (c->vm) {
            uint32_t code0 = 0;
            if (e->len >= 4) memcpy(&code0, e->data, 4);
            fprintf(c->vm,
                    "%llu,%u,0x%llX,0x%llX,0x%X,0x%X,0x%08X\n",
                    (unsigned long long)e->seq, e->aux,
                    (unsigned long long)e->eip, (unsigned long long)e->esp,
                    e->flags, e->aux2, code0);
        }
        emit_bytes(c, e, e->data, e->len, "vm");
        break;
    }
    case VMPX_DYN_EV_FREE:
        c->mem_records++;
        if (c->pages)
            fprintf(c->pages,
                    "seq=%llu addr=0x%llX size=0x%llX type=%s crc=0x%08X "
                    "flags=0x%X validity=released hash_algo=%u page_epoch=%u\n",
                    (unsigned long long)e->seq, (unsigned long long)e->addr,
                    (unsigned long long)e->size, mem_type(e->aux), e->crc32,
                    e->flags, e->hash_algo, e->page_epoch);
        break;
    default:
        break;
    }
}

#define VMPX_DRAIN_BATCH 512

typedef struct {
    vmpx_dyn_event_t ev;
    uint32_t shard;
} drain_item_t;

static int drain_cmp(const void* a, const void* b) {
    const drain_item_t* x = (const drain_item_t*)a;
    const drain_item_t* y = (const drain_item_t*)b;
    if (x->ev.tick != y->ev.tick)
        return x->ev.tick < y->ev.tick ? -1 : 1;
    if (x->shard != y->shard) return x->shard < y->shard ? -1 : 1;
    if (x->ev.seq != y->ev.seq) return x->ev.seq < y->ev.seq ? -1 : 1;
    return 0;
}

/* Copy only release-published slots. The tail is advanced only for records
 * that were committed, so a delayed producer blocks its own shard without
 * exposing a partial slot. */
static uint32_t drain_ready(report_ctx_t* c, vmpx_dyn_ctl_t* ctl,
                            drain_item_t* batch, uint32_t cap) {
    uint32_t n = 0;
    uint32_t shards = ctl->shard_count;
    if (shards > VMPX_DYN_MAX_PRODUCERS) shards = VMPX_DYN_MAX_PRODUCERS;

    for (uint32_t i = 0; i < shards && n < cap; i++) {
        vmpx_dyn_shard_t* s = &ctl->shards[i];
        uint32_t head = s->head;
        uint32_t tail = s->tail;

        while (tail != head && n < cap) {
            uint32_t seq = tail + 1;
            vmpx_dyn_event_t* slot =
                &s->events[seq & (uint32_t)(VMPX_DYN_SHARD_EVENTS - 1)];
            uint32_t ready = slot->ready;
            if (ready != seq) {
                c->shard_stalled[i]++;
                /* One ledger record per distinct stalled sequence, not one
                 * per drain pass: a producer that stays unpublished would
                 * otherwise flood loss.jsonl at the poll rate. */
                if (c->stall_noted_seq[i] != seq) {
                    c->stall_noted_seq[i] = seq;
                    (void)vmpx_loss_ledger_note(&c->ledge, VMPX_LOSS_STALL,
                                                VMPX_LOSS_TYPE_UNKNOWN, 0,
                                                c->loss, i, seq);
                }
                break;
            }
            MemoryBarrier();
            if (slot->epoch != ctl->epoch || slot->seq != seq ||
                slot->producer != i) {
                c->shard_invalid[i]++;
                (void)vmpx_loss_ledger_note(&c->ledge, VMPX_LOSS_INVALID,
                                            slot->type, slot->flags,
                                            c->loss, i, seq);
                tail++;
                continue;
            }
            /* Decode through the explicit wire codec: a slot whose fields do
             * not fit the declared layout is a typed rejection, not a
             * reinterpreted struct. */
            if (codec_decode_event((const uint8_t*)(const void*)slot,
                                   (uint32_t)sizeof(vmpx_dyn_event_t),
                                   &batch[n].ev) != CODEC_OK) {
                c->shard_invalid[i]++;
                (void)vmpx_loss_ledger_note(&c->ledge, VMPX_LOSS_INVALID,
                                            slot->type, slot->flags,
                                            c->loss, i, seq);
                tail++;
                continue;
            }
            batch[n].shard = i;
            n++;
            tail++;
        }

        s->tail = tail;
        c->last_ack[i] = tail;
    }

    if (n > 1) qsort(batch, n, sizeof(batch[0]), drain_cmp);
    return n;
}

static uint32_t drain_and_process(report_ctx_t* c, vmpx_dyn_ctl_t* ctl,
                                  drain_item_t* batch) {
    if (c->events_seen >= c->max_events) return 0;
    uint32_t room = c->max_events - c->events_seen;
    if (room > VMPX_DRAIN_BATCH) room = VMPX_DRAIN_BATCH;

    uint32_t n = drain_ready(c, ctl, batch, room);
    for (uint32_t i = 0; i < n; i++) process_event(c, &batch[i].ev);
    c->events_seen += n;
    return n;
}

static uint32_t parse_mode(const char* s) {
    if (!s || !*s) return VMPX_DYN_MODE_ALL;
    uint32_t m = 0;
    for (const char* p = s; *p; p++) {
        if (*p == 'm' || *p == 'M') m |= VMPX_DYN_MODE_MEM;
        else if (*p == 'e' || *p == 'E') m |= VMPX_DYN_MODE_EXEC;
        else if (*p == 't' || *p == 'T') m |= VMPX_DYN_MODE_THREAD;
        else if (*p == 'a' || *p == 'A') m |= VMPX_DYN_MODE_API;
    }
    return m ? m : VMPX_DYN_MODE_ALL;
}

static int agent_dll_path(const char* override, wchar_t* out, size_t cap) {
    return agent_materialize(override, out, cap);
}

static HANDLE wait_mapping(uint32_t pid, vmpx_dyn_ctl_t** out, int timeout_ms) {
    wchar_t name[96];
    swprintf_s(name, 96, L"Local\\VMPX_DYN_%u", pid);
    DWORD start = GetTickCount();
    while ((DWORD)(GetTickCount() - start) < (DWORD)timeout_ms) {
        HANDLE map = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
        if (map) {
            vmpx_dyn_ctl_t* ctl = (vmpx_dyn_ctl_t*)MapViewOfFile(
                map, FILE_MAP_ALL_ACCESS, 0, 0, VMPX_DYN_MAP_SIZE);
            if (ctl && ctl->magic == VMPX_DYN_MAGIC &&
                ctl->version == VMPX_DYN_VERSION) {
                *out = ctl;
                return map;
            }
            if (ctl) UnmapViewOfFile(ctl);
            CloseHandle(map);
        }
        Sleep(100);
    }
    return NULL;
}

/* Host-side bounded reset rendezvous. The host does not link the agent's
 * control.c, so the ritual is mirrored here against the mapped control block:
 * advance the epoch, then wait bounded for every registered owner to publish
 * departure (`reset_ack == epoch`) or be observed drained (`head == tail`).
 * Owners that settle neither way before the deadline are returned in
 * `out_shard`/`out_tid` (up to `cap`) for the loss ledger; the caller then
 * clears the shards with host_reset_clear. Neither call allocates. */
static uint32_t host_reset_wait(vmpx_dyn_ctl_t* ctl, uint32_t timeout_ms,
                                uint32_t* out_shard, uint32_t* out_tid,
                                uint32_t cap) {
    uint32_t epoch =
        (uint32_t)InterlockedIncrement((volatile LONG*)&ctl->epoch);
    DWORD start = GetTickCount();
    if (!timeout_ms) timeout_ms = VMPX_DYN_RESET_WAIT_MS;

    for (;;) {
        uint32_t pending = 0;
        for (uint32_t i = 0; i < VMPX_DYN_MAX_PRODUCERS; i++) {
            vmpx_dyn_shard_t* s = &ctl->shards[i];
            if (!s->owner_tid) continue;
            if (s->reset_ack == epoch) continue;
            if (s->head == s->tail) continue;
            if (out_shard && out_tid && pending < cap) {
                out_shard[pending] = i;
                out_tid[pending] = s->owner_tid;
            }
            pending++;
        }
        if (!pending) return 0;
        if ((uint32_t)(GetTickCount() - start) >= timeout_ms) return pending;
        Sleep(5);
    }
}

static void host_reset_clear(vmpx_dyn_ctl_t* ctl) {
    for (uint32_t i = 0; i < VMPX_DYN_MAX_PRODUCERS; i++) {
        vmpx_dyn_shard_t* s = &ctl->shards[i];
        InterlockedExchange((volatile LONG*)&s->owner_tid, 0);
        s->reset_ack = 0;
        s->epoch = 0;
        s->head = 0;
        s->tail = 0;
        s->dropped = 0;
        s->committed = 0;
    }
    MemoryBarrier();
}

int dyn_report_run(int argc, char** argv) {
    const char* out = arg_get(argc, argv, "--out");
    if (!out || !*out) {
        printf("[-] usage: vmpx deobf [--pid N | --name exe] --out <dir> "
               "[--profile <file>] [--seconds N] [--mode met a] "
               "[--mem-ms N] [--thread-ms N] [--addr 0xADDR --size N] "
               "[--no-strings] [--max-mb N] [--all-events]\n");
        return 2;
    }
    ensure_dir(out);

    vmpx_profile_t profile;
    vmpx_profile_defaults(&profile);
    char perr[256];
    const char* profile_path = arg_get(argc, argv, "--profile");
    if (profile_path && *profile_path) {
        if (vmpx_profile_load(profile_path, &profile, perr, sizeof(perr)) !=
            0) {
            printf("[-] %s\n", perr);
            return 2;
        }
    }
    if (vmpx_profile_validate(&profile, perr, sizeof(perr)) != 0) {
        printf("[-] %s\n", perr);
        return 2;
    }
    if (!arg_get(argc, argv, "--pid") && !arg_get(argc, argv, "--name") &&
        !arg_get(argc, argv, "--exe")) {
        printf("[-] deobf requires --pid, --name, or --exe\n");
        return 2;
    }

    uint32_t pid = 0;
    if (resolve_pid(argc, argv, &pid) != 0)
        return vmpx_run_status_exit(VMPX_RUN_CAPTURE_FAILED);

    vmpx_dyn_session_t dyn_sess;
    if (vmpx_dyn_session_start(&dyn_sess, pid, out, &profile, perr,
                               sizeof(perr)) != 0) {
        printf("[-] %s\n", perr);
        return vmpx_run_status_exit(VMPX_RUN_CAPTURE_FAILED);
    }

    enable_debug_privilege();
    wchar_t agent[MAX_PATH] = { 0 };
    if (agent_dll_path(arg_get(argc, argv, "--dll"), agent, MAX_PATH) != 0) {
        printf("[-] cannot resolve vmpxagent.dll\n");
        vmpx_dyn_session_fail(&dyn_sess, perr, sizeof(perr));
        return vmpx_run_status_exit(VMPX_RUN_CAPTURE_FAILED);
    }

    vmpx_dyn_ctl_t* ctl = NULL;
    HANDLE map = wait_mapping(pid, &ctl, 200);
    if (!ctl) {
        printf("[*] agent mapping absent; injecting %ls\n", agent);
        if (inject_dll(pid, agent) != 0) {
            printf("[-] agent injection failed\n");
            vmpx_dyn_session_fail(&dyn_sess, perr, sizeof(perr));
            return vmpx_run_status_exit(VMPX_RUN_CAPTURE_FAILED);
        }
        map = wait_mapping(pid, &ctl, 4000);
    }
    if (!ctl) {
        printf("[-] no dynamic deobf mapping after injection\n");
        vmpx_dyn_session_fail(&dyn_sess, perr, sizeof(perr));
        return vmpx_run_status_exit(VMPX_RUN_CAPTURE_FAILED);
    }
    if (ctl->header_size != sizeof(vmpx_dyn_ctl_t) ||
        ctl->record_size != sizeof(vmpx_dyn_event_t) ||
        ctl->pointer_width != VMPX_DYN_POINTER_WIDTH ||
        ctl->endianness != VMPX_DYN_ENDIAN ||
        ctl->shard_count != VMPX_DYN_MAX_PRODUCERS ||
        ctl->shard_events != VMPX_DYN_SHARD_EVENTS) {
        printf("[-] dynamic deobf protocol layout mismatch "
               "(header=%u/%u record=%u/%u ptr=%u/%u endian=0x%08X)\n",
               ctl->header_size, (uint32_t)sizeof(vmpx_dyn_ctl_t),
               ctl->record_size, (uint32_t)sizeof(vmpx_dyn_event_t),
               ctl->pointer_width, VMPX_DYN_POINTER_WIDTH,
               ctl->endianness);
        UnmapViewOfFile(ctl);
        CloseHandle(map);
        vmpx_dyn_session_fail(&dyn_sess, perr, sizeof(perr));
        return vmpx_run_status_exit(VMPX_RUN_UNSUPPORTED);
    }

    g_proc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
                         FALSE, pid);
    if (!g_proc) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        UnmapViewOfFile(ctl);
        CloseHandle(map);
        vmpx_dyn_session_fail(&dyn_sess, perr, sizeof(perr));
        return vmpx_run_status_exit(VMPX_RUN_CAPTURE_FAILED);
    }

    if (vmpx_session_enter(&dyn_sess.session, VMPX_SESSION_OBSERVING, perr,
                           sizeof(perr)) != 0) {
        printf("[-] %s\n", perr);
        CloseHandle(g_proc);
        g_proc = NULL;
        UnmapViewOfFile(ctl);
        CloseHandle(map);
        vmpx_dyn_session_fail(&dyn_sess, perr, sizeof(perr));
        return vmpx_run_status_exit(VMPX_RUN_INTERNAL_ERROR);
    }

    char d1[MAX_PATH * 2], d2[MAX_PATH * 2], d3[MAX_PATH * 2], d4[MAX_PATH * 2];
    char d5[MAX_PATH * 2], d6[MAX_PATH * 2];
    _snprintf_s(d1, sizeof(d1), _TRUNCATE, "%s\\events", out);
    _snprintf_s(d2, sizeof(d2), _TRUNCATE, "%s\\memdelta", out);
    _snprintf_s(d3, sizeof(d3), _TRUNCATE, "%s\\codecov", out);
    _snprintf_s(d4, sizeof(d4), _TRUNCATE, "%s\\threadctx", out);
    _snprintf_s(d5, sizeof(d5), _TRUNCATE, "%s\\vmtrans", out);
    _snprintf_s(d6, sizeof(d6), _TRUNCATE, "%s\\apievents", out);
    ensure_dir(d1); ensure_dir(d2); ensure_dir(d3); ensure_dir(d4);
    ensure_dir(d5); ensure_dir(d6);
    char ds[MAX_PATH * 2];
    _snprintf_s(ds, sizeof(ds), _TRUNCATE, "%s\\strings", out);
    ensure_dir(ds);

    report_ctx_t c;
    memset(&c, 0, sizeof(c));
    vmpx_loss_ledger_init(&c.ledge);
    uint64_t max_mb = arg_has(argc, argv, "--max-mb")
                          ? arg_num(argc, argv, "--max-mb", 0)
                          : profile.host_budget_mib;
    if (!max_mb) max_mb = profile.host_budget_mib;
    c.max_capture = max_mb << 20;
    if (c.max_capture > MAX_CAPTURE_BYTES) c.max_capture = MAX_CAPTURE_BYTES;
    c.max_events = (uint32_t)arg_num(argc, argv, "--max-events", 200000);
    if (!c.max_events) c.max_events = 200000;

    drain_item_t* batch =
        (drain_item_t*)malloc(sizeof(drain_item_t) * VMPX_DRAIN_BATCH);
    if (!batch) {
        printf("[-] cannot allocate event drain buffer\n");
        vmpx_dyn_session_fail(&dyn_sess, perr, sizeof(perr));
        return vmpx_run_status_exit(VMPX_RUN_INTERNAL_ERROR);
    }

    char p[MAX_PATH * 2];
    _snprintf_s(p, sizeof(p), _TRUNCATE, "%s\\events.txt", d1);
    fopen_s(&c.events, p, "wb");
    _snprintf_s(p, sizeof(p), _TRUNCATE, "%s\\pages.txt", d2);
    fopen_s(&c.pages, p, "wb");
    _snprintf_s(p, sizeof(p), _TRUNCATE, "%s\\capture.bin", d2);
    fopen_s(&c.capture, p, "wb");
    _snprintf_s(p, sizeof(p), _TRUNCATE, "%s\\exec.csv", d3);
    fopen_s(&c.exec, p, "wb");
    _snprintf_s(p, sizeof(p), _TRUNCATE, "%s\\samples.csv", d4);
    fopen_s(&c.thread, p, "wb");
    _snprintf_s(p, sizeof(p), _TRUNCATE, "%s\\transitions.csv", d5);
    fopen_s(&c.vm, p, "wb");
    _snprintf_s(p, sizeof(p), _TRUNCATE, "%s\\events.csv", d6);
    fopen_s(&c.api, p, "wb");
    _snprintf_s(p, sizeof(p), _TRUNCATE, "%s\\loss.jsonl", d1);
    fopen_s(&c.loss, p, "wb");
    _snprintf_s(p, sizeof(p), _TRUNCATE, "%s\\strings.txt", ds);
    if (!arg_has(argc, argv, "--no-strings"))
        c.strings = dyn_strings_open(p);

    if (c.capture) {
        capture_hdr_t h;
        h.magic = 0x42445856u; /* VXDB */
        h.version = 3;
        h.page_size = VMPX_DYN_PAGE;
        h.reserved = 0;
        fwrite(&h, sizeof(h), 1, c.capture);
    }
    if (c.pages)
        fputs("seq,addr,size,type,crc,flags,validity,hash_algo,page_epoch\n",
              c.pages);
    if (c.exec) fputs("seq,tid,eip,esp,flags\n", c.exec);
    if (c.thread) fputs("seq,tid,eip,esp,code0,code1,stack0,flags,aux\n", c.thread);
    if (c.vm) fputs("seq,tid,eip,esp,flags,transition,code0\n", c.vm);
    if (c.api) fputs("seq,type,addr,size,oldprot,newprot\n", c.api);

    ctl->active = 0;
    int keep = arg_has(argc, argv, "--all-events") ? 1 : 0;
    ctl->mode = parse_mode(arg_get(argc, argv, "--mode"));
    ctl->mem_interval_ms = (uint32_t)arg_num(argc, argv, "--mem-ms", 1000);
    ctl->thread_interval_ms = (uint32_t)arg_num(argc, argv, "--thread-ms", 25);
    if (ctl->mem_interval_ms < 100) ctl->mem_interval_ms = 100;
    if (ctl->thread_interval_ms < 5) ctl->thread_interval_ms = 5;

    /* Bounded reset rendezvous replaces the fixed pause. Anything already
     * published is drained first so a quiet owner is observed drained rather
     * than mistaken for a stalled one; an owner that neither acknowledges the
     * new epoch nor drains before the deadline is recorded, then cleared --
     * never cleared silently. */
    if (!keep) {
        uint32_t unsettled_shard[VMPX_DYN_MAX_PRODUCERS];
        uint32_t unsettled_tid[VMPX_DYN_MAX_PRODUCERS];
        uint32_t pre = c.events_seen;
        (void)drain_and_process(&c, ctl, batch);
        /* Anything the agent published before this attach belongs to the
         * session. It is counted here because the reset below zeroes the
         * producer-side total the summary otherwise reports. */
        c.reset_pre += c.events_seen - pre;
        uint32_t unsettled_n =
            host_reset_wait(ctl, VMPX_DYN_RESET_WAIT_MS,
                            unsettled_shard, unsettled_tid,
                            VMPX_DYN_MAX_PRODUCERS);
        for (uint32_t i = 0; i < unsettled_n; i++)
            (void)vmpx_loss_ledger_note(&c.ledge, VMPX_LOSS_STALL,
                                        VMPX_LOSS_TYPE_UNKNOWN, 0, c.loss,
                                        unsettled_shard[i], 0);
        host_reset_clear(ctl);
        ctl->dropped = 0;
        ctl->total = 0;
        ctl->producer_overflow = 0;
        ctl->reentrant = 0;
    }
    ctl->range_count = 0;

    uint64_t addr = arg_num(argc, argv, "--addr", 0);
    uint64_t size = arg_num(argc, argv, "--size", 0);
    if (addr) {
        ctl->range_base[0] = addr;
        ctl->range_size[0] = size ? size : VMPX_DYN_PAGE;
        ctl->range_count = 1;
    }

    wchar_t evt_name[96];
    swprintf_s(evt_name, 96, L"Local\\VMPX_DYN_EVT_%u", pid);
    HANDLE evt = OpenEventW(EVENT_MODIFY_STATE, FALSE, evt_name);
    MemoryBarrier();
    ctl->active = 1;
    if (evt) SetEvent(evt);

    uint64_t seconds = arg_num(argc, argv, "--seconds", 20);
    if (!seconds) seconds = 20;
    uint64_t deadline = GetTickCount64() + seconds * 1000;

    while (GetTickCount64() < deadline && c.events_seen < c.max_events) {
        (void)drain_and_process(&c, ctl, batch);
        if (!proc_alive(pid)) break;
        Sleep(15);
    }

    ctl->active = 0;
    if (evt) SetEvent(evt);
    Sleep(50);

    /* Final drain: committed records that were published before the stop
     * flag still belong to the capture. Uncommitted slots are never read. */
    uint64_t drain_deadline = GetTickCount64() + 1000;
    uint32_t empty_passes = 0;
    while (GetTickCount64() < drain_deadline &&
           c.events_seen < c.max_events) {
        uint32_t n = drain_and_process(&c, ctl, batch);
        if (!n) {
            empty_passes++;
            /* Bounded stall retirement: with the collectors stopped, a full
             * drain pass that recovers nothing for 100 ms cannot recover
             * anything later, so waiting out the deadline is waste. */
            if (empty_passes >= 20) break;
            if (GetTickCount64() + 1 >= drain_deadline) break;
            Sleep(5);
        } else {
            empty_passes = 0;
        }
    }

    uint32_t dropped = ctl->dropped;
    uint32_t mem_pages = ctl->mem_pages;
    uint32_t mem_changed = ctl->mem_changed;
    uint32_t exec_pages = ctl->exec_pages;
    uint32_t exec_hits = ctl->exec_hits;
    uint32_t thread_samples = ctl->thread_samples;
    uint64_t image_base = ctl->image_base;
    uint32_t image_size = ctl->image_size;
    uint32_t flags = ctl->flags;
    uint32_t mem_ticks = ctl->mem_ticks;
    uint32_t exec_ticks = ctl->exec_ticks;
    uint32_t thread_ticks = ctl->thread_ticks;
    uint32_t mem_ranges = ctl->mem_ranges;
    uint32_t mem_errors = ctl->mem_errors;
    uint32_t strings = dyn_strings_count(c.strings);
    dyn_strings_stats_t sstats;
    memset(&sstats, 0, sizeof(sstats));
    (void)dyn_strings_get_stats(c.strings, &sstats);
    uint32_t overflow = ctl->producer_overflow;
    uint32_t reentrant = ctl->reentrant;
    uint32_t stalled = 0, invalid = 0, shard_dropped = 0;
    for (uint32_t i = 0; i < VMPX_DYN_MAX_PRODUCERS; i++) {
        stalled += c.shard_stalled[i];
        invalid += c.shard_invalid[i];
        shard_dropped += ctl->shards[i].dropped;
    }

    if (c.loss) {
        for (uint32_t i = 0; i < VMPX_DYN_MAX_PRODUCERS; i++) {
            vmpx_dyn_shard_t* s = &ctl->shards[i];
            fprintf(c.loss,
                    "{\"shard\":%u,\"owner\":%u,\"head\":%u,\"ack\":%u,"
                    "\"committed\":%u,\"dropped\":%u,\"stalled\":%u,"
                    "\"invalid\":%u}\n",
                    i, s->owner_tid, s->head, s->tail, s->committed,
                    s->dropped, c.shard_stalled[i], c.shard_invalid[i]);
        }
        vmpx_loss_ledger_add(&c.ledge, VMPX_LOSS_DROP, VMPX_LOSS_TYPE_UNKNOWN,
                             0, dropped);
        vmpx_loss_transport_t lt;
        memset(&lt, 0, sizeof(lt));
        lt.total = ctl->total + c.reset_pre;
        lt.events = c.events_seen;
        lt.dropped = dropped;
        lt.shard_dropped = shard_dropped;
        lt.overflow = overflow;
        lt.reentrant = reentrant;
        lt.stalled = stalled;
        lt.invalid = invalid;
        vmpx_loss_ledger_global(c.loss, &c.ledge, &lt);
    }

    vmpx_session_refresh_modules(&dyn_sess.session);
    vmpx_session_refresh_regions(&dyn_sess.session);

    const char* ended = "timeout";
    if (c.events_seen >= c.max_events) ended = "limit";
    else if (!proc_alive(pid)) ended = "exited";
    uint32_t sess_modules = dyn_sess.session.module_count;
    uint32_t sess_regions = dyn_sess.session.regions.count;
    char sess_id[VMPX_SESSION_ID_CAP];
    _snprintf_s(sess_id, sizeof(sess_id), _TRUNCATE, "%s", dyn_sess.session.id.id);

    char sum_path[MAX_PATH * 2];
    _snprintf_s(sum_path, sizeof(sum_path), _TRUNCATE, "%s\\summary.txt", out);
    FILE* sf = NULL;
    fopen_s(&sf, sum_path, "wb");
    if (sf) {
        fprintf(sf, "VMPX dynamic deobfuscation summary\n");
        fprintf(sf, "pid=%u image_base=0x%llX image_size=0x%X page_size=0x%X\n",
                pid, (unsigned long long)image_base, image_size, VMPX_DYN_PAGE);
        fprintf(sf, "session_id=%s modules=%u regions=%u profile=%s ended=%s\n",
                sess_id, sess_modules, sess_regions,
                profile.source_path[0] ? profile.source_path : "default",
                ended);
        fprintf(sf,
                "flags=0x%X mem_ticks=%u exec_ticks=%u "
                "thread_ticks=%u\n",
                flags, mem_ticks, exec_ticks, thread_ticks);
        fprintf(sf, "events=%u dropped=%u strings=%u captured=%llu\n",
                c.events_seen, dropped, strings,
                (unsigned long long)c.captured);
        fprintf(sf,
                "transport_total=%u shard_dropped=%u overflow=%u reentrant=%u "
                "stalled=%u invalid=%u\n",
                ctl->total + c.reset_pre, shard_dropped, overflow, reentrant,
                stalled, invalid);
        fprintf(sf, "mem_pages=%u mem_changed=%u mem_records=%u read_fail=%u\n",
                mem_pages, mem_changed, c.mem_records, c.read_fail);
        fprintf(sf, "mem_ranges=%u mem_errors=%u\n", mem_ranges, mem_errors);
        fprintf(sf,
                "strings_feeds=%llu bytes_in=%llu entries=%llu dup=%llu "
                "dup_origin=%llu truncated=%llu\n",
                (unsigned long long)sstats.feeds,
                (unsigned long long)sstats.bytes_in,
                (unsigned long long)sstats.entries,
                (unsigned long long)sstats.dup,
                (unsigned long long)sstats.dup_origin,
                (unsigned long long)sstats.truncated);
        fprintf(sf,
                "strings_origin preview=%llu reread=%llu unknown=%llu "
                "confirmed_preview=%llu confirmed_reread=%llu\n",
                (unsigned long long)sstats.origin_seen[DYN_STRING_ORIGIN_PREVIEW],
                (unsigned long long)sstats.origin_seen[DYN_STRING_ORIGIN_REREAD],
                (unsigned long long)sstats.origin_seen[DYN_STRING_ORIGIN_UNKNOWN],
                (unsigned long long)sstats.origin_confirmed[DYN_STRING_ORIGIN_PREVIEW],
                (unsigned long long)sstats.origin_confirmed[DYN_STRING_ORIGIN_REREAD]);
        fprintf(sf,
                "strings_reject short=%llu noalpha=%llu binary=%llu "
                "null=%llu empty=%llu cap_entries=%llu cap_bytes=%llu "
                "table_full=%llu\n",
                (unsigned long long)sstats.reject_short,
                (unsigned long long)sstats.reject_noalpha,
                (unsigned long long)sstats.reject_binary,
                (unsigned long long)sstats.reject_null,
                (unsigned long long)sstats.reject_empty,
                (unsigned long long)sstats.cap_entries,
                (unsigned long long)sstats.cap_bytes,
                (unsigned long long)sstats.table_full);
        fprintf(sf, "exec_pages=%u exec_hits=%u exec_records=%u\n",
                exec_pages, exec_hits, c.exec_records);
        fprintf(sf, "thread_samples=%u thread_records=%u\n",
                thread_samples, c.thread_records);
        fprintf(sf, "vm_records=%u api_records=%u\n",
                c.vm_records, c.api_records);
        for (uint32_t i = 1; i < 10; i++)
            fprintf(sf, "type_%s=%u\n", ev_name(i), c.by_type[i]);
        fprintf(sf, "hash_algo fnv1a32=%u crc32=%u none=%u\n",
                c.by_algo[VMPX_HASH_FNV1A32], c.by_algo[VMPX_HASH_CRC32],
                c.by_algo[VMPX_HASH_NONE]);
        fclose(sf);
    }

    if (c.events) fclose(c.events);
    if (c.pages) fclose(c.pages);
    if (c.capture) fclose(c.capture);
    if (c.exec) fclose(c.exec);
    if (c.thread) fclose(c.thread);
    if (c.vm) fclose(c.vm);
    if (c.api) fclose(c.api);
    if (c.loss) fclose(c.loss);
    dyn_strings_close(c.strings);
    free(batch);

    if (evt) CloseHandle(evt);
    if (g_proc) CloseHandle(g_proc);
    g_proc = NULL;
    UnmapViewOfFile(ctl);
    CloseHandle(map);

    int finish_rc = vmpx_dyn_session_finish(&dyn_sess, perr, sizeof(perr));
    printf("STATUS deobf-dynamic pid=%u session=%s ended=%s events=%u mem=%u "
           "exec=%u threads=%u vm=%u api=%u strings=%u dropped=%u manifest=%s\n",
           pid, sess_id, ended, c.events_seen, mem_changed, exec_hits,
           thread_samples, c.vm_records, c.api_records, strings, dropped,
           finish_rc == 0 ? "ok" : "failed");
    if (finish_rc != 0) {
        printf("[-] session: %s\n", perr);
        return vmpx_run_status_exit(VMPX_RUN_INTERNAL_ERROR);
    }
    if (strcmp(ended, "exited") == 0 && c.events_seen == 0)
        return vmpx_run_status_exit(VMPX_RUN_PROCESS_EXITED);
    return 0;
}
