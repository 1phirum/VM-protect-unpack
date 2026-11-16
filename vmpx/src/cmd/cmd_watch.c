/* cmd_watch.c - drive the in-agent memory guard and API event sink */
#include "vmpx.h"
#include "unpack/hook/watch.h"
#include "util/file.h"
#include "util/str.h"
#include <stdio.h>
#include <string.h>

static uint32_t parse_mode(const char* s) {
    uint32_t mode = 0;
    if (!s) return VMPX_WATCH_MODE_WRITE | VMPX_WATCH_MODE_EXEC;
    for (const char* p = s; *p; p++) {
        if (*p == 'r' || *p == 'R') mode |= VMPX_WATCH_MODE_READ;
        else if (*p == 'w' || *p == 'W') mode |= VMPX_WATCH_MODE_WRITE;
        else if (*p == 'x' || *p == 'X') mode |= VMPX_WATCH_MODE_EXEC;
    }
    return mode ? mode : (VMPX_WATCH_MODE_WRITE | VMPX_WATCH_MODE_EXEC);
}

static const char* ev_type(uint32_t t) {
    switch (t) {
    case VMPX_WATCH_EV_GUARD:   return "guard";
    case VMPX_WATCH_EV_PROTECT: return "protect";
    case VMPX_WATCH_EV_WRITE:   return "write";
    default:                    return "event";
    }
}

static const char* access_type(uint32_t a) {
    if (a == 0) return "read";
    if (a == 1) return "write";
    if (a == 8) return "exec";
    return "?";
}

/* Advance the shared tail only if the ring still belongs to the epoch this
 * poll round started under. A second reader (or an agent restart) that reset
 * the block in the meantime owns the counters now, and a stale store here
 * would drag tail back into the new run's range. */
static void publish_tail(vmpx_watch_ctl_t* ctl, uint32_t epoch, uint32_t tail) {
    if (ctl->epoch != epoch) return;
    MemoryBarrier();
    ctl->tail = tail;
}

int cmd_watch(int argc, char** argv) {
    uint32_t pid = 0;
    if (resolve_pid(argc, argv, &pid) != 0) return 1;

    wchar_t map_name[128];
    swprintf_s(map_name, 128, L"Local\\VMPX_WATCH_%u", pid);
    HANDLE map = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, map_name);
    if (!map) {
        printf("[-] watch: no agent mapping for pid %u; inject vmpxagent.dll first\n", pid);
        return 1;
    }
    vmpx_watch_ctl_t* ctl = (vmpx_watch_ctl_t*)MapViewOfFile(
        map, FILE_MAP_ALL_ACCESS, 0, 0, VMPX_WATCH_MAP_SIZE);
    if (!ctl) {
        CloseHandle(map);
        printf("[-] watch: MapViewOfFile failed (%lu)\n", GetLastError());
        return 1;
    }
    if (ctl->magic != VMPX_WATCH_MAGIC || ctl->version != VMPX_WATCH_VERSION ||
        ctl->capacity != VMPX_WATCH_MAX_EVENTS) {
        UnmapViewOfFile(ctl);
        CloseHandle(map);
        printf("[-] watch: agent watch block version or ring size mismatch\n");
        return 1;
    }
    vmpx_watch_event_t* events =
        (vmpx_watch_event_t*)((uint8_t*)ctl + sizeof(vmpx_watch_ctl_t));

    uint64_t addr = arg_num(argc, argv, "--addr", 0);
    uint64_t size = arg_num(argc, argv, "--size", 0);
    if (addr && !size) size = 0x1000;
    if (addr) {
        ctl->range_base[0] = addr;
        ctl->range_size[0] = size;
        ctl->range_count = 1;
    } else {
        ctl->range_count = 0;
    }
    ctl->mode = parse_mode(arg_get(argc, argv, "--mode"));
    /* Quiesce before resetting. Producers only enter while active is set; one
     * already inside log_event is caught by the epoch bump at the end of this
     * sequence, because no publication in flight can carry the new epoch. */
    ctl->active = 0;
    MemoryBarrier();
    /* Counters and seals first, epoch last. A producer that claimed a position
     * before the head store still carries the old epoch and is rejected; one
     * that claims after it can only see the new head, whatever epoch it read.
     * Bumping the epoch before the counters would instead let a producer claim
     * an old position and tag it with the new run's epoch. */
    ctl->head = 0;
    ctl->tail = 0;
    ctl->dropped = 0;
    ctl->stalled = 0;
    ctl->total = 0;
    for (uint32_t i = 0; i < VMPX_WATCH_MAX_EVENTS; i++)
        events[i].seal = VMPX_WATCH_GEN_IDLE;
    MemoryBarrier();
    {
        uint32_t next_epoch = ctl->epoch + 1u;
        if (!next_epoch) next_epoch = 1u;
        ctl->epoch = next_epoch;
    }
    MemoryBarrier();
    ctl->active = 1;

    wchar_t ev_name[128];
    swprintf_s(ev_name, 128, L"Local\\VMPX_WATCH_EVT_%u", pid);
    HANDLE ev = OpenEventW(EVENT_MODIFY_STATE, FALSE, ev_name);
    if (ev) SetEvent(ev);

    const char* out = arg_get(argc, argv, "--out");
    FILE* f = NULL;
    if (out) fopen_s(&f, out, "w");
    const char* cap = arg_get(argc, argv, "--capture");
    if (cap) CreateDirectoryA(cap, NULL);

    uint64_t seconds = arg_num(argc, argv, "--seconds", 10);
    int once = arg_has(argc, argv, "--once") ? 1 : 0;
    DWORD start = GetTickCount();
    uint32_t seen = 0;
    uint32_t stall_pos = 0;      /* position the reader is waiting on */
    uint32_t stall_wait = 0;     /* poll rounds spent on that position */
    while (1) {
        /* The desktop stop action clears this shared control flag. */
        if (!ctl->active) break;
        if (!once && (DWORD)(GetTickCount() - start) >= (DWORD)(seconds * 1000))
            break;
        uint32_t epoch = ctl->epoch;
        uint32_t tail = ctl->tail;
        uint32_t head = ctl->head;
        if ((uint32_t)(head - tail) > VMPX_WATCH_MAX_EVENTS) {
            /* Producers never advance head more than one ring past tail, so
             * this is a counter reset underneath the reader. Resynchronise
             * instead of walking a wrapped range of dead slots. */
            vmpx_watch_counter_bump(&ctl->stalled);
            tail = head;
            publish_tail(ctl, epoch, tail);
        }
        while (tail != head) {
            vmpx_watch_event_t* e = &events[tail & VMPX_WATCH_EVENT_MASK];
            uint32_t gen = vmpx_watch_gen_for(tail);
            uint32_t seal = e->seal;
            MemoryBarrier();    /* acquire: payload reads follow the seal */
            if (seal != gen || e->epoch != epoch) {
                if (seal == gen) {
                    /* Sealed for this position under another run's epoch: the
                     * reset already happened, so waiting cannot help. */
                    vmpx_watch_counter_bump(&ctl->stalled);
                    tail++;
                    publish_tail(ctl, epoch, tail);
                    continue;
                }
                /* head points at a claimed position before its seal lands, so
                 * an in-flight publish must not be consumed or dropped. The
                 * slot at tail cannot be recycled by a later generation while
                 * tail is unadvanced, so a fast retry settles it either way. */
                if (tail != stall_pos) { stall_pos = tail; stall_wait = 0; }
                if (stall_wait < VMPX_WATCH_STALL_RETRIES) {
                    stall_wait++;
                    break;      /* re-poll the same position next round */
                }
                /* Producer died between claim and seal. Skip and account. */
                vmpx_watch_counter_bump(&ctl->stalled);
                tail++;
                publish_tail(ctl, epoch, tail);
                continue;
            }
            vmpx_watch_event_t snap;
            snap.seal = e->seal;
            snap.epoch = e->epoch;
            snap.seq = e->seq;
            snap.tid = e->tid;
            snap.type = e->type;
            snap.access_or_old = e->access_or_old;
            snap.addr = e->addr;
            snap.size = e->size;
            snap.ip = e->ip;
            snap.newprot = e->newprot;
            snap.reserved = e->reserved;
            MemoryBarrier();
            if (e->seal != gen || snap.seq != gen || snap.epoch != epoch) {
                /* The seal moved during the copy, so the producer reclaimed
                 * the slot and the payload is torn. Drop it and account. */
                vmpx_watch_counter_bump(&ctl->stalled);
                tail++;
                publish_tail(ctl, epoch, tail);
                continue;
            }
            stall_wait = 0;     /* a valid seal clears the wait budget */

            char line[320];
            if (snap.type == VMPX_WATCH_EV_GUARD)
                _snprintf_s(line, sizeof(line), _TRUNCATE,
                            "EVT seq=%u tid=%u %s addr=0x%llX size=0x%llX "
                            "access=%s ip=0x%llX\n",
                            snap.seq, snap.tid, ev_type(snap.type),
                            (unsigned long long)snap.addr,
                            (unsigned long long)snap.size,
                            access_type(snap.access_or_old),
                            (unsigned long long)snap.ip);
            else
                _snprintf_s(line, sizeof(line), _TRUNCATE,
                            "EVT seq=%u tid=%u %s addr=0x%llX size=0x%llX "
                            "old=0x%X new=0x%X\n",
                            snap.seq, snap.tid, ev_type(snap.type),
                            (unsigned long long)snap.addr,
                            (unsigned long long)snap.size,
                            snap.access_or_old, snap.newprot);
            printf("%s", line);
            if (f) fputs(line, f);
            seen++;

            if (cap && (snap.type == VMPX_WATCH_EV_WRITE ||
                        snap.type == VMPX_WATCH_EV_PROTECT)) {
                uint64_t n = snap.size;
                if (n > (4u << 20)) n = 4u << 20;
                uint8_t* buf = (uint8_t*)malloc((size_t)n);
                if (buf) {
                    if (proc_read(pid, snap.addr, buf, (size_t)n) == 0) {
                        char path[MAX_PATH * 2];
                        _snprintf_s(path, sizeof(path), _TRUNCATE,
                                    "%s\\evt_%08u_%08llX.bin", cap, snap.seq,
                                    (unsigned long long)snap.addr);
                        file_write_all(path, buf, n);
                    }
                    free(buf);
                }
            }
            tail++;
            /* Release the slot only after its payload has been captured. */
            publish_tail(ctl, epoch, tail);
        }
        if (once && seen) break;
        Sleep(40);
    }

    ctl->active = 0;
    if (ev) SetEvent(ev);

    if (f) fclose(f);
    if (ev) CloseHandle(ev);
    uint32_t total = ctl->total;
    uint32_t dropped = ctl->dropped;
    uint32_t stalled = ctl->stalled;
    UnmapViewOfFile(ctl);
    CloseHandle(map);
    printf("STATUS watch ok pid=%u events=%u dropped=%u stalled=%u\n",
           pid, total, dropped, stalled);
    return 0;
}
