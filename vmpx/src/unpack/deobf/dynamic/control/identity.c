/* identity.c - bounded mapping-name builder and session verifier
 *
 * Every mapped name this module produces is built character by character with
 * an explicit capacity check. There is no variadic format string, so no format
 * specifier can overrun a buffer, and a name that will not fit is reported as a
 * failure with the buffer emptied rather than truncated silently.
 *
 * The verifier is the single place that decides whether a mapped control
 * header belongs to the session the host started. It is allocation free and
 * reads only plain values, so it is safe to call on a mapping opened by pid.
 */
#include "unpack/deobf/dynamic/control/identity.h"

#include <string.h>

/* Append one wide character, always leaving room for the terminating NUL. */
static int id_put(wchar_t* out, size_t cap, size_t* pos, wchar_t c) {
    if (*pos + 1 >= cap) return -1;
    out[*pos] = c;
    *pos = *pos + 1;
    return 0;
}

static int id_puts(wchar_t* out, size_t cap, size_t* pos, const wchar_t* s) {
    for (; *s; s++) {
        if (id_put(out, cap, pos, *s) != 0) return -1;
    }
    return 0;
}

static int id_put_u32(wchar_t* out, size_t cap, size_t* pos, uint32_t v) {
    wchar_t tmp[10];
    size_t n = 0;
    do {
        tmp[n] = (wchar_t)(L'0' + (v % 10u));
        n++;
        v /= 10u;
    } while (v != 0 && n < 10);
    while (n != 0) {
        n--;
        if (id_put(out, cap, pos, tmp[n]) != 0) return -1;
    }
    return 0;
}

/* Fixed width, sixteen upper-case hex digits, most significant first. */
static int id_put_hex64(wchar_t* out, size_t cap, size_t* pos, uint64_t v) {
    static const wchar_t hex[] = L"0123456789ABCDEF";
    int i;
    for (i = 15; i >= 0; i--) {
        wchar_t c = hex[(v >> (i * 4)) & 0xFu];
        if (id_put(out, cap, pos, c) != 0) return -1;
    }
    return 0;
}

int vmpx_dyn_identity_name(vmpx_dyn_identity_kind_t kind, uint32_t pid,
                           uint64_t nonce, wchar_t* out, size_t cap) {
    if (!out || cap < 8) return -1;
    out[0] = L'\0';

    size_t pos = 0;
    int rc = id_puts(out, cap, &pos, L"Local\\");
    if (rc == 0) {
        switch (kind) {
        case VMPX_DYN_ID_NAME_MAP:
            rc = id_puts(out, cap, &pos, L"VMPX_DYN_");
            break;
        case VMPX_DYN_ID_NAME_EVT:
            rc = id_puts(out, cap, &pos, L"VMPX_DYN_EVT_");
            break;
        case VMPX_DYN_ID_NAME_SEED:
            rc = id_puts(out, cap, &pos, L"VMPX_DYN_SEED_");
            break;
        default:
            rc = -1;
            break;
        }
    }
    if (rc == 0) rc = id_put_u32(out, cap, &pos, pid);
    /* The seed record is deliberately pid-only: it is the rendezvous that
     * carries the nonce, so it cannot be named by it. A zero nonce means the
     * agent found no seed; keep the legacy pid-only name so pid-only callers
     * still locate the mapping, and let the verifier reject the unbound
     * session. */
    if (rc == 0 && kind != VMPX_DYN_ID_NAME_SEED && nonce != 0) {
        rc = id_put(out, cap, &pos, L'_');
        if (rc == 0) rc = id_put_hex64(out, cap, &pos, nonce);
    }

    if (rc != 0) {
        out[0] = L'\0';
        return -1;
    }
    out[pos] = L'\0';
    return 0;
}

/* Bounded, terminator-required comparison. Two ids are equal only if they
 * match through a NUL that both reach inside the fixed cap; a string that runs
 * the full cap without terminating is a mismatch. */
static int id_eq(const char* a, const char* b) {
    size_t i;
    for (i = 0; i < VMPX_DYN_IDENTITY_ID_CAP; i++) {
        if (a[i] != b[i]) return 0;
        if (a[i] == '\0') return 1;
    }
    return 0;
}

vmpx_dyn_identity_result_t
vmpx_dyn_identity_verify(const vmpx_dyn_identity_t* declared,
                         const vmpx_dyn_identity_t* expected,
                         const vmpx_dyn_identity_layout_t* layout) {
    if (!declared || !expected || !layout) return VMPX_DYN_ID_MISMATCH;

    if (layout->header_size != (uint32_t)sizeof(vmpx_dyn_ctl_t) ||
        layout->record_size != (uint32_t)sizeof(vmpx_dyn_event_t) ||
        layout->pointer_width != VMPX_DYN_POINTER_WIDTH ||
        layout->endianness != VMPX_DYN_ENDIAN ||
        layout->shard_count != VMPX_DYN_MAX_PRODUCERS ||
        layout->shard_events != VMPX_DYN_SHARD_EVENTS) {
        return VMPX_DYN_ID_UNSUPPORTED;
    }

    /* An unbound mapping declares no nonce. It is never accepted, and it is
     * checked before the id string so a zeroed header cannot accidentally
     * match an empty expected id. */
    if (declared->nonce == 0) return VMPX_DYN_ID_MISMATCH;
    if (declared->pid != expected->pid) return VMPX_DYN_ID_MISMATCH;
    if (declared->nonce != expected->nonce) return VMPX_DYN_ID_MISMATCH;
    if (!id_eq(declared->session_id, expected->session_id))
        return VMPX_DYN_ID_MISMATCH;
    return VMPX_DYN_ID_OK;
}

const char* vmpx_dyn_identity_result_name(vmpx_dyn_identity_result_t result) {
    switch (result) {
    case VMPX_DYN_ID_OK:          return "ok";
    case VMPX_DYN_ID_MISMATCH:    return "mismatch";
    case VMPX_DYN_ID_UNSUPPORTED: return "unsupported";
    default:                      return "unknown";
    }
}
