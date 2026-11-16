/* identity.h - session-bound mapping identity for the dynamic control plane
 *
 * The pid alone does not identify a capture session. A pid is reused after the
 * process exits, and a mapping left behind by an earlier run of the same
 * executable, or created by a foreign process, would satisfy a pid-only lookup.
 * Every mapping name therefore carries the 64-bit session nonce in fixed-width
 * hex, and the control header declares the pid, the nonce and the session id
 * string so the host can verify the mapping it opened belongs to the session it
 * started.
 *
 * On the agent side the nonce arrives through a pid-named seed record the host
 * publishes before the agent is loaded (see vmpx_dyn_seed_t). An agent that
 * finds no seed keeps the legacy pid-only name and declares no session, which
 * the verifier rejects - an unbound mapping is never accepted.
 *
 * Nothing here allocates and nothing here formats through a variadic format
 * string; every write is bounded and any truncation zeroes the buffer and
 * fails.
 */
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stddef.h>

#include "unpack/deobf/dynamic/control/control.h"

/* Same bound as the session id string the host formats (see session.h,
 * VMPX_SESSION_ID_CAP, which is 128 - this is deliberately tighter because the
 * producer formats at most "%u-%016llX-%016llX" = 44 bytes). The control header
 * field uses the same literal; the assert below fails the build if the two
 * ever drift once control.h carries VMPX_DYN_SESSION_ID_CAP. */
#define VMPX_DYN_IDENTITY_ID_CAP   64
#define VMPX_DYN_IDENTITY_NAME_CAP 64

#ifdef VMPX_DYN_SESSION_ID_CAP
typedef char vmpx_dyn_identity_idcap_assert
    [(VMPX_DYN_SESSION_ID_CAP == VMPX_DYN_IDENTITY_ID_CAP) ? 1 : -1];
#endif

#define VMPX_DYN_SEED_MAGIC   0x44534556u   /* "VESD" little-endian */
#define VMPX_DYN_SEED_VERSION 1u

/* Which mapping a call to vmpx_dyn_identity_name() builds. */
typedef enum {
    VMPX_DYN_ID_NAME_MAP = 0,   /* Local\VMPX_DYN_<pid>_<nonce>      */
    VMPX_DYN_ID_NAME_EVT = 1,   /* Local\VMPX_DYN_EVT_<pid>_<nonce>  */
    VMPX_DYN_ID_NAME_SEED = 2   /* Local\VMPX_DYN_SEED_<pid>         */
} vmpx_dyn_identity_kind_t;

/* Typed verifier outcome. A caller never has to parse a string to tell a
 * layout it cannot read from a session it did not start. */
typedef enum {
    VMPX_DYN_ID_OK = 0,
    VMPX_DYN_ID_MISMATCH = 1,
    VMPX_DYN_ID_UNSUPPORTED = 2
} vmpx_dyn_identity_result_t;

/* Session key. The host fills the expected form from its live session; the
 * agent writes the declared form into the shared header. */
typedef struct {
    uint32_t pid;
    uint64_t nonce;
    char     session_id[VMPX_DYN_IDENTITY_ID_CAP];
} vmpx_dyn_identity_t;

/* The header fields the verifier reads for layout. Kept as plain values so the
 * declared side can be snapshotted without holding the mapped volatile type. */
typedef struct {
    uint32_t header_size;
    uint32_t record_size;
    uint32_t pointer_width;
    uint32_t endianness;
    uint32_t shard_count;
    uint32_t shard_events;
} vmpx_dyn_identity_layout_t;

/* Seed record published by the host under the pid-only name before the agent
 * loads. Fixed width, no packing pragma; both sides compile the same type. */
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t pid;
    uint32_t reserved;
    uint64_t nonce;
    char     session_id[VMPX_DYN_IDENTITY_ID_CAP];
} vmpx_dyn_seed_t;

/* Build a mapping name. `nonce` is ignored for VMPX_DYN_ID_NAME_SEED. On any
 * overflow, an unknown kind, or a null/short buffer the call returns -1 and
 * leaves `out` as the empty string. Returns 0 on success. */
int vmpx_dyn_identity_name(vmpx_dyn_identity_kind_t kind, uint32_t pid,
                           uint64_t nonce, wchar_t* out, size_t cap);

/* Compare a mapped header's declared identity and layout against the session
 * the host started. Layout is checked first (UNSUPPORTED), then pid, nonce and
 * the session id string (MISMATCH). A null argument or an unbound session
 * (nonce == 0) is a MISMATCH, never OK. */
vmpx_dyn_identity_result_t
vmpx_dyn_identity_verify(const vmpx_dyn_identity_t* declared,
                         const vmpx_dyn_identity_t* expected,
                         const vmpx_dyn_identity_layout_t* layout);

const char* vmpx_dyn_identity_result_name(vmpx_dyn_identity_result_t result);
