/* loss_ledger.c - severity-classified bounded loss accounting
 *
 * See loss_ledger.h. The classifier is a pure function of the event type and
 * the VMPX_DYN_F_* flag word; the accumulator is a fixed array sized by the
 * event-type count. No path allocates or loops over input volume.
 */
#include "unpack/deobf/dynamic/report/loss_ledger.h"

#include <string.h>

/* A VM event is a context pair when it carries the transition marker. Every
 * vmtrans event sets F_VM and adds F_VM_ENTER or F_VM_LEAVE; the IMAGE and
 * PRIVATE bits only say which side of the boundary the sample landed on. */
#define LOSS_VM_TRANSITION \
    (VMPX_DYN_F_VM | VMPX_DYN_F_VM_ENTER | VMPX_DYN_F_VM_LEAVE)

static uint32_t loss_clamp_type(uint32_t type) {
    return type < VMPX_LOSS_TYPE_COUNT ? type : VMPX_LOSS_TYPE_UNKNOWN;
}

static vmpx_loss_cause_t loss_clamp_cause(vmpx_loss_cause_t cause) {
    return (uint32_t)cause < VMPX_LOSS_CAUSE_COUNT ? cause : VMPX_LOSS_DROP;
}

/* Saturating add. A producer drop count is a 32-bit field the host does not
 * own; a corrupted or wrapped value must not roll the ledger backwards. */
static uint32_t loss_sat_add(uint32_t cur, uint32_t add) {
    if (add > UINT32_MAX - cur) return UINT32_MAX;
    return cur + add;
}

void vmpx_loss_ledger_init(vmpx_loss_ledger_t* l) {
    if (l) memset(l, 0, sizeof(*l));
}

vmpx_loss_sev_t vmpx_loss_severity(uint32_t event_type, uint32_t flags) {
    /* A flagged code page or a first-execution event is a code change. Any
     * producer may set F_EXEC; the exec type always carries it. */
    if ((flags & VMPX_DYN_F_EXEC) || event_type == VMPX_DYN_EV_EXEC)
        return VMPX_LOSS_SEV_CRITICAL;

    switch (event_type) {
    case VMPX_DYN_EV_VM:
        return (flags & LOSS_VM_TRANSITION) ? VMPX_LOSS_SEV_CRITICAL
                                            : VMPX_LOSS_SEV_IMPORTANT;
    case VMPX_DYN_EV_WRITE:      /* native bridge effect: a live write */
    case VMPX_DYN_EV_PROTECT:    /* native bridge effect: a live protect */
        return VMPX_LOSS_SEV_CRITICAL;
    case VMPX_DYN_EV_MARK:       /* checkpoint boundary (OEP arm) */
        return VMPX_LOSS_SEV_CRITICAL;
    case VMPX_DYN_EV_MEM:
        if (flags & VMPX_DYN_F_NEW) return VMPX_LOSS_SEV_DISCOVERY;
        if (flags & VMPX_DYN_F_CHANGED) return VMPX_LOSS_SEV_IMPORTANT;
        return VMPX_LOSS_SEV_DISCOVERY;
    case VMPX_DYN_EV_FREE:       /* region released / decommitted */
        return VMPX_LOSS_SEV_IMPORTANT;
    case VMPX_DYN_EV_THREAD:     /* runtime context sample */
    case VMPX_DYN_EV_ERROR:      /* collector fault signal */
        return VMPX_LOSS_SEV_IMPORTANT;
    default:
        return VMPX_LOSS_SEV_DISCOVERY;
    }
}

const char* vmpx_loss_class_name(uint32_t event_type, uint32_t flags) {
    if ((flags & VMPX_DYN_F_EXEC) || event_type == VMPX_DYN_EV_EXEC)
        return "code_change";
    switch (event_type) {
    case VMPX_DYN_EV_VM:      return "vm_context_pair";
    case VMPX_DYN_EV_WRITE:
    case VMPX_DYN_EV_PROTECT: return "native_bridge";
    case VMPX_DYN_EV_MARK:    return "checkpoint_boundary";
    case VMPX_DYN_EV_MEM:
        if (flags & VMPX_DYN_F_NEW) return "new_region";
        if (flags & VMPX_DYN_F_CHANGED) return "memory_change";
        return "page_seen";
    case VMPX_DYN_EV_THREAD:  return "context_sample";
    case VMPX_DYN_EV_FREE:    return "region_release";
    case VMPX_DYN_EV_ERROR:   return "error_signal";
    default:                  return "unknown";
    }
}

const char* vmpx_loss_type_name(uint32_t event_type) {
    switch (event_type) {
    case VMPX_DYN_EV_MEM:     return "mem";
    case VMPX_DYN_EV_EXEC:    return "exec";
    case VMPX_DYN_EV_THREAD:  return "thread";
    case VMPX_DYN_EV_WRITE:   return "write";
    case VMPX_DYN_EV_PROTECT: return "protect";
    case VMPX_DYN_EV_MARK:    return "mark";
    case VMPX_DYN_EV_ERROR:   return "error";
    case VMPX_DYN_EV_VM:      return "vm";
    case VMPX_DYN_EV_FREE:    return "free";
    default:                  return "unknown";
    }
}

const char* vmpx_loss_sev_name(vmpx_loss_sev_t sev) {
    switch (sev) {
    case VMPX_LOSS_SEV_CRITICAL:  return "critical";
    case VMPX_LOSS_SEV_IMPORTANT: return "important";
    case VMPX_LOSS_SEV_DISCOVERY: return "discovery";
    default:                      return "unknown";
    }
}

const char* vmpx_loss_cause_name(vmpx_loss_cause_t cause) {
    switch (cause) {
    case VMPX_LOSS_DROP:    return "drop";
    case VMPX_LOSS_STALL:   return "stall";
    case VMPX_LOSS_INVALID: return "invalid";
    default:                return "unknown";
    }
}

static void loss_account(vmpx_loss_ledger_t* l, vmpx_loss_cause_t cause,
                         uint32_t type, uint32_t flags, uint32_t count) {
    vmpx_loss_sev_t sev = vmpx_loss_severity(type, flags);
    l->by_cause_type[cause][type] =
        loss_sat_add(l->by_cause_type[cause][type], count);
    l->by_cause[cause] = loss_sat_add(l->by_cause[cause], count);
    l->by_type[type] = loss_sat_add(l->by_type[type], count);
    l->by_sev[sev] = loss_sat_add(l->by_sev[sev], count);
    l->total = loss_sat_add(l->total, count);
    if (type == VMPX_LOSS_TYPE_UNKNOWN)
        l->unreadable = loss_sat_add(l->unreadable, count);
}

void vmpx_loss_ledger_add(vmpx_loss_ledger_t* l, vmpx_loss_cause_t cause,
                          uint32_t event_type, uint32_t flags, uint32_t count) {
    if (!l || !count) return;
    loss_account(l, loss_clamp_cause(cause), loss_clamp_type(event_type),
                 flags, count);
}

vmpx_loss_sev_t vmpx_loss_ledger_note(vmpx_loss_ledger_t* l,
                                      vmpx_loss_cause_t cause,
                                      uint32_t event_type, uint32_t flags,
                                      FILE* jsonl, uint32_t shard,
                                      uint64_t seq) {
    vmpx_loss_sev_t sev = vmpx_loss_severity(loss_clamp_type(event_type),
                                             flags);
    if (!l) return sev;

    cause = loss_clamp_cause(cause);
    event_type = loss_clamp_type(event_type);
    loss_account(l, cause, event_type, flags, 1u);

    /* The record cap bounds the file, never the counters. Names are static
     * [a-z_] literals, so no escaping is required. */
    if (jsonl && l->emitted < VMPX_LOSS_MAX_RECORDS) {
        fprintf(jsonl,
                "{\"loss\":1,\"cause\":\"%s\",\"type\":\"%s\","
                "\"sev\":\"%s\",\"class\":\"%s\",\"shard\":%u,"
                "\"seq\":%llu}\n",
                vmpx_loss_cause_name(cause), vmpx_loss_type_name(event_type),
                vmpx_loss_sev_name(sev),
                vmpx_loss_class_name(event_type, flags), shard,
                (unsigned long long)seq);
        if (ferror(jsonl) == 0) l->emitted++;
    }
    return sev;
}

void vmpx_loss_ledger_global(FILE* f, const vmpx_loss_ledger_t* l,
                             const vmpx_loss_transport_t* t) {
    if (!f || !l || !t) return;

    /* Legacy keys, unchanged and in the same order. */
    fprintf(f,
            "{\"global\":1,\"total\":%u,\"events\":%u,\"dropped\":%u,"
            "\"shard_dropped\":%u,\"overflow\":%u,\"reentrant\":%u,"
            "\"stalled\":%u,\"invalid\":%u,",
            t->total, t->events, t->dropped, t->shard_dropped, t->overflow,
            t->reentrant, t->stalled, t->invalid);

    fprintf(f, "\"classified\":%u,\"unreadable\":%u,", l->total,
            l->unreadable);

    fputs("\"by_type\":{", f);
    for (uint32_t i = 0; i < VMPX_LOSS_TYPE_COUNT; i++)
        fprintf(f, "\"%s\":%u%s", vmpx_loss_type_name(i), l->by_type[i],
                i + 1 < VMPX_LOSS_TYPE_COUNT ? "," : "");

    fputs("},\"by_severity\":{", f);
    for (uint32_t i = 0; i < VMPX_LOSS_SEV_COUNT; i++)
        fprintf(f, "\"%s\":%u%s",
                vmpx_loss_sev_name((vmpx_loss_sev_t)i), l->by_sev[i],
                i + 1 < VMPX_LOSS_SEV_COUNT ? "," : "");

    fputs("},\"by_cause\":{", f);
    for (uint32_t i = 0; i < VMPX_LOSS_CAUSE_COUNT; i++)
        fprintf(f, "\"%s\":%u%s",
                vmpx_loss_cause_name((vmpx_loss_cause_t)i), l->by_cause[i],
                i + 1 < VMPX_LOSS_CAUSE_COUNT ? "," : "");

    fputs("}}\n", f);
}
