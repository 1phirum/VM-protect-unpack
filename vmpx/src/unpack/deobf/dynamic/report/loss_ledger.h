/* loss_ledger.h - severity-classified bounded loss accounting
 *
 * The drain loop refuses, stalls, and rejects ring slots. Before this the
 * only record of that was a bare per-shard count, so a lost code page and a
 * lost memory sample were indistinguishable in events/loss.jsonl. This
 * ledger attaches the event type and a severity class to every loss and
 * emits both a per-loss JSONL record and a per-type / per-severity roll-up,
 * while keeping the legacy loss.jsonl keys and their order.
 *
 * Allocation is fixed: one uint32 per (cause, event-type) cell plus one per
 * severity. Nothing grows with capture volume. Per-loss JSONL records stop
 * after VMPX_LOSS_MAX_RECORDS; the counters keep counting.
 *
 * The classifier reads only the event type and the VMPX_DYN_F_* flag word.
 * Critical losses are the ones a reconstruction cannot silently drop:
 * a code change, a VM context pair, a native bridge effect, or a checkpoint
 * boundary.
 */
#pragma once

#include <stdint.h>
#include <stdio.h>

#include "unpack/deobf/dynamic/control/control.h"

/* Event-type buckets. Slot 0 is the unknown/unreadable slot; slots 1..9
 * mirror VMPX_DYN_EV_MEM..VMPX_DYN_EV_FREE. The count is the bound for the
 * accumulator arrays below. */
#define VMPX_LOSS_TYPE_UNKNOWN 0u
#define VMPX_LOSS_TYPE_COUNT   10u

/* Individual per-loss records are capped so a long stall period cannot
 * write an unbounded file. Counters are never capped. */
#define VMPX_LOSS_MAX_RECORDS  20000u

/* Why a slot was lost. */
typedef enum {
    VMPX_LOSS_DROP    = 0,   /* reservation refused by the producer */
    VMPX_LOSS_STALL   = 1,   /* slot not release-published at read time */
    VMPX_LOSS_INVALID = 2,   /* slot read but failed the identity gate */
    VMPX_LOSS_CAUSE_COUNT = 3
} vmpx_loss_cause_t;

/* How much a lost event mattered. */
typedef enum {
    VMPX_LOSS_SEV_DISCOVERY = 0,
    VMPX_LOSS_SEV_IMPORTANT = 1,
    VMPX_LOSS_SEV_CRITICAL  = 2,
    VMPX_LOSS_SEV_COUNT     = 3
} vmpx_loss_sev_t;

/* Fixed-size accumulator. Every array is sized by the event-type count or
 * the cause/severity counts, so the whole struct is a compile-time
 * constant. */
typedef struct {
    uint32_t by_cause_type[VMPX_LOSS_CAUSE_COUNT][VMPX_LOSS_TYPE_COUNT];
    uint32_t by_cause[VMPX_LOSS_CAUSE_COUNT];
    uint32_t by_type[VMPX_LOSS_TYPE_COUNT];
    uint32_t by_sev[VMPX_LOSS_SEV_COUNT];
    uint32_t total;       /* every counted loss */
    uint32_t unreadable;  /* losses whose slot type could not be read */
    uint32_t emitted;     /* per-loss JSONL records written */
} vmpx_loss_ledger_t;

/* Transport counters carried by the global record. These are the values the
 * legacy loss.jsonl line already publishes; the ledger keeps them verbatim. */
typedef struct {
    uint32_t total;
    uint32_t events;
    uint32_t dropped;
    uint32_t shard_dropped;
    uint32_t overflow;
    uint32_t reentrant;
    uint32_t stalled;
    uint32_t invalid;
} vmpx_loss_transport_t;

void vmpx_loss_ledger_init(vmpx_loss_ledger_t* l);

/* Pure classifiers. They never mutate and never allocate. */
vmpx_loss_sev_t vmpx_loss_severity(uint32_t event_type, uint32_t flags);
const char*     vmpx_loss_class_name(uint32_t event_type, uint32_t flags);
const char*     vmpx_loss_type_name(uint32_t event_type);
const char*     vmpx_loss_sev_name(vmpx_loss_sev_t sev);
const char*     vmpx_loss_cause_name(vmpx_loss_cause_t cause);

/* Count one loss. `event_type` is the slot's type, or VMPX_LOSS_TYPE_UNKNOWN
 * when the slot could not be read. `flags` is the slot flag word, or 0 when
 * unknown. When `jsonl` is non-NULL one per-loss record is appended (subject
 * to VMPX_LOSS_MAX_RECORDS). Returns the severity that was accumulated. */
vmpx_loss_sev_t vmpx_loss_ledger_note(vmpx_loss_ledger_t* l,
                                      vmpx_loss_cause_t cause,
                                      uint32_t event_type, uint32_t flags,
                                      FILE* jsonl, uint32_t shard,
                                      uint64_t seq);

/* Bulk count, for losses only available as a total (producer-side drops).
 * Saturates instead of wrapping; writes no record. */
void vmpx_loss_ledger_add(vmpx_loss_ledger_t* l, vmpx_loss_cause_t cause,
                          uint32_t event_type, uint32_t flags, uint32_t count);

/* Write the global roll-up. The legacy keys and their order come first,
 * then "classified", "unreadable", "by_type", "by_severity", "by_cause". */
void vmpx_loss_ledger_global(FILE* f, const vmpx_loss_ledger_t* l,
                             const vmpx_loss_transport_t* t);
