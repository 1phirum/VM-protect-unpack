/* budget.h - bounded host and agent memory accounting
 *
 * A charge either succeeds completely or is refused without changing usage.
 * Limits are bytes. The read chunk is separate: it caps one cross-process read
 * so a single request cannot pin an unbounded intermediate buffer.
 */
#pragma once

#include <stdint.h>

typedef struct {
    uint64_t host_limit;
    uint64_t agent_limit;
    uint64_t read_chunk;
    uint64_t host_used;
    uint64_t agent_used;
    uint64_t host_peak;
    uint64_t agent_peak;
    uint32_t host_refused;
    uint32_t agent_refused;
} vmpx_budget_t;

void     vmpx_budget_init(vmpx_budget_t* b, uint64_t host_limit,
                          uint64_t agent_limit, uint64_t read_chunk);
int      vmpx_budget_charge(vmpx_budget_t* b, int agent, uint64_t bytes);
void     vmpx_budget_release(vmpx_budget_t* b, int agent, uint64_t bytes);
uint64_t vmpx_budget_available(const vmpx_budget_t* b, int agent);
uint64_t vmpx_budget_chunk(const vmpx_budget_t* b, uint64_t want);
