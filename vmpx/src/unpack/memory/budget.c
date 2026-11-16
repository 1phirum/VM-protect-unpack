/* budget.c - saturating accounting; refusal is the only failure mode */
#include "unpack/memory/budget.h"
#include <string.h>

void vmpx_budget_init(vmpx_budget_t* b, uint64_t host_limit,
                      uint64_t agent_limit, uint64_t read_chunk) {
    if (!b) return;
    memset(b, 0, sizeof(*b));
    b->host_limit = host_limit;
    b->agent_limit = agent_limit;
    b->read_chunk = read_chunk ? read_chunk : (1u << 20);
}

static uint64_t* used_of(vmpx_budget_t* b, int agent) {
    return agent ? &b->agent_used : &b->host_used;
}

static uint64_t* peak_of(vmpx_budget_t* b, int agent) {
    return agent ? &b->agent_peak : &b->host_peak;
}

static uint64_t limit_of(const vmpx_budget_t* b, int agent) {
    return agent ? b->agent_limit : b->host_limit;
}

int vmpx_budget_charge(vmpx_budget_t* b, int agent, uint64_t bytes) {
    if (!b) return -1;
    uint64_t* used = used_of(b, agent);
    uint64_t limit = limit_of(b, agent);
    if (*used >= limit || bytes > limit - *used) {
        if (agent) b->agent_refused++;
        else b->host_refused++;
        return -1;
    }
    *used += bytes;
    uint64_t* peak = peak_of(b, agent);
    if (*used > *peak) *peak = *used;
    return 0;
}

void vmpx_budget_release(vmpx_budget_t* b, int agent, uint64_t bytes) {
    if (!b) return;
    uint64_t* used = used_of(b, agent);
    *used = bytes >= *used ? 0 : *used - bytes;
}

uint64_t vmpx_budget_available(const vmpx_budget_t* b, int agent) {
    if (!b) return 0;
    uint64_t limit = limit_of(b, agent);
    uint64_t used = agent ? b->agent_used : b->host_used;
    return used >= limit ? 0 : limit - used;
}

uint64_t vmpx_budget_chunk(const vmpx_budget_t* b, uint64_t want) {
    if (!b || !want) return 0;
    uint64_t cap = b->read_chunk ? b->read_chunk : (1u << 20);
    if (want > cap) want = cap;
    uint64_t avail = vmpx_budget_available(b, 0);
    return want > avail ? avail : want;
}
