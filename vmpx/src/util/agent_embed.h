/* agent_embed.h - resolve the dynamic agent for injection */
#pragma once

#include <stddef.h>
#include <wchar.h>

/* Resolve a path to vmpxagent.dll for injection, in this order:
 *   1. an explicit override passed on the command line,
 *   2. a side-by-side vmpxagent.dll (development builds),
 *   3. the copy embedded in this executable, written to %TEMP% on first use.
 * Returns 0 on success. */
int agent_materialize(const char* override, wchar_t* out, size_t cap);

/* Remove the extracted copy if this process created it. The target's loader
 * holds its own section handle, so deleting the on-disk file leaves the
 * already-injected agent mapped. */
void agent_release(void);
