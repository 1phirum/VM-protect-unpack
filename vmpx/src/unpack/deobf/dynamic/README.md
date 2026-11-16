# Dynamic deobfuscation suite

`vmpx deobf` is a live-process collector. It attaches to a running target,
injects `vmpxagent.dll` when the control section is absent, enables one or
more techniques, and writes artifacts while the target keeps executing. The
old dump-file scanner is no longer linked into the command; the static source
files remain in the parent directory only as historical reference.

## Layout

| folder | technique | implementation |
|---|---|---|
| `control/` | named control plane, per-thread shards, API event publication, hidden mapping | `control.h`, `control.c` |
| `memdelta/` | live committed-page hashing and page-change deltas | `memdelta.c` |
| `codecov/` | first-execution coverage with `PAGE_GUARD` and a VEH | `codecov.c` |
| `threadctx/` | suspend/sample/resume thread context timeline | `threadctx.c` |
| `vmtrans/` | private-executable entry/exit classification | `vmtrans.h`, `vmtrans.c` |
| `strings/` | runtime ASCII and UTF-16LE recovery from captured bytes | `runtime_strings.h`, `runtime_strings.c` |
| `report/` | CLI consumer, live full-page reread, artifact writer | `report.h`, `report.c` |
| `profile/` | run profile parse, validation, effective-profile output | `profile.c` |
| `session/` | session identity, manifest, module/region snapshots | `session.c`, `session_write.c`, `session_bridge.c` |

The agent side is `control`, `memdelta`, `codecov`, `threadctx`, and `vmtrans`.
`report`, `strings`, `profile`, and `session` compile into `vmpx.exe`.

## Control plane

The agent creates two named objects for its own PID:

- `Local\VMPX_DYN_<pid>`: one `vmpx_dyn_ctl_t` followed by
  `VMPX_DYN_MAX_PRODUCERS` shards.
- `Local\VMPX_DYN_EVT_<pid>`: auto-reset event used to wake collectors and the
  CLI.

`vmpx_dyn_ctl_t` carries the protocol magic/version, header and record sizes,
the mode bitmask, sampling intervals, the capture epoch, global counters, the
main image base/size read from the live module, the first observed application
entry context, and up to 16 caller-supplied address ranges.

Each `vmpx_dyn_shard_t` is single-producer. `owner_tid` registers the publishing
thread, `epoch` binds the shard to the current capture, `head` is the last
reserved sequence, `tail` is the last sequence acknowledged by the host,
`dropped` counts refused reservations, `committed` is diagnostic, and
`events[VMPX_DYN_SHARD_EVENTS]` is the bounded slot array.

`vmpx_dyn_event_t` is a fixed 288-byte record: `ready`, `epoch`, `producer`,
`tid`, QPC `tick`, `seq`, type, flags, payload length, FNV-1a preview hash,
two auxiliary words, address, size, EIP, ESP, a 192-byte data preview, and a
reserved word. Types are `mem`, `exec`, `thread`, `write`, `protect`, `mark`,
`error`, and `vm`.

Publication uses one shard per publishing OS thread:

1. acquire or reuse the shard owned by the current TID for the current epoch;
2. reserve the next sequence with a CAS on `head`, refusing the event when the
   shard holds `VMPX_DYN_SHARD_EVENTS` unacknowledged slots;
3. clear `ready`, fill the slot privately, and write the timestamp;
4. release-publish `ready = seq`, then update `committed` and `total`;
5. the host copies a slot only when `ready`, `epoch`, `seq`, and `producer`
   match the expected sequence, then acknowledges it by advancing `tail`.

Sequence zero is reserved as the unpublished-slot marker. The 32-bit sequence
wrap is a known P2 gate gap: a shard that reaches `0xFFFFFFFF` reserves zero,
which the publisher refuses, and the host cannot advance past it without a
wider per-slot generation. A default capture resets after lowering `active`,
waiting for producers to settle, zeroing shard indices, and incrementing
`epoch`. `--all-events` keeps the boot shard indices and does not increment the
epoch.

The control mapping is registered with `stealth_hidden_region`, so the existing
`NtQueryVirtualMemory` / `NtReadVirtualMemory` hooks report it consistently with
the rest of the agent image.

## Techniques

### `memdelta`

Enumerates committed, readable, non-guard regions with `VirtualQuery`, skips
agent/hook/control ranges, and hashes each 4 KiB page with 64-bit and 32-bit
FNV-1a. The first pass is a baseline. Each later pass rebuilds the sorted
page vector, binary-searches the previous vector, and publishes changed or new
pages. The event carries the first 192 bytes; the CLI rereads the full page
from the live process through its persistent `PROCESS_VM_READ` handle. The
collector is capped at 262,144 pages (1 GiB) and sets
`VMPX_DYN_F_MEM_TRUNC` when the cap is reached. Per-pass publication is capped
at 512 changed pages to keep the ring from collapsing under churn.

### `codecov`

Enumerates executable pages in the main image or caller ranges, sets
`PAGE_GUARD` on each page while preserving the page's original protection, and
installs a first-chance VEH. On `STATUS_GUARD_PAGE_VIOLATION`:

- read/write accesses are not instruction fetches: the kernel has already
  cleared `PAGE_GUARD` on that page for the retry, so the handler disarms the
  page and restores its original protection instead of re-arming; the next arm
  cycle picks the page up again;
- instruction fetches (`ExceptionInformation[0] == 8`) record `EIP`, `ESP`,
  first 96 code bytes, page type, and sequence, then restore the page to its
  original protection and disarm it.

The worker disarms all remaining pages when the control block is deactivated.
Guard arming is wrapped in `dyn_api_suppress` so the collector's own
`NtProtectVirtualMemory` calls do not flood the API event stream.

### `threadctx`

Enumerates process threads with `CreateToolhelp32Snapshot`, skips the sampler
thread and hidden agent ranges, suspends one thread at a time, reads
`CONTEXT_CONTROL | CONTEXT_INTEGER`, reads 32 code bytes at EIP and 16 stack
dwords at ESP, then resumes it. A `thread` event is emitted only when the
thread's EIP changes. The payload layout is:

```
0..31    code bytes at EIP
32..67   EAX ECX EDX EBX ESP EBP ESI EDI EFLAGS
68..131  sixteen stack dwords
```

`aux` is the target thread ID. `thread_samples` counts successful context reads;
`thread_ticks` counts sampler passes.

### `vmtrans`

Observes the same context samples and tracks whether EIP is in private
executable memory and inside the main image. An entry or exit of private
executable memory publishes a `vm` event with the complete thread payload.
`transition` is the packed `(previous_private << 8) | current_private` value.
This is the primary runtime signal for decoded VM handlers and bytecode pages.

### `strings`

Scans captured byte ranges for printable ASCII and UTF-16LE runs. Retention
requires one ASCII letter per run, at least 50% alphanumeric bytes, and at most
25% symbols; there is no vowel gate, so identifiers and short IDs survive.
Bounds are 512 chars per record, 500,000 records, 8 MiB of emitted text, and a
131,072-entry open-addressed hash set dedicated to content. Rejections and
capacity refusals are counted rather than silent. Each record carries its
source, a preview/reread/unverified origin tag, runtime address, encoding,
length, and escaped text.

### `report`

`dyn_report_run` is the CLI side. It:

1. resolves the target with an explicit `--pid`, `--name`, or `--exe` selector;
2. opens an existing control mapping or builds the agent DLL path and calls
   `inject_dll`;
3. opens one `PROCESS_VM_READ` handle for full-page rereads;
4. creates technique directories and result files, starts the session, and
   loads the optional profile;
5. sets mode, intervals, optional address range, resets shards, and raises
   `active`;
6. drains only release-published slot sequences, writing each event and
   reading full pages while the target is live;
7. lowers `active`, waits for collectors to settle, writes `summary.txt`, the
   session manifest, and `events/loss.jsonl`.

## Output

```
<out>/
  summary.txt
  events/events.txt
  events/loss.jsonl
  session/manifest.json
  session/profile.effective.json
  memdelta/capture.bin        self-describing records: header + {addr,seq,size,len,crc,flags,type,validity,data}
  memdelta/pages.txt
  codecov/exec.csv
  threadctx/samples.csv
  vmtrans/transitions.csv
  apievents/events.csv
  strings/strings.txt
```

`capture.bin` starts with `VXDB` version 2 and a 4 KiB page size. Each record is
packed little-endian `{uint64 addr, uint64 seq, uint32 size, uint32 len,
uint32 crc32, uint32 flags, uint32 event_type, uint32 validity}`, immediately
followed by `len` bytes. `validity` is `preview_only` for producer bytes and
`later_reread` when the host reread succeeded; a reread is never silently
substituted for the event-epoch preview. `crc32` currently holds FNV-1a, not
CRC-32.

## Build and use

```bat
cmd /c build.bat

vmpx deobf --pid 1234 --out artifacts\run-1 --seconds 30 --mode meta
vmpx deobf --name target.exe --out artifacts\run-2 --mode met --mem-ms 500
vmpx deobf --pid 1234 --out artifacts\run-3 --addr 0x400000 --size 0x10000000
```

`--mode` is a character mask: `m` memory delta, `e` guard-page execution,
`t` thread context and VM transitions, `a` API write/protect events. Default is
all four. `--mem-ms` defaults to 1000, `--thread-ms` to 25, `--seconds` to 20,
`--max-mb` to 256, and `--max-events` to 200000.

## Invariants

- No file parsing in the command path. Image base and size come from the live
  main module; pages come from `VirtualQuery` and `ReadProcessMemory`.
- Every loop over target data is bounded: 16 ranges, 16 producer shards with
  2,048 slots each, 512 changed pages per pass, 262,144 memory pages, 65,536
  coverage pages, 512 tracked threads, 192-byte event previews, 256 MiB
  capture cap.
- Inaccessible or concurrently changing pages are handled with SEH or
  `ReadProcessMemory` failure; they never produce stale bytes.
- The API event bridge only runs when the `a` mode bit is set. Agent-internal
  protection changes are suppressed with a thread-local guard.
- The control section is hidden from the existing memory-query hooks; the
  output mapping remains writable and readable only by the agent and the CLI.
