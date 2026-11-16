# VMPX runtime unpacking system design

Date: 2026-11-15  
Status: architecture and contracts. P0 result/restore boundaries, the P1
profile, session, budget, arena, region-map, and partial-read substrate, and
the P2 transport v2 are implemented in the working tree; later-layer
interfaces remain proposals.  
Implementation sequence: [DYNAMIC_UNPACK_PLAN.md](DYNAMIC_UNPACK_PLAN.md).

## 1. Architecture decisions

### ADR-01 — Live execution is the discovery source

Discover pages, imports, phases, VM contexts, and handler effects from the live
target. Decode instruction bytes captured at their execution epoch. Runtime PE
header/export reads are layout metadata, not an offline packed-file workflow.

Persist evidence for reconstruction, trace processing, and regression testing.
A saved dump alone cannot establish when a page executed, whether it was later
rewritten, or what semantics a VM instruction had.

### ADR-02 — Preserve the original process during discovery

Perform initial observation and semantic work against the original live process.
Do not make cross-process snapshot restoration a prerequisite for deobfuscation.
It introduces module, TLS, heap, and kernel-state differences before the VM has
been understood.

### ADR-03 — No universal OEP assumption

Treat unpack handoff as a collection of candidates and dependencies. An observed
instruction is a continuation until a normal startup route is demonstrated.
TLS initialization, worker execution, VM entry, and application readiness are
different events.

### ADR-04 — No universal VMProtect handler template

Infer VM models per instance and per code epoch. A section name, private-memory
transition, register convention, or public handler signature can propose a
candidate but cannot certify the context layout or semantics.

### ADR-05 — Evidence carries identity, generation, and validity

Represent module-relative addresses and allocation-relative addresses explicitly.
Preserve unreadable spans, dropped events, sampled intervals, and competing
hypotheses. A matching number is not necessarily a pointer.

### ADR-06 — Instrumentation owns every modification

One registry owns hooks, guarded pages, temporary instruction changes, VEH
registrations, timers, and thread suspension performed by VMPX. No technique
restores another technique's modification independently.

### ADR-07 — Standalone execution and checkpoint continuation are separate

A standalone PE must establish its own runtime state through a normal loader
and startup path. Checkpoint continuation may require captured state and remains
diagnostic until all required dependencies are accounted for.

### ADR-08 — Verified coverage is bounded and explicit

Dynamic analysis covers exercised behavior. Unknown paths are not equivalent,
unreachable, or devirtualized merely because they were not observed. Reports
state the feature inventory, corpus, covered VM instances, and unresolved edges.

## 2. Process topology and data flow

```text
                    profile + workflows
                            |
                            v
                  host session controller
                  /         |           \
                 v          v            v
       external observer  agent route  focused trace adapter
                 \          |            /
                  \         v           /
                   bounded event/payload transport
                            |
                            v
             identity + page epochs + evidence journal
                  /                     \
                 v                       v
          phase/handoff model       VM discovery/context
                 |                       |
                 v                       v
          import/bridge graph       handler trace/effects
                 |                       |
                 v                       v
          reconstruction plan       IR/CFG/simplification
                  \                     /
                   v                   v
                   differential and workflow validation
                            |
                            v
                   typed results + evidence report
```

- **Host:** owns session configuration, process identity, planning, storage,
  inference, reconstruction, and final results.
- **Agent:** publishes bounded observations and supplies narrowly scoped
  capture/probe services. It does not perform symbolic analysis or PE rebuilding.
- **Focused trace adapter:** supplies instruction/branch/context detail for a
  selected interval. Its capabilities and observer effects are part of evidence.
- **Workers:** process runtime-origin evidence through versioned jobs. Workers
  cannot write target memory without a controller-issued instrumentation lease.

An external observer is read-only with respect to target memory. The agent route
changes the process by loading instrumentation. Focused tracing can be more
intrusive. None is described as undetectable or zero-overhead.

## 3. Layer contracts

### L0 — Memory and identity

Owner: `memory/` and existing process support in `src/proc`.

Inputs: process handle, verified architecture, address span, and read policy.
Outputs: valid bytes/spans, memory metadata, module/allocation identities, and
typed failures. Side effects: handle/cache ownership only unless a separate
writer lease is supplied.

Required records:

- `process_id`: session nonce, PID, creation time, architecture, observation start.
- `module_id`: runtime image identity, path, image size, generation, load interval;
  content identity when obtainable from valid runtime bytes.
- `allocation_id`: reservation base, generation, type, bounds, lifetime.
- `address_ref`: process identity plus module/RVA, allocation/offset, or an
  explicitly unresolved raw VA.
- `read_result`: requested span, valid spans, byte count, error, and read interval.

Track aliases and mixed protection subregions. A reused VA receives a new
generation. Cache lookups require both identity and generation.

### L1 — Session and profiles

Owner: `deobf/dynamic/session/` and `profile/` (P1 substrate implemented;
workflow inventory and stage scheduling remain proposed).

Inputs: target selector, effective profile, workflow inventory, requested stages.
Outputs: lifecycle state, capability selection, capture jobs, result aggregation.
Side effects: launch/attach and controlled instrumentation activation.

Lifecycle:

```text
CREATED -> IDENTIFIED -> BASELINING -> OBSERVING
                                  -> FOCUSED_CAPTURE -> OBSERVING
                                  -> CHECKPOINTING -> OBSERVING
OBSERVING -> RECONSTRUCTING -> VALIDATING -> COMPLETED
any active state -> STOPPING -> STOPPED
any active state -> FAILED -> STOPPING
```

Host inference jobs may overlap observation. Lifecycle ownership remains in one
controller. A target exit seals evidence and creates an explicit exit result.
`COMPLETED` means requested stages reached their declared gates, not that every
possible application function was recovered.

### L2 — Instrumentation policy

Owner: proposed `hook/registry.*`, `page_owner.*`, `policy.*`; existing watch and
armor/stealth code become adapters behind these contracts.

Each lease records purpose, address generation, original bytes/protection,
owner, installation epoch, deadline, nesting, rollback data, and status.

- One page-guard dispatcher routes faults to interested techniques.
- Unknown exceptions return to the application's exception chain.
- If the target changes a protection/code epoch, recompute the lease; do not
  restore a stale saved value over a newer target modification.
- Installation verifies instruction boundaries and patch compatibility.
- Callbacks use preallocated storage, bounded work, and reentrancy suppression.
- Expired probes and abandoned sessions enter an explicit cleanup path.

Proposed `antidebug/` records observed checks and behavior changes. An existing
compatibility hook is usable only with declared semantics and paired behavior
tests. Report observer-induced divergence instead of inferring that hidden
mappings or fewer debugger artifacts guarantee transparency.

### L3 — Transport and evidence

Owner: `control/` (agent publisher) and `report/` (host consumer). An `events`
directory under a capture output is storage, not a source folder.

Protocol v2 is one versioned header followed by fixed-layout records: magic
`KDYN`, version `2`, `header_size`, `record_size`, pointer width, endianness
marker, shard count, and events per shard. The host validates that layout
before collection starts. The header carries the target PID but no session
nonce, so object identity is still name-scoped.

Transport records carry the producer index, publishing thread, per-shard
sequence, QPC timestamp, event kind, flags, address/size, EIP/ESP, two
auxiliary words, a bounded data preview, and a 32-bit digest. Code/page epoch
is not a record field; the consumer attaches capture validity. Loss is counted
per shard and globally, not per event type.

Detailed publication and persistence rules appear in section 6.

### L4 — Memory materialization and page epochs

Owner: existing `memdelta/` and proposed `pageepoch/`.

Track these observations separately:

```text
reservation -> commit -> valid bytes -> write/protection change
                                      -> observed execution -> rewrite
release/free invalidates the allocation generation
```

A protection becoming executable does not prove execution. A changed checksum
does not identify the writer or prove code semantics. A stable checksum does not
exclude a rewrite that happened between observations.

Each page version stores capture interval, valid spans, hash algorithm/value,
allocation/module reference, protections, writer evidence if available, and
execution links. Full bytes and short previews have separate identities.

Page state changes invalidate dependent decode, CFG, and handler results.

### L5 — Execution evidence

Owner: existing `threadctx/`, `codecov/`, proposed `trace/`.

Evidence kinds remain distinct:

- Context sample: instruction pointer at one sampling instant; no implied
  control-flow edge between consecutive samples.
- First page execution: an observed fetch within the probe's scope and epoch;
  not whole-function coverage.
- Branch trace: ordered branches over the adapter's supported interval; memory
  effects require additional context/memory capture.
- Instruction trace: executed instructions with captured code versions and
  explicit gaps.

Thread identity includes creation generation and role evidence. Prefer the
primary thread returned by launch when available; an earliest-thread heuristic
is only a fallback, and application work can move to other threads.

### L6 — Unpack phase and handoff service

Owner: proposed `phase/` and evolved `oep/`.

Candidate evidence includes page materialization, write/execute correlation,
execution continuity, native startup/bridge behavior, TLS activity, and repeated
observations across runs. Score evidence categories and record contradictions;
do not publish an uncalibrated score as a statistical probability.

Candidate classifications:

- loader entry;
- unpack materialization boundary;
- observed application instruction;
- VM entry/exit;
- native function entry;
- resumable checkpoint;
- demonstrated standalone startup route;
- workflow-ready milestone.

Capture consistency and checkpoint requirements appear in section 8.

### L7 — Imports, bridges, and strings

Owner: existing live-import/PE helpers and proposed dynamic `imports/`,
`apievents/`; existing runtime `strings/`.

Import nodes store resolution origin, requested module/name/ordinal, actual
module generation/RVA, forwarder chain, call site, code epoch, and evidence.
Use live export metadata and observed calls; a nearest-export lookup is only a
labeling hint for internal addresses.

Bridge nodes store input/output spans, calling convention, argument widths,
register and stack effects, relevant last-error/flag state, exceptions, and
external side effects. Distinguish data exports, code exports, and thunks.

String nodes retain encoding, valid length, lifetime, buffer generation, and
consumption sites. Printable runs are candidates; API consumption or repeated
runtime uses strengthen their interpretation. Never retain an agent-local
pointer as if it were a durable payload.

### L8 — VM discovery and context hypotheses

Owner: proposed `vmdiscovery/`, `vmstate/`; `vmtrans/` remains a coarse signal.

Combine evidence for repeated dispatch, bytecode consumption, context-state
updates, VM-stack behavior, handler families, and native bridges. Include
negative controls such as JIT and ordinary private executable code.

A VM model names instance identity, dispatch evidence, VIP/VSP hypotheses,
register/flag storage, decode state, bytecode/code epochs, entry/exit contracts,
and confidence per field. Do not require an explicit handler table: threaded,
computed, or polymorphic dispatch may not provide one stable table.

Nested/reentrant VM calls receive invocation IDs with parent relationships.
Thread migrations and reused context buffers must not merge unrelated invocations.

### L9 — Handler traces and semantic effects

Owner: proposed `vmtrace/`, `handlers/`.

An observation capsule contains:

1. VM/invocation identity and model revision.
2. Before/after native and inferred VM state with known/unknown masks.
3. Executed instruction bytes tied to code epochs.
4. Ordered memory reads/writes and alias references where the backend supports them.
5. Observed fetch/decode inputs and rolling-state changes.
6. Native bridge outcomes and nondeterministic inputs.
7. Exception/control-transfer outcome and collection gaps.

Effect summaries use width-aware operations, not mnemonic similarity. Two
handlers with different code can have equivalent effects; one code address can
change semantics after rewrite or under a different decode state.

Before merging handlers, test varied flags, carries, overflow, partial registers,
unaligned/aliased memory, exceptional cases, and different VM-stack layouts.
Unsupported instruction/state behavior stays in the handler's contract.

### L10 — IR, CFG, and deobfuscation

Owner: proposed `ir/`, `lift/`, `cfg/`, `simplify/`.

IR values have explicit bit widths and knownness. Memory effects use an explicit
memory state/token; flags, native bridges, code writes, and exceptions remain
first-class effects. Unknown is not zero.

Transformations:

- copy/constant propagation within proven dependencies;
- modular-width arithmetic and mixed Boolean/arithmetic normalization;
- dead-effect removal when no visible memory/flag/exception effect is lost;
- VM-stack slot normalization with alias analysis;
- dispatch plumbing removal after VIP/context effects are accounted for;
- CFG simplification only for evidenced or proven edges.

An unobserved branch remains unresolved. A trace cannot prove the opposite edge
unreachable merely because it was not taken. Preserve guards or emit a coverage
boundary rather than inventing a complete function.

Every transformed node retains source-event/code-epoch lineage and proof status.
Readable IR is the first output. Native replacement requires section 11 gates.

### L11 — Reconstruction and checkpoint diagnostics

Owner: proposed dynamic `reconstruct/`, existing `snapshot/`, existing `src/pe`.

Input: selected page epochs, live layout metadata, import/bridge evidence,
startup contract, TLS/resources/runtime dependencies, optional verified IR.
Output: image plan and serialized PE with provenance, or an explicit partial
result. Optional output: checkpoint and dependency-checked restore plan.

Reconstruction may preserve VM code. Removing packing and removing virtualization
are separate operations. Do not delete bytecode, handlers, or integrity-dependent
data unless replaced behavior and dependencies are verified.

### L12 — Verification and application workflows

Owner: proposed `validate/` plus existing command adapters.

Compare live original behavior, lifted behavior, and any emitted native behavior
over declared contexts and workflows. Check return values, registers, flags,
memory effects, exceptions, ABI, and relevant external outputs.

Application results cover a profile-defined feature inventory rather than one
class name. Process survival and window creation are observations, not proof of
resource loading, worker progress, device functionality, or normal shutdown.

## 4. Proposed folder boundaries

Existing `dump.c`, `imports.c`, `mempe.*`, `meta.c`, and `sanity.c` remain narrow
adapters. Implemented under `deobf/dynamic/`: `session/`, `profile/`,
`control/`, `memdelta/`, `codecov/`, `threadctx/`, `oep/`, `strings/`,
`vmtrans/`, and `report/`. Everything else in the tree below is proposed.
Capture output directories are created under `--out`, not in the source tree.

```text
src/unpack/
  DYNAMIC_UNPACK_PLAN.md
  SYSTEM_DESIGN.md
  memory/
    proc_reader.*  peb_modules.*  mapfile.*  file_writer.*  crc32.*
    region_map.*   arena.*        budget.*
  hook/
    watch.*        registry.*     page_owner.*  policy.*
  result.h        result.c
  snapshot/
    snapshot_int.h  snap_file.c  capture.c  rebase.c  debug.c
    restore_int.h  restore.c  restore_input.c
    restore_map.c  restore_context.c  restore_tls.c  restore_modules.c
  deobf/dynamic/
    session/      profile/      control/
    antidebug/    memdelta/     pageepoch/    codecov/
    threadctx/    trace/        phase/        oep/
    apievents/    imports/      strings/      vmtrans/
    vmdiscovery/  vmstate/      vmtrace/      handlers/
    ir/           lift/         cfg/          simplify/
    reconstruct/ validate/     report/
```

Each technique owns its public header, implementation files, private state,
configuration parser, and unit-test contract. Avoid one large `dynamic.c` or
one large replacement `restore.c`.

Dependency direction:

```text
commands -> session -> stage services
stage services -> evidence/memory interfaces
agent collectors -> control/hooks/memory interfaces
PE serializer <- reconstruction plan
validation -> immutable stage outputs
```

The transport ABI and shared result types are reviewed centrally. Agent and host
build lists remain distinct. Do not move host inference into the DLL simply to
share an internal helper.

## 5. Ownership, concurrency, and memory

### 5.1 Resource ownership

- Session owns process handles and a bounded handle cache.
- Collector owns its timer requests and worker handles.
- Probe registry owns modifications and restoration.
- Producer owns one transport shard; the host consumer owns draining.
- Evidence writer owns output files, buffered payloads, and checksums.
- Inference job owns its arena and borrows immutable evidence views.
- Restore transaction owns only mappings/allocations it created in the child.

Teardown order: stop new jobs/probes -> acknowledge collector quiescence ->
drain committed events -> restore owned modifications -> balance suspensions
and timer requests -> join workers -> close handles/mappings -> seal artifacts.
If the target has exited, record which target-side cleanup operations became
unnecessary or impossible. Do not claim a live-target rollback occurred.

### 5.2 Memory budget

Initial proposed defaults, subject to fixture measurements:

- host working-memory ceiling: 256 MiB, separately accounting mappings/arenas;
- agent dynamic scratch/queues ceiling: 32 MiB;
- bulk process-read/write chunk: 1 MiB;
- per-source capture-page size: discovered page size, normally 4 KiB on x86 Windows;
- focused guard window: at most 64 pages and 250 ms per lease by default;
- instruction trace window: at most 100,000 instructions or 250 ms;
- control deadline: 2 seconds, with explicit cancellation/cleanup deadlines;
- evidence disk budget: 2 GiB per session by default, separately configurable.

These are resource ceilings, not promised throughput. Record actual bytes,
instructions, durations, and backend costs. On saturation, reduce optional
collection or end a bounded interval; do not silently discard semantic evidence.

Use streaming payload storage and indexed/mapped evidence. Do not allocate a
buffer of `SizeOfImage`, nor load an entire snapshot into private heap as the
new generic restore path. Preserve immutable original bytes before relocations.

### 5.3 Sampling and scheduling

The existing fast sampler uses cached thread handles and a 500 ms refresh.
Evolve this into an explicit profile-controlled scheduler, with measured actual
sample intervals. `Sleep(1)` and timer-resolution requests do not imply 1 kHz
sampling.

Separate cheap discovery from focused semantic collection:

1. sparse maps/page hashes and context samples;
2. small recent-write/execute ranges;
3. candidate-specific branch/context capture;
4. bounded exact semantic windows;
5. validation-driven additional windows.

Run broad hashing on a budgeted schedule. Avoid expensive thread-list walks and
filesystem logging in hook/exception callbacks. Account for agent worker stacks,
code, queues, and control ranges so collectors do not classify themselves as
application materialization.

## 6. Event transport and consistency protocol

### 6.1 Producer shards

Implemented in `control.h`/`control.c` for the agent and `report.c` for the host.
One preallocated bounded SPSC shard per publishing OS thread, one host consumer.
A thread caches its shard pointer in TLS and re-registers when the shard epoch
no longer matches the control epoch.

Shard fields (`vmpx_dyn_shard_t`, 16 shards):

| field | meaning |
|---|---|
| `owner_tid` | registration token, set by CAS; 0 means free |
| `epoch` | capture epoch the shard was registered in |
| `head` | last reserved sequence |
| `tail` | last sequence the host acknowledged |
| `dropped` | reservations refused for this shard |
| `committed` | last sequence whose slot was release-published |

Capacity is 2048 events per shard. Registration is bounded to 16 producers;
exhaustion sets `producer_overflow` and the refused event is charged to the
global drop counter. Reentrant publication on the same thread is refused and
counted in `reentrant`; it never acts as a second producer.

Event fields (`vmpx_dyn_event_t`, 288 bytes): `ready`, `epoch`, `producer`,
`tid`, `tick`, `seq`, `type`, `flags`, `len`, `crc32`, `aux`, `aux2`, `addr`,
`size`, `eip`, `esp`, `data[192]`, `reserved`. Compile-time assertions fix
`ready` at offset 0, `data` at 88, the record at 288 bytes, and the shard event
array at offset 32, so a reordering fails the build instead of changing the
wire layout.

Publication:

1. Reserve by CAS on `head`; refuse when `head - tail` reaches 2048 and charge
   the drop to the shard and the control block.
2. Zero `ready`, fill the slot, stamp `epoch`, `producer`, `tid`, `seq`,
   `QueryPerformanceCounter` in `tick`, and copy at most 192 payload bytes,
   setting `VMPX_DYN_F_TRUNC` on overflow.
3. Write a memory barrier, then store `ready = seq`.
4. Write a memory barrier, store `committed = seq`, and increment `total`.
5. Signal the host event every 64th sequence. The signal is a latency hint;
   the host polls `head` and never depends on the wakeup.

Consumption:

1. Read `head` and `tail` for each shard.
2. For `seq = tail + 1 .. head`, require `ready == seq`; otherwise stop at that
   shard and count a stall.
3. Write a memory barrier, then require `epoch == ctl->epoch`, `seq` equal to
   the expected sequence, and `producer` equal to the shard index; otherwise
   count the slot invalid and skip it.
4. Copy the 288-byte record into a 512-record drain batch and sort the batch by
   `(tick, shard, seq)`.
5. Store the advanced `tail`. The producer uses `tail` as its capacity bound.

Producer sequences are reset only while `active` is clear at capture start, not
mid-capture. The host clears `active`, waits 150 ms, zeroes every shard's
`owner_tid`, `epoch`, `head`, `tail`, `dropped`, and `committed`, resets
`dropped`, `total`, `producer_overflow`, and `reentrant`, then increments
`ctl->epoch`. The pause is a bounded wait, not a per-producer acknowledgment;
a producer stalled inside a hook across the reset can still race the clear.
`--all-events` skips that reset so boot records survive.

An abandoned producer does not block other shards; `events/loss.jsonl` records
its `head`, `ack`, `committed`, `dropped`, stall count, and invalid count.

### 6.2 Ordering

Implemented: per-shard sequence order is exact for one publishing thread. The
host sorts each drain batch by `(tick, shard, seq)`, which stabilizes file order
only; equal or close timestamps across threads do not establish a total
instruction order, and v2 carries no explicit causal links.

Critical events are code changes, VM context pairs, native bridge effects, and
checkpoint boundaries. Losing one invalidates dependent results. **Later:** the
loss ledger does not classify counts by event type or severity, so a critical
loss and a discovery-sample loss are currently indistinguishable in the
artifact.

### 6.3 Page bytes and delayed rereads

Implemented: MEM and WRITE events carry at most 192 producer bytes, and the host
may reread the full page from the live process. Each `memdelta/pages.txt` row
and each `memdelta/capture.bin` v2 record carries `validity=preview_only` or
`validity=later_reread`.

`preview_only` means the producer preview is the only evidence for that event.
`later_reread` means the bytes came from a separate host observation with its
own timing; the preview is not replaced in place, and later bytes are never
labeled as the executed version.

**Later:** `same_epoch`, `partial`, and `inconsistent` are not produced because
nothing yet computes a page-epoch identity for the payload. There is no
producer-side bounded capture that binds full bytes to the event epoch, and no
before/after hash pair is stored with the record.

### 6.4 Protocol and object identity

Implemented header fields (`vmpx_dyn_ctl_t`): `magic` (`KDYN`), `version` (2),
`pid`, `header_size`, `record_size`, `pointer_width`, `endianness`
(`0x01020304`), `shard_count` (16), `shard_events` (2048), `active`, `mode`,
sampling intervals, `dropped`, `total`, `epoch`, `producer_overflow`,
`reentrant`, collector counters, image base/size/page size, up to 16 requested
ranges, `app_lo`/`app_hi`, the entry-context block, and the 16 shards.

- The host compares `header_size`, `record_size`, `pointer_width`,
  `endianness`, `shard_count`, and `shard_events` after mapping and returns
  `unsupported` (8) before collection. `version` is a single integer; there is
  no separate major/minor pair.
- Integer widths are fixed in the record and asserted at compile time rather
  than negotiated at runtime.
- **Later:** nonce binding in the mapping names (`Local\VMPX_DYN_<pid>` and
  `Local\VMPX_DYN_EVT_<pid>`). The header carries `pid` but not the session
  nonce, and the host does not verify a declared session before accepting
  records.
- **Later:** a read-only v1 adapter. The current host rejects a v1 mapping in
  the layout check; old records are not reinterpreted as v2.
- `crc32` is a 32-bit FNV-1a value (offset 2166136261, prime 16777619) over the
  event preview in every current producer. The record carries no algorithm tag
  and no valid length for the digest, so the field is a corruption check, not a
  provenance identity.

## 7. Instrumentation and observer effects

The compatibility/anti-debug layer is not a universal bypass promise. Treat it
as a measurable part of the runtime experiment.

For each backend/profile combination, run paired workflows with and without
instrumentation. Compare startup timing, feature outcomes, exception patterns,
thread progress, code epochs, memory behavior, and cleanup.

Proposed baseline acceptance targets:

- median workflow-duration overhead no more than 5%;
- p95 workflow-duration overhead no more than 10%;
- no instrumentation-induced unhandled exception in the fixture corpus;
- no persistent guard, patch, timer request, or VMPX-owned suspension after stop.

These are proposed gates, not measured results. Focused tracing may exceed the
baseline timing budget; label those windows and exclude them from claims of
normal timing equivalence.

A backend capability record states whether it supplies samples, branches,
instruction bytes, memory effects, complete registers, and exception outcomes.
Hardware tracing support varies by CPU, OS, and access model. Do not silently
replace an unavailable exact backend with sampling and retain exact-trace labels.

Probe failures disable the affected technique and preserve evidence. They do
not justify broad exception swallowing or automatic repeated patching.

## 8. Handoff and checkpoint consistency

### 8.1 Capture modes

- **Rolling:** page/context evidence with independent intervals; useful for
  discovery, not an atomic process checkpoint.
- **Thread-local:** one parked thread and its verified dependency spans;
  other threads can still mutate shared state.
- **Coordinated:** producer quiescence and a bounded thread capture barrier;
  records the discovered thread set, successful stops, failures, and mutations.

Stopping discovered user threads does not freeze kernel activity or external
state and is not automatically an atomic checkpoint. Thread creation races and
loader/heap lock ownership must be represented. A capture worker must not wait
for a lock held by a thread it suspended.

### 8.2 Captured state

Preserve architecture-specific general registers, flags, valid stack spans,
relevant x87/SSE/extended state when required, thread role/identity, exception
chain, TLS dependencies, code epochs, and allocation/module references.

Use a suspend ledger: record each successful VMPX increment and undo exactly
that increment. Do not resume until an arbitrary suspend count reaches zero.
Handoff ownership transfers explicitly when a thread remains parked.

### 8.3 Dependency closure

Distinguish references to:

- reconstructed image bytes;
- captured private allocations and interior pointers;
- source-process module code/data;
- loader/TEB/PEB/CRT state;
- kernel handles and synchronization objects;
- callbacks, pending I/O, services, devices, and external resources.

Unknown pointer-like words are candidates, not verified dependencies. A required
unknown or unavailable dependency blocks faithful continuation. A synthetic
zero page can aid a diagnostic experiment but cannot satisfy that gate.

## 9. Restoration transaction and relocation rules

### 9.1 Preflight before any child writes

1. Validate snapshot format, lengths, checksums, valid spans, and architecture.
2. Create/identify the child and reach a declared loader barrier when required.
3. Discover the child module/layout generations and mitigation constraints.
4. Build a collision map against child images, heaps, stacks, PEB/TEB, and
   mapped regions.
5. Build a plan for every required region: retain child-owned, map exact,
   relocate with recipes, reconstruct through startup, or unsupported.
6. Reject required missing state before applying registers or resuming.

### 9.2 Reservation and page mapping

Query page size and allocation granularity. On ordinary x86 Windows, commitment
is page-granular and reservation is normally 64 KiB-granular. Reserve a verified
free reservation extent first; commit its required pages second.

A page inside a foreign reservation cannot be acquired by pretending that its
4 KiB address is an independent reservation. A read-only mapped page is not
automatically private writable memory. Do not overwrite child DLL pages or
release allocations VMPX does not own.

Track mixed page protections and partial mapping results. Rollback frees only
transaction-owned allocations and restores only transaction-owned changes.
If rollback cannot restore a controlled diagnostic child, terminate that child
and report the cleanup result rather than leaving it to execute partial state.

### 9.3 Provenance-bound pointer translation

Each relocation recipe records source location/epoch, reference kind, original
identity plus offset, destination identity, confidence, expected bytes, and
applied transaction ID.

- Apply recipes to immutable captured source bytes or to expected-byte-checked
  locations. Do not repeatedly mutate an already translated snapshot buffer.
- Preserve freshly loader-resolved IAT/TLS/index fields; they belong to the
  child generation, not the original image generation.
- Verify module identity before translating RVA. Same basename or same RVA
  alone is insufficient when module builds differ.
- Do not translate every dword inside an old module range. Integers can match
  those ranges, and live child addresses can overlap them.
- Treat relocated heap/internal pointers as a separate allocation graph.
  Relocating one 4 KiB TLS page does not relocate every pointer it contains.
- Audit every translated location and make retries idempotent.

Debugger stale-EIP translation remains a diagnostic adapter. It can reveal a
dependency but cannot prove normal execution, and it misses stale calls whose
addresses happen to be executable in an unrelated child module.

### 9.4 TLS and thread state

Read TLS metadata and `AddressOfIndex` from valid live-image metadata, with
architecture and bounds checks. A profile override requires provenance and an
explicit override flag; there is no generic literal TLS-index VA.

Preserve the rebuilt loader's assigned TLS index. Map source slot/block identity
to the correct destination block per module and thread; account for static TLS,
dynamic TLS, callbacks, expansion slots, and internal allocation references.

Initialize new-process TLS through a demonstrated loader/startup contract where
possible. Do not run callbacks twice or import unknown source CRT state over
child-initialized state. Document unsupported dynamic thread-local state.

Do not copy an entire captured TEB page into the child. Use a minimal adapter
for verified fields, preserve child identity/PEB/loader ownership, and model
stack/exception/TLS dependencies explicitly.

Kernel handles are not byte-address relocations. Recreate or duplicate supported
objects with recorded semantics and appropriate lifetimes; otherwise classify
them as unsupported. Pending operations and external device state are separate.

## 10. Runtime reconstruction contracts

### 10.1 Image plan

The plan stores runtime layout, selected compatible code/data epochs, valid
bytes, original and synthesized section extents, protections, resources,
imports, relocations, TLS, exception support, startup requirements, and unresolved
dependencies.

The appended import section belongs to the rebuilt image extent even when it
lies beyond the original snapshot image size. Inclusion does not authorize
blind rebasing of loader-written IAT values.

Reconstruction checks all offsets and alignments before serialization. Required
unreadable executable/bootstrap data is a failure, not a silently zero-filled
valid section. Noncritical missing data remains explicit in the result.

### 10.2 Startup

Select one declared output mode:

- **unpacked with original VM retained:** recovered packing state plus remaining
  VM runtime; normal bootstrap still must be demonstrated;
- **partially devirtualized:** verified selected regions replaced, remaining VM
  regions retained and reported;
- **checkpoint-assisted:** captured continuation state required; diagnostic;
- **standalone:** fresh-process startup reconstructs required runtime state and
  passes the declared workflows without checkpoint/debug repair.

Do not replace PE entry with a sampled mid-loop instruction. An emitted bootstrap
must have an explicit import/TLS/runtime initialization contract and proven
handoff. If startup cannot yet be reconstructed, emit a partial result.

### 10.3 Lazy materialization

Discover code/resources loaded after startup through feature workflows. A
startup snapshot cannot demonstrate coverage of delayed plugins, worker tasks,
device paths, error dialogs, or subsequently decrypted functions.

Select code/data versions that coexisted in a compatible runtime interval;
merging the last observed version of every page can create an image that never
existed in the source process.

## 11. Semantic and behavioral verification

### 11.1 Semantic equivalence

Compare original live effect, inferred handler effect, lifted IR, and emitted
native effect at agreed boundaries. Include widths, flags, memory aliases,
stack balance, ABI, exceptions, and relevant external state.

Test varied/randomized contexts and edge cases within declared preconditions.
For deterministic subsets, bounded symbolic checks may strengthen the result;
their bounds and modeled state remain explicit. Finite test passes are not a
proof for all inputs.

Native emission is blocked by unknown effects, missing trace bytes, incompatible
code epochs, unresolved bridges, or unsupported exception behavior. Preserve
the VM region rather than emitting an approximate replacement.

### 11.2 Application feature inventory

Profiles declare workflows with IDs, prerequisites, actions, expected outputs,
timeouts, and evidence selectors. A generic adapter supports process, module,
window, resource, file-output, worker-progress, and shutdown observations.

No built-in completion gate uses `TFormLogin` or any other product-specific
class. A window-class selector can be an optional profile observation, never
the entire application's proof of success.

Compare original and reconstructed results under controlled inputs. Record
blocked prerequisites for unavailable hardware/service/plugin workflows.
Perform repeated clean launches without the original process and without the
diagnostic debugger. Validate multiple address layouts when the output claims
relocatable startup.

### 11.3 Result schema

The logical result contains:

- requested/completed stages;
- process creation, lifetime, exit code, and terminal exception;
- captured byte validity and event/trace loss intervals;
- mapped/unmapped required dependencies;
- covered/uncovered VM instances, handlers, functions, and CFG edges;
- deobfuscation proof/test scope;
- reconstruction mode and diagnostic assists used;
- per-workflow `passed`, `failed`, `blocked`, or `untested`;
- unsupported capabilities/state and cleanup status;
- evidence manifest identity.

CLI exit policy, implemented for `vmpx run` in `unpack/result.h`:

| code | status | meaning |
|---|---|---|
| 0 | `ok`, `launched` | requested outcome reached; `ok` is observed, `launched` is restore applied without observation |
| 2 | `invalid-arg` | malformed command line |
| 3 | `capture-failed` | snapshot missing, truncated, corrupt, or unsupported layout |
| 4 | `restore-incomplete` | restore preflight, child creation, entry gate, or context application failed |
| 5 | `terminal-exception` | diagnostic window ended on a terminal exception |
| 6 | `process-exited` | observed process exited non-zero |
| 7 | `timeout` | diagnostic window ended without a verdict; process was terminated |
| 8 | `unsupported` | requested capability unavailable |
| 9 | `internal-error` | result layer reached an unclassified path |

A launch-only `run` is exit 0 because launch was the requested stage; its
`STATUS` line prints `restore=complete|incomplete` and never prints `ok`.
`--wait` upgrades `launched` to `alive` or `exited`. `alive` means the process
survived the requested wait window; `ok` is reserved for a completed diagnostic
observation with no terminal event. Neither `launched` nor `alive` is an
application validation pass. Cancellation has a separate non-success result.

## 12. Profiles and proposed command surface

The following schema and commands are design examples. They are not accepted
by the current CLI until their implementation phases land.

```json
{
  "schema_version": 1,
  "architecture": "auto",
  "discovery": {
    "image": "main",
    "regions": "materialized-and-executed",
    "entry_policy": "evidence-candidates"
  },
  "observation": {
    "backend": "auto",
    "baseline_required": true,
    "max_guard_pages": 64,
    "max_probe_ms": 250,
    "max_trace_instructions": 100000
  },
  "memory": {
    "host_budget_mib": 256,
    "agent_budget_mib": 32,
    "read_chunk_kib": 1024
  },
  "reconstruction": {
    "prefer_loader_initialization": true,
    "allow_checkpoint_diagnostics": false,
    "require_dependency_preflight": true
  },
  "validation": {
    "feature_inventory": "workflows.json",
    "fresh_process_required": true,
    "diagnostic_repair_allowed_for_pass": false
  }
}
```

Selectors use module identities/RVAs or allocation roles where possible. Resolve
them against the current generation. Absolute overrides are optional,
architecture-checked, logged, and never copied into the generic implementation.

Proposed commands:

```text
vmpx deobf --pid <pid> --profile <profile.json> --out <session-dir>
vmpx trace --session <id> --candidate <vm-id> --budget <trace-budget>
vmpx reconstruct --session <id> --mode <output-mode> --out <exe>
vmpx validate --session <id> --exe <exe> --workflows <workflows.json>
```

Retain the current `deobf --pid/--name --out --mode` adapter while introducing
new sessions. Document unsupported new flags rather than implying they already
work. Unify environment-variable tuning behind the effective profile over time;
keep compatibility translations visible in the manifest.

## 13. Artifact schema and provenance

Proposed per-session output:

```text
session/
  manifest.json
  profile.effective.json
  capabilities.json
  modules.jsonl
  allocations.jsonl
  events/events.bin
  events/loss.jsonl
  memory/pages.bin
  memory/page-index.jsonl
  trace/intervals.jsonl
  trace/code.bin
  phase/candidates.jsonl
  imports/evidence.jsonl
  strings/observations.jsonl
  vm/instances.jsonl
  vm/contexts.jsonl
  vm/handlers.jsonl
  ir/functions/
  reconstruct/plan.json
  reconstruct/image.exe
  snapshot/                 optional checkpoint diagnostics
  validate/result.json
  report.md
```

Current `vmpx deobf` output (implemented):

```text
<out>/
  summary.txt
  session/manifest.json       session/profile.effective.json
  session/capabilities.json   session/modules.jsonl
  session/regions.jsonl
  events/events.txt           events/loss.jsonl
  memdelta/pages.txt          memdelta/capture.bin
  codecov/exec.csv            threadctx/samples.csv
  vmtrans/transitions.csv     apievents/events.csv
  strings/strings.txt
```

Only create outputs whose stages ran. Seal chunks with format/version,
checksums, session identity, source sequence ranges, and validity metadata.
Use content hashes for durable artifact identity; CRC is a corruption check,
not a substitute for a provenance identity.

The manifest records tool build identity, effective profile, observation
backends, runtime architecture/OS, module identities, capture intervals,
diagnostic changes, omissions, and schema versions. Capture data can include
sensitive runtime strings; export selection/redaction must not modify the
original evidence or silently change semantic test inputs.

`report/` becomes a formatter/aggregator, not the owner of collection, memory
inference, string semantics, and lifecycle policy in one function.

## 14. Failure handling and recovery

- Process exit: seal committed evidence, cancel probes/jobs, classify incomplete
  stages, preserve exit/exception data.
- Read race/unreadable page: preserve valid spans and capture timing; invalidate
  dependent semantics rather than reuse stale bytes.
- Transport saturation: record producer/epoch gaps; shed optional discovery or
  terminate a focused window with an incomplete result.
- Backend unavailable: select a supported requested outcome or return unsupported;
  never relabel samples as exact traces.
- Candidate/model contradiction: retain counterexample, revise the model, and
  invalidate dependent handlers/IR by revision.
- Restore collision/missing dependency: fail preflight or return diagnostic-only;
  do not count skipped required regions as faithful restoration.
- Instrumentation divergence: disarm the affected lease, retain the paired
  experiment, and reject that backend/profile for equivalence claims.
- Timeout: stop new work, perform bounded cleanup, record incomplete state;
  timeout does not imply the application succeeded.
- Serialization/ABI mismatch: reject the stream before decoding payloads.

## 15. Decisions that prevent another ad-hoc restore loop

1. Fix result truthfulness and split modules before adding more fault repairs.
2. Fix transport and page-generation consistency before training VM hypotheses
   on collected records.
3. Trace bad arguments and computed call targets to their producers rather than
   diagnosing them from visually suggestive numeric values.
4. Preserve loader-owned child state and immutable source provenance.
5. Require module/allocation identity for translations, not old numeric ranges.
6. Keep snapshot continuation diagnostic until dependency closure is verified.
7. Recover VM effects in bounded live windows, then validate transformations.
8. Validate the feature inventory, not one window or one successful API call.

These decisions define the implementation gates. They do not claim that the
existing target is unpacked, devirtualized, or fully runnable today.
