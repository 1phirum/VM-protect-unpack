# VMPX dynamic VMProtect unpacking and deobfuscation plan

Date: 2026-11-15  
Status: implementation roadmap; P0, P1, and the P2 transport v2 are implemented
in the working tree. Later phases remain proposals, not claims of capability.  
Scope: `src/unpack`, its agent integration, and its runtime-facing commands.  
System contracts: [SYSTEM_DESIGN.md](SYSTEM_DESIGN.md).

## 1. Outcome

Build a runtime-first analysis system that can observe protected execution,
recover materialized code and data, identify virtual-machine behavior, recover
verified semantics, and reconstruct an application with measurable functional
coverage. A memory dump, a sampled instruction, or one visible window is not
the completion criterion.

The system must report these outcomes separately:

1. **Runtime capture:** execution evidence and versioned memory were collected.
2. **Unpacked image:** observed code and data were reconstructed; VM execution
   may still be present.
3. **Deobfuscated regions:** specific transformations were verified against
   runtime evidence.
4. **Devirtualized functions:** specific VM functions have verified equivalent
   representations; unsupported instructions and unobserved paths remain explicit.
5. **Standalone application:** a reconstructed executable starts normally,
   without the source process, captured register state, snapshot loader, or
   debugger-assisted exception repair.
6. **Application validation:** the declared feature inventory passes its
   configured workflows. Unexercised features are reported as untested.

Snapshot-assisted continuation is a diagnostic outcome, not outcome 5.

## 2. Scope and design constraints

- Discover from a live process. Do not make an on-disk packed image or an
  offline dump scanner the primary unpacking/deobfuscation input.
- Allow persisted runtime traces and snapshots as evidence, regression inputs,
  and reconstruction inputs. Every derived result retains its runtime origin.
- Start with the existing PE32/x86 Windows build. Design address records for
  wider targets, but do not advertise x64 support until its backend is tested.
- Keep one base technique per folder under `deobf/dynamic/`.
- Keep process-memory ownership in `memory/`, instrumentation ownership in
  `hook/`, and checkpoint/restoration ownership in `snapshot/`.
- Put target-specific addresses, selectors, expected behaviors, and workflow
  inputs in profiles. Discover values before accepting explicit overrides.
- Do not embed a target product name, login class, TLS index address, dispatcher
  address, VM-register assignment, or fixed module base in generic code.
- Use small C modules with explicit contracts. Aim for approximately 250 lines
  per implementation file; review files exceeding 350 lines for separation.
- Preserve existing user work and legacy artifacts. Retire old paths by build
  and command selection, not by deleting historical sources.
- Do not require authentication changes or protocol substitution to demonstrate
  unpacking. Preserve application behavior and exercise available workflows.

## 3. Current implementation baseline

The following inventory comes from the source tree and `build.bat`, not from
the older aspirational architecture documents.

### 3.1 Existing runtime components

- `deobf/dynamic/control/`: shared mapping, mode configuration, event publication,
  and an entry-context handoff.
- `deobf/dynamic/memdelta/`: bounded committed-page change collection.
- `deobf/dynamic/codecov/`: page-guard first-execution collection.
- `deobf/dynamic/threadctx/`: thread context sampling and entry parking; includes
  the cached-handle `VMPX_TC_FAST_SAFE` path.
- `deobf/dynamic/vmtrans/`: transitions between sampled private-executable and
  other memory. This is a candidate signal, not VM identification or lifting.
- `deobf/dynamic/oep/`: intrusive DR, software-breakpoint, and guarded-range
  capture paths, separate from the thread-only sampler.
- `deobf/dynamic/strings/`: extraction from runtime-derived captured bytes.
- `deobf/dynamic/report/`: current `vmpx deobf` host driver and artifact writer.
- `hook/watch.*`: another guarded-range control/event path.
- `memory/`: process reads, mapped files, buffered writes, module enumeration,
  and checksums.
- `snapshot/`: private-region capture, snapshot I/O, pointer rebasing, restore,
  and diagnostic debugger continuation.
- `dump.c`, `mempe.*`, `meta.c`, `sanity.c`, `imports.c`: live-image support.

`cmd_deobf.c` calls `dyn_report_run`; the old `deobf_run.c` and other static
deobfuscation sources are not linked by the current `build.bat`.

### 3.2 Gaps that must be resolved before deeper inference

1. **Transport publication:** `control.c` increments `head` before filling a
   slot; `report.c` consumes through `head` without checking a per-slot committed
   generation. Concurrent producers can expose incomplete records.
2. **Capture timing:** the host rereads full pages after receiving a short event
   preview. Those bytes can belong to a later page generation than the event.
3. **Entry meaning:** the first sampled instruction in the lowest executable
   section can be a mid-loop continuation. It is not automatically the original
   entry point or a valid standalone executable entry.
4. **Instrumentation interference:** watch, coverage, and OEP guards have
   separate ownership paths. Broad guard arming previously stalled execution.
5. **VM evidence:** private executable memory alone does not prove a VM; VM
   handlers can also execute inside image-backed memory.
6. **Pointer identity:** range-based dword rebasing does not prove a value is a
   pointer. Old module ranges can overlap valid addresses in a new process.
7. **Runtime state:** committed private bytes do not restore kernel handles,
   loader state, CRT state, threads, or every allocation reservation.
8. **Target coupling:** `snapshot/restore.c` contains a literal TLS index address;
   launch/OEP code outside this directory still uses `TFormLogin`.
9. **Result reporting:** the inspected restore log ends in a terminal exception
   and still prints `STATUS run ok`. Launch/restore status is not behavioral
   validation.
10. **Module size:** `snapshot/restore.c` exceeds 1,100 lines and combines policy,
    mapping, thread context, TLS work, rebasing, and orchestration.

### 3.3 Evidence boundary

`artifacts/stageb-login/run-oep11.log`, as inspected on this date, records a
relocated TLS block, one debugger-assisted stale execute-address translation,
then a read access violation and a terminal exception. It reports 106 mapped
regions, 17 failed regions, 14,286 of 14,416 pages, and 36 child modules versus
83 snapshot modules. It does not establish full application execution.

The read-fault value resembles two UTF-16 characters, but that resemblance does
not prove an ANSI/Unicode mismatch, a bad import, or TLS corruption. Trace the
argument's origin before selecting a repair.

The older [repository plan](../../docs/plan.md) includes target-specific and
login-path goals. This plan governs new work under `src/unpack`; it does not
overwrite the older document. A precise VMProtect version is not established
by section naming, entropy, or these source files.

## 4. Layered execution pipeline

Read the detailed responsibilities and contracts in `SYSTEM_DESIGN.md`.

```text
L0  memory and identity
L1  session, profiles, workflow controller
L2  instrumentation policy and hook ownership
L3  transport, event ordering, evidence storage
L4  memory generations and materialization history
L5  thread/branch execution evidence
L6  unpack phases and handoff candidates
L7  imports, native bridges, runtime strings
L8  VM discovery and context hypotheses
L9  focused VM tracing and handler semantics
L10 runtime-derived IR, CFG, deobfuscation
L11 image reconstruction and optional checkpoint diagnostics
L12 differential and full-application validation
```

A layer consumes declared outputs from lower layers; collectors never depend
on lifting or native emission. Validation feeds new collection requests through
the session controller, not by calling instrumentation directly.

There are two related execution paths:

- **Materialization path:** runtime observation -> page epochs -> handoff and
  dependencies -> image/import reconstruction -> fresh-process validation.
- **Semantic path:** runtime observation -> VM candidates -> focused trace ->
  context model -> handler effects -> IR -> differential verification.

Run these paths incrementally. A complete application image is not required to
begin tracing a selected VM function in the original live process.

## 5. Implementation phases

Every phase below names concrete files, artifacts, prerequisites, and gates.
New file names and commands are proposals until implementation lands.

### P0 — Result correctness and module boundaries

**Prerequisites:** none; use existing logs and source behavior as the baseline.

**Work:**

- Introduce typed run results: capture completeness, restore completeness,
  process lifetime, terminal exception, workflow results, and unsupported state.
- Make `STATUS` and exit codes distinguish launch, diagnostics, and validation.
- Split `snapshot/restore.c` into `restore.c`, `restore_input.c`,
  `restore_map.c`, `restore_context.c`, `restore_tls.c`, and
  `restore_modules.c`. The proposed `restore_plan.c` was not needed: input
  preflight lives in `restore_input.c` and mapping policy in `restore_map.c`.
  Keep `rebase.c` and `debug.c` as separate concerns.
- Put shared private types in `restore_int.h`, not in the public `vmpx.h`.
- Inventory every target literal and convert it to discovery or a profile
  override. Remove login-class assumptions from generic completion rules.
- Record current diagnostic behavior as regression fixtures before changing it.

**Artifacts:** inventory, literal audit, module contracts, regression manifests.

**Gate:** the refactor builds; a known failed fixture cannot report application
success; this phase does not claim to fix the target's execution.

**Status:** landed in the working tree.

- `unpack/result.h` and `unpack/result.c` define the typed status, result
  fields, status names, exit mapping, and the single run classifier.
- `snapshot/restore_int.h` holds the private contracts. `restore.c` is
  orchestration only; input, map, module, context, and TLS work live in their
  own translation units.
- `snap_restore_ex` returns the typed status. `cmd_run.c` prints
  `STATUS run launched|ok|alive|exited|failed` and maps exits `2` through `9`;
  a terminal exception returns `5` and can never print `STATUS run ok`.
- The TLS index is read from the rebuilt PE's `PEHDR_DIR_TLS`
  `AddressOfIndex` field. The literal `0x18AFC3C` is gone; the discovered RVA
  is `0x14AFC3C` for the current capture.
- The `TFormLogin` completion gate is removed from generic launch and OEP
  waits. The default is any visible titled top-level window; `--class` selects
  a specific class when a workflow needs one.
- Tests: `tests/run_result_test.bat`, `tests/run_restore_input_test.bat`, and
  `tests/check_run_log.ps1`. The historical `run-oep11.log` is the failing
  fixture; it fails the checker and a corrected log passes.
- Not executed in this shell: the elevated target run. The shell is not
  elevated, so the live `terminal-exception` exit `5` check remains the next
  manual gate.

### P1 — Session, profiles, and memory substrate

**Prerequisites:** P0 result types and ownership boundaries.

**Work:**

- Add `session/` and `profile/` under `deobf/dynamic/`.
- Use process creation time plus session ID, not PID alone, for identity.
- Give modules and allocations generation IDs; track unload/reload and
  free/reuse of the same address.
- Extend `memory/proc_reader.*` with exact/partial read results and validity
  spans; unreadable bytes must not become indistinguishable zero bytes.
- Add `memory/region_map.*`, `memory/arena.*`, and `memory/budget.*`.
- Discover page size, allocation granularity, address limits, architecture,
  mitigation policy, module layout, and available observation capabilities.
- Validate profile selectors and numeric bounds before activating collectors.

**Artifacts:** session manifest, effective profile, capability manifest,
module-generation map, region-generation map.

**Gate:** PID reuse, allocation reuse, overflow, partial-read, and cleanup tests
pass; a profile contains no mandatory product-specific value.

**Status:** substrate and session artifacts landed; the report command is
integrated. P2 transport v2 has since landed; see its status for the remaining
consistency gaps.

- `memory/budget.*` provides saturating host/agent charges with an explicit
  refusal counter and a per-read chunk ceiling. `memory/arena.*` is a bounded
  block arena with 8/16-byte alignment and a maximum block size.
- `memory/region_map.*` merges sorted enumerations, keeps a generation per
  base/properties tuple, and returns readable spans. Absence followed by
  reactivation receives a new generation; reuse that occurs entirely between
  two refreshes remains unobservable without an event source.
- `proc_reader_read_ex` returns requested/read counts, partial status, the
  readable span at the start address, and the Windows error. Reads are capped
  to one readable region at a time, so a readable prefix is preserved instead
  of being lost when `ReadProcessMemory` crosses into a `PAGE_NOACCESS` page.
- `util/json.*` is a bounded parser (depth 32, 8192 nodes) used for profiles
  and future manifests. It rejects duplicate keys, control bytes, embedded
  U+0000, trailing data, and malformed numbers.
- `deobf/dynamic/profile/` defaults, loads, validates, and writes the effective
  profile. The file schema requires `schema_version`; numeric ranges and enum
  values are checked before collectors activate.
- `deobf/dynamic/session/` owns PID plus creation-time identity, a random
  nonce, lifecycle transitions, module path/base/size generations, region
  generations, and session artifacts. `session_bridge.c` is the single
  lifecycle owner used by `dyn_report_run`.
- `vmpx deobf` now requires `--pid`, `--name`, or `--exe`; it no longer scans
  the working directory for a target. `--profile` is optional, and `--max-mb`
  overrides the profile's host budget. Output includes
  `out/session/manifest.json`, `profile.effective.json`, `capabilities.json`,
  `modules.jsonl`, and `regions.jsonl`.
- Live build verification: attached to a 32-bit `cmd.exe`, injected the agent,
  collected for two seconds, returned `0`, and wrote a manifest with
  `state=stopped`, `writes=1`, 15 modules, and 304 regions. No elevation was
  needed for the same-user attach. A target selector omitted returned `2`.
- Gate evidence is partial: overflow, partial-read, allocation reuse, generation
  stability, lifecycle rejection, and cleanup are covered; a live PID-reuse
  fixture is not yet automated. The session ID includes creation time and nonce
  so a reused PID cannot collide, but that property is structural rather than
  measured across two live processes.

### P2 — Event transport and capture consistency

**Prerequisites:** P1 identities and memory budgets.

**Work:**

- Version the agent/host protocol with explicit lengths, architecture, and
  session nonce; never use compiler-dependent struct layout as a wire format.
- Replace uncommitted global-head consumption with per-producer bounded SPSC
  shards and release/acquire publication, as specified in the system design.
- Add producer registration limits, sequence gaps, drop reasons, drain
  acknowledgments, and an epoch-based reconfiguration handshake.
- Preserve boot records without resetting producer indices during collection.
- Bind event previews and full-page captures to specific capture/page epochs.
- Serialize an explicit hash algorithm; a field called CRC must not silently
  carry a different algorithm's output.

**Artifacts:** versioned event stream, payload store, loss ledger, consistency
report, protocol layout fixtures.

**Gate:** delayed-producer, wraparound, saturation, host-crash, and late-attach
tests never deliver a partial or stale slot as a valid event. Dropped critical
events make the affected inference incomplete, not successful.

**Status:** transport v2 landed in the working tree. Binding full page bytes to
a page epoch and the automated transport fixtures remain open.

**Landed in:** `deobf/dynamic/control/control.h`, `control.c`,
`deobf/dynamic/report/report.c`; runtime output `out/events/events.txt`,
`out/events/loss.jsonl`, `out/memdelta/pages.txt`, `out/memdelta/capture.bin`,
`out/summary.txt`, and `out/session/manifest.json`.

- `control.h` defines protocol v2: magic `KDYN`, version `2`, endianness marker
  `0x01020304`, 16 producer slots, 2048 events per shard, a 192-byte preview,
  and a 288-byte `vmpx_dyn_event_t`. Compile-time `offsetof`/`sizeof`
  assertions fail the build if the asserted layout moves; the host compares
  `header_size`, `record_size`, `pointer_width`, `endianness`, `shard_count`,
  and `shard_events` after mapping and returns `unsupported` before collection.
- Shards are one per publishing thread with `owner_tid` (CAS registration),
  `epoch`, `head`, `tail`, `dropped`, and `committed`. Registration is limited
  to 16 producers; a 17th sets `producer_overflow`, and the refused event is
  charged to the global drop counter. Reservation refuses at 2048 outstanding
  records and charges the drop to the shard and to the control block.
- Publication zeroes `ready`, fills `epoch`, `producer`, `tid`, `seq`, `tick`,
  `type`, `flags`, `addr`, `size`, `eip`, `esp`, `crc32`, `aux`, `aux2`, and
  the preview, then release-publishes `ready = seq` and updates `committed`.
  The host event is signalled every 64th sequence; it is a latency hint, not
  the correctness source.
- The host walks `tail + 1 .. head`, accepts only `ready == seq` with matching
  `epoch`, `seq`, and `producer`, and advances `tail`. A slot that is not ready
  stalls that shard without blocking others; a foreign epoch, sequence, or
  producer is counted invalid and skipped. Each 512-record batch is sorted by
  `(tick, shard, seq)` before it is written.
- Reset happens only at capture start: `active` clears, 150 ms passes, the host
  zeroes every shard's `owner_tid`, `epoch`, `head`, `tail`, `dropped`, and
  `committed`, resets `dropped`, `total`, `producer_overflow`, and `reentrant`,
  then increments `epoch`. Producers re-register on the epoch change.
  `--all-events` skips the reset and keeps boot records.
- `events/loss.jsonl` carries one record per shard (`shard`, `owner`, `head`,
  `ack`, `committed`, `dropped`, `stalled`, `invalid`) and one global record
  (`total`, `events`, `dropped`, `shard_dropped`, `overflow`, `reentrant`,
  `stalled`, `invalid`).
- `memdelta/capture.bin` is capture format 2: a `VXDB` header carrying the page
  size, then records carrying `addr`, `seq`, `size`, `len`, `crc32`, `flags`,
  `event_type`, and `validity`. Validity is `preview_only` for producer bytes
  and `later_reread` for a host reread of the full page.
- Gate evidence: a live 10 s default-mode capture (mode mask `meat`) against 32-bit
  `%SystemRoot%\SysWOW64\cmd.exe` running a long built-in loop returned `0` and
  printed `STATUS deobf-dynamic ... events=4583 mem=4713 exec=10 threads=469
  dropped=0 manifest=ok`. The summary reported `mem_ticks=28`, `exec_ticks=1`,
  `exec_hits=10`, `mem_changed=4713`, `strings=3662`, and a loss ledger whose
  shard and global records were all `stalled=0`, `invalid=0`, `overflow=0`,
  `reentrant=0`. No elevation was needed for the same-user attach.
- Code coverage and memory delta now coexist in the default mode. Guard faults
  raised by data reads or writes drop that page's guard for the pass instead of
  re-arming it, which previously produced an endless retry loop and stalled
  `memdelta` at `mem_ticks=1`.

**Open gaps:**

- No automated delayed-producer, wraparound, or saturation fixture. The
  transport gate is evidenced by one live run plus reader logic, not by a
  repeatable test.
- Reset uses a fixed 150 ms pause after clearing `active`; there is no
  per-producer acknowledgment that a publishing thread has left the shard.
  A producer stalled inside a hook across the reset can race the shard clear.
- Mapping names are still `Local\VMPX_DYN_<pid>` and
  `Local\VMPX_DYN_EVT_<pid>`. The header carries `pid` but no session nonce, the
  nonce is not bound into the names, and the host does not verify a declared
  session before accepting records.
- The wire format is still the mapped C struct with fixed-width fields and
  compile-time offset assertions, not an independently serialized codec.
- The payload store is still the 192-byte event preview plus a later host
  reread. No producer-side bounded capture binds full page bytes to the event
  epoch, and no before/after hash pair is stored with the record.
- The loss ledger has no separate schema for critical events; `dropped`,
  `stalled`, and `invalid` are counts without event type or severity.
- `crc32` is a 32-bit FNV-1a value over the preview in every current producer
  and the record carries no algorithm tag.
- A data read or write through a guarded page costs that page's coverage until
  the next arm cycle. The access is not recorded and the immediately following
  instruction fetch can be missed; the page is re-armed only after the worker's
  next `cov_collect`/`cov_arm_all` pass.

### P3 — Low-perturbation baseline and instrumentation controller

**Prerequisites:** P2 trustworthy transport.

**Work:**

- Add `hook/registry.*`, `hook/page_owner.*`, and `hook/policy.*`.
- Centralize guard/VEH ownership for watch, coverage, and OEP probes.
- Keep an external observation route usable without an injected agent.
- Add an agent-assisted route and a separate focused-trace route; advertise
  backend capabilities and gaps explicitly.
- Measure observer effects against uninstrumented workflow runs.
- Record timing, exception, memory-query, and instrumentation-integrity signals
  under `deobf/dynamic/antidebug/`; do not equate an installed hook with silent
  or behavior-preserving operation.
- Gate active probes by tested scope, lifetime, and perturbation budget.

**Artifacts:** paired baseline reports, probe ledger, backend capability map.

**Gate:** bounded probes cleanly restore protections and handlers; target
exceptions are not consumed by an unrelated collector; no full-image guard
arming is the default.

### P4 — Memory generations and execution history

**Prerequisites:** P3 selected observation route.

**Work:**

- Extend `memdelta/` to track allocation, commit, write, protection, execution,
  and release events as distinct facts.
- Add `pageepoch/` and `trace/` technique folders.
- Prioritize recently materialized executable ranges instead of continuously
  hashing an entire large virtual image.
- Keep cached thread handles with creation-time identities and a suspend-count
  ledger. Balance timer-resolution requests during teardown.
- Label samples as samples; exact traces require a backend that provides exact
  instruction/branch evidence for the scoped interval.
- Record instruction bytes at execution epochs and invalidate them after writes.

**Artifacts:** page lifecycles, branch/thread evidence, code-epoch store,
sampling gaps, overhead measurements.

**Gate:** allocate/free/reuse and write/execute/rewrite fixtures create distinct
versions; all execution records reference valid bytes or an explicit gap.

### P5 — Unpack phases and semantic handoff

**Prerequisites:** P4 page and execution histories.

**Work:**

- Add `phase/`; evolve `oep/` into a candidate/handoff service.
- Correlate materialization, write-to-execute events, native call boundaries,
  thread roles, and repeated region stability.
- Retain multiple candidates and contrary observations instead of latching the
  first instruction in one section as definitive OEP.
- Distinguish loader entry, observed app instruction, VM entry, native entry,
  checkpoint continuation, and application-ready milestone.
- Capture the dependency closure of a candidate, including registers, TLS,
  stack validity, code versions, referenced allocations, and loaded modules.
- Publish the strength of cross-thread consistency achieved during capture.

**Artifacts:** phase graph, candidate evidence, handoff context, dependency and
consistency manifests.

**Gate:** mid-loop and worker-thread fixtures are not promoted to standalone
entry; candidate readiness requires explicit dependencies and capture quality.

### P6 — Import and native-bridge recovery

**Prerequisites:** P4; P5 improves bootstrap reconstruction but is not required
for observing API boundaries.

**Work:**

- Add `apievents/` and `imports/` under `deobf/dynamic/`.
- Correlate runtime resolutions, indirect native calls, module generations,
  export identities, API-set mappings, forwarders, and delay loads.
- Record calling convention, argument widths, observed return values, stack
  balance, last-error state, and data/output spans when relevant.
- Separate decoy import descriptors from demonstrated call dependencies.
- Treat pointers decrypted/computed during VM execution as dynamic resolution
  evidence, not as values a pre-run image scan can necessarily repair.
- Extend runtime string extraction with byte-span validity and consumption
  evidence; preserve identifiers that existing vowel filters would discard.

**Artifacts:** import evidence graph, bridge contracts, runtime strings with
provenance, unresolved/ambiguous dependencies.

**Gate:** exercised bridge calls resolve to the correct module identity and
ABI in a fresh process; unresolved or ambiguous calls cannot be silently cast
to the nearest exported symbol.

### P7 — VM discovery and context recovery

**Prerequisites:** P4 execution evidence and P6 native boundaries.

**Work:**

- Add `vmdiscovery/` and `vmstate/`.
- Detect recurring dispatch behavior, bytecode consumption, VM-stack effects,
  context movement, and native bridge transitions.
- Cluster candidates by execution/context evidence, not section names or one
  fixed byte pattern. Support multiple and nested VM instances.
- Infer VIP, VSP, virtual registers, flags, decode state, and context storage
  through repeated before/after observations.
- Keep competing hypotheses until discriminating traces resolve them.
- Do not hardcode a register allocation, opcode width, or handler-table shape
  based on one public VMProtect example.

**Artifacts:** VM candidate catalog, instance graph, context models with
confidence and counterexamples.

**Gate:** a candidate fixture is classified using semantic evidence;
non-VM private executable code remains a negative control; unsupported context
fields remain unknown rather than guessed.

### P8 — Focused VM trace and handler semantics

**Prerequisites:** P7 validated candidate/context model and P3 focused backend.

**Work:**

- Add `vmtrace/` and `handlers/`.
- Trace selected VM intervals with paired context states, ordered memory effects,
  decoded-byte observations, exceptions, and native bridge contracts.
- Separate fetch/decode, dispatch, semantic operation, and next-state update.
- Identify a handler by VM instance and code epoch, not just its address.
- Preserve partial-register behavior, operand widths, flags, aliasing, memory
  ordering, and exception behavior in effect summaries.
- Validate deterministic handler effects using runtime-derived test contexts;
  isolate OS calls and nondeterministic inputs instead of executing them blindly
  in a semantic harness.

**Artifacts:** trace capsules, handler catalog, effect summaries, equivalence
results, unsupported-instruction ledger.

**Gate:** selected handler families pass adversarial and randomized context
tests; passing one input does not establish universal equivalence.

### P9 — Runtime-derived deobfuscation and lifting

**Prerequisites:** P8 effects with sufficient evidence.

**Work:**

- Add `ir/`, `lift/`, `cfg/`, and `simplify/` technique folders.
- Build width-aware SSA with explicit memory and flag dependencies.
- Model native bridges, exceptions, indirect control flow, and code writes.
- Apply copy/constant propagation, dead-effect removal, expression normalization,
  stack normalization, and dispatcher removal only with the required proof.
- Keep trace-proven paths distinct from unexplored paths. One observed branch
  does not prove an opaque predicate or unreachable alternative.
- Preserve source-event and code-epoch lineage through every transformation.
- Emit readable IR first; native replacement is a later, verified operation.

**Artifacts:** per-function IR, observed CFG, unresolved edges, transformation
proof records, differential reports.

**Gate:** each transformed region matches the original live behavior over the
declared corpus; unresolved effects prevent native replacement of that region.

### P10 — Runtime image reconstruction and checkpoint diagnostics

**Prerequisites:** P5/P6 for images; P9 only for replacing verified VM regions.

**Work:**

- Add `reconstruct/` as a runtime-evidence coordinator; keep PE serialization
  in the existing `src/pe` layer.
- Select compatible page epochs and require validity for executable/bootstrap
  bytes. Preserve runtime resources, data, TLS, exception support, and delay loads.
- Build normal loader imports and a demonstrated startup route. Never set PE
  entry to an arbitrary captured EIP and call the result standalone.
- Separate the memory-image extent from synthesized section extents, including
  the appended import section; track loader-owned writes independently.
- Make snapshot restore optional, explicit, and dependency-checked.
- Replace blind rebasing and copied-TEB pages with provenance-bound relocation
  recipes and a minimal, validated thread-state adapter.
- Model unsupported handles, synchronization objects, heaps, and pending I/O;
  reject required missing state instead of substituting dummy pages.

**Artifacts:** image plan, reconstructed PE, import/relocation/TLS manifests,
optional checkpoint and restore preflight reports.

**Gate:** image outputs identify whether VM code remains; restore results
identify unsupported state; standalone candidates start without diagnostic
stale-EIP repair or source-process state.

### P11 — Full-application validation and release criteria

**Prerequisites:** trustworthy results from P0 and outputs from P10.

**Work:**

- Add `validate/` with configurable workflow adapters and feature inventories.
- Compare original and reconstructed processes under the same controlled inputs.
- Exercise startup, navigation, resource loading, worker tasks, delayed code,
  plugin/module loads, failure paths, and shutdown where those features exist.
- Include device- or service-dependent workflows only when their prerequisites
  are available; otherwise retain a blocked/untested result.
- Test repeated launches, address-layout changes, changed working directories,
  timer behavior, and absence of the source process.
- Publish feature results, uncovered VM regions, loss intervals, dependencies,
  and any remaining diagnostic-only behavior.

**Artifacts:** machine-readable validation results, feature evidence, trace
coverage, reproducibility manifest, release report.

**Gate:** every declared release workflow passes; terminal failures are absent;
missing evidence or missing prerequisites cannot become a pass.

## 6. Implementation order and parallel boundaries

```text
P0 -> P1 -> P2 -> P3 -> P4
                         |-> P5 -----------|
                         |-> P6 -----------|-> P10 -> P11
                               |-> P7 -> P8 -> P9 --|
```

- P5 and P6 can progress independently after page/trace contracts stabilize.
- P7/P8 can run against the original live process while image reconstruction
  remains incomplete.
- P9 is not a prerequisite for an unpacked image that intentionally retains VM
  execution; it is required for verified VM-region replacement.
- Do not assign multiple implementers to edit the transport ABI, public result
  types, or build source list independently. Land shared contracts first.
- Future parallel work packages are memory identity, transport, instrumentation,
  phase detection, imports/bridges, VM modeling, reconstruction, and validation.
  This document does not start agents or perform those code changes.

## 7. Test corpus and gates

Use small source-available fixtures before treating the protected application
as the only test case.

- **Memory:** partial/unreadable pages, allocation reuse, changing protections,
  large virtual images, allocation-granularity collisions, missing data.
- **Transport:** multiple publishers, delayed completion, wraparound, saturation,
  attach after boot, abandoned producer, protocol mismatch, cancellation.
- **Execution:** tight loops, worker-first execution, JIT negative controls,
  self-modifying code, exception-heavy code, thread creation during capture.
- **Imports:** forwarded and ordinal exports, API sets, delay loading, dynamic
  pointer computation, valid addresses overlapping previous module ranges.
- **TLS/runtime:** static and dynamic TLS, callbacks, multiple threads, x87/SSE
  state, CRT initialization, stale handles, loader-owned index writes.
- **VM:** source-available small interpreters with different dispatch/context
  layouts, nested calls, variable decoding, and native bridges.
- **Application:** multi-window GUI and non-GUI fixtures, lazy resources,
  plugin loading, background work, error recovery, shutdown.

Performance thresholds and initial defaults are proposed in the system design.
They are acceptance targets, not measurements of the current implementation.

## 8. First implementation slice

The next code change should implement P0, not add another address-specific
exception workaround:

1. Extract typed result and failure reporting.
2. Freeze the existing failed-run fixture as a regression input.
3. Split restore orchestration from mapping/context/TLS policy.
4. Add tests that reject `run ok` after terminal failure.
5. Record discovered versus overridden target values.
6. Continue with identity and transport corrections in P1/P2.

This creates a trustworthy foundation for deeper dynamic tracing. Adding more
collectors before fixing event consistency would increase data volume without
increasing the reliability of the conclusions.
