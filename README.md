# vmpx

Live-process unpacking and inspection for VM-protected Windows binaries.

`vmpx` is a single 32-bit executable. There is no installer, no side-by-side DLL,
and no Visual C++ runtime dependency: the injection agent is compiled into the
executable as a resource and written to disk only when a run actually needs it.

The deobfuscation path is dynamic. `vmpx` attaches to a **running** target,
injects a collector agent, and records what the process does — page identity and
content, executed addresses, thread contexts, VM transitions, API traffic, and
strings built at runtime. It never scans a static dump and guesses.

```
content=page identity + bytes    execution=guard-page coverage
contexts=thread samples          transitions=VM enter/exit classification
api=inline hooks                 strings=live buffer recovery
```

Everything a run observes is either written to an artifact or counted in a loss
ledger. Nothing is dropped silently.

- Targets: x86 Windows processes.
- Host: one file, `vmpx.exe`, static CRT, no external libraries.
- Release: **v1.0.0** — 488 KB, SHA-256 `DDC0D9362E22871809D733F38DBAD8054218C15A7198A8BBC1623C8C01FDE797`.

---

## Contents

- [Download](#download)
  - [Windows](#windows)
  - [Linux](#linux)
- [Quick start](#quick-start)
- [Commands](#commands)
- [The `deobf` session](#the-deobf-session)
  - [Options](#options)
  - [Artifacts](#artifacts)
  - [File formats](#file-formats)
  - [Reading `summary.txt`](#reading-summarytxt)
- [How the capture pipeline works](#how-the-capture-pipeline-works)
- [Exit codes](#exit-codes)
- [Build from source](#build-from-source)
- [Compatibility and limits](#compatibility-and-limits)
- [License](#license)

---

## Download

### Windows

PowerShell:

```powershell
Invoke-WebRequest -Uri "https://github.com/1phirum/VM-protect-unpack/releases/latest/download/vmpx.exe" -OutFile vmpx.exe
.\vmpx.exe version
```

GitHub CLI:

```powershell
gh release download --repo 1phirum/VM-protect-unpack --pattern vmpx.exe
```

There is nothing to install. Drop the file anywhere, run it from that directory
or from `PATH`. Windows 10 and 11 run it natively through WOW64; there is no
64-bit build.

Verify the download:

```powershell
Get-FileHash .\vmpx.exe -Algorithm SHA256
```

```
DDC0D9362E22871809D733F38DBAD8054218C15A7198A8BBC1623C8C01FDE797
```

The executable imports only `KERNEL32`, `USER32`, `ADVAPI32`, `SHELL32` and
`bcrypt`. No `VCRUNTIME140.dll`, no `MSVCP140.dll`, no runtime installer.

### Linux

There is no native Linux build. The binary is a Win32 PE32 console program and
runs under 32-bit Wine. The static commands (`info`, `imports`, `dump` on a file)
work well there; the dynamic capture path does not.

Install 32-bit Wine.

Debian / Ubuntu:

```bash
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install -y wine32
```

Fedora:

```bash
sudo dnf install wine.i686
```

Arch:

```bash
sudo pacman -S wine
```

Then:

```bash
curl -LO https://github.com/1phirum/VM-protect-unpack/releases/latest/download/vmpx.exe
wine vmpx.exe version
wine vmpx.exe info target.exe
wine vmpx.exe imports target.exe --limit 40
```

Run the dynamic commands (`deobf`, `watch`, `oep`, `oepcap`, `snap`, `run`) on
Windows. They depend on debug privileges, guard pages, remote thread creation
and shared-memory rings, and a protected target will not behave the same inside
Wine.

---

## Quick start

`deobf` attaches to a process that is already running. It does not launch the
target.

```powershell
# 1. start the target yourself
Start-Process .\target.exe

# 2. find the pid
Get-Process target | Select-Object Id, ProcessName

# 3. capture 20 seconds of live behaviour
.\vmpx.exe deobf --pid 1234 --out .\capture
```

The run prints one line and returns a typed exit code:

```
STATUS deobf-dynamic pid=1234 session=1234-01DD75CF6A578020-5109405068D2324E
       ended=timeout events=12444 mem=12693 exec=0 threads=196 vm=0 api=12062
       strings=4933 dropped=0 manifest=ok
```

Open `capture\summary.txt` first, then the artifact folders under it.

Attach to a process by name instead of pid:

```powershell
.\vmpx.exe deobf --name target.exe --out .\capture --seconds 60
```

Inspect without attaching:

```powershell
.\vmpx.exe info .\target.exe
.\vmpx.exe imports .\target.exe --limit 50
```

Protected targets usually deny `OpenProcess` to a normal user. Run `vmpx` from
an elevated shell for those. If the refusal is an access error, the exit code is
`3` (`CAPTURE_FAILED`), not a quiet zero.

---

## Commands

```
vmpx <command> [options]          vmpx version
```

Target selectors, where accepted: `--pid N`, `--name exe`, `--exe path`.
`deobf` requires `--out`.

| Command | Usage | What it does |
|---|---|---|
| `info` | `info <file>` | PE header facts: machine, timestamp, image base and size, entry point, section table with rights, header/section bound validation. |
| `imports` | `imports <file> [--limit N]` | Static import directory: libraries, named functions, ordinals, delay-load entries. |
| `launch` | `launch [--no-armor] [--wait-ms N] [--class name] [--exe path \| -- <exe>]` | Start the target suspended, inject the agent, wait for its application window. Armored targets relaunch elevated unless `--no-armor`. |
| `modules` | `modules [--pid N \| --name exe] [--filter name]` | Module list for a live process: base, size, path. |
| `inject` | `inject [--pid N \| --name exe] --dll <path>` | Inject a DLL into a running process and report the loaded base. |
| `dump` | `dump [--pid N \| --name exe] [--out file] [--max-mb N]` | Dump the live main module to a file plus a `.meta` sidecar (pid, base, image size, dump size). Refuses a partially committed image unless `--force`. |
| `liveimports` | `liveimports [--pid N \| --name exe] [--limit N]` | Walk the live import address table and print where each import resolved. |
| `agentstatus` | `agentstatus [--pid N \| --name exe]` | Agent block: hooks installed/failed, stealth entries, hidden modules, parent state. |
| `peek` | `peek [--pid N \| --name exe] --addr 0xADDR [--size N]` | Read live memory and print a hex/ASCII dump. |
| `poke` | `poke [--pid N \| --name exe] --addr 0xADDR --bytes "90 90"` | Write bytes to live memory, printing the old and new contents. |
| `rebuild` | `rebuild --live <dump> --out <pe> [--file <original.exe>] [--pid N] [--cast]` | Rebuild a PE from a live dump plus the original file; `--cast` repairs the IAT from the live process. |
| `windows` | `windows [--pid N \| --name exe]` | Top-level windows of a process: class and title. |
| `memmap` | `memmap [--pid N] [--near 0xADDR] [--radius N] [--all] [--private] [--min-kb N]` | Virtual memory map: base, size, state, protection, type, plus private/image/mapped totals. |
| `oep` | `oep [--pid N \| --name exe \| --launch] [--wait-ms N] [--out file]` | Original-entry-point discovery: watch the main module for execution outside the initial stub and snapshot on the hit. |
| `oepcap` | `oepcap --exe <target.exe> --out <snapshot> [--lo 0x10000] [--oep-rva 0x1234]` | Launch a target under capture, arm the OEP watch, snapshot when it is hit. |
| `snap` | `snap [--pid N \| --name exe \| --exe path] --out <snapshot> [--all-private]` | Full process snapshot: modules, regions, memory, thread context, TLS. |
| `run` | `run --snap <snapshot> --exe <rebuilt.exe> [--wait N] [--ctx file]` | Restore a snapshot into a rebuilt executable and observe it, returning a typed status. |
| `deobf` | `deobf [--pid N \| --name exe \| --exe path] --out <dir> [options]` | Live deobfuscation session. The collector described below. |
| `watch` | `watch [--pid N \| --name exe] [--addr 0xADDR --size N] [--mode rwx] [--seconds N] [--out file] [--capture dir]` | Stream the agent's guard/API ring to the console or a file, without a full session. |
| `version` | `version`, `--version`, `-V` | Print the version. |

`memmap` with no filter shows everything within the default radius of the image.
`--private` restricts to `MEM_PRIVATE` regions, which is where a packer's
unpacked image usually lands. `--min-kb` suppresses small allocations.

---

## The `deobf` session

`deobf` opens a session with a stable identity, injects the agent if its mapping
is absent, enables the collectors, drains the shared ring to disk until the
deadline, and closes with a manifest and a summary.

### Options

| Option | Default | Meaning |
|---|---|---|
| `--pid N` / `--name exe` / `--exe path` | required | Target selector. `--exe` matches a running process by image path. |
| `--out <dir>` | required | Session directory. Created if absent. |
| `--seconds N` | `20` | Capture duration. |
| `--mode <letters>` | all | Enable collectors: `m` memory delta, `e` execution coverage, `t` thread contexts, `a` API events. Letters combine, e.g. `--mode ma`. |
| `--mem-ms N` | `1000` | Page-scan interval. |
| `--thread-ms N` | `25` | Thread-context sampling interval. |
| `--addr 0xADDR --size N` | image range | Restrict memory collection to one range. |
| `--no-strings` | off | Disable runtime string recovery. |
| `--all-events` | off | Keep every event record rather than the per-type summaries. |
| `--max-mb N` | profile budget | Cap captured page bytes. |
| `--max-events N` | `200000` | Stop the capture once this many events are accepted; `ended=limit`. |
| `--profile <json>` | none | Load a JSON profile (intervals, budgets, region rules). The effective profile is written to `session/profile.effective.json`. |
| `--dll <path>` | embedded agent | Override the agent DLL. |

Collector selection is the practical speed dial. `--mode m` scans page identity
only and is the fastest way to see whether a target is unpacking at all;
`--mode mae` adds execution coverage and API events.

### Artifacts

```
<out>/
  summary.txt
  events/events.txt              one line per accepted event
  events/loss.jsonl              loss ledger checkpoints
  apievents/events.csv           protect/write/guard events from hooks
  memdelta/pages.txt             page identity, hash and epoch
  memdelta/capture.bin           page content, indexed by seq
  codecov/exec.csv               first-execution coverage
  threadctx/samples.csv          thread context samples
  vmtrans/transitions.csv        VM enter/exit classification
  strings/strings.txt            strings recovered from live buffers
  session/manifest.json          identity, state, counts, artifact index
  session/capabilities.json      collectors that actually attached
  session/modules.jsonl          modules at capture time
  session/regions.jsonl          regions at capture time
  session/profile.effective.json profile after CLI overrides
```

`session/capabilities.json` is the honest list: a collector is `available: true`
only once its mechanism was installed, with the evidence string that proves it
(`control-ring`, `page-hash-delta`, `guard-page-first-exec`,
`thread-context-sample`, `private-exec-classification`,
`runtime-string-recovery`).

### File formats

`events/events.txt` — one record per line:

```
seq=1 tid=26480 type=thread addr=0x7790837C size=0x1 eip=0x7790837C esp=0x336F4A8 crc=0x684DC8B2 flags=0x60 len=132 aux=0x9944
```

`memdelta/pages.txt` — a header line, then `key=value` records:

```
seq,addr,size,type,crc,flags,validity,hash_algo,page_epoch
seq=17 addr=0x30B6000 size=0x1000 type=private crc=0xC8795DA7 flags=0x24 validity=later_reread hash_algo=1 page_epoch=12782
```

`hash_algo` values: `1` = FNV-1a 32, `2` = CRC-32, `0` = none (mark, VM and
error events). `page_epoch` is a per-page monotonic counter: two records with
different epochs are the same address at different points in time, which is what
makes an unpacked image distinguishable from the packed one.

`memdelta/capture.bin` — binary page content:

```
capture_hdr_t { magic=0x42445856 "VXDB", version=3, page_size=0x1000, reserved }
repeat:
  capture_rec_t { addr, seq, size, len, crc32, hash_algo, flags, event_type,
                  validity, page_epoch }        48 bytes, packed
  len bytes                                       page preview
```

`validity` is `preview_only` when the preview came from the producer and
`later_reread` when the host re-read the page from the live process.

`events/loss.jsonl` — one JSON object per drain checkpoint:

```json
{"global":1,"total":12444,"events":12444,"dropped":0,"shard_dropped":0,
 "overflow":0,"reentrant":0,"stalled":0,"invalid":0,"classified":0,
 "unreadable":0,"by_type":{...},"by_severity":{...},"by_cause":{...}}
```

`total` counts every accepted event including those drained before a reset, so
`transport_total` in `summary.txt` always equals the accepted event count. A
nonzero `dropped`, `stalled` or `invalid` says where the capture lost data and
why; it is never a silent gap.

### Reading `summary.txt`

```ini
pid=30708 image_base=0xF50000 image_size=0x5F000 page_size=0x1000
session_id=30708-01DD75CF6A578020-5109405068D2324E modules=15 regions=307 profile=default ended=timeout
flags=0xE mem_ticks=71 exec_ticks=1 thread_ticks=28
events=12444 dropped=0 strings=4933 captured=49486784
transport_total=12444 shard_dropped=0 overflow=0 reentrant=0 stalled=0 invalid=0
mem_pages=12752 mem_changed=12693 mem_records=12278 read_fail=176
```

- `ended` — `timeout` (deadline reached), `limit` (`--max-events`), `exited`
  (target died first).
- `mem_pages` / `mem_changed` — pages observed / pages whose hash differed from
  the previous pass.
- `read_fail` — host re-reads refused by the target's own page protection.
- `mem_errors` — pages never observed or unreadable.
- `exec_pages` / `exec_hits` / `exec_records` — armed coverage pages, pages that
  actually executed, and emitted records.
- `captured` — bytes of page content written to `capture.bin`.

A capture with `dropped=0` and `transport_total` equal to `events` is complete:
every event the producers published is on disk or accounted for in the ledger.

---

## How the capture pipeline works

1. **Resolve and open the target.** `deobf` never launches. It opens the process
   with the access the collectors need; protected targets require elevation.
2. **Attach the agent.** If `Local\VMPX_DYN_<pid>` is absent, the agent is
   injected. The agent is embedded in `vmpx.exe`, extracted to
   `%TEMP%\vmpxagent-<fnv32>.dll` (content-addressed, so builds never collide),
   and deleted on exit; a target that still has it mapped defers deletion to the
   next boot.
3. **Publish the control block.** The agent creates a shared ring: 16 shards of
   2048 events, 296-byte wire records, epoch and producer tags on every slot.
4. **Produce.** Each collector reserves slots with an atomic sequence, stamps the
   epoch captured at acquire time, and writes the record. A mid-publish reset
   leaves the slot stale instead of relabelling it.
5. **Drain.** The host merges shards in tick order, acknowledges tails, and
   classifies any hole as `drop`, `stall` or `invalid`. The ledger records one
   entry per distinct stalled sequence, not per drain pass.
6. **Collect.**
   - `memdelta` — hash every page, publish identity changes, capture content.
     Page reads go through the kernel (`ReadProcessMemory`) because guarded code
     pages fault on direct access; the hash pass runs across up to 8 threads.
   - `codecov` — arm guard pages, re-arm on single-step, record first execution
     per page.
   - `threadctx` — sample `EIP`/`ESP`/stack of running threads.
   - `vmtrans` — classify execution that lands in private memory as VM entry or
     exit, keyed on the surrounding context.
   - `apievents` — inline hooks report `VirtualProtect`, writes and guard hits.
   - `strings` — recover strings from live buffers with an origin tag (preview vs
     re-read) and a dedupe count.
7. **Close.** Final drain, session manifest, summary, typed exit code.

---

## Exit codes

Every command maps its outcome through the same enum, so scripted use never has
to parse prose.

| Code | Status | Meaning |
|---|---|---|
| `0` | `OK` | Requested observation completed. |
| `1` | `LAUNCHED` | Restore applied; no observation was requested. |
| `2` | `INVALID_ARG` | Usage, validation, or target-selector error. |
| `3` | `CAPTURE_FAILED` | Attach, capture, or injection failed. |
| `4` | `RESTORE_INCOMPLETE` | Restore left pages or modules unmapped. |
| `5` | `TERMINAL_EXCEPTION` | Target raised a terminal exception under the observer. |
| `6` | `PROCESS_EXITED` | Target exited before the observation completed. |
| `7` | `TIMEOUT` | Deadline reached without the requested event. |
| `8` | `UNSUPPORTED` | Wire/ring version mismatch, architecture, or no OEP found. |
| `9` | `INTERNAL_ERROR` | Internal invariant or allocation failure. |

`STATUS` lines carry the same status name, so the log and the exit code never
disagree.

---

## Build from source

Requirements:

- Visual Studio 2022 or newer with the **x86/x64 C++ build tools**
- Windows SDK (`rc.exe` for the embedded agent resource)

No CMake, no package manager, no third-party libraries.

```powershell
git clone https://github.com/1phirum/VM-protect-unpack.git
cd VM-protect-unpack
.\vmpx\build.bat
```

`build.bat` locates `vcvars32.bat` through `vswhere`, compiles the agent, embeds
it with `rc` from `resources.rc`, then links the host:

```
cl ... /MT /LD /Fe:vmpxagent.dll   <agent sources>   /link user32.lib
rc  /nologo /fo resources.res resources.rc
cl ... /MT /Fe:vmpx.exe            <host sources> resources.res /link shell32.lib ...
```

Output:

```
vmpx\vmpx.exe          the product, agent embedded
vmpx\vmpxagent.dll     development copy, picked up when it sits beside the exe
```

The build is `/W4` clean. A side-by-side `vmpxagent.dll` takes precedence over
the embedded copy, which keeps the agent debuggable during development; delete
it and the executable still works.

Project layout:

```
vmpx/
  build.bat          toolchain detection, agent, resource, host
  resources.rc       embedded agent + version info
  include/vmpx.h     shared types and command interface
  src/
    cmd/             one file per command
    pe/              headers, import tables, rebuild
    proc/            process, modules, memory, injection
    armor/           elevation, launch, stealth hooks (agent side)
    unpack/
      memory/        reader, region map, arena, budgets
      snapshot/      capture and staged restore
      deobf/dynamic/
        control/     296-byte wire, shared ring, identity, codec
        memdelta/    page identity and content
        codecov/     execution coverage
        threadctx/   context sampling
        vmtrans/     VM transition classification
        apievents/   hook events
        strings/     runtime string recovery
        session/     manifest, capabilities, artifact writer
        report/      host drain, summary, loss ledger, capture.bin
```

---

## Compatibility and limits

- **x86 only.** Host and agent are 32-bit. A 64-bit target cannot be injected or
  captured.
- **`deobf` attaches; it does not launch.** Start the target yourself, or use
  `launch`, `oep` or `oepcap` for the launched paths.
- **Elevation.** Protected targets commonly deny `OpenProcess` to unelevated
  callers. Run from an elevated shell; a refusal surfaces as exit `3`.
- **Self-terminating targets.** A target that detects the observer and exits ends
  the capture there (`ended=exited`). On the reference armored target that
  happens around 17 seconds: the unpack is observed, not completed.
- **Execution coverage is conservative.** The armed set on the reference target
  reports a small, deterministic handler set; the region that actually executes
  the unpacking loop is not yet covered. Page content and API events still land.
- **Guarded pages.** A page the target holds guard-armed is refused on re-read
  and counted in `read_fail` / `mem_errors`, not hidden.
- **Hashing.** Page digests in this build are FNV-1a 32 (`hash_algo=1`); the wire
  and artifact formats reserve CRC-32 (`hash_algo=2`).
- **Linux.** Wine runs the static side. The dynamic path is Windows-only.

---

## License

MIT. See [LICENSE](LICENSE).

Copyright (c) 2026 1phirum
