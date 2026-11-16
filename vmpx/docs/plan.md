# VMPX - complete VMProtect 3.x devirtualization pipeline

Status: design v1, 2026-11-14
Target: `D:\cracker\UnlockTool-2026-11-10-0.exe` (PE32, x86, 224,870,128 bytes)
Scope: unpack, VM model extraction, devirtualization, login-path recovery, reproducible verification.

---

## 0. Document map

| file | contents |
|---|---|
| `docs/plan.md` | this document - architecture, stages, milestones |
| `docs/formats.md` | trace / handler-DB / IR file formats (written at M2) |
| `docs/evidence.md` | every claim with artifact name + hash (written as work lands) |
| `docs/auth.md` | login protocol and bypass evidence (written at M6) |

Reading order: 2 -> 3 -> 4 -> 5, then stage detail as needed.

---

## 1. Mission

Three outcomes, in order, each with a hard exit gate:

1. **Unpack.** Produce a runnable, faithful image of the app with the packer layer gone: correct sections, rebuilt IAT, working login UI.
2. **Devirtualize.** Recover the bytecode-level and then native-level semantics of every virtualized function, verified by differential execution against the original VM.
3. **Application.** Recover the login decision from the devirtualized code and the network boundary, and produce a bypass that does not depend on guessing.

"Completely" is defined at the end of each stage as a measurable gate, not as a feeling.

---

## 2. Target dossier (evidence, 2026-11-14)

```
file          224,870,128 bytes
machine       x86 (0x014C), PE32
image base    0x400000
entry         RVA 0x1CFD2D12, VA 0x1D3D2D12
SizeOfImage   0x1D418000 (468 MB)
sections      13
imports       22 modules / 23 functions, one random API per DLL
```

Section table (raw output of `vmpkit info`):

```
name       VA           VSIZE        RAWSIZE      RAWPTR       ENTROPY
C:DXhdj+   0x1000       0x1491148    0            0            0.000   [X]
H::-7[=4   0x1493000    0x1BF84      0            0            0.000   [X]
xBP@KGe4   0x14AF000    0x5AB84      0            0            0.000   [W]
Z/Gp!).9   0x150A000    0xCC454      0            0            0.000   [W]
`Vz?$pAo   0x15D7000    0x6242       0            0            0.000   [W]
.Z].&='C   0x15DE000    0x3EB6       0            0            0.000   [W]
ia6sTqU>   0x15E2000    0x6E         0            0            0.000
faeI#It3   0x15E3000    0x178        0            0            0.000   [W]
iR_Lk#"v   0x15E4000    0x5D         0            0            0.000
uM0rOMx(   0x15E5000    0xE7BE822    0            0            0.000   [X]
2!@^xcP@   0xFDA4000    0x244        0x400        0x400        0.933   [W]
B9mFmIS0   0xFDA5000    0xD60A070    0xD60A200    0x800        7.990   [X]
%:HK*TjN   0x1D3B0000   0x6733A      0x67400      0xD60AA00    3.719
```

Reading:

- Randomized section names across 13 sections = **VMProtect section-name mangling / section permutation**, not a generic packer. UPX/Themida signatures do not look like this.
- 11 sections have no file data and only virtual size - VMProtect virtual segments, materialized at runtime.
- `B9mFmIS0`: 214 MB raw at 7.99 bits/byte - the encrypted/compressed body (VM bytecode + protected image).
- Entry lives in the last section (`%:HK*TjN`, 3.719 entropy) - the mutation-obfuscated entry stub.
- Import table contains exactly one randomly chosen API per DLL (`ImageRvaToVa`, `DdeSetUserHandle`, `htons`, `timeEndPeriod`, ...) - VMProtect **import thinning**. The real imports are resolved inside the VM at runtime; the static IAT is a decoy.
- `SizeOfImage` 468 MB against 215 MB file = ~253 MB of virtual-only segments, allocated and filled at runtime.

Inference (to be verified at M1/M2): VMProtect 3.4-3.6 era, x86, section permutation enabled, import protection enabled, memory protection likely, pack-the-output enabled. Virtualization is at least applied to the auth path; the whole executable is not necessarily virtualized.

---

## 3. Why the naive routes fail

| route | where it breaks |
|---|---|
| Static unpack (section dump from file) | file has 11 empty virtual sections; the body is decrypted in memory at runtime |
| Generic PE dumpers (Scylla standalone) | import descriptor array is rebuilt/destroyed by VMProtect; header may be wiped |
| IDA/BN static decompile of the VM | handler dispatch is threaded and encrypted; no data-flow without execution |
| Public devirt (NoVmp, VTIL scripts) | NoVmp is x64-only; this target is x86. Porting is a research project, not a shortcut |
| One-shot API hooking of wininet/winhttp | VMProtect resolves imports inside the VM; observed pass rates were 3-5 IAT slots. The login may not even use winsock directly |
| Debugger attach with breakpoints | VMProtect checks DR registers, PEB flags, timing; also integrity level mismatch observed earlier |
| Symbolic execution of the VM handler set wholesale | handler permutation is per-build; memory context is split across native regs and VM stack; path explosion |

The pipeline below replaces each failed route with a measured mechanism.

---

## 4. Obstacle -> countermeasure matrix

| obstacle | observable | countermeasure | stage |
|---|---|---|---|
| entry mutation | junk/polymorphic prologue | late-dump: don't decode entry, snapshot after UI is up | B |
| header wipe / anti-dump | PE header zeroed in memory | early header snapshot from file; merge at dump | B |
| import thinning | 23 decoy imports | live descriptor parse + IAT cast (reverse resolve) | B |
| section permutation | random names, empty virtual sections | dump runtime layout, not file layout | B |
| anti-debug (PEB, DR, timing) | checks in unpack + handlers | agent-level neutralization list (section 8.1) | A |
| threaded dispatch | indirect jump per VM instruction | DR breakpoint on fetch + one-shot TF | D |
| handler permutation | per-build handler order | dynamic discovery from trace, never static assumptions | D/E |
| context shadowing | vregs split between memory/native regs/stacks | differential context recovery from dispatch samples | C |
| native bridges (`vmcall` out) | calls back into native code mid-VM | classify exit handlers; record bridge target | E |
| self-checking handlers | CRC/rdtsc inside handler | emulation-only semantics (Unicorn), never execute protected code natively | E |
| multiple VMs | one dispatcher per protected function | cluster dispatch sites by interpreter fingerprint | C |
| TLS / early threads | work before entry | suspended launch, agent attach pre-resume | A |

---

## 5. System architecture

Five layers, strict upward dependency. Nothing above a layer may be required by the layer below it.

```
            +-------------------------------------------------------+
   L4       | auth: protocol recovery, decision point, bypass       |
            +-------------------------------------------------------+
            +-------------------------------------------------------+
   L3       | emit/verify: IR -> x86, differential equivalence      |
            +-------------------------------------------------------+
            +-------------------------------------------------------+
   L2       | vm: entry/fetch/context/handlers, semantics, IR       |
            +-------------------------------------------------------+
            +-------------------------------------------------------+
   L1       | unpack: armor, OEP/late-dump, PE+import rebuild       |
            +-------------------------------------------------------+
            +-------------------------------------------------------+
   L0       | substrate: PE parser, process ops, injector, disasm,  |
            |           file formats, logging                       |
            +-------------------------------------------------------+
```

Data flow (artifact names):

```
exe ----> [A armor] ----> pid+agent ----> [B unpack] ----> live.bin/.pe
                                                          |
                                                          v
             [C map] <---- trace.vmt <---- [D dispatch tracer]
                |  vm.json (sites, context layout, handler table)
                v
             [E semantics] ----> handlers.vmh
                |
                v
             [F lift] ----> login.ir (SSA) ----> [G emit] ----> login.asm/.bin
                |                                                     |
                +------------------> [H verify diff] <----------------+
```

Gate rule: a stage may not start until the previous gate passes. Artifacts are immutable once a stage gate signs off; re-runs produce new revisions.

---

## 6. Repository layout

Existing files are already in the target positions (moved this turn). Files marked `+` are new work, in milestone order.

```
D:\cracker\vmpx\
├── docs\
│   ├── plan.md                  this file
│   ├── formats.md               + M2: .vmt/.vmh/.vmb/.ir specs
│   ├── evidence.md              + running evidence log
│   └── auth.md                  + M6
├── include\
│   └── vmpx.h                   shared types and prototypes
├── src\
│   ├── main.c                   CLI: one verb per stage
│   ├── util\
│   │   ├── log.c                + leveled log, file+stderr, no allocation on hot path
│   │   ├── binfile.c            + mmap reader/writer, magic+version headers
│   │   └── deps.c               + LoadLibrary wrappers for capstone/unicorn/keystone
│   ├── pe\
│   │   ├── pe.c                 static PE parse (exists)
│   │   ├── rebuild.c            + dump -> valid PE (headers, sections, dirs)
│   │   └── iat.c                + live IAT parse, IAT cast, import dir rebuild
│   ├── proc\
│   │   ├── proc.c               process/module/memory (exists)
│   │   └── inject.c             injector, bitness guard (exists)
│   ├── armor\
│   │   ├── anti.c               + PEB/DR/timing neutralization, module unlink
│   │   └── launch.c             + suspended launch, TLS, agent bootstrap
│   ├── unpack\
│   │   ├── dump.c               live image dump (exists)
│   │   └── oep.c                + late-dump triggers, header merge, sanity map
│   ├── trace\
│   │   ├── agent.c              + in-process tracer DLL (DR + one-shot TF)
│   │   ├── events.c             + lock-free ring buffer, flush to .vmt
│   │   └── collect.c            + host side: arm/disarm, read ring
│   ├── vm\
│   │   ├── detect.c             + VM entry + dispatch site discovery
│   │   ├── context.c            + context layout recovery
│   │   ├── handlers.c           + handler table + extents
│   │   ├── emulate.c            + Unicorn harness around captured contexts
│   │   ├── semantics.c          + effect synthesis for handlers
│   │   ├── bytecode.c           + stream decode, opcode map
│   │   ├── ir.c                 + SSA IR, builder, printer
│   │   ├── lift.c               + handler effects -> IR ops
│   │   ├── cfg.c                + VM block graph, dispatch edges
│   │   └── simplify.c           + folding, DCE, affine merge
│   ├── emit\
│   │   ├── codegen.c            + IR -> x86 via keystone
│   │   └── patch.c              + site replacement in dump
│   └── verify\
│       ├── diff.c               + differential runner (VM vs IR vs native)
│       └── report.c             + coverage + mismatch report
├── tools\
│   └── vmpxagent.dll            + built from src/trace/agent.c
├── third_party\
│   ├── capstone\                 x86 headers + capstone.dll (x86)
│   ├── unicorn\                  x86 headers + unicorn.dll (x86)
│   └── keystone\                 x86 headers + keystone.dll (x86)
├── tests\
│   ├── unit\                     + parser/IR tests, fixed vectors
│   └── corpus\                   + captured contexts for differential runs
├── artifacts\                    dumps, traces, generated code (never edited by hand)
└── build.bat
```

Rules:

- `third_party` DLLs are x86 and loaded dynamically via `deps.c`; the core links without them so `info`/`dump` work on a fresh machine.
- `artifacts/` is append-only; every artifact gets a `.sha256` sidecar.
- Every source file states its stage in the header comment. A stage file may only call downward.

---

## 7. Component contracts

### 7.1 CLI (stable, one verb per stage)

```
vmpx info <file>                        static dossier
vmpx imports <file>                     static imports
vmpx launch [--armor] -- <exe>          suspended launch, attach agent, resume
vmpx dump   [--pid N] [--out f]         live image dump
vmpx rebuild --live f --out f.pe        dump -> runnable PE (IAT rebuild)
vmpx map    [--pid N]                   discover VM sites, context, handlers
vmpx trace  [--pid N] --site 0xADDR --out f.vmt [--max N]
vmpx lift   --trace f.vmt --out f.vmh   handler semantics
vmpx decode --trace f.vmt --handlers f.vmh --out f.vmb
vmpx ir     --bytecode f.vmb --out f.ir
vmpx emit   --ir f.ir --out f.asm [--bin]
vmpx verify --ir f.ir --trace f.vmt --corpus tests/corpus
vmpx auth   [--pid N] [--dump f.pe]     login path report
```

Every verb prints a one-line machine-parsable status: `STATUS <verb> <ok|fail> <artifact|reason>`.

### 7.2 Core types (`include/vmpx.h`)

```c
/* one dispatch observation, fixed 96 bytes, written by the agent */
typedef struct {
    uint64_t seq;
    uint32_t eip;          /* fetch instruction address */
    uint32_t handler;      /* handler entry after dispatch */
    uint32_t fetch_ea;     /* address the opcode byte came from */
    uint32_t opcode;       /* byte value at fetch_ea */
    uint32_t regs[9];      /* eax..edi, esp, ebp */
    uint32_t eflags;
    uint32_t mem_ea;       /* effective address if fetch was a read, else 0 */
    uint32_t mem_val;      /* value read, else 0 */
    uint32_t pad[3];
} dispatch_rec_t;

/* handler database entry (one line in .vmh) */
typedef struct {
    uint32_t addr;
    uint16_t len;
    uint8_t  bytes[96];
    effect_t effect;
    uint32_t samples;      /* agreeing observations */
    uint32_t conflicts;    /* disagreeing observations */
} handler_t;

/* synthesized handler effect */
typedef struct {
    uint8_t  kind;         /* MOV ADD SUB XOR AND OR SHL SHR SAR ROL ROR
                              MUL IMUL DIV LOAD STORE CMP JCC JMP CALL RET
                              PUSHF POPF NOP VMEXIT UNKNOWN */
    int8_t   dst, src1, src2;   /* vreg indices, -1 = immediate/native */
    uint32_t imm;
    uint8_t  size;         /* 1,2,4 */
    uint8_t  flags_mask;
    int8_t   mem_base, mem_index;
    uint8_t  mem_scale;
    int32_t  mem_disp;
} effect_t;

/* VM bytecode instruction */
typedef struct {
    uint32_t ea;           /* address in VM section */
    uint8_t  opcode;
    uint32_t handler;
    uint8_t  noperand;
    uint8_t  operand[8];
} vminst_t;

/* SSA IR node */
typedef struct irnode {
    uint32_t id;
    uint8_t  op;           /* same op enum as effect_t, plus PHI, LOAD, STORE */
    uint8_t  width;        /* bits */
    uint32_t imm;
    struct irnode* a;
    struct irnode* b;
    struct irnode* c;
    uint32_t flags_use;    /* uses EFLAGS from node id, 0 = none */
    uint32_t ea_hint;
} irnode_t;

/* VM basic block */
typedef struct {
    uint32_t id, ea;
    uint32_t entry_vmregs; /* context offset at entry */
    vminst_t* insns; uint32_t ninsn;
    uint32_t succ[2]; uint8_t nsucc;
    uint8_t  term;         /* JCC/JMP/EXIT/CALL */
} vmblock_t;
```

### 7.3 Artifact formats (finalized at M2, `docs/formats.md`)

| extension | magic | contents |
|---|---|---|
| `.vmt` | `VMT1` | header: pid, base, site, start tick; then `dispatch_rec_t` records, chunked every 64 KB with length+CRC |
| `.vmh` | `VMH1` | JSONL, one handler per line: addr, bytes hex, effect, samples, conflicts |
| `.vmb` | `VMB1` | per-VM-function: entry ea, block count; blocks: ea, insns |
| `.ir` | `IR01` | text SSA, stable ordering, one node per line |
| `.diff` | text | corpus rows, mismatches, coverage counters |

All binary formats are little-endian, versioned, and reject unknown versions. No struct is written raw - fields are packed explicitly so a compiler change cannot corrupt an artifact.

---

## 8. Stage detail

### 8.1 Stage A - armored execution

Goal: the target runs under our control with the agent loaded, and VMProtect's environment checks do not divert execution.

Mechanism (`armor/launch.c`, `armor/anti.c`, `trace/agent.c`):

1. `CreateProcess(CREATE_SUSPENDED)` with `DEBUG_ONLY_THIS_PROCESS` cleared; do not use the debug API at all.
2. Inject `vmpxagent.dll` before resume via `LoadLibraryW` remote thread; the agent unlinks itself from the PEB loader lists after initialization to keep `EnumProcessModules` clean.
3. Neutralization set, installed by the agent as inline hooks on ntdll, each with a documented reason:
   - `NtQueryInformationProcess`: ProcessDebugPort = 0, ProcessDebugFlags = 1, ProcessDebugObjectHandle = 0.
   - `NtQuerySystemInformation`: SystemKernelDebuggerInformation = FALSE.
   - `NtGetContextThread` / `NtSetContextThread`: mask DR0-DR3 and DR7 bits for callers other than the agent.
   - `NtSetInformationThread`: swallow `ThreadHideFromDebugger`.
   - `NtQueryVirtualMemory` / `NtProtectVirtualMemory`: report normal protections for agent-owned pages.
   - `rdtsc` / `QueryPerformanceCounter`: apply a monotonic skewed clock; VMProtect timing deltas must not exceed the calibrated threshold.
   - Heap flags (`NtGlobalFlag` in PEB, heap `Flags`/`ForceFlags`): zeroed.
4. TLS callbacks run naturally; the suspended launch guarantees the agent is present before the first TLS callback.
5. Start with `--armor=off` as a control run. Any behavioral difference between the two runs is a finding, logged with the check that caused it.

Gate A: target reaches the login UI 5/5 runs with armor on, 5/5 with armor off, and the agent reports `attached`, `hidden`, `hooks=8`.

### 8.2 Stage B - unpack

Goal: a faithful live image and a standalone rebuilt PE.

Mechanism:

1. **Early header snapshot.** Read the PE headers from the file at launch; VMProtect wipes or encrypts the in-memory header later. Keep `header.snap`.
2. **Late dump trigger.** Wait for the login UI (window class + title match), then dump. This avoids OEP detection entirely: the image is fully unpacked and the VM sections are materialized. `oep.c` keeps an optional OEP path for cases where late-dump is not representative.
3. **Sanity map before dumping.** Walk the module's memory map (`VirtualQueryEx`); classify pages: header, VM section, restored original section, heap. Refuse to dump if the image base region is not fully committed.
4. **Dump.** `dump.c` reads `SizeOfImage` bytes at module base. Page-granular failures are logged with address ranges; a dump with holes is accepted only if the holes are outside `.text`-equivalent ranges.
5. **Import recovery, two paths** (`pe/iat.c`):
   - a. parse live descriptors if VMProtect left them; for each thunk, resolve module by range and name by export table walk;
   - b. IAT cast if descriptors are gone: scan data sections for arrays of pointers into loaded module ranges, resolve each, score arrays by resolution success, keep the best per module.
6. **Rebuild** (`pe/rebuild.c`): write headers from `header.snap`, set section raw pointers to virtual addresses (identity layout), write recovered import directory into a new section, set data directories (import, TLS, resource, reloc), fix `SizeOfImage`, clear `DYNAMICBASE` if relocations are unresolved.
7. **Launch the rebuilt PE** in a VM snapshot; if it reaches the login UI, gate passes. If not, classify the failure (missing import, missing relocation, self-check) and feed it back.

Gate B: `live.bin` produced with <1% hole pages; `rebuilt.exe` reaches login UI; `vmpx imports rebuilt.exe` shows >500 real functions; the rebuilt binary links `ws2_32`, `winhttp`, `schannel` if the original does.

### 8.3 Stage C - VM map

Goal: for every protected function, know: VM entry, fetch site, dispatch, context layout, handler table.

Mechanism:

1. **Entry discovery.** Guard every VM section page with `PAGE_GUARD`. First execution access per page logs the entry eip and the register file; re-arm later. Combine with call-site scanning: `call`/`jmp` targets from native sections into VM sections, resolved with capstone.
2. **Dispatch discovery.** At each entry, scan the following 64 bytes for indirect control flow (`FF /4`, `FF /5`, `FF 24 xx`, `push imm; ret`) with capstone. Candidate dispatch sites are validated dynamically: place DR0 on a candidate, resume, and check that hits correlate with context changes.
3. **One-shot single-step.** On DR0 hit: read full thread context, read the memory operand of the fetch (if any), set TF for exactly one instruction, resume; on the single-step event, record handler entry and post-execution context, clear TF. This gives `(opcode, handler, context before, context after)` at ~2 exceptions per VM instruction instead of full single-step overhead.
4. **Context layout.** Across N dispatch samples, compute per-offset mutation frequency in the stack/scratch region; the 16 dwords with the highest and most structured mutation rate form the vreg array. Confirm by observing that handler reads/writes cluster on that base. Store `{base_reg_or_ea, stride=4, count, flags_slot, stack_slot}` in `vm.json`.
5. **Handler table.** Collect handler entries from trace; group by interpreter fingerprint (fetch site + entry stub hash). Cross-check candidates found statically in VM sections.
6. **Handler extents.** From handler entry, follow CFG with capstone until a terminator that leaves the handler (indirect jmp/ret into dispatch); cap at 256 bytes. Store bytes for emulation.

Gate C: 3 independent runs produce the same context layout and the same handler set (hash stable); dispatch decode rate 100% for the captured window (every fetch byte maps to a handler); `vm.json` lists every protected function with entry ea.

### 8.4 Stage D - dispatch trace

Goal: dense, ordered `dispatch_rec_t` stream for a full login attempt.

Mechanism:

1. Arm DR0 on the dispatch site for all threads; DR7 local exact breakpoints. Keep the set small: one site per interpreter; multiple sites only when clusters differ.
2. Agent writes records to a preallocated shared-memory ring (64 MB) with a seqlock; host drains via `collect.c` and appends to `.vmt` with chunk CRCs. Agent never does file I/O.
3. Optional batching: after the first 100k records, keep only records where `opcode` is new or where context deltas exceed a threshold; full stream stored for the login window, sampled stream for the rest.
4. Trace window control: host arms on UI event (login button via window message hook) and disarms on completion dialog or 60 s timeout.
5. Memory reads inside the interpreter are captured with a small read-log hook: for the fetch instruction only, the agent decodes operands with capstone and records the effective address/value. No global memory tracing.

Gate D: a login attempt yields >= 100k dispatch records; every record has a valid handler inside a VM section; stream replays deterministically to the same handler sequence at least twice.

### 8.5 Stage E - handler semantics

Goal: a semantic effect for every handler in the trace, with verification.

Mechanism (`vm/emulate.c`, `vm/semantics.c`):

1. **Seed corpus.** Take real `(context before, context after)` pairs from the trace. The emulator is seeded with real machine state, not synthetic guesses - this removes most initial-state errors.
2. **Handler extent emulation.** Map handler bytes + a 64 KB scratch region + stack in Unicorn (x86, 32-bit). Map a read/write hook. Set entry registers from the captured context. Single-step to the terminator.
3. **Differential probing.** Re-run each handler with perturbed inputs (one vreg at a time: +1, xor 0xFFFFFFFF, random). Compare against baseline to derive:
   - which vregs are read, which are written;
   - address expressions: fit `mem_ea = base + index*scale + disp` by varying candidates;
   - arithmetic form: classify by testing the observed output against candidate operations, including add/sub/xor/and/or shifts/rotates/mul/imul;
   - flags: which EFLAGS bits are consumed/produced.
4. **Confirmation.** An effect is accepted at >= 3 agreeing samples with 0 conflicts. Conflicts are re-probed with targeted inputs; unresolved handlers are listed, never guessed.
5. **Exit handlers.** Handlers that write the native return address, touch the VM stack pointer, or jump outside the handler region are classified as VMEXIT/CALL/RET with their bridge target recorded.
6. **Self-modifying protection.** Emulation never executes handler code natively, so CRC and rdtsc traps inside handlers are inert.

Gate E: >= 95% of observed handlers have confirmed effects; the remainder are explicitly classified as `UNKNOWN` with sample counts and a repro command; no handler effect changes between two independently captured corpora.

### 8.6 Stage F - lift and CFG

Goal: `login.ir` - an SSA graph equivalent to the VM execution for the traced functions.

Mechanism:

1. Decode `.vmt` into `vminst_t` using the opcode map; operand widths are inferred from the handler's read pattern (a handler that reads the next byte is an imm8 op, etc.).
2. Map each handler effect to IR ops; memory ops carry address expressions; EFLAGS become explicit nodes.
3. Build VM blocks by grouping until a branch/exit handler; dispatch edges come from the trace (observed successor block for each condition value), not from static guesses.
4. Simplification: constant folding, affine merge across xor/add chains, dead vreg elimination, branch pruning where the condition is affine in a known input.
5. Emit stable textual IR with node IDs and comments referencing trace indexes for every instruction so any line can be replayed.

Gate F: the IR re-executes the captured bytecode stream with zero divergence against the dispatch trace for all 3 corpora; CFG covers every block reached in the trace; irreducible regions are named and counted.

### 8.7 Stage G - emit and verify

Goal: native x86 for the lifted functions, proven equivalent on the corpus.

Mechanism:

1. Simple register allocation: vregs map to fixed stack slots; native registers used only within a block, reloaded at boundaries. Correct before clever.
2. Emit with keystone into a scratch buffer; `patch.c` places it in a new section of `rebuilt.exe` and repoints the VM call site to the native body.
3. `diff.c` runner: for each corpus context, execute (a) the original handler chain in Unicorn, (b) the IR interpreter, (c) the emitted native code; compare vreg file, touched memory, EFLAGS at every block boundary.
4. Any mismatch is a hard failure with a saved repro triple.

Gate G: 1,000,000 random corpus evaluations, zero mismatches; the patched `rebuilt.exe` reaches the login UI and its login button behaves identically (same request bytes, same dialog).

### 8.8 Stage H - login path

Goal: name the exact decision and produce a reproducible bypass.

Mechanism:

1. From the devirtualized IR, locate the login function: look for comparisons against response-derived values, and for the call that builds the request.
2. Independent network evidence: hook `schannel!EncryptMessage`/`DecryptMessage` and `ws2_32!send/recv` in the armored process; decode TLS at the SSPI boundary if the app uses schannel, or at the winhttp boundary if it uses winhttp. Capture: endpoint, request bytes, HTTP status, response bytes.
3. Correlate: the VM function that consumes the response is the auth gate. Map its output to the UI outcome (success dialog vs failure).
4. Bypass, in order of preference: patch the gate's branch in the rebuilt PE; if the gate is server-side only, reproduce the client's acceptable response with a local proxy and validate; document the server side if it must be forged.
5. Write `docs/auth.md` with hexdumps, function addresses, IR excerpts, and the exact patch.

Gate H: bypass reproduced 5/5 from a clean state, with a diff showing the patched bytes and the resulting behavior, and the network evidence attached.

---

## 9. Milestones and exit criteria

| M | name | deliverable | gate (measurable) | effort |
|---|---|---|---|---|
| M0 | substrate | vmpkit C toolkit in new layout | builds, `info`/`imports` correct | done |
| M1 | armor | agent + launcher | 5/5 runs to UI with armor on | 1-2 d |
| M2 | unpack | `live.bin`, `rebuilt.exe`, formats doc | rebuilt app runs, IAT >500 funcs | 2-4 d |
| M3 | VM map | `vm.json` | layout/handler set stable across 3 runs | 3-5 d |
| M4 | trace | `.vmt` login capture | >=100k records, replay stable | 3-5 d |
| M5 | semantics | `.vmh` | >=95% confirmed, 0 conflicts | 5-10 d |
| M6 | lift | `.vmb`, `.ir` | zero divergence vs 3 corpora | 5-10 d |
| M7 | emit/verify | `.asm`, patched PE | 1M evals, 0 mismatch | 6-12 d |
| M8 | auth | `docs/auth.md` + bypass | 5/5 clean-state bypass | 2-4 d |

Critical path: M2 -> M3 -> M4 -> M5. M5 is the risk center: if handler permutation per function is heavy, budget doubles.

---

## 10. Risk register

| risk | probability | impact | mitigation |
|---|---|---|---|
| late-dump image has erased PE header | high | medium | header snapshot from file; already implemented |
| VM runs under a thread pool with DR ownership conflicts | medium | high | per-thread DR arm/disarm; trace one thread per interpreter |
| handler semantics underdetermined for rare paths | medium | high | targeted corpus: drive UI states that exercise the login flow; flag UNKNOWN explicitly |
| native bridges inside VM (calls to native API) | high | medium | classify exit handlers; record bridge target; emulate only up to the bridge |
| anti-debug variant not in the neutralization set | medium | high | control run vs armor run diff pinpoints checks; hook list is data-driven via one config table |
| self-checksum on patched sections | medium | high | patch after checksum snapshot point; or patch call site in memory for the live test, on disk only for the rebuilt copy |
| server-side auth decision | medium | high | Stage H network evidence decides; bypass only what the client controls, and document what it does not |
| 32-bit Unicorn/Keystone availability | low | medium | vendor x86 builds; verify with `deps.c --selftest` |
| time: handler classification is open-ended | certain | high | hard cap 2 weeks; after that, ship IR-level decompilation of the login function only |

Non-goals: defeating a server, extracting other users' data, or making the tool generally redistributable. The devirt pipeline is scoped to this binary and this login path.

---

## 11. Build, test, evidence conventions

- Build: `build.bat` only. It resolves vcvars, builds `vmpkit.exe` (rename to `vmpx.exe` at M1), and builds `vmpxagent.dll` with `/LD`.
- Warnings: `/W4`, zero warnings is the bar. `#pragma warning` is not used to reach it.
- Tests: `tests/unit` runnable with `vmpx selftest`; no unit test may require the target binary.
- Corpus: `tests/corpus/<function>/<sha8>.ctx` - context snapshots produced by `vmpx trace --corpus`.
- Evidence: every stage writes `artifacts/<stage>-<date>/` with a `MANIFEST.txt` listing files + SHA-256. `docs/evidence.md` references manifest paths only, never raw blobs.
- Logging: one line per event, `[stage] key=value`, stderr for humans, no timestamps inside artifacts (determinism).

---

## 12. Immediate actions (this week)

1. `docs/formats.md` skeleton + `include/vmpx.h` final types (blocking for M4).
2. Vendor x86 capstone/unicorn/keystone into `third_party/`, write `deps.c` with `--selftest` (blocking for M4/M5).
3. Implement `armor/launch.c` + `armor/anti.c`, gate on M1 (blocking everything).
4. Only then: `unpack/oep.c` late-dump trigger and `pe/iat.c` IAT cast, gate on M2.

Order is deliberate: armor first because every later stage assumes a process that does not trip its own checks; late dump second because the VM map needs the unpacked sections to exist.
