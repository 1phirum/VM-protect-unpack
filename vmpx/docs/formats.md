# VMPX artifact formats

Status: v1, 2026-11-14. Complements `docs/plan.md` section 7.3.

Conventions, all binary formats:

- little-endian, packed fields written byte by byte (no raw struct dumps)
- magic + version header first; unknown version = hard reject
- CRC-32 (IEEE) over payload chunks, not over headers
- artifacts are append-only; a rewrite produces a new revision

## .vmt - dispatch trace (stage D)

Header, 64 bytes:

| off | size | field |
|---|---|---|
| 0x00 | 4 | magic `VMT1` |
| 0x04 | 2 | version = 1 |
| 0x06 | 2 | header size = 64 |
| 0x08 | 4 | pid |
| 0x0C | 4 | module base |
| 0x10 | 4 | dispatch site (fetch eip) |
| 0x14 | 4 | flags (bit0 sampled stream) |
| 0x18 | 8 | start tick (QPC at arm) |
| 0x20 | 8 | record count (filled at seal) |
| 0x28 | 4 | chunk payload size = 65536 |
| 0x2C | 4 | reserved 0 |
| 0x30 | 16 | reserved 0 |

Chunk:

| off | size | field |
|---|---|---|
| 0x00 | 4 | payload bytes (multiple of 96, <= 65536) |
| 0x04 | 4 | CRC-32 of payload |
| 0x08 | 8 | first record sequence in chunk |
| 0x10 | n | records |

`dispatch_rec_t` is 96 bytes, field order exactly as `include/vmpx.h`; `pad[6]`
is written zero. Sequence is global and strictly increasing; gaps mean drops
and are reported by the collector.

## .vmh - handler database (stage E)

JSONL, one object per line, key order fixed:

```json
{"addr":134512640,"len":17,"bytes":"558bec83ec...","effect":{"kind":"ADD","dst":3,"src1":3,"src2":-1,"imm":0,"size":4,"flags_mask":143,"mem_base":-1,"mem_index":-1,"mem_scale":0,"mem_disp":0},"samples":4,"conflicts":0}
```

- `addr`: handler entry VA
- `len`: bytes captured, <= 96
- `bytes`: lowercase hex, no separators
- `effect.kind`: one of the enum names in `include/vmpx.h`
- `samples` / `conflicts`: confirmation counters (accept at >= 3, 0 conflicts)
- unknown handlers are still written with `effect.kind = "UNKNOWN"` and a
  `repro` string; they are never guessed

## .vmb - decoded VM bytecode (stage F)

Header, 32 bytes:

| off | size | field |
|---|---|---|
| 0x00 | 4 | magic `VMB1` |
| 0x04 | 2 | version = 1 |
| 0x06 | 2 | header size = 32 |
| 0x08 | 4 | function entry ea |
| 0x0C | 4 | block count |
| 0x10 | 4 | insn count |
| 0x14 | 4 | flags |
| 0x18 | 8 | reserved |

Block record: `u32 id, u32 ea, u32 entry_vmregs, u32 ninsn, u32 succ0, u32 succ1,
u8 nsucc, u8 term, u16 reserved`, then `ninsn` instruction records:
`u32 ea, u8 opcode, u32 handler, u8 noperand, u8 operand[8]` (18 bytes,
written explicitly, no padding).

## .ir - SSA text (stage F)

```
IR01
func entry=0x0804A000 blocks=42
b0:
  %1 = LOAD32 v0
  %2 = ADD32 %1, 0x10
  %3 = CMP32 %2, 0x0
  JCC EQ %3, b2
b2:
  ...
```

One node per line, stable numbering by trace order. Every line ends with
`; t=<first trace seq>` so a node can be replayed against `.vmt`. Widths are
part of the op name (`ADD32`). PHI nodes appear only at block heads.

## .diff - differential report (stage G)

```
# vmpx diff v1
corpus tests/corpus/login/ab12cd34.ctx
vm  : vreg hash match
ir  : vreg hash match
nat : vreg hash match
flags: match
memory: 0 differing bytes
```

Summary footer: `coverage=<evaluated>/<total> mismatches=<n>`; any mismatch
writes a `repro <ctx> <block> <field>` line and exits non-zero.

## Agent status block (not an artifact)

Named mapping `Local\VMPX_AGENT_<pid>`, 544 bytes, `vmpx_agent_status_t` from
`include/vmpx.h`. Magic `VXAS`, version 1. Written once in `DllMain` after the
hooks are installed and updated with `hidden=1` after the loader unlink.
Read-only for the host (`vmpx agentstatus --pid N`).
