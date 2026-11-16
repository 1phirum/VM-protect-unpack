# P0 literal audit

Scope: target-specific values in the live restore path and in generic
completion rules. Evidence is the working tree after the P0 split. Target
paths under `artifacts/` are excluded because they are capture inputs, not
runtime code.

## Removed or converted

| Literal | Old location | Resolution |
|---|---|---|
| `0x18AFC3C` | `snapshot/restore.c` TLS index | Removed. `restore_pe_info` reads `PEHDR_DIR_TLS`, maps the directory RVA, and subtracts the image base from `AddressOfIndex`. Verified RVA `0x14AFC3C` on both `rebuilt-oep2.exe` and the original image. |
| `0x1DB22000` and the fixed probe addresses | `snapshot/restore.c` mapping diagnostics | Removed with the probe helper. Mapping failures are reported by region index, base, and size. |
| `TFormLogin` | `armor/launch.c`, `armor/winwait.c`, `cmd/cmd_oep.c` | Removed from the default completion gate. `launch_armored_ex` accepts an optional class; `vmpx launch --class <name>` selects one. The default is any visible top-level window with a nonempty title. |
| `0x400000` pre-map boundary | `snapshot/restore.c` `VMPX_PREMAP` phase | Replaced with `in.h.image_base`, so the low-heap phase follows the capture rather than the current target. |
| `rebuilt-oep2.exe`, `stageb-login` | runtime paths | Present only in test/fixture documentation. No runtime module embeds them. |

## Remaining fixed values and why they are not target identity

| Value | Use | Classification |
|---|---|---|
| `0x1000` | page size in map, TEB copy, TLS block copy | x86 Windows page size. P1 profiles will query page size and allocation granularity. |
| `0x10000` | 64 KiB reservation block | Windows allocation granularity. P1 profiles will query it. |
| `0x7FFE0000` | user-mode address ceiling for snapshot mapping | Architecture bound; regions at or above it are not mapped. |
| `0x100000` | module owner bitmap entries | One entry per 4 KiB page across the 4 GiB x86 address space. |
| `0x04`, `0x08`, `0x18`, `0x20`, `0x2C`, `0x30` | x86 TEB stack, Self, ClientId, TLS array, PEB fields | x86 TEB ABI layout. |
| `0x18` | TEB lookup self/pid probe | x86 TEB ABI layout. |
| `0x40` | minimum TEB page prefix inspected | x86 TEB ABI layout. |

## Policy

1. Discovery order is PE header, child module list, live process query, then
   profile override.
2. A target-specific value must not enter `snapshot/`, `armor/`, or a generic
   command module. Put it in a profile or a command-line selector.
3. A literal is acceptable only when it is an ABI or architecture constant, or
   when a bounded architecture range is the actual specification.
4. New literals must be added to this table with their classification in the
   same change.

## Verification

- `tests/run_restore_input_test.bat` asserts `tls_index_rva == 0x14AFC3C` for
  the rebuilt artifact and rejects CRC, zero-size, and missing-snapshot inputs.
- `tests/run_result_test.bat` asserts terminal, timeout, exit, and
  completeness classification.
- `tests/check_run_log.ps1` rejects `stopping on terminal exception` followed by
  `STATUS run ok`.
