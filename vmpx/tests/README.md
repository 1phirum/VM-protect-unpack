# VMPX tests

## Result-layer gate

`run_result_test.bat` compiles and runs `result_test.c` against
`src/unpack/result.c`. It does not create a target process.

It covers the P0 gate that a created process cannot report application success
after a terminal exception, a diagnostic timeout or a process exit. It also
checks initialization, the CLI exit-code mapping and the completeness
predicate.

```bat
tests\run_result_test.bat
```

Expected:

```text
result_test: ok
```

## Snapshot input and TLS discovery

`run_restore_input_test.bat` writes a minimal packed snapshot and checks:

- missing, CRC-mismatched and zero-size inputs fail before a child exists;
- region bounds, TEB lookup and stack bounds behave as specified;
- the rebuilt PE's TLS index is discovered from `PEHDR_DIR_TLS`
  `AddressOfIndex` and equals RVA `0x14AFC3C` for the current artifact.

```bat
tests\run_restore_input_test.bat
```

Expected ends with:

```text
restore_input_test: ok
```

## Run-log invariant

`check_run_log.ps1` rejects any log that contains
`stopping on terminal exception` and a later `STATUS run ok`. It also enforces
the expected terminal status when requested.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\check_run_log.ps1 `
    -Log artifacts\stageb-login\run-oep11.log
```

This command must fail on the historical fixture; that failure is the P0
evidence. A corrected elevated run must pass:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\check_run_log.ps1 `
    -Log artifacts\stageb-login\run-oep12.log -Expect terminal-exception
```

## Live deobf build verification

Attach `vmpx.exe` to a running 32-bit process and collect for ten seconds.
`%SystemRoot%\SysWOW64\cmd.exe` is the reference target; the same-user attach
needs no elevation.

```bat
start "" %SystemRoot%\SysWOW64\cmd.exe
vmpx.exe deobf --pid <pid> --out <dir> --seconds 10
```

Expected exit `0` and a STATUS line of this shape:

```text
STATUS deobf-dynamic pid=<pid> session=<id> ended=timeout events=<n> mem=<n> exec=<n> threads=<n> vm=<n> api=<n> strings=<n> dropped=0 manifest=ok
```

`ended=timeout` is the normal end for a bounded `--seconds` run. `mem` is the
changed-page count, not the event count. Transport health reads from `dropped=0`
plus the loss ledger's global record.

Artifacts:

- `<dir>\summary.txt` - counters, capture size, and transport totals.
- `<dir>\session\manifest.json` - session identity, modules, regions, profile.
- `<dir>\events\loss.jsonl` - one record per shard, then the global record with
  `stalled` and `invalid`.
- `<dir>\events\events.txt` - accepted event stream.

The reference 10 s run recorded `events=4948`, `mem=5109`, `strings=516`,
`dropped=0`, and loss `stalled=0 invalid=0`. Treat those numbers as a reference
point, not a fixed expectation; window length and target activity change them.
A non-zero `stalled` or `invalid` is a transport finding and belongs in the run
record.

## Manual restore fixtures

The restore path requires elevation because it creates the target process.
Record each fixture as a command line and the full `STATUS` line, not only the
final window observation.

Minimum fixtures:

1. **Invalid snapshot:** `vmpx run --snap missing.vxsn --exe <rebuilt.exe>`
   must return `3` and print `STATUS run failed status=capture-failed`.
2. **Terminal diagnostic exception:** run with `VMPX_RUN_DEBUG=1` against a
   known crashing capture; the command must return `5` and print
   `STATUS run failed status=terminal-exception`, even though the child was
   created and modules were mapped.
3. **Launch-only path:** no `--wait`, no debug environment; the command must
   print `STATUS run launched ... restore=complete|incomplete` and return `0`.
   This is not an application pass.
4. **Alive wait window:** `--wait` against a capture that reaches a live window;
   the command must print `STATUS run alive` and return `0`.
5. **Early exit:** `--wait` against a process that exits non-zero; the command
   must print `STATUS run exited` and return `6`.

The existing diagnostic capture under
`artifacts/stageb-login/oep-oep.vxsn` is the first fixture for cases 2 and 4.
Its recorded terminal-exception behavior is historical evidence, not a pass.
See `tests/fixtures/run-oep11.md`.

`run-oep12.bat` runs that fixture in an elevated shell, writes
`artifacts/stageb-login/run-oep12.log`, checks the log invariant, and then
returns the target's status code. In the P0 state the checker passes and the
batch exits `5` because the target still hits a terminal exception. A passing
checker is a reporting pass, not an application pass.
