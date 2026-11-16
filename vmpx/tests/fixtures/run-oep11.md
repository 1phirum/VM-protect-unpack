# Run fixtures

## run-oep11 - terminal exception after a full restore

Source log: `artifacts/stageb-login/run-oep11.log`

Recorded command, reconstructed from the artifact names and the log:

```bat
set VMPX_RUN_DEBUG=1
vmpx run --snap artifacts\stageb-login\oep-oep.vxsn ^
         --exe artifacts\stageb-login\rebuilt-oep2.exe ^
         --ctx artifacts\stageb-login\oep-oep.vxsn.ctx
```

Recorded tail:

```text
[*] run: tls block relocated to 0x1E230000 slot=0
[+] run: entry context eip=0x00D5F351 esp=0x001AED28 ...
[+] run: debugger attached after context apply
[dbg] stopping on terminal exception
[+] run: pid=9984 mapped=106 failed=17 pages=14286/14416 modules=36 snapshot_modules=83
STATUS run ok pid=9984
```

This is a failing run. The loader completed, 106 of 123 non-system regions
mapped, the captured TEB was copied, and the TLS block was relocated. The
process then hit a terminal access violation at `ucrtbase.dll + 0x31BD2`
reading `0x003A0043`, followed by `0x80000002` at `0x7BBAD3DF`.

The historical `STATUS run ok` line is the P0 defect. After the result change,
the same log must end in:

```text
STATUS run failed status=terminal-exception ...
```

and the command must exit `5`.

The fixture is not a claim that the target works. It is a check that the
reporter cannot call a terminal fault a pass.

## Checking a new log

```powershell
powershell -ExecutionPolicy Bypass -File tests\check_run_log.ps1 `
    -Log artifacts\stageb-login\run-oep12.log -Expect terminal-exception
```

The checker fails when a log contains `stopping on terminal exception` and any
`STATUS run ok` line, or when the terminal status is missing. It does not parse
the target's output.
