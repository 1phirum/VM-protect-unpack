# unpack memory layer

This folder owns every allocation that crosses the unpack/dump/snapshot boundary.
The rules are intentionally narrow: one owner per handle, one owner per mapping,
and every size is checked before it reaches a pointer.

## Ownership

| object | owner | release |
|---|---|---|
| `vmpx_file_map_t` | caller | `vmpx_file_map_close`; unmaps view, then closes mapping/file |
| `vmpx_proc_reader_t` | caller | `vmpx_proc_reader_close`; one process handle, never re-opened per chunk |
| `vmpx_writer_t` | caller | `vmpx_writer_close`; flushes the bounded buffer, then closes/frees |
| `snap_meta_t[]` | `snap_write` | released after the descriptor pass |
| region bytes | `snap_restore` | one region at a time, freed after map/write |
| `proc_mem_snapshot` list | caller | `proc_mem_free` |

## Invariants

- `dump_image` keeps peak heap at the 4 MiB chunk. It never allocates
  `SizeOfImage`; a 490 MiB image is streamed to disk.
- `snap_write` keeps peak heap at the 1 MiB read chunk. Descriptors are written
  first, then data; each descriptor is patched with a CRC32 after its payload.
- `snap_restore` keeps peak heap at one region plus the two small module/owner
  tables. A full `VirtualAllocEx` failure falls back to page-granular mapping.
- `deobf_run` maps the dump and original file read-only. A 490 MiB dump plus a
  224 MiB source does not commit 714 MiB of private heap.
- File and process sizes are rejected when they exceed `SIZE_MAX` on the 32-bit
  analyzer. Snapshot region sizes are capped before allocation.
- `ReadProcessMemory`/`WriteProcessMemory`/`ReadFile`/`WriteFile` are treated as
  partial-operation APIs. Every loop advances by the byte count actually moved
  and fails on zero progress.
- Page ownership is derived from the snapshot module table; every page index is
  checked against the 4 GiB / 4 KiB owner map before use.

## Failure behavior

- A dump read failure is zero-filled and counted; the output file always has the
  requested size.
- A snapshot read failure is zero-filled, flagged `VMPX_SNAP_REG_ZERO`, and
  still carries a valid CRC over the zero-filled payload.
- A snapshot CRC mismatch skips that region and reports it; truncated payloads
  abort the restore and terminate the child before it can execute.
- `proc_mem_snapshot` now fails cleanly instead of returning a silently
  truncated region list when its vector growth fails.
