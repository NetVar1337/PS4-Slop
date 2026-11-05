# Validation record: 0.3 consolidation

Date: **2026-11-05**. Base commit `93a803a` plus the uncommitted consolidation.
Windows, rustc/cargo **1.99.1**, Python **3.15.2**. [VALIDATION.md](VALIDATION.md)
and [VALIDATION_02.md](VALIDATION_02.md) are historical records for the retired
Python server.

## What changed

- The Rust binary is the only server. The duplicate Python server modules
  (`broker`, `rsp`, `mcp`, `tools`, `workbench`, `debugger`, `transports`,
  `analysis`, `artifacts`, `development`, `desktop`, `cli`) and their tests were
  removed. `ps4_workbench/` keeps only the analysis-agent adapters, the broker
  client and `AnalysisWorker`.
- Each retired Python server test either already had a Rust equivalent or was
  ported to `tests/server_contract.rs` (85 tests). Gaps found by the port were fixed
  in Rust:
  - integers above 2^53 in tool results are returned as hex strings;
  - MCP stdio enforces a 1 MiB line limit and returns `-32700` for invalid JSON;
  - `ftp_extract` rejects traversal and duplicate paths before any network use;
  - an interrupted payload transfer reports "execution uncertain, never retry".
- `address_correlate` was merged into `address_rebase`. It now also returns the
  process map containing the address and falls back to a map-offset estimate for
  addresses outside the module list.
- `debug_stack`'s description now names its DWARF `.eh_frame` → frame pointer →
  stack scan order.

## Automated checks executed

- `cargo test --locked`: 101 unit tests and 85 contract tests passed.
- `cargo clippy --all-targets --locked -- -D warnings`: clean.
- `cargo clippy --all-targets --features fixture --locked -- -D warnings`: clean.
- `python -m compileall -q ps4_workbench tests integrations`: passed.
- `python -m unittest discover -q`: 12 adapter tests passed. They run against the
  real `ps4-workbench broker` binary: agent registration, job round trip, error
  propagation, duplicate-agent rejection, unregistration and wrong-token rejection.

## Installed-app checks executed (loopback fixture, not PS4)

`cargo build --release --features fixture --bins` builds `ps4debug-fixture`. This
fixture serves a generated ELF over the ps4debug-NG protocol. It emits a stop on
attach and on halt, and advances RIP by the decoded instruction length on step. It
executes no code.

1. `python tests/manual/run_ida_dynamic.py`: passed.
   - Path: IDA 9.5 Remote GDB → Rust `gdb-server` → Rust `broker` → fixture.
   - RIP `0x400100` and bytes `b82a000000c3` read correctly.
   - Single step reached `0x400105`.
   - Software breakpoint inserted and removed.
   - The IDA adapter imported 2 regions through the broker.
2. `python tests/manual/run_ghidra_agent.py`: passed.
   - Path: Rust MCP `serve --broker` → Rust broker → Ghidra 12.2 Java agent.
   - Decompiler output: `return 0x2a;`.
3. `python tests/manual/run_installed_apps.py`: IDA and Ghidra static smoke tests passed.

## Live read-only console checks

- `ftp_list /data` against `192.168.86.25:2121` returned a listing.
- `pi mcp list` reports `ps4-workbench` connected with 66 tools: the 54 default
  tools, minus the broker-owned `debug_events`, plus 13 analysis/session tools.
- Memory-map decoding fixed to the upstream packed 58-byte `proc_vm_map_entry`
  (name[32], start, end, offset, u16 prot); the old 64-byte decoder failed with
  "Invalid map range" on hardware. `process_maps` on SceShellUI (PID 42) with
  ps4debug-NG 1.3.4 returned 1728 maps, none inverted. `module_list` now keeps only
  names with an executable segment: 533 groups (mostly heaps/shm) → 227, including
  the `.sprx` libraries. Remaining `anon:` entries are executable (JIT) regions.

## Not verified

- No payload was sent to `9090`.
- No debugger session on real hardware.
- No qualification record exists for the console.
- Binary Ninja and iaito adapters have not been run inside those applications; the
  apps are not installed.
- The GitHub Actions jobs have not been observed running.
