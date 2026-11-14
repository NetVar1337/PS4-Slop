# Emulation and devirtualization

## Emulator

`emulate.run` executes x86-64 in an isolated Unicorn instance:

- start from raw bytes, a loaded-image address, or a live target address;
- demand paging from the loaded image or live memory, so untouched pages cost nothing;
- IAT stubs that log calls;
- custom registers, stack and memory;
- stop conditions, bounded traces and byte-granular taint.

```json
{ "tool": "emulate", "action": "run",
  "params": { "file_addr": "0x140001000", "code_len": 256, "count": 200, "trace": true } }
```

The code source is `hex`, `file_addr` (an address in the loaded image) or `target_addr`
(live memory, with `code_len`); `entry` overrides the start address, `count` caps
instructions, `until` stops at an address, and `page_in` (default true) faults pages in from
the image or the target on demand. `arch` accepts `x64`/`x86_64`/`amd64` or
`arm64`/`aarch64`, and `orbis_syscalls:true` services PS4 syscalls.

### Slices from a recorded trace

```json
{ "tool": "emulate", "action": "slice",
  "params": { "trace_id": 1, "reg": "rax", "at": "0x140001020" } }
```

`run` with `trace:true` returns a `trace_id` (the last eight traces stay addressable).
`slice` walks that trace backwards from `at` (or from the instruction that last wrote
`reg`, or from `addr`) and returns the instructions that produced the value.

### Persistent sessions

```json
{ "tool": "emulate", "action": "session_create",
  "params": { "file_addr": "0x140001000", "count": 0 } }
{ "tool": "emulate", "action": "session_run", "params": { "session": 1, "count": 500 } }
{ "tool": "emulate", "action": "session_step", "params": { "session": 1 } }
{ "tool": "emulate", "action": "snapshot", "params": { "session": 1 } }
{ "tool": "emulate", "action": "restore", "params": { "session": 1 } }
{ "tool": "emulate", "action": "session_destroy", "params": { "session": 1 } }
```

A session keeps the VM between calls: `session_step` runs one instruction, `session_run`
runs `count` (0 = until a stop condition, 5 s default budget), and every reply carries the
register state. `snapshot` checkpoints the pages written so far and `restore` returns to the
newest checkpoint; up to eight sessions are live at once.

## Devirtualization

The `devirt` tool covers VM-based protectors:

| Action | Purpose |
| --- | --- |
| `identify` | recognize the VM and its entry points |
| `handlers`, `opcode_map` | handler discovery and the opcode → handler map |
| `trace`, `lift`, `pseudocode` | run the VM, lift handlers, emit pseudocode |
| `recover_cfg` | rebuild the control-flow graph behind the VM |
| `prove_predicates`, `invariants` | prove opaque predicates, list invariants |
| `iat_audit` | audit the import table for redirected entries |

## Magicmida (Themida)

Supervised Magicmida jobs with architecture checks, cancellation and timeouts:

```json
{ "tool": "devirt", "action": "themida_status", "params": {} }
{ "tool": "devirt", "action": "themida_start",
  "params": { "path": "C:/samples/packed.exe", "output_path": "C:/samples/unpacked.exe" } }
{ "tool": "devirt", "action": "themida_job", "params": { "id": 1 } }
{ "tool": "devirt", "action": "themida_cancel", "params": { "id": 1 } }
```

The sidecars are fetched by `tools/install_magicmida.ps1` and cached in CI; the ImGui shell
has a dedicated **Unpacker** view for this, the Tauri app drives it through MCP
(see the [parity matrix](../imgui-shell.md#feature-parity)).
