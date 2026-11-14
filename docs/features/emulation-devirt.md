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
the image or the target on demand.

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
