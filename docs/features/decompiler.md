# Decompiler

The `decomp` tool lifts code through the vendored Hyperion engine: p-code lifting, SSA,
dead-code elimination, type inference and structuring to C-like output. Calling conventions
supported are SysV AMD64, Win64 and AAPCS64.

```json
{ "tool": "decomp", "action": "function", "params": { "addr": "0x140001000" } }
```

`decomp.function` is the only action. It waits up to 10 s for the background analysis, then
returns the pseudocode. Failure modes are explicit:

| Reply | Meaning |
| --- | --- |
| `no image loaded in reverse-slop` | load a binary first (`disasm.load`) |
| `hyperion engine unavailable for this image` | the format has no Hyperion backend |
| `hyperion analysis in progress` | still running — poll `disasm.loaded` → `hype.ready` |
| `hyperion analysis not running, <error>` | it failed or was cancelled; re-run `disasm.load` |

Related calls that read the same database:

```json
{ "tool": "disasm", "action": "blocks", "params": { "addr": "0x140001000" } }
{ "tool": "disasm", "action": "globals", "params": {} }
{ "tool": "disasm", "action": "vtables", "params": {} }
{ "tool": "xray", "action": "cff", "params": {} }
```

From Lua: `slop.decomp.decompile(va)`, `blocks(va)`, `vtables()`, `globals()`, `rtti()`.

## Reading the output

- Names come from the analyzer (`functions[].name`) unless you renamed the address with
  `disasm.symbol_set`; user names win.
- Types come from inference, so structs are reconstructions. Declare your own with the
  `types` tool (`create_struct`, `add_member`, `read_field`, `format_at`) and they persist
  per image.
- Control-flow flattening shows up as a `while` over a state variable; `xray.cff` scores it
  and `patch.resolve_opaque` can clean up the predicates.
