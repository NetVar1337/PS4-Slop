# On-console tooling

These actions run **inside the payload** on the console, so they are fast and do not stream
memory over the network.

- **Turbo Scan & bulk writes**: `ps4_turbo_caps`, `ps4_turbo_regions`, `ps4_turbo_config`,
  `ps4_turbo_scan`, `ps4_turbo_rescan`, `ps4_turbo_results`, `ps4_turbo_cancel`,
  `ps4_turbo_end`, and `ps4_write_multi` (up to 65,535 verified writes in one round-trip).
- **Fork extensions**: `ps4_modules` (server-side module list) and `ps4_snapshot`
  (one-round-trip region stream); `target.modules` uses `CMD_PROC_MODULES` with a
  client-side fallback on upstream payloads.
- **Native scan** (unlocked by `ps4_auth`): `ps4_scan`, `ps4_rescan`, `ps4_scan_state`,
  `ps4_scan_reset`, `ps4_scan_all`, `ps4_scan_aob` (`??` wildcards).
- **Code analysis**: `ps4_disasm`, `ps4_xrefs`, `ps4_xrefs_to`.
- **Assembly**: `ps4_assemble {asm, base?, syntax?}` (payload-side Keystone).
- **ELF upload**: `ps4_elf_rpc {path}`, `ps4_elf_load {path}`.
- **Console**: `ps4_notify`, `ps4_print`, `ps4_app` (foreground pid, title ID, content ID).

## When to use which

| Situation | Use |
| --- | --- |
| Narrow a large value scan | `ps4_turbo_scan` / `ps4_turbo_rescan` (server-side) |
| Write many addresses at once | `ps4_write_multi` |
| Disassemble live console code | `ps4_disasm` (payload Zydis) |
| Find references to a live address | `ps4_xrefs`, `ps4_xrefs_to` |
| Load your own code | `ps4_elf_load` / `ps4_elf_rpc` — see [Injection recipes](../injection/README.md) |
| Tell the player something | `ps4_notify` |

All of these are mutating actions where they write: with `mcp_require_confirm` on they need
`"confirm": true`, and every call lands in the JSONL audit log.

## Turbo scan

```json
{ "tool": "debugger", "action": "ps4_turbo_caps", "params": {} }
{ "tool": "debugger", "action": "ps4_turbo_scan",
  "params": { "value_type": "u32", "compare": "exact", "value": 100 } }
{ "tool": "debugger", "action": "ps4_turbo_results", "params": { "limit": 100 } }
```

`ps4_turbo_caps` tells you whether the payload build supports turbo scan at all (it is a
ps4debug-NG fork extension); on an upstream payload the native `ps4_scan*` family is the
fallback, and `ps4_auth` unlocks it.
