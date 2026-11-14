# Live memory

The `memory` tool works on the console session and on a local Windows process alike.

- Read/write in hex, UTF-8, integer and float formats; allocate, free, change protection.
- Initial and refined numeric scans: exact/range/changed/unchanged, signed/unsigned/float
  widths, rounding, region/protection/alignment filters, worker/chunk/result caps.
- AOB wildcard search, pointer-chain scans and verification, signature generation, live
  crypto-constant search.
- Memory snapshots with compare/list/free; `scan_save`/`scan_load` persist an address-list
  scan across restarts.
- `offsets_verify`: fingerprint-gated offset manifests. A manifest pins the build (title
  ID, app version, SHA-256 of the module's executable segment) and gives every offset an
  anchor signature that must match exactly once; any mismatch returns no addresses at all.
  Format in [`src/core/memory/offsets.hpp`](https://github.com/NetVar1337/SlopStation/blob/main/src/core/memory/offsets.hpp).
- Shared watchlist sampled about 10 Hz with freeze writes; UI and MCP edits appear in
  both. `watch_freeze_once` releases after the first write-back and `watch_undo` restores
  the captured value.

## Scans

```json
{ "tool": "memory", "action": "scan",
  "params": { "kind": "exact", "width": "u32", "value": 100 } }
{ "tool": "memory", "action": "rescan",
  "params": { "kind": "decreased", "width": "u32" } }
{ "tool": "memory", "action": "scan_state", "params": {} }
```

Kinds: `exact`, `between`, `bigger`, `smaller`, `unknown`, `increased`, `increased_by`,
`increased_percent`, `decreased`, `decreased_by`, `changed`, `unchanged`. Widths: `i8`,
`u8`, `i16`, `u16`, `i32`, `u32`, `i64`, `u64`, `f32`, `f64`, or `all`.

Useful extras on `scan`: `begin`/`end` to bound the range, `alignment` (fastscan),
`tail` (1–8 hex digits, "ends with" fastscan), `writable`/`executable` region filters,
`max_results`, `threads`, `chunk_bytes`.

## Watchlist and freeze

```json
{ "tool": "memory", "action": "watch_add",
  "params": { "addr": "0x200001000", "width": "u32", "label": "player.health" } }
{ "tool": "memory", "action": "watch_set", "params": { "id": 1, "freeze": true } }
```

`watch_add` latches the live value immediately, so a freeze has something to write back;
`freeze_armed` in the reply tells you whether it actually armed.

## AOB and pointer chains

```json
{ "tool": "memory", "action": "aob", "params": { "pattern": "48 8B ?? ?? 89" } }
{ "tool": "memory", "action": "pointerscan",
  "params": { "target": "0x200001000", "depth": 5, "max_results": 32 } }
{ "tool": "memory", "action": "pointerscan_verify",
  "params": { "chains": [ { "base": "0x200000000", "offsets": [16, 32] } ] } }
```

`??` matches any byte. `pointerscan` walks static roots and reads pointer chains out of
live memory, returning the address path for each hit; `pointerscan_verify` re-checks
explicit chains (or the last pointerscan of this target) against the current session.

## Snapshots and diffs

```json
{ "tool": "memory", "action": "snapshot", "params": { "label": "before" } }
{ "tool": "memory", "action": "diff", "params": { "a": 1, "b": 2 } }
{ "tool": "memory", "action": "snapshots", "params": {} }
```

`diff` takes two snapshot ids and returns the changed `offset`/`length` ranges.

## Offsets that survive a game update

`offsets_verify` takes a manifest that pins the exact build and gives every offset an
anchor signature. If the game updated, the fingerprints or signatures stop matching and the
call returns no addresses instead of silently wrong ones.

## Walkthrough

[Find and freeze a value](../tutorials/local-process.md) — the scanner and watchlist on a
local process, and [Live debugging](live-debugging.md) for the "who writes this" flow.
