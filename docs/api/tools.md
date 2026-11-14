# Tool index

Every tool takes an `action`; `tools/list` returns the exact schemas.

| Tool | Actions |
| --- | --- |
| `target` | `list`, `attach`, `detach`, `status`, `modules`, `dump_module`, `threads`, `regions`, `handles`, `heaps`, `heap_blocks`, `icon`, `ps4_connect`, `ps4_disconnect`, `ps4_reconnect`, `ps4_auto`, `ps4_discover`, `ps4_send_payload`, `ps4_dump_module` |
| `memory` | `read`, `write`, `scan`, `rescan`, `scan_state`, `scan_reset`, `scan_save`, `scan_load`, `aob`, `pointerscan`, `snapshot`, `snapshots`, `diff`, `snapshot_free`, `protect`, `alloc`, `free`, `siggen`, `live_crypto`, `watch_list`, `watch_add`, `watch_remove`, `watch_clear`, `watch_set`, `watch_undo`, `watch_freeze_once`, `pointerscan_verify`, `offsets_verify`, `dissect` |
| `debugger` | `status` plus every `ps4_*` action |
| `disasm` | `assemble`, `disassemble`, `loaded`, `pe`, `functions`, `xrefs`, `strings`, `symbols`, `symbol_set`, `blocks`, `globals`, `vtables`, `load`, `unload`, `analyze_stop`, `managed` |
| `decomp` | `function` |
| `xray` | `cfg`, `complexity`, `cff`, `obfuscation`, `strings_recon`, `indirect_calls`, `anti_analysis`, `hooks`, `syscalls`, `apihash`, `entropy`, `pages`, `crypto_range`, `gadgets` |
| `patch` | `nop_junk`, `resolve_opaque`, `patch_antidebug`, `unpack_xor`, `decode_strings`, `write_bytes`, `revert_all`, `journal`, `full_pass`, `rebuild` |
| `devirt` | `themida_status`, `themida_start`, `themida_job`, `themida_cancel`, `identify`, `handlers`, `opcode_map`, `trace`, `lift`, `pseudocode`, `recover_cfg`, `prove_predicates`, `invariants`, `iat_audit` |
| `emulate` | `run` |
| `analyze` | `packer`, `signatures`, `diff` |
| `re` | `rtti_scan`, `vftable`, `danger`, `libsig` |
| `types` | `declare`, `create_struct`, `get_struct`, `list_structs`, `add_member`, `remove_member`, `create_enum`, `get_enum`, `list_enums`, `remove_enum`, `read_field`, `format_at` |
| `notes` | `set_comment`, `get_comment`, `comments`, `bookmark_toggle`, `bookmarks` |
| `network` | `status`, `capture_start`, `capture_stop`, `packets`, `dns`, `stats`, `export_pcap`, `streams`, `stream_data`, `reassemble_stream`, `connections`, `deep_inspect`, `clear` |
| `proxy` | `start`, `stop`, `status`, `entries`, `entry`, `replay`, `clear`, `mitm_status`, `mitm_enable`, `mitm_disable`, `mitm_uninstall` |
| `persist` | `save`, `list`, `load`, `delete`, `kv_set`, `kv_get`, `hype_save`, `hype_load` |
| `fs` | `read_file`, `write_file`, `list_directory`, `create_directory`, `delete_path`, `search_files`, `grep_in_files` |
| `web` | `fetch`, `post` |
| `script` | `run` |
| `gdb` | `start` (loopback-only, `allow_writes` opt-in), `stop`, `status` — GDB Remote bridge sharing the console session |
| `host` | `start`, `stop`, `status`, `put` — HTTP payload host with sha256 `manifest.json`, token on non-loopback binds |
| `guide` | `list`, `get` |

`app` (`status`, `ping`, `output`, `output_clear`, `log`, `diag`, `shutdown`,
`settings_get`, `settings_set`, `rotate_token`, `events_ticket`) is frontend plumbing,
reachable through `/api` only and hidden from `tools/list`.

## Action hints

`tools/list` carries a description per tool and per action. The engine also returns a
`hint` on failure when it knows the right next call — for example a PE-only action on an
ELF image points at `target.ps4_dump_module`, and `ps4_*` on a local session points at the
composite flows that do work locally.

## Mutating actions

Writes, patches, scans that allocate on the console, payload sends and `script.run` are
classified as mutating. With `mcp_require_confirm` on they need `"confirm": true`, and
every call — allowed or refused — is written to the JSONL audit log with secrets redacted.
