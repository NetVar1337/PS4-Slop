# Tool index

Every tool takes an `action`; `tools/list` returns the exact schemas.

| Tool | Actions |
| --- | --- |
| `target` | `list`, `attach`, `detach`, `status`, `modules`, `dump_module`, `threads`, `regions`, `handles`, `heaps`, `heap_blocks`, `icon`, `ps4_connect`, `ps4_disconnect`, `ps4_reconnect`, `ps4_auto`, `ps4_discover`, `ps4_send_payload`, `ps4_dump_module`, `ps5_connect`, `ps5_disconnect`, `ps5_reconnect`, `ps5_auto`, `ps5_notify`, `consoles_list`, `consoles_save`, `consoles_remove`, `consoles_switch` |
| `memory` | `read`, `write`, `scan`, `rescan`, `scan_state`, `scan_reset`, `scan_save`, `scan_load`, `scan_export`, `aob`, `pointerscan`, `pointerscan_verify`, `snapshot`, `snapshots`, `diff`, `snapshot_free`, `protect`, `alloc`, `free`, `siggen`, `live_crypto`, `watch_list`, `watch_add`, `watch_remove`, `watch_clear`, `watch_set`, `watch_undo`, `watch_freeze_once`, `watch_export_ct`, `watch_import_ct`, `offsets_verify`, `dissect` |
| `debugger` | `status` plus every `ps4_*` and `ps5_*` action (see [Console actions](#console-actions)) |
| `disasm` | `assemble`, `disassemble`, `loaded`, `pe`, `functions`, `xrefs`, `strings` (`decode:true` for XOR/ROT/base64 previews), `symbols`, `symbol_set`, `blocks` (`graph`), `globals`, `vtables`, `load`, `load_self`, `unload`, `analyze_stop`, `managed` |
| `decomp` | `function` |
| `xray` | `cfg`, `complexity`, `cff`, `obfuscation`, `strings_recon`, `indirect_calls`, `anti_analysis`, `hooks`, `syscalls`, `apihash`, `entropy`, `pages`, `crypto_range`, `gadgets` |
| `patch` | `nop_junk`, `resolve_opaque`, `patch_antidebug`, `unpack_xor`, `decode_strings`, `write_bytes`, `revert_all`, `journal`, `full_pass`, `rebuild` |
| `devirt` | `themida_status`, `themida_start`, `themida_job`, `themida_cancel`, `identify`, `handlers`, `opcode_map`, `trace`, `lift`, `pseudocode`, `recover_cfg`, `prove_predicates`, `invariants`, `iat_audit` |
| `emulate` | `run`, `slice`, `session_create`, `session_step`, `session_run`, `session_destroy`, `snapshot`, `restore` — `arch:"arm64"` for Mach-O/iOS, `orbis_syscalls:true` for PS4 syscalls |
| `analyze` | `packer`, `signatures`, `diff`, `diff_start`, `diff_job`, `diff_cancel` |
| `re` | `rtti_scan`, `vftable`, `danger`, `libsig` (JSON sigsets or an IDA FLIRT `.sig`) |
| `types` | `declare`, `create_struct`, `get_struct`, `list_structs`, `add_member`, `remove_struct`, `create_enum`, `get_enum`, `list_enums`, `remove_enum`, `read_field`, `format_at` |
| `notes` | `set_comment`, `get_comment`, `comments`, `bookmark_toggle`, `bookmarks`, `export`, `import` |
| `network` | `status`, `capture_start`, `capture_stop`, `packets`, `dns`, `stats`, `export_pcap` (`pcap`/`pcapng`), `import_pcap`, `annotate`, `streams`, `stream_data`, `reassemble_stream`, `connections`, `deep_inspect`, `clear` |
| `proxy` | `start`, `stop`, `status`, `entries`, `entry`, `replay`, `clear`, `mitm_status`, `mitm_enable`, `mitm_disable`, `mitm_uninstall` |
| `persist` | `save`, `list`, `load`, `delete`, `kv_set`, `kv_get`, `hype_save`, `hype_load` |
| `fs` | `read_file`, `write_file`, `list_directory`, `create_directory`, `delete_path`, `search_files`, `grep_in_files` |
| `web` | `fetch`, `post` |
| `script` | `run`, `api`, `list`, `save`, `load`, `delete` |
| `gdb` | `start` (loopback-only, `allow_writes` opt-in), `stop`, `status` — GDB Remote bridge sharing the console session |
| `host` | `start`, `stop`, `status`, `files`, `manifest`, `put` — HTTP payload host with sha256 `manifest.json`, token on non-loopback binds |
| `guide` | `list`, `get` |

`app` (`status`, `ping`, `output`, `output_clear`, `log`, `diag`, `diag_bundle`,
`settings_get`, `settings_set`, `rotate_token`, `register_token`, `events_ticket`,
`shutdown`) is frontend plumbing, reachable through `/api/v1` only and hidden from
`tools/list`.

## Console actions

`target` carries the connection actions (`ps4_*`, `ps5_*`, `consoles_*`); everything that
acts on the attached console session lives in `debugger`, and `target.modules` /
`target.regions` read the same session.

| Group | Actions |
| --- | --- |
| Session | `ps4_attach`, `ps4_detach`, `ps4_status`, `ps4_console_info`, `ps4_app`, `ps5_attach`, `ps5_detach`, `ps5_status`, `ps5_console_info`, `ps5_threads`, `ps5_app` |
| Breakpoints | `ps4_bp_set`, `ps4_bp_clear`, `ps4_bp_list`, `ps5_bp_set`, `ps5_bp_clear`, `ps5_bp_list` |
| Watchpoints | `ps4_watch_set`, `ps4_watch_clear`, `ps4_watch_list`, `ps5_watch_set`, `ps5_watch_clear`, `ps5_watch_list` |
| Run control | `ps4_continue`, `ps4_step`, `ps4_suspend`, `ps4_resume`, `ps4_process_stop`, `ps5_continue`, `ps5_step`, `ps5_suspend`, `ps5_resume` |
| Events | `ps4_wait`, `ps4_events`, `ps5_wait`, `ps5_events` |
| Registers | `ps4_regs`, `ps4_set_reg`, `ps4_dbregs`, `ps4_set_dbregs`, `ps4_fpregs`, `ps4_set_fpregs`, `ps4_fsgs`, `ps4_set_fsgs`, `ps5_regs`, `ps5_set_reg` |
| Stack | `ps4_callstack`, `ps4_stack` |
| Remote calls | `ps4_call` |
| Power actions | `ps4_until`, `ps4_find_write`, `ps4_trace_calls`, `ps4_trace_steps`, `ps4_trace_start`, `ps4_trace_stop`, `ps4_trace_status` |
| On-console | `ps4_auth`, `ps4_scan`, `ps4_rescan`, `ps4_scan_all`, `ps4_scan_aob`, `ps4_scan_state`, `ps4_scan_reset`, `ps4_turbo_caps`, `ps4_turbo_scan`, `ps4_turbo_rescan`, `ps4_turbo_results`, `ps4_turbo_end`, `ps4_turbo_config`, `ps4_turbo_regions`, `ps4_turbo_cancel`, `ps4_write_multi`, `ps4_modules`, `ps4_snapshot`, `ps4_disasm`, `ps4_xrefs`, `ps4_xrefs_to`, `ps4_assemble`, `ps4_elf_rpc`, `ps4_elf_load`, `ps4_notify`, `ps4_print`, `ps5_notify`, `ps5_print` |

## Action hints

`tools/list` carries a description per tool and per action. The engine also returns a
`hint` on failure when it knows the right next call — for example a PE-only action on an
ELF image points at `target.ps4_dump_module`, and `ps4_*` on a local session points at the
composite flows that do work locally.

## Mutating actions

Writes, patches, scans that allocate on the console, payload sends and `script.run` are
classified as mutating. With `mcp_require_confirm` on they need `"confirm": true`, and
every call — allowed or refused — is written to the JSONL audit log with secrets redacted.
