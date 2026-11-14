# Feature map

| Area | Summary |
| --- | --- |
| **Console connection** | ps4debug-NG over TCP 744 plus the TCP 755 debug-event callback; ps5debug-NG for PS5. UDP auto-discovery, saved consoles with quick-switch, manual reconnect (`ps4_reconnect`), native/turbo scan and bulk writes. |
| **Live memory** | Regions, modules, threads, read/write/protect/alloc, Cheat Engine-style scans, AOB wildcards, pointer chains, snapshots and diffs, object dissection, a shared watchlist with freeze/freeze-once/undo. |
| **Live debugging** | Software breakpoints (conditional, hit counts), DR0–DR3 watchpoints, continue/step/suspend, stop events with registers, callstacks, FP/FS-GS, remote calls, trace/find-write one-shots, JSONL trace sessions; the `ps5_*` subset for PS5. |
| **On-console tooling** | Native scan/rescan, Turbo Scan, verified bulk writes, fork module/snapshot commands, Zydis disassembly, xrefs, Keystone assembly, ELF upload. |
| **Static analysis** | ELF64 with NID→name resolution, SELF, PE, Mach-O/`.ipa`, .NET; function/xref/string indexes; Xray passes; patching with a journal; binary diffing; packer heuristics. |
| **Decompiler** | Hyperion p-code lifting, SSA, DCE, type inference and structuring to C-like output (SysV AMD64, Win64, AAPCS64). |
| **Emulation** | Isolated Unicorn x86-64/arm64 runs with demand paging from the loaded image or live memory, tracing, backward slices, persistent sessions with checkpoints, byte-level taint and devirtualization helpers. |
| **Automation** | Lua 5.4 against the shared session, plus an MCP server with action-based tools, task playbooks (`guide`), a JSONL audit log and an optional confirm gate. |
| **Payload host** | Built-in HTTP payload host with a sha256 `manifest.json`; UDP broadcast discovery; the bundled ps4debug-NG payload. |
| **Host network** | Raw-socket capture, DNS log, stream reassembly, PCAP export, and a localhost HTTP inspection proxy. |

Two desktop shells drive the same C++ core: the **Tauri v2 + React** app (the one that
ships) and a legacy **ImGui/DX11** shell ([documented here](../imgui-shell.md)). The
engine also runs headless for MCP/HTTP clients only.

## Pages

- [Console connection](console-connection.md)
- [Live memory](live-memory.md)
- [Live debugging](live-debugging.md)
- [On-console tooling](on-console-tooling.md)
- [Static analysis](static-analysis.md)
- [Decompiler](decompiler.md)
- [Emulation and devirtualization](emulation-devirt.md)
- [Host network and proxy](network-proxy.md)
- [Persistence, filesystem and web](persistence.md)
- [Lua scripting](lua.md)
