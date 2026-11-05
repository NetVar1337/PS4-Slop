# Implemented debugger subset

Wire reference: ps4debug-NG source at
`8be828fe09f05f9327d7babdf9dcec4c67fbb816`. See `COMPATIBILITY.md` for documented
source/documentation discrepancies. No legacy backend fallback is implemented.

Every command uses packed little-endian header `<III>`:
magic `0xFFAABBCC`, command, fixed-body length. Write data phases are trailing
bytes, not counted in that body length. Success is uint32 `0x80000000`.

Implemented commands:

- Identity: `BD000001` version, `BD000500` decimal firmware, `BD000501` brand and
  capability, `BD000502` platform, `BDAACC06` liveness.
- Processes: `BDAA0001` list (36-byte entries), `BDAA0002` read,
  `BDAA0003` write (ready status, bytes, terminal status), `BDAA0004` maps
  (58-byte packed entries: name[32], start, end, offset u64, prot u16), `BDAA0008` memory protection change (with optional trailing
  `CMD_DATA_NULL` status drain and `maps` readback verification), `BDAA000A`
  process info (188 bytes), `BDAA000B` virtual memory allocation, `BDAA000C`
  virtual memory free, `BDAA000E` hinted virtual memory allocation.
- Debug: `BDBB0001` attach, `BDBB0002` detach, `BDBB0003` breakpoint,
  `BDBB0004` watchpoint, `BDBB0005` threads, `BDBB0006/7` suspend/resume thread,
  `BDBB0008` GP registers (176 bytes), `BDBB0009` set GP registers (with readback
  verification), `BDBB000A` FPU/XMM/YMM `savefpu_ymm` read (832 bytes),
  `BDBB000B` FPU/XMM/YMM `savefpu_ymm` write (with `xstate_bv` update and readback
  verification), `BDBB000C` hardware debug registers `dr0`..`dr7` (128 bytes),
  `BDBB000E` thread TLS `fsbase`/`gsbase` read (16 bytes), `BDBB000F` thread TLS
  `fsbase`/`gsbase` write (with readback verification), `BDBB0010` halt/continue,
  `BDBB0012/13` step all/specific thread.
- Kernel: `BDCC0001` base, `BDCC0002` read, `BDCC0003` write
  (ready and terminal statuses). Kernel tools require separate opt-in.

Attach body is `<I pid>` followed by four network-order IPv4 address bytes.
The local callback listens on the selected interface at fixed TCP 755 (verified
locally on `link_status(probe=true)` without contacting BinLoader port 9090).
Events are 1184 bytes: header/thread name 48, GP registers 176, FPU/YMM 832, DB
registers 128. GP, FPU/XMM/YMM, and TLS register writes perform read-modify-write
followed by independent readback verification.

Wire scalars are parsed exactly, not with native alignment. Length/count limits
are checked before allocation or receive. Exchanges have a bounded socket
deadline and are abandoned on EOF, error status or malformed response. A failed
mutating command is never auto-retried. There is no claim of atomic reads or writes.

No server-side scan/auth extensions, injected RPC calls, process ELF injection,
arbitrary remote shell, reboot/kill, automatic loader bootstrapping, DRM/SELF/PKG
decryption keys, or kernel breakpoint debugging are implemented. Multi-pass memory
value scanning (`memory_scan`), x86-64 Intel-syntax instruction assembly (`assemble` /
`memory_patch`), DWARF `.eh_frame` CFI stack unwinding, Orbis SHA-1 NID symbol
demangling (`orbis_nid_resolve`), and sectionless in-memory ELF64 header/segment
reconstruction (`memory_elf_dump`) run entirely on the host PC over bounded reads.
The same holds for the reverse-engineering suite in `docs/features/`: tracing, coverage,
access finding and scripted breakpoints are composed from the commands listed above
(breakpoints, watchpoints, resume/halt, register and memory reads); no new wire commands
are used.
Debugger capabilities outside the implemented subset are not inferred from an open
port or successful handshake.

MCP uses stdio JSON-RPC (`rmcp` in the native Rust binary) with structured tool
schemas, MCP resources (`ps4://workbench/...`), and workflow prompts.
Transport reference: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports

## Shared service and native debugger bridge

The optional broker is a separate, bearer-authenticated JSON service bound to
IPv4 loopback only. It is not MCP Streamable HTTP. MCP clients still use the
stdio proxy; desktop reverse-engineering agents (IDA Pro, Ghidra, Binary Ninja,
iaito/radare2) and the GDB bridge use the private broker API (`decompile`,
`functions`, `xrefs`, `disasm`, `strings`, `imports` with Orbis NID enrichment,
`rename`, `comment`, and bidirectional `analysis_sync_annotations`). Requests are
profile-fingerprint-bound and no policy changes or arbitrary remote eval are
exposed. One controller owns execution; retained events have per-client cursors,
and read-only `state`/`events` queries remain non-blocking while synchronous
stepping or run-loops execute.

The RSP listener is loopback-only, supports one native connection per listener,
and is configured with an explicit PID. Implemented packets include checksummed/
escaped framing, ACK/NAK and no-ACK negotiation, target-description XML
(`org.gnu.gdb.i386.core` + `org.gnu.gdb.i386.sse` with `xmm0`..`xmm15` and `mxcsr`),
cached memory-map XML, SVR4 shared-library XML (`qXfer:libraries-svr4:read::`),
thread selection/listing, GP + FPU/XMM register reads, bounded memory reads,
attach/detach, all-stop continue, selected-thread step, interrupt and
software/aligned hardware breakpoints. Stops are derived from actual callback
events. The known FreeBSD stop-signal subset is mapped explicitly; unsupported
wait statuses are errors, not guessed stop replies.

By default the RSP listener rejects memory/register mutations (`M`, `P`, `G`) with
`E01`. Passing `--allow-writes` on a non-observer `gdb-server` enables audited,
profile-qualified `M`, `P`, and `G` writes (with binary `X` returning empty so GDB
falls back to hex `M`), while `k`, `vKill`, `R`, `vRun`, and `qRcmd` remain
unconditionally rejected.

Packet reference: https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html
Ghidra launcher reference: its installed `Debugger-agent-gdb/data/debugger-launchers/remote-gdb.ps1`.
