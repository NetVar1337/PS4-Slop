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
  (64-byte entries), `BDAA000A` process info (188 bytes).
- Debug: `BDBB0001` attach, `BDBB0002` detach, `BDBB0003` breakpoint,
  `BDBB0004` watchpoint, `BDBB0005` threads, `BDBB0006/7` suspend/resume thread,
  `BDBB0008` GP registers (176 bytes), `BDBB0010` halt/continue,
  `BDBB0012/13` step all/specific thread.
- Kernel: `BDCC0001` base, `BDCC0002` read, `BDCC0003` write
  (ready and terminal statuses). Kernel tools require separate opt-in.

Attach body is `<I pid>` followed by four network-order IPv4 address bytes.
The local callback listens on the selected interface at fixed TCP 755. Events
are 1184 bytes: header/thread name 48, GP registers 176, FPU/YMM 832, DB registers
128. GP register offsets are derived from the source structure; raw events are
retained for additional analysis. No FPU/register-setting API is exposed.

Wire scalars are parsed exactly, not with native alignment. Length/count limits
are checked before allocation or receive. Exchanges have a bounded socket
deadline and are abandoned on EOF, error status or malformed response. A failed
command is not retried. There is no claim of atomic reads or writes.

No server-side scan/auth extensions, injected RPC calls, protection changes,
allocation/free, process ELF injection, arbitrary remote shell, reboot/kill,
automatic loader bootstrapping or kernel breakpoint debugging are implemented.
Pattern scans run on bounded local captures. Debugger capabilities outside the
implemented subset are not inferred from an open port or successful handshake.

MCP uses newline-delimited JSON-RPC over local stdio, with initialize/initialized,
ping, tools/list and tools/call. Supported protocol versions are 2025-11-25,
2025-06-18, 2025-03-26 and 2024-11-05. It advertises only tool capabilities;
resources, prompts, HTTP, batching and asynchronous task APIs are not advertised.
Transport reference: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports

## Shared service and native debugger bridge

The optional broker is a separate, bearer-authenticated JSON service bound to
IPv4 loopback only. It is not MCP Streamable HTTP. MCP clients still use the
stdio proxy; app agents and the GDB bridge use the private broker API. Requests
are profile-fingerprint-bound and no policy changes or arbitrary remote eval
are exposed. One controller owns execution; retained events have per-client cursors.

The RSP listener is loopback-only, supports one native connection per listener,
and is configured with an explicit PID. Implemented packets include checksummed/
escaped framing, ACK/NAK and no-ACK negotiation, target-description XML, cached
memory-map XML, thread selection/listing, GP register reads, bounded memory
reads, attach/detach, all-stop continue, selected-thread step, interrupt and
software/aligned hardware breakpoints. Stops are derived from actual callback
events. The known FreeBSD stop-signal subset is mapped explicitly; unsupported
wait statuses are errors, not guessed stop replies.

The x86-64 core description includes x87 register slots as unavailable; only
the existing NG GP layout is implemented. No register-setting, arbitrary RSP
memory writes, kill/reboot, monitor commands, reverse execution, mixed-thread
vCont, multiprocess or native trace-replay protocol is advertised. These are
intentional boundaries, not a complete gdbserver implementation.

Packet reference: https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html
Ghidra launcher reference: its installed `Debugger-agent-gdb/data/debugger-launchers/remote-gdb.ps1`.
