# Console connection (ps4debug-NG)

SlopStation speaks the [ps4debug-NG](https://github.com/Pharaoh2k/ps4debug-NG) wire
protocol directly: commands on TCP 744, debug events on TCP 755.

- `target.ps4_connect {host, port=744, pid?}`, `ps4_disconnect`, `ps4_reconnect`,
  `ps4_auto`, `ps4_discover` (UDP broadcast), `ps4_dump_module`, `ps4_send_payload`.
- Reads are validated against the console VM map, so unmapped ranges fail instead of
  returning zeros. Windows `PAGE_*` constants are translated to FreeBSD `VM_PROT_*`.
- The port-755 listener accepts only the attached console and drains each connection on
  its own thread.
- Reconnect keeps the session usable: the engine resets debug and turbo-scan sessions,
  restores breakpoint slots where the payload allows it, and says so in the error text
  when a connection generation changed mid-call.

## Discovery

`ps4_discover` broadcasts the 4-byte magic `0xFFFFAAAA` to `255.255.255.255:1010` and
collects every payload that answers with the same magic (the ps4debug-mcp convention).
`host: "auto"` on `ps4_connect`/`ps4_auto`/`ps4_send_payload` runs the same probe and uses
the first answer.

## Bundled payload

The installer and the app carry the ps4debug-NG payload (GPLv3). The build always fetches
the **latest release**:

- `tools/fetch_ps4debug.ps1` queries `releases/latest`, downloads the `.bin` asset and
  writes `build/ps4debug-ng/manifest.json` (tag, asset, URL, SHA-256, fetch time) plus the
  GPLv3 license text.
- The manifest and payload are bundled under `payloads/ps4debug-ng/`.
- The **Targets → ps4debug-NG payload** card shows the bundled/local tag, checks the latest
  release and downloads a newer payload to
  `%LOCALAPPDATA%\dev.slopstation.ui\payloads\ps4debug-ng\`.
- **Send to console** streams the payload to the console's BinLoader over one fresh TCP
  connection (port 9090); **Save payload…** exports the `.bin` for FTP or a GoldHEN
  payload loader. The engine action is `target.ps4_send_payload {host, port, path?}`.

ps4debug-NG is a separate GPLv3 program, not linked into the MIT-licensed SlopStation code;
its source is at <https://github.com/Pharaoh2k/ps4debug-NG>.

## Payload host

`host.start {port, bind, token}` serves a directory over HTTP with an index page,
`/files/<name>` and an auto-generated `/manifest.json` carrying a sha256 per file. A token
is required on non-loopback binds. `host.put` uploads a file. This is how you serve your
own payloads to the console without a separate web server.

## GDB bridge

`gdb.start` (loopback only, `allow_writes` opt-in) exposes the console session over the GDB
Remote Serial Protocol so IDA, Ghidra, Binary Ninja or iaito can attach through the same
connection the UI and MCP use. See
[`integrations/ps4-mcp-adapters/`](https://github.com/NetVar1337/SlopStation/tree/main/integrations).

## Walkthrough

[First console connect](../tutorials/first-console-connect.md) covers the whole path with
the failure modes.
