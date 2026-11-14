# Quick start

1. **Launch SlopStation.** The splash waits for the engine handshake (up to 180 s, which
   covers the UAC prompt on first run).
2. **Load the payload on the PS4.** In **Targets**, the *ps4debug-NG payload* card shows
   the bundled release. **Send to console** streams the `.bin` to BinLoader (port 9090)
   over TCP; **Save payload…** writes it wherever you want for FTP or a GoldHEN loader.
   **Check latest** compares the bundled build with the newest GitHub release;
   **Download v\<tag\>** fetches a newer one. **Discover** in the connect form finds
   consoles on the LAN via UDP broadcast.
3. **Connect.** Enter the console IP (port 744) and press **Connect**, or let an agent do
   it in one call:

```json
{ "tool": "target", "action": "ps4_auto", "params": { "host": "192.168.1.50" } }
```

`ps4_auto` connects, authenticates the native scanner, picks the game process (the one
with `/app0/` modules, eboot-named preferred), attaches a session and the debug session,
and returns modules, threads and regions.

No console handy? Click **“List this PC's processes instead”** in Targets and attach to
any local process — everything except the `ps4_*` actions works. See
[A local process, no console](tutorials/local-process.md).

## The three surfaces

| Surface | What it is | Entry point |
| --- | --- | --- |
| Desktop app | Tauri v2 + React shell over the engine's HTTP/SSE API | `SlopStation.exe` |
| MCP server | Action-based tools for AI agents, JSON-RPC 2.0 | `http://127.0.0.1:8765/mcp` |
| Lua | Scripts against the same session as the UI and MCP | Scripts panel, `script.run` |

All three share one session: a rename, a comment or a watchlist entry made in one shows up
in the others.

## Keyboard

| Key | Action |
| --- | --- |
| `Ctrl+K` | Command palette — functions, addresses, tabs and actions |
| `Ctrl+Enter` | Run the script in the Scripts panel |
