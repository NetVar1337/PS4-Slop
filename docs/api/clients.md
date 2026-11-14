# MCP client registration

On the first successful start on the configured port, a `slopstation` HTTP entry is added
(existing entries are kept) to:

| Client | File |
| --- | --- |
| Claude Code | `%USERPROFILE%\.claude.json` (user scope, `"type": "http"`) |
| Cursor | `%USERPROFILE%\.cursor\mcp.json` |
| Windsurf | `%USERPROFILE%\.codeium\windsurf\mcp_config.json` |
| VS Code | `%APPDATA%\Code\User\settings.json` (`mcp.servers`) |
| OpenCode | `%USERPROFILE%\.config\opencode\config.json` |

Unparseable config files are left untouched. When a token is set, it is written into these
files — **do not sync them publicly**. Run the engine with `--no-onboard` to skip
registration; set `mcp_onboarded` to `false` to request another pass.

## Stdio-only clients

Claude Desktop and friends run the engine with `--stdio`: JSON-RPC arrives on stdin and
leaves on stdout one message per line, logs go to stderr, and a per-process token is
generated automatically. If an engine is already running (the desktop app), the stdio
process bridges to it instead of starting a second one.

```json
{ "mcpServers": { "slopstation": {
    "command": "C:\\Users\\you\\AppData\\Local\\dev.slopstation.ui\\engine\\reverse-slop-engine.exe",
    "args": ["--stdio"] } } }
```

## Manual HTTP entry

```json
{ "mcpServers": { "slopstation": {
    "type": "http",
    "url": "http://127.0.0.1:8765/mcp",
    "headers": { "Authorization": "Bearer <token>" } } } }
```

The token is in `%LOCALAPPDATA%\reverse-slop\settings.json` (`mcp_token`), or in the
`SLOP_ENGINE_READY <port> <token>` line the engine prints on start when it is run as a
sidecar.

## Live checks in the repo

`tools/mcp_stdio_test.py` drives a stdio session, `tools/mcp_live_test.py` drives the HTTP
endpoint of a running app. Both are dependency-free Python and are what CI uses to prove
the wire protocol still works.
