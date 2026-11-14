# MCP and HTTP endpoints

The engine's listener binds `127.0.0.1` only.

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | Liveness and version |
| `POST /mcp` | MCP JSON-RPC 2.0: `initialize`, `ping`, `tools/list`, `tools/call` (protocol `2025-06-18`) |
| `GET /mcp` | MCP SSE endpoint / keepalive |
| `POST /api` | Direct frontend RPC; one request or an array |
| `GET /events` | Frontend SSE stream: `hello`, `output`, `boot.stage`, `target.changed`, `backend.changed`, `hype.progress`, `watch.list`, `watch.values`, `app.quitting` |

`initialize` also returns `instructions` (a usage preamble) and `state` (backend badge,
attached target, debugger state, loaded image, analysis readiness). The same context is
available through `target.status` and `disasm.loaded`.

## Examples

```powershell
Invoke-RestMethod http://127.0.0.1:8765/health

$body = @{ tool = 'target'; action = 'ps4_auto'; params = @{ host = '192.168.1.50' } } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8765/api -ContentType 'application/json' -Body $body

$body = @{ jsonrpc = '2.0'; id = 1; method = 'tools/call'
           params = @{ name = 'target'; arguments = @{ action = 'list' } } } | ConvertTo-Json -Depth 8
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8765/mcp -ContentType 'application/json' -Body $body
```

Every request needs the bearer token unless the endpoint says otherwise:

```powershell
$h = @{ Authorization = "Bearer $env:SLOP_MCP_TOKEN" }
Invoke-RestMethod -Headers $h http://127.0.0.1:8765/health
```

## Response shape

`/api` answers `{ "ok": true, "data": … }`; a tool failure is
`{ "ok": false, "data": { "error": "…", "hint": "…" } }` (the hint is added when the engine
knows a better call). `/mcp` answers plain JSON-RPC: `result.content[0].text` carries the
JSON payload, and tool failures come back as `isError: true` with the same object.

## Event stream

`/events` authenticates with a single-use ticket from `app.events_ticket` — no token in
URLs. Events are `text/event-stream` frames named after the list above; `watch.values`
carries the sampled watchlist at about 10 Hz.

## Guides

`guide.list` and `guide.get {topic}` return ready-to-run tool sequences:
`ps4_setup`, `ps4_breakpoint`, `ps4_api_trace`, `ps4_find_write`, `ps4_step_trace`,
`ps4_remote_call`, `find_health`, `find_damage_source`, `pointer_chain` and more. They are
the fastest way to learn the intended call order for a task.
