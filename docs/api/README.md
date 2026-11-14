# MCP and HTTP endpoints

The engine's listener binds `127.0.0.1` only.

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | Liveness and version |
| `POST /mcp` | MCP JSON-RPC 2.0: `initialize`, `ping`, `tools/list`, `tools/call`, `resources/list`, `resources/read`, `prompts/list`, `prompts/get` (protocol `2025-06-18`) |
| `GET /mcp` | MCP SSE endpoint: keepalive plus `notifications/progress` for a `tools/call` that carried `_meta.progressToken` |
| `POST /api/v1` | Direct frontend RPC; one request or an array |
| `POST /api` | Deprecated alias of `/api/v1` (answers with a `Deprecation` header) |
| `GET /api/v1/events` | Frontend SSE stream: `hello`, `output`, `boot.stage`, `target.changed`, `backend.changed`, `hype.progress`, `watch.list`, `watch.values`, `debugger.stop`, `debugger.state`, `debugger.log`, `types.changed`, `disasm.index_updated`, `app.quitting` |
| `GET /events` | Deprecated alias of `/api/v1/events` |
| `GET /api/v1/openapi.json` | OpenAPI 3.1 descriptor generated from the MCP tool schemas |

`initialize` also returns `instructions` (a usage preamble) and `state` (backend badge,
attached target, debugger state, loaded image, analysis readiness). The same context is
available through `target.status` and `disasm.loaded`.

## Examples

```powershell
Invoke-RestMethod http://127.0.0.1:8765/health

$body = @{ tool = 'target'; action = 'ps4_auto'; params = @{ host = '192.168.1.50' } } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8765/api/v1 -ContentType 'application/json' -Body $body

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

`/api/v1` answers `{ "ok": true, "data": … }`; a tool failure is
`{ "ok": false, "data": { "error": "…", "hint": "…" } }` (the hint is added when the engine
knows a better call). A request body that is an array is answered with an array of the same
envelopes, so opening a view costs one round trip. `/mcp` answers plain JSON-RPC:
`result.content[0].text` carries the JSON payload, and tool failures come back as
`isError: true` with the same object.

## Event stream

`/api/v1/events` authenticates with a single-use ticket from `app.events_ticket` (60 s
TTL) — no token in URLs. Events are `text/event-stream` frames named after the list above;
`watch.values` carries the sampled watchlist at about 10 Hz, and `hello` opens the stream.
Concurrent streams are capped by the `events_max_streams` setting (default 64).

## OpenAPI

`GET /api/v1/openapi.json` returns an OpenAPI 3.1 document generated from the same tool
schemas `tools/list` serves, so a generated client and an MCP agent never disagree about
parameters.

## Resources

`resources/list` exposes the live state and every guide playbook as a resource:

| URI | Content |
| --- | --- |
| `slop://state/target` | active backend, attached target (pid, name, arch), busy flag |
| `slop://state/image` | shared binary session: path, format, arch, analysis state |
| `slop://guide/<topic>` | the playbook JSON for one `guide` topic |

`resources/read {uri}` returns `contents[0].text` with the JSON body; an unknown URI is an
error.

## Prompts

`prompts/list` returns one prompt per guide topic (name, title, summary, no arguments), and
`prompts/get {name}` returns that playbook as a single user message, so an MCP client can
offer the workflows as slash commands.

## Guides

`guide.list` and `guide.get {topic}` return ready-to-run tool sequences:
`ps4_setup`, `ps4_breakpoint`, `ps4_api_trace`, `ps4_find_write`, `ps4_step_trace`,
`ps4_remote_call`, `find_health`, `find_damage_source`, `pointer_chain` and more. They are
the fastest way to learn the intended call order for a task.
