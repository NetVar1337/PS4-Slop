# Configuration and security

Settings live in `%LOCALAPPDATA%\reverse-slop\settings.json`:

```json
{
  "mcp_enabled": true,
  "mcp_port": 8765,
  "mcp_token": "<auto>",
  "mcp_onboarded": false,
  "script_unsafe": false,
  "web_allow_private": false,
  "mcp_onboard_clients": [],
  "mcp_token_in_configs": false,
  "mcp_rate_limits": {},
  "events_max_streams": 64,
  "proxy_redact_secrets": true,
  "fs_root": []
}
```

| Key | Type | Meaning |
| --- | --- | --- |
| `mcp_enabled` | bool | start the MCP/HTTP listener (default `true`) |
| `mcp_port` | int 1–65535 | listener port (default 8765) |
| `mcp_token` | string | bearer token; **not settable** through `app.settings_set`, use `app.rotate_token` |
| `mcp_onboarded` | bool | set `false` to request another client-registration pass |
| `mcp_onboard_clients` | array of strings | clients to register (empty = Tern when installed, else every known client) |
| `mcp_token_in_configs` | bool | write the literal bearer into client configs instead of `${SLOP_MCP_TOKEN}` (default `false`) |
| `mcp_rate_limits` | object | per-tool token buckets `{tool: {rate, burst}}`; tools without an entry use the built-in defaults |
| `mcp_require_confirm` | bool | mutating actions need `"confirm": true` |
| `mcp_audit_enabled` | bool | write the JSONL audit log (default `true`) |
| `mcp_audit_path` | string | where the audit log goes (default `%LOCALAPPDATA%\reverse-slop\mcp_audit.jsonl`) |
| `events_max_streams` | int 1–1024 | concurrent `/api/v1/events` streams (default 64) |
| `script_unsafe` | bool | full Lua standard library (`io`/`os`) |
| `web_allow_private` | bool | allow loopback/LAN targets in `web.fetch`/`web.post` |
| `web_allowlist` | array of strings | hosts reachable when private targets are allowed |
| `proxy_token` | string | token for the localhost inspection proxy |
| `proxy_redact_secrets` | bool | redact secret headers and query values in stored proxy entries (default `true`) |
| `fs_root` | string or array of strings | jail every `fs` action to these folders; unset keeps the historic whole-profile access |

`app.settings_get` returns the settings with `mcp_token`/`proxy_token` redacted to
`"set"`/`"unset"`; `app.settings_set {key, value}` validates the typed keys above and
erases a key when `value` is `null`.

## Rate limits

`mcp_rate_limits` is a per-tool token bucket, consulted on `/mcp` only (`/api/v1` never
throttles the UI). An entry is `{"rate": <tokens per second, > 0>, "burst": <>= 1>}`; a
malformed entry means no limit for that tool rather than a wrong one. Tools without an
entry use the built-in defaults:

| Tool | rate | burst |
| --- | --- | --- |
| `memory` | 50 | 100 |
| `emulate` | 20 | 40 |
| `xray` | 30 | 60 |
| `analyze` | 10 | 20 |
| `devirt` | 20 | 40 |
| `script` | 20 | 40 |

## Filesystem jail

`fs_root` is unset by default, which keeps the historic whole-profile access. Set it to one
path or a list of paths and every `fs` action is confined to them: paths are canonicalised
first, so `..`, junctions, 8.3 names, `\\?\` prefixes and alternate data streams cannot
walk out, and directory walks never follow reparse points. The engine data directory is
refused either way.

## Tokens

- **A bearer token is generated automatically on first start**; every `/mcp` and `/api/v1`
  call needs `Authorization: Bearer <token>`. Regenerate it from Settings
  (`app.rotate_token`) — client configs and `engine.json` are updated in place.
  `SLOP_MCP_TOKEN` adds a per-process token without persisting anything.
- `SLOP_MCP_PORT` or `--port` overrides the port. If the port is busy the engine takes an
  ephemeral port and skips onboarding.
- The event stream (`/api/v1/events`) authenticates with a **single-use ticket** from
  `app.events_ticket` (60 s TTL) — no token in URLs.

## Request hardening

- Request bodies are capped at 32 MiB.
- Every route validates `Host` and browser `Origin` (DNS-rebinding and cross-site
  JSON-RPC get 403).
- The listener binds `127.0.0.1` only.
- The audit log records every tool call, allowed or refused, with secrets redacted.

## What is dangerous

Treat `script.run` as code execution regardless of the sandbox — the `slop.*` surface
writes memory and files. Live writes and `ps4_*` mutating actions are code execution
against the target: a bad write can crash the console or the game. Read
[`SECURITY.md`](https://github.com/NetVar1337/SlopStation/blob/main/SECURITY.md) and the
[audit](../AUDIT.md) before running untrusted payloads or scripts.
