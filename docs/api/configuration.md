# Configuration and security

Settings live in `%LOCALAPPDATA%\reverse-slop\settings.json`:

```json
{
  "mcp_enabled": true,
  "mcp_port": 8765,
  "mcp_token": "<auto>",
  "mcp_onboarded": false,
  "script_unsafe": false,
  "web_allow_private": false
}
```

| Key | Type | Meaning |
| --- | --- | --- |
| `mcp_enabled` | bool | start the MCP/HTTP listener |
| `mcp_port` | int 1–65535 | listener port (default 8765) |
| `mcp_token` | string | bearer token; **not settable** through `app.settings_set`, use `app.rotate_token` |
| `mcp_onboarded` | bool | set `false` to request another client-registration pass |
| `mcp_require_confirm` | bool | mutating actions need `"confirm": true` |
| `mcp_audit_enabled` | bool | write the JSONL audit log |
| `mcp_audit_path` | string | where the audit log goes |
| `script_unsafe` | bool | full Lua standard library (`io`/`os`) |
| `web_allow_private` | bool | allow loopback/LAN targets in `web.fetch`/`web.post` |
| `web_allowlist` | array of strings | hosts reachable when private targets are allowed |
| `proxy_token` | string | token for the localhost inspection proxy |

`app.settings_get` returns the settings with `mcp_token`/`proxy_token` redacted to
`"set"`/`"unset"`; `app.settings_set {key, value}` validates the typed keys above and
erases a key when `value` is `null`.

## Tokens

- **A bearer token is generated automatically on first start**; every `/mcp` and `/api`
  call needs `Authorization: Bearer <token>`. Regenerate it from Settings
  (`app.rotate_token`) — client configs and `engine.json` are updated in place.
  `SLOP_MCP_TOKEN` adds a per-process token without persisting anything.
- `SLOP_MCP_PORT` or `--port` overrides the port. If the port is busy the engine takes an
  ephemeral port and skips onboarding.
- The event stream (`/events`) authenticates with a **single-use ticket** from
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
