# Security and qualification

- The engine binds `127.0.0.1` only and requires a bearer token on `/mcp` and `/api`.
  Mutating tools can require confirmation (`mcp_require_confirm`), and every call is
  written to a JSONL audit log with secrets redacted.
- Live writes and `script.run` are code execution against the target; a bad write can
  crash the console or the game. Read
  [`SECURITY.md`](https://github.com/NetVar1337/SlopStation/blob/main/SECURITY.md) and the
  [audit](../AUDIT.md) before running untrusted payloads or scripts.
- Host packet capture needs administrator rights; TLS interception is opt-in and
  reversible.
- The app's auto-updater verifies the installer against the embedded Tauri public key; the
  private key is a CI secret and never ships.
- Outbound `web` calls do not inherit browser cookies, and private/loopback targets are
  denied unless explicitly allowed.
- `fs` refuses the engine's own data directory, so a script cannot rewrite the session
  database or the token store.

## Qualification

Use SlopStation only on consoles, games, and systems you own or are authorized to test.
The repository's scope rule is the same one the [merge plan](../MERGE.md) states: homebrew
payloads, your own debug builds, your own dumps. Anything whose purpose is cheating in live
online games, evading bans, or circumventing licensing is out of scope.

## Reporting

Security issues go through GitHub's private vulnerability reporting on the repository, not
a public issue — see `SECURITY.md` for the current contact and the supported versions.
