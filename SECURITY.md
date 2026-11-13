# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/NetVar1337/SlopStation/security/advisories/new)
(Security tab -> "Report a vulnerability"). Do not open a public issue for an
unfixed vulnerability.

Include the affected version (`VERSION` / the release tag), the component, a
description of the impact, and reproduction steps or a proof of concept. You
can expect an acknowledgement within 7 days and a fix or mitigation plan
within 30 days for confirmed issues; we will credit you in the release notes
unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes.

## Scope

In scope:

- The engine's local MCP/HTTP server (`127.0.0.1:8765`): authentication, origin
  and host checks, the SSE event stream, and every tool reachable through it
  (filesystem, web fetch, proxy, scripting, memory and debugger tools).
- The Tauri front end and its engine supervisor.
- Parsers that handle attacker-controlled input: executable/SELF/Mach-O
  loaders, `.hdb` databases, captured network traffic, the MITM proxy, the
  ps4debug wire protocol.
- Release integrity: installers, `SHA256SUMS`, signatures, the dependency
  pins in `cmake/deps.cmake`.

Out of scope: the intended capabilities of a debugging/reverse-engineering tool
used by its own operator (reading and writing memory of a process or console
you attached to, running Lua you supplied with `script_unsafe` enabled), and
vulnerabilities in third-party software analyzed with the tool.

## Handling untrusted input

Analyze untrusted samples in a disposable VM. The engine requests no elevation
by itself, but the shipped front end runs elevated.
