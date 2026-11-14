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

## Binary hardening

Every first-party target (engine, legacy shell, test harness) is compiled and
linked with the Windows exploit mitigations below, and the release lane verifies
them on the artifact that actually ships (`tools/check_binaries.ps1`, which also
rejects an import or section the build does not expect):

| Mitigation | Flag | What it buys |
|---|---|---|
| ASLR | `/DYNAMICBASE` | the image is relocated to a random base |
| High-entropy ASLR | `/HIGHENTROPYVA` | 64-bit images get the full random range |
| DEP | `/NXCOMPAT` | no executable data pages |
| Control Flow Guard | `/guard:cf` + `/GUARD:CF` | indirect calls are checked against a compiler-emitted target table |
| CET compatibility | `/CETCOMPAT` | the image is marked safe for hardware shadow-stack enforcement |
| Stack cookies | `/GS` | stack buffer overruns are detected on return |

The mitigations are link-time, so they cover the whole image including the
vendored static libraries (Zydis, Capstone, Unicorn, spdlog, ...). `/CETCOMPAT`
only marks the image as compatible: Windows enables user-mode shadow stacks for
the process when the machine's policy asks for it. The one component that can
disagree with an enforced shadow stack is the Unicorn emulator's JIT, which
generates code at runtime without the CET-aware allocation APIs; if a machine
enforces shadow stacks and the emulator faults there, drop `/CETCOMPAT` for the
targets that link Unicorn rather than the whole tree.

## Handling untrusted input

Analyze untrusted samples in a disposable VM. The engine requests no elevation
by itself, but the shipped front end runs elevated.
