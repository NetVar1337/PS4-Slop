# Linux (x86-64) engine

The headless engine (`reverse-slop-engine`) builds and runs on Linux. The
window shell (`reverse-slop.exe`, DX11/ImGui) is Windows-only and is not part
of this build.

## Build

```sh
sudo apt-get install -y cmake ninja-build g++ libssl-dev
cmake -S . -B build-linux -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux --target reverse-slop-engine slop_tests
```

Dependencies (zydis, fmt, spdlog, capstone, zlib, cpp-httplib, Unicorn, SQLite,
Lua, nlohmann/json) are fetched into `_ext/` exactly as on Windows. OpenSSL is
the system package.

## Run

```sh
./build-linux/src/engine/reverse-slop-engine --no-onboard --port 8799
# SLOP_ENGINE_READY 8799 <token>
curl -s http://127.0.0.1:8799/health
curl -s -H "Authorization: Bearer <token>" -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' http://127.0.0.1:8799/mcp
```

State lives under `$XDG_DATA_HOME/reverse-slop` (default
`~/.local/share/reverse-slop`). `--stdio` works the same as on Windows.

## What works

| Area | Notes |
|---|---|
| MCP server (`/health`, `/api/v1`, `/mcp`) | httplib, unchanged |
| `target.*` local processes | `/proc` enumeration, modules from `/proc/pid/maps`, threads from `/proc/pid/task` |
| `memory.*` read/write | `process_vm_readv`/`process_vm_writev`, fallback `/proc/<pid>/mem` |
| `disasm.*`, `analysis.*`, `re.*` | Hyperion + Zydis/capstone, same code as Windows |
| `script.*` (Lua) | Lua 5.4 built as C++ with `LUA_USE_POSIX` |
| `emu.*` | Unicorn builds on Linux |
| `fs.*`, `web.*` | `std::filesystem`; HTTPS through OpenSSL |
| localhost HTTP proxy | plain HTTP + CONNECT; upstream TLS via OpenSSL |
| packet capture | `AF_PACKET` raw sockets; needs `CAP_NET_RAW` (not exercised by the WSL checks) |
| PS4/PS5 backends | the ps4debug/ps5debug wire protocol is platform-neutral; only the socket layer was ported. Exercised by the fake-server tests |

## Gated, and why

| Area | Behaviour on Linux |
|---|---|
| Local debugger (`debugger` local actions) | Win32 debug API only; `attach` reports that. Use a console backend. |
| Thread contexts, handle tables | `ERROR_NOT_SUPPORTED`; `/proc` has no equivalent of `GetThreadContext` |
| `protect`/`alloc`/`free` on another process | `ERROR_NOT_SUPPORTED`; `mprotect`/`mmap` only affect this address space, so they work for the engine's own pid |
| MITM TLS interception | needs a local CA in a certificate store (CNG). `mitm.*` reports that; plain HTTP proxying still works |
| Server-side TLS (`tls_stream::accept`) | same reason; the client side is implemented with OpenSSL |
| Process icons | no shell icon extraction; the UI draws its generic glyph |
| Heap enumeration | Toolhelp only; `heap.*` reports that |
| Magicmida unpack | the sidecar is a Windows PE; `analyze.unpack` reports that |
| MCP onboarding | writes XDG config paths (`~/.claude.json`, `~/.cursor/mcp.json`, `~/.config/Code/User/settings.json`, `~/.config/opencode/config.json`) |

## Verified

Built and run inside WSL (Kali, gcc 16, Release): `reverse-slop-engine` links,
prints `SLOP_ENGINE_READY <port> <token>`, and answers

- `GET /health` -> `{"ok":true,"server":"slopstation","version":"0.2.3"}`
- `tools/list` -> the 22 core tools
- `target.list` -> the WSL processes (`/proc`), `target.attach` -> `backend: "posix"`
- `memory.read` on a spawned `python3` -> the ELF header bytes at `0x400000`
- `disasm.load /bin/ls` -> `format: "elf"`, `functions: 22`, then `disasm.functions`
- `script.run` -> `return: 42`

`slop_tests` (portable subset) passes 97 of 98 cases. The one failure,
`ps4_debug_port_in_use_names_owner`, needs `/proc/net/tcp`, which this WSL
kernel reports empty; it passes on a normal Linux host.

## Privileges

- Cross-process memory access needs `CAP_SYS_PTRACE` (or a parent/child
  relationship; `kernel.yama.ptrace_scope=1` otherwise denies it).
- Packet capture needs `CAP_NET_RAW`; `network.capture_start` reports the
  missing capability instead of failing silently.

## Tests

`slop_tests` on Linux builds a portable subset: `ipa`, `emu`, `ps4`,
`ps4_chaos`, `ps4_debug`, `ps5`, `disasm_accuracy`. The other areas need
`SlopTarget.exe` or Win32 APIs and stay Windows-only.
