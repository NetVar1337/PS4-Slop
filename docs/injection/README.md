# Loading your own code on a jailbroken PS4 (homebrew recipes)

Condensed from the ps4-injection-lab method table. These are for **your own
homebrew payloads** on hardware you own. The kernel/DMA/controller-spoof
methods (07, 14–19) and the cheat-XML method (10) are intentionally not
covered — they exist for anti-cheat evasion, not development.

| # | Method | Use it when | PS4-side scope | Persistent |
| --- | --- | --- | --- | --- |
| 01 | `CMD_PROC_ELF` (`ps4_elf_load` in the debugger tool) | run a freestanding ELF in the game process now | freestanding ELF | until crash |
| 02 | `CMD_PROC_ELF_RPC` (`ps4_elf_rpc`) | same, with a deferred entry point | freestanding ELF | until crash |
| 03 | `CMD_PROC_INTALL` + `CMD_PROC_CALL` (`ps4_call`) | call one function with args, get rax | none (host-driven) | no |
| 04 | GoldHEN SPRX plugin | load a proper `.sprx` plugin into the game | SPRX plugin | game session |
| 05 | `sceKernelLoadStartModule` via RPC | load an SPRX from a stub ELF | stub ELF + SPRX | game session |
| 06 | custom BinLoader daemon (port 7777) | repeated loads without re-sending the ELF | custom daemon | until reboot |
| 08 | SELF + GoldHEN patch XML | patch the game's own code/data on disk | none | until game update |
| 09 | elfldr (port 9021) | classic payload loader | freestanding ELF | until crash |
| 11 | fake PKG sidecar | run as a real PS4 application | PS4 application | app launcher |
| 12 | SPRX hotswap | swap a loaded module at runtime | ELF + replacement SPRX | game session |
| 13 | shared-memory sidecar | game↔sidecar IPC channel | ELF + sidecar | game session |

## From the MCP server

```
target.ps4_discover                      # or ps4_connect {host:"auto"}
target.ps4_auto {host}                   # connect + pick game + attach + debug
debugger.ps4_elf_load {path}             # method 01, your own ELF
debugger.ps4_call {addr, args:[...]}     # method 03
host.start {port:9090, bind:"0.0.0.0", token:"..."}   # serve payloads to the console
```

Serve your payload with the `host` tool, then load it on the console with
method 09 (elfldr) or 01 (`ps4_elf_load`). Every load is a mutating action:
with `mcp_require_confirm` on it needs `"confirm": true`, and every call is
in the JSONL audit log.

Full mechanism docs, protocol details and failure modes for each method live
in the ps4-injection-lab repository (`NN-<name>/README.md` per method).
