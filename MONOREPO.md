# Monorepo layout

PS4-Slop is the umbrella repo. The companion projects live here as **git
subtrees** (full history preserved), each buildable in place:

| Path                     | Source fork                                   | What it is |
|--------------------------|-----------------------------------------------|------------|
| `.` (root)               | `NetVar1337/PS4-Slop`                          | Tauri/C++ desktop app — live memory, scanning, debugging, static analysis |
| `vendor/ps4debug-NG`     | `NetVar1337/ps4debug-NG` (`master`)            | Debugger payload the app speaks to (TCP 744 + port-755 events) |
| `mcp/ps4-mcp`            | `May-Ethereal/PS4-MCP` (`main`)                | Python MCP server — typed research, SDK gen, durable sessions |
| `mcp/ps4debug-mcp`      | `NetVar1337/ps4debug-mcp` (`main`)             | Lightweight MCP server + Python client for ps4debug-NG |
| `exploit/afterglow-web` | `May-Ethereal/afterglow-web` (`main`)          | Browser kernel exploit (FW 12.00–14.00) to launch the payload |

## Re-sync a component from its fork

```bash
git subtree pull -P vendor/ps4debug-NG   https://github.com/NetVar1337/ps4debug-NG   master
git subtree pull -P mcp/ps4-mcp          https://github.com/May-Ethereal/PS4-MCP     main
git subtree pull -P mcp/ps4debug-mcp     https://github.com/NetVar1337/ps4debug-mcp  main
git subtree pull -P exploit/afterglow-web https://github.com/May-Ethereal/afterglow-web main
```

## Push a local change back up to a fork

```bash
git subtree push -P <path> <fork-url> <branch>
```

Each subtree keeps its own README and build instructions. The app builds from
root as before; the MCP servers and payload build from their own directories.
