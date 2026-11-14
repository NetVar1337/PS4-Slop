# Tests

```powershell
.\build\tests\slop_tests.exe                       # full suite
ctest --test-dir build --output-on-failure         # registered CTest subsets
$env:SLOP_TEST_FILTER = 'ps4'; .\build\tests\slop_tests.exe; Remove-Item Env:SLOP_TEST_FILTER
```

Areas are `src/tests/test_<area>.cpp` against the harness in `harness.hpp`; one executable,
`slop_tests.exe`. `SLOP_TEST_AREA` selects one area, `SLOP_TEST_FILTER` filters by name.

The PS4 tests run the backend and the `ps4_*` MCP flows against a fake ps4debug-NG server
on loopback, including chaos modes (fragmented replies, mid-transfer disconnects) and the
reconnect/slot-restore flows.

Other suites cover infrastructure, memory, disassembly, MCP wire/schemas, analysis,
emulation, the capture store, persistence, RTTI/types, Lua, module dumping,
Hyperion/decompilation, Mach-O/`.ipa`, Xray/patching and Magicmida supervision.

## The fixture

`SlopTarget.exe` (`src/target`) is a real process with known values, a pointer chain, an
AOB fixture set, a region zoo and a mutator, so tests (and the screenshots) can attach to
something deterministic. Its console commands (`tick`, `auto <hz>`, `set <name> <val>`,
`mutate`, `report`, …) let a human drive it by hand.

## End-to-end

| Command | What it does |
| --- | --- |
| `node app/e2e/run.mjs smoke` | API battery: health, attach, read, watchlist, script, detach |
| `node app/e2e/run.mjs screenshots` | regenerates `docs/screenshots/*.png` from the real UI |
| `python tools/mcp_stdio_test.py` | stdio JSON-RPC session against the engine |
| `python tools/mcp_live_test.py` | HTTP battery against a running engine |

CI runs `smoke` in the nightly `tests` lane; screenshots mode is manual (image-compare
flakiness).

## Benchmarks

Weekly CI benchmarks guard the hot paths against regressions — see
[Benchmarks](../benchmarks/README.md).
