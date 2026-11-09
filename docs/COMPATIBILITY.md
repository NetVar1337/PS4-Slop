# Compatibility contract

Target profile: **PS4 14.00 with Afterglow**. The console address is deliberately
not duplicated here; use the local profile. Research references checked on
2026-11-06. The tracked profile's installed versions remain null.

## What the checks do and do not establish

The workbench does not contain exploit code, firmware offsets, a debugger binary,
or replacement HEN. It is a PC-side client. It refuses profiles other than
14.00/Afterglow and refuses unknown debugger protocols/brands/platforms. This is
a compatibility boundary, not a claim that every operation is safe on 14.00.

The NG handshake checks protocol `1.3`, NG branding, firmware `1400` decoded as
`14.00`, and platform `4`. It does **not** establish HEN identity, validate kernel
patches, prove the debugger executable hash, or guarantee application stability.
Unknown capability levels are not granted verified-write semantics. Only
capability `1.1` is accepted for process writes in this release.

Read-only debugger commands can run before qualification so that identity and
small test captures can be collected. They still carry target-side crash risk.
Kernel reads require explicit qualification too. Debugger connections are never
automatically re-established after an uncertain command within that tool call.
A later explicit read can reconnect and will repeat the identity handshake.

## Pinned source references

- Afterglow host: `well0nez/afterglow-web`, reference commit
  `688fd1565f36c54aa9aaaa2e9d0ad121968db775`.
  Its README warns that the upstream unpatched `hen.bin` (MD5
  `9aff7544eddef2f8202f72fc633d2be3`) freezes every app launch on 14.00. The
  patched build is pinned as MD5 `6417a84a72f9c7988f0e33b3ae190542` plus SHA-256.
  https://github.com/well0nez/afterglow-web/tree/688fd1565f36c54aa9aaaa2e9d0ad121968db775
- Debugger wire source: `Pharaoh2k/ps4debug-NG`, reference commit
  `8be828fe09f05f9327d7babdf9dcec4c67fbb816`.
  Its README lists 14.00; that is an upstream support claim, not our hardware test.
  https://github.com/Pharaoh2k/ps4debug-NG/tree/8be828fe09f05f9327d7babdf9dcec4c67fbb816
- GoldHEN's original ps4debug README lists firmware only through 12.02. This
  project does not fall back to that payload for 14.00.
  https://github.com/GoldHEN/ps4debug
- GoldHEN documents BinLoader 9090, FTP 2121 and Klog 3232. A configured port does
  not imply its service is enabled.
  https://github.com/GoldHEN/GoldHEN

**Do not confuse reference_commit with installed_commit.** Record the actual
host and payloads you use, even if they differ from these references. Any debugger
with a different layout requires source inspection and client/test updates, not
an offset or protocol guess. This repository does not download payload binaries.

## Local 14.00 preflight

The workbench's `afterglow_verify` checks the checkout's git HEAD, patched
`hen.bin`, `goldhen.bin`, `patchset-1400.bin`, and `cache.appcache` hashes. It
refuses the known unpatched HEN hash. This is local file verification, not proof
of what the console serves or has loaded; it does not remotely attest the PS4.

```powershell
$env:PS4_AFTERGLOW_DIR = "C:/path/to/afterglow-web"
$env:PS4DEBUG_NG_PAYLOAD = "C:/path/to/ps4debug-ng_v1.3.4_release_2026-11-05.bin"
ps4-mcp --profile profiles/ps4-1400.local.json afterglow-verify
ps4-mcp --profile profiles/ps4-1400.local.json debugger-payload-verify
ps4-mcp --profile profiles/ps4-1400.local.json preflight
```

After loading Afterglow and manually loading the separate ps4debug-NG BIN,
`preflight --probe` explicitly checks FTP/Klog reachability and performs the
debugger identity handshake. It never probes the payload port or sends a
payload. Record actual installed commit/HEN identity only after inspecting them;
changing the local profile makes its previous qualification stale.

## Known source/documentation discrepancies

The pinned NG protocol document is insufficient by itself:

1. It describes firmware as BCD. `debugger/source/fw.c` actually returns decoded
   decimal `major * 100 + minor`. This client requires raw uint16 `1400` for 14.00
   and deliberately rejects `0x1400` instead of heuristically guessing.
2. It calls the GP register structure 184 bytes. The source structure in
   `debugger/include/debug.h` is **176 bytes**, and `debug_getregs_handle` in
   `debugger/source/debug.c` sends exactly 176.
3. It calls the FPU/YMM component 512 bytes. The pinned handler sends **832**.
   The asynchronous packet is `48 + 176 + 832 + 128 = 1184` bytes; this client
   parses the GP registers and preserves the full raw event packet.
4. Some protocol-document handler locations use old source filenames. The
   implementation uses the current pinned headers/handlers, not those locations.

Tests cover literal wire bytes, partial reads, EOF, oversized lengths/counts,
both write statuses, callback address byte order and register/event offsets.
These are mock/loopback tests, not hardware certification.

## SDK boundaries

- OpenOrbis provides a homebrew toolchain, not debugger firmware compatibility.
  https://github.com/OpenOrbis/OpenOrbis-PS4-Toolchain
- GoldHEN Plugins SDK provides plugin APIs; a plugin still needs a compatible
  HEN, game version and hooks. No included plugin is declared tested here.
  https://github.com/GoldHEN/GoldHEN_Plugins_SDK
- The PS4 Payload SDK README's published firmware list does not include 14.00
  at the research date. Its ELF loader requirements also differ from BinLoader.
  Its integration here is **build/export only, unqualified for 14.00 execution**.
  https://github.com/ps4-payload-dev/sdk

## Honest compatibility states

- `configured_not_probed`: local configuration only.
- `tcp_reachable_not_protocol_verified`: TCP connect only; never payload-port probing.
- Successful `debugger_info`: expected self-reported wire identity only.
- `hardware_unverified`: missing/stale local user qualification.
- `user_attested_not_guaranteed`: profile matches the user's saved test record.

None means 100% compatible. A guarantee would require control over the exact
hardware, HEN/payload binaries, kernel state, application and every operation;
even that testing cannot eliminate all failure modes.
