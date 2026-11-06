# Qualifying your actual setup

There is no automatic 100%-compatibility check. This procedure records what
**you actually tested** and explicitly permits matching advanced operations.
The default configuration remains unqualified and does not execute payloads.

## 1. Record the real versions

Copy `profiles/ps4-1400.json` to `profiles/ps4-1400.local.json` before editing.
Use `--profile profiles/ps4-1400.local.json` for every following command.
Do not change firmware to make an incompatible payload pass a check.

Record, without guessing:

- Console model and firmware as observed in system settings.
- Actual deployed Afterglow source commit in `jailbreak.installed_commit`.
- Actual HEN variant/build in `jailbreak.hen_build`.
- For debugger operations, exact `debugger.expected_brand` from the inspected
  payload's branding and `debugger.payload_sha256` from the actual local binary.
- SDK/compiler revisions and application title/version/module hashes in evidence.

Before opening apps or enabling debugger actions, run the local checks in
`COMPATIBILITY.md`: `afterglow-verify`, `debugger-payload-verify`, then
`preflight`. The 14.00 patched `hen.bin` hash is a safety gate because the known
upstream unpatched build freezes app launches. The manifest check also catches
stale browser-cache entries. These checks verify local files only; still confirm
the served version and loaded debugger manually.

The HEN build string is a manually recorded identity; the workbench does not
remotely attest it. Identical branding cannot prove identical debugger binaries.

Use `ps4-workbench hash PATH_TO_FILE` to hash an actual binary. Keep
the binary and source/build provenance. Do not load an arbitrary debugger just
because its filename says 14.00. Read `COMPATIBILITY.md` first.

## 2. Collect read-only evidence first

With services you deliberately enabled, explicitly run `debugger_info`, then
process list/info/maps. Use a disposable homebrew test process and start with a
tiny, known mapped region. Capture Klog and record all failures too. Do not use
example PID/address values without observing them on your console.

Prepare your own evidence file using `examples/hardware-test-evidence.md` as a
checklist. That template itself is **not completed test evidence**.

Advanced actions need prior human-controlled hardware testing and inspection
with your existing tools. Qualification intentionally has no bypass for a first
untested payload. It is not a way to turn an unknown payload into a safe one.

## 3. Enable only permissions you tested

Available permission names:

- `ftp_upload`: remote writes under configured upload roots; readback verified.
- `payload_execute`: one BIN send; requires separately tested SHA-256 allowlist.
- `process_write`: expected-byte checks, backups, write and independent readback.
- `debug_control`: attach, breakpoints, watchpoints and process/thread controls.
- `kernel_read`: separately qualified, high-risk kernel inspection.
- `kernel_write`: requires `kernel_read` too for compare/readback; highest risk.
- `build`: locally reviewed recipe execution; requires recipe hash allowlist.

Set the relevant flags to true in your **local profile**, then record a local
qualification. The command does not contact the console or perform tests:

```powershell
ps4-workbench --profile profiles/ps4-1400.local.json qualify `
  --evidence C:/research/my-completed-hardware-tests.md `
  --attest I_TESTED_THIS_EXACT_CONFIGURATION `
  --approve ftp_upload `
  --afterglow-directory C:/research/afterglow-web
```

Advanced approvals (`payload_execute`, `process_write`, `debug_control`, kernel
access, or `build`) hash and record the verified Afterglow checkout (patched HEN,
GoldHEN, 14.00 patchset and cache manifest). Debugger permissions additionally require
`debugger-payload-verify` to pass; pass `--debugger-payload` or set
`PS4DEBUG_NG_PAYLOAD` when qualifying.

For payload execution, additionally supply `--approve payload_execute` and one
or more `--payload-sha256 ACTUAL_TESTED_BIN_HASH` options. For builds, supply
`--approve build` and `--build-recipe-sha256 ACTUAL_REVIEWED_RECIPE_HASH`.
For debugger mutations or kernel reads, pin exact branding and binary hash first.

Qualification saves a copy of the evidence and binds the entire profile hash,
permissions and allowlists. It is **user attestation and risk acceptance**, not
proof automatically established by this application. The local files are not
cryptographically signed or protected against someone who controls your PC.

Changing any profile field makes the record stale. Re-test as appropriate,
re-run with `--replace`, and include the **complete** desired approval/allowlist
set; replacement does not implicitly preserve old approvals. Restart your MCP
server after changing profile or qualification configuration.

Toolsets (`static`, `read-only`, `debug`, `full`) are an additional exposure
filter, not an authorization bypass. Even `full` still requires the profile
permission and a matching qualification record for each mutating action. Use
`read-only` unless you specifically need the capabilities of another set.

## 4. Payload manifests and transport separation

1. Import the exact BIN using `ingest` and note the returned relative artifact path/hash.
2. Complete `examples/payload-manifest.json` with that path/hash and actual
   firmware, installed host commit, HEN build, loader and payload source commit.
3. Import that completed manifest with `ingest` too. The `manifest` tool argument
   is its imported artifact path, not an arbitrary PC filesystem path.
4. Run `payload_inspect` first; inspection never executes.
5. Only after explicit testing/qualification, call `payload_execute` with the
   manifest artifact path and exact allowlisted BIN digest.

An ELF executable, PRX plugin or PKG application is not a GoldHEN BinLoader BIN.
This release deliberately refuses those through `payload_execute`; use the
appropriate independently qualified application/plugin/ELF deployment flow.
It does not install PKGs or switch HEN variants.

Successful `sendall` is not an execution acknowledgement. A connection reset may
occur after some bytes reached the console. **Do not automatically retry** a
failed transfer; inspect console state and recover manually first.

## 5. Debug sessions

Use one persistent owner. Shared mode (`LIVE_WORKFLOW.md`) is recommended when
combining IDA, Ghidra and MCP. Independent standalone CLI invocations do not
retain their sessions; `remote-call --client-id NAME` can deliberately share a
stable identity with an already-running broker:

1. `debug_attach` needs a known disposable process PID and your PC's explicit
   console-reachable local IPv4 interface (`listen_address`).
2. The listener binds that interface on TCP **755** before attachment. Configure
   your firewall deliberately for traffic from the console only. Do not use a
   public interface or disable the firewall wholesale.
3. The debugger opens an outbound callback from the PS4. Unexpected peers are
   rejected; there is no callback authentication beyond source-IP checking.
4. Poll `debug_events` while using breakpoints or stepping. The adapter reads the
   event stream when polled; it does not maintain an infinite background buffer.
5. Explicitly `debug_detach` when done. CLI calls and server EOF attempt cleanup.

A debug error can leave the target halted or otherwise uncertain. Cleanup is
best-effort, not guaranteed. Closing a client socket is not proof of a successful
detach. Inspect the console and audit log before starting another session.

## 6. Writes and recovery

`memory_write`/`kernel_write` require `hex_data` and same-length `expected_hex`.
They preserve the original and intended bytes before sending, then save and
verify readback. This is **not an atomic compare-and-swap**: a running target can
change between checks. A partial write is possible even on an error response.

There is no automatic rollback. Restoring a backup is itself a new, explicitly
qualified write with current expected bytes and can fail too. Never restore stale
addresses after a process restart or ASLR change. Experiment artifacts include
profile and runtime provenance; use it before attempting recovery.

Keep logs/captures out of source control and back up important console data
before experiments. Stop when a console crash or uncertain operation occurs.
