# Validation record

**Historical 0.1 record.** Current shared-broker, installed IDA/Ghidra and MCP
validation is in [VALIDATION_02.md](VALIDATION_02.md).

Implementation validation date: **2026-11-05**.
Local environment: Windows, Python **3.15.2**. Minimum declared runtime: 3.11.

## Executed successfully

- `python -m unittest discover -q`: **95 tests passed**.
- `python -m compileall -q ps4_workbench tests`.
- `git diff --check` for tracked changes; Git reports only its normal LF/CRLF notice.
- Built `ps4_debugmcps-0.1.0-py3-none-any.whl` with `pip wheel --no-deps`.
- Installed that wheel into a separate temporary target and ran its CLI with
  Python isolated mode against the absolute profile path.
- Parsed all five supplied JSON example/profile files.
- Default `validate` reports `hardware_unverified` and no probed services.

Tests include exact debugger packet bytes, fragmented responses, EOF/errors,
source-correct firmware/register/event layouts, permission denials, stale
qualification, allowlisted single-attempt payload sends, path containment, FTP
limits, expected-byte writes/readback journals, snapshot tools, build recipe
hash/time/log limits, MCP lifecycle/framing, and a real local stdio subprocess.
Loopback integration tests exercise TCP debugger exchanges, Klog, and FTP
login/LIST/RETR/STOR with independent local fixture servers.

The GitHub Actions workflow defines Windows/Linux Python 3.11/3.13 checks.
Those CI jobs have **not** been observed running as part of this local work.

## Not performed or claimed

- **No connection to 192.168.86.25.** No payload, debugger or plugin loaded.
- No console filesystem write, process attachment, kernel access or hardware experiment.
- No identification of the user's actual installed Afterglow commit/HEN/debugger binary.
- No OpenOrbis, GoldHEN plugin or PS4 Payload SDK compilation/runtime test.
- No Ghidra/IDA installation or live analysis integration test. The included
  Java Ghidra script was API-checked against upstream source, not compiled/run.
- No qualification record created for the user's console.
- No claim of 100% firmware/jailbreak compatibility or crash freedom.

See `QUALIFICATION.md` for the separate, explicit user-controlled hardware
testing and evidence process. A local test suite cannot substitute for it.
