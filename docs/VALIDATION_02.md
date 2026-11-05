# Validation record: 0.2

Implementation validation date: **2026-11-05**, workbench **0.2.0**.
Local environment: Windows, Python **3.15.2**, Java **25**. Minimum declared
workbench runtime: Python 3.11. No console was contacted.

## Automated checks

- `python -m unittest discover -q`: **144 tests passed**.
- Includes the original wire/safety suite plus authenticated loopback broker,
  independent event cursors, single control ownership, profile binding, shared
  MCP subprocess, RSP framing/XML/registers/controls, analysis worker/job queues,
  multi-file extraction limits and partial raw-region dumps.
- Python compilation, configuration JSON checks and tracked whitespace checks pass.
- The final 0.2 wheel was built and installed into an isolated temporary target.
  Isolated-mode imports of broker, RSP and both adapters plus CLI validation pass.

The GitHub Actions workflow defines Windows/Linux Python 3.11/3.13 checks. Those
CI jobs have not been observed running as part of this local work.

## Installed application tests actually executed

Applications:

- IDA Professional 9.5, `C:/Program Files/IDA Professional 9.5`.
- Ghidra 12.2, `C:/Users/Admin/Desktop/Ghidra`.

Tests generate a tiny x86-64 ELF in a temporary directory. Its SHA-256 is
`b733b207426c0d410dc63706fc924fb379c763ec25708edae9e73091f6a91c5f`.
It is analyzed, never executed. Existing user databases are not opened or
overwritten. Normal application licensing is handled by the installed app;
tests do not inspect licensing files or report license credentials.

1. `python tests/manual/run_installed_apps.py`: passed in both applications.
   IDA's actual adapter enumerated the fixture function, retrieved input SHA-256
   and decompiled it as `return 42`. Ghidra's actual native decompiler produced
   `return 0x2a` for the same input and hash.
2. `python tests/manual/run_ida_dynamic.py`: passed. Actual IDA 9.5 Remote GDB
   attached through this project's real RSP socket and authenticated broker to a
   loopback fixture backend. Verified PC `0x400100`, bytes `b82a000000c3`, native
   selected-thread stepping, software-breakpoint insertion/removal and manual
   debugger memory-region import. The target backend is mocked: this validates
   the native client/bridge path, not a PS4 instruction executing.
3. `python tests/manual/run_ghidra_agent.py`: passed.
   Actual path: MCP tools/call → authenticated broker → installed Ghidra 12.2
   `PS4Workbench.java` agent → real Ghidra decompiler. The returned static
   function text contains the fixture's return value. The final Java source,
   including explicit HTTP-client cleanup, was compiled and exercised.

Manual tests require the installed applications and suitable licenses. They are
not part of portable CI and operate only on generated temporary fixtures.

## What remains unverified

- No connection to 192.168.86.25. No payload, debugger or plugin loaded.
- No console file write, attachment, kernel access or hardware experiment.
- No identification of the user's installed Afterglow commit/HEN/debugger binary.
- No OpenOrbis, GoldHEN plugin or PS4 Payload SDK compilation/runtime test.
- No native Ghidra GDB Debugger UI test: no local GDB executable was found.
  The dependency-free Java MCP agent is tested separately as described above.
- The optional PyGhidra adapter and annotation-only `ApplyWorkbenchAnnotation.java`
  have not been runtime-tested; these differ from the tested Java agent.
- No user-console qualification record created and no 100%-compatibility claim.

See `QUALIFICATION.md` for hardware evidence/approvals, and `LIVE_WORKFLOW.md`
for connection commands and remaining native-GDB dependency setup. Local fixture
success is not hardware certification.
