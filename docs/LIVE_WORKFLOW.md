# Live IDA + Ghidra + MCP workflow

This implements a **shared control plane**, not two debuggers independently
attaching to the same PS4 callback. One broker owns the NG socket/callback;
native IDA/Ghidra and MCP clients share it. **One client controls execution**;
other clients can inspect memory, static analysis and replayable events.

Your installed applications were inspected and tested locally:

- `C:/Program Files/IDA Professional 9.5`: native Remote GDB plugin is present.
- `C:/Users/Admin/Desktop/Ghidra`: installed version **12.2**, Java 25.
- No `gdb` executable was found in PATH or standard MSYS locations. Ghidra's
  native GDB Debugger UI needs that dependency; the included **Java integration
  does not need GDB, Python, PyGhidra, or a separately installed Ghidra MCP**.

## 1. Start the shared broker

From this repository:

```powershell
ps4-workbench call desktop_status
ps4-workbench broker
```

Startup does not connect to the console. The broker binds only `127.0.0.1:8765`
and creates `profiles/broker-token.local` if absent. It prints the token **path**,
not the secret. Keep that file outside `workspace/`, private, and uncommitted.
On Windows protect its inherited ACL; Unix mode 0600 does not establish a Windows ACL.

Connect your MCP client using `examples/mcp-shared.json`. This starts a stdio
MCP proxy, not another PS4 connection. Use an absolute installed interpreter if
the client cannot honor `cwd`. Keep the example's stable `mcp-primary` identity
if you need to reconnect to its existing control lease after a client restart.

If using a locally qualified profile, use the **same** absolute `--profile`
everywhere, including the broker, proxy, GDB bridge and CLI. A mismatched profile
is rejected; clients bind to the broker's fingerprint so a restarted service
cannot silently switch them to a different console configuration.

Read-only commands through the already-running broker:

```powershell
ps4-workbench remote-call console_status
ps4-workbench remote-call process_list
ps4-workbench remote-call session_state
ps4-workbench remote-call analysis_status
```

The actual console debugger still must be enabled and independently qualified
for 14.00/your HEN. **The broker does not bootstrap or install it.** Firmware,
branding, permissions, binary hashes and payload allowlists remain enforced.
Follow `QUALIFICATION.md` before any attachment, breakpoint or mutation.

## 2. Connect IDA directly

Open the authorized original ELF/module in IDA. Run
`integrations/ida/ps4_connect.py` using File → Script file. It connects the local
broker and registers a read-only IDA analysis agent; it does **not** attach to
the console or start a GDB listener. IDA 9.5's main-thread APIs are used for
database access. Set `PS4_WORKBENCH_ROOT` first if you move this checkout.

Keep the script's `ps4` object alive. In a namespace-isolated IDAPython setup,
instantiate `IDAWorkbench` explicitly in the Python console instead. Stop the
static agent with `ps4.close()` before changing databases or registering another.

The shared MCP now provides:

```json
{"name":"analysis_functions","arguments":{"target":"ida","limit":20}}
{"name":"analysis_decompile","arguments":{"target":"ida","address":"0x400100"}}
{"name":"analysis_xrefs","arguments":{"target":"ida","address":"0x400100","limit":50}}
```

These are **static database addresses**, not assumed PS4 runtime addresses.
Replace examples with addresses actually present in your database. Hex-Rays
must be available for that input architecture; failure is returned explicitly.

For native live debugging, first use your qualified profile and an observed PID:

```powershell
$targetPid = [int](Read-Host 'Observed PS4 process PID')
$callbackIp = Read-Host 'PC IPv4 reachable from the PS4'
ps4-workbench gdb-server --pid $targetPid --listen-address $callbackIp
```

The bridge listens only on PC loopback `127.0.0.1:1234`. It does not attach until
the native debugger requests it. TCP **755** must be reachable from the PS4 to
the chosen PC interface; limit any firewall rule to the console source address.

In IDA's Python console, after loading `ps4_connect.py`:

```python
import ida_dbg
ida_dbg.load_debugger("gdb", True)
ida_dbg.set_remote_debugger("127.0.0.1", "", 1234)
```

Set `target_pid` to your observed PID, then explicitly preview/import its regions:

```python
ps4.sync_debugger_regions(target_pid, apply=False)
ps4.sync_debugger_regions(target_pid, apply=True)
ida_dbg.attach_process(target_pid, -1)
```

This imports the dynamic memory layout into **IDA's manual debugger regions**;
it does not rebase the static database or alter the console. Previous regions
are returned for your records. IDA's generic GDB backend may otherwise show
unknown regions even when direct memory reads work. Breakpoints, register reads,
single-step and detach now use the shared bridge.

GDB register writes, arbitrary memory-write packets, kill/reboot, monitor shell,
reverse execution and mixed per-thread `vCont` actions are intentionally refused.
Use the guarded MCP `memory_write` with expected bytes for deliberate patches.
Unavailable FPU/SIMD registers are marked unavailable, never fabricated as zero.

## 3. Connect Ghidra directly without additional dependencies

Add `integrations/ghidra` to Ghidra's Script Manager directories. Run
**`PS4Workbench.java`** with the intended static program open.

Choose an explicit action and select the broker token file:

- **Serve static-analysis MCP agent**: exposes functions, decompilation and xrefs
  to the shared MCP. The script remains running; cancel it to unregister/stop.
- Session state, process list, live memory peek, threads and registers.
- Attach/detach, halt/resume and step a selected thread, subject to control ownership.
- Extract a remote file to a hashed workbench artifact.
- Send a qualified BIN using an imported manifest and allowlisted digest.
- Refresh a selected **local static-memory shadow**, requiring a matching module
  hash, explicit runtime base, bounds checks and confirmation. This edits only
  the Ghidra program database, not the original input file or PS4 memory.

The Java script uses the same authenticated broker as MCP and IDA. Its interactive
controls identify as `ghidra-console`; static agents use distinct identifiers.
If IDA owns execution, Ghidra remains an observer until that owner detaches.

Static MCP calls use `target: "ghidra"`. The agent only accepts the three
read-only analysis operations; no remote eval, arbitrary Java or Python commands
are exposed. Decompilation has a timeout and a capped text result. Large outputs
become artifact references. Closing the program or canceling the script stops
the agent; job timeout is not represented as successful analysis.

`integrations/ghidra/ps4_connect.py` is an **optional PyGhidra/Python 3** equivalent.
Do not run it in Jython/Python 2. The Java script is the tested, dependency-free
route for this installation.

### Optional native Ghidra Debugger UI

Install/configure a local GDB with x86-64 ELF support and embedded Python, plus
the dependencies required by Ghidra 12.2's shipped GDB trace agent. These are
not installed by this project; `desktop_status` currently reports GDB missing.

In Ghidra's Debugger tool use the shipped **gdb remote** launcher, target type
`remote`, host `127.0.0.1`, port `1234`, and the real local module image. This
talks to this project's GDB Remote bridge, not to the PS4 directly on port 744.
Verify static/dynamic module mappings in Ghidra before applying labels or relying
on static addresses. Generic memory-map XML is not proof of an ELF load bias.

For simultaneous native windows, keep one controlling bridge on 1234 and start
a second observer bridge on 1235 with identical PID/profile/callback arguments
plus `--observer`. Attach/stop the controller first, then connect the observer.
Observer controls are refused; it never resumes or detaches the controller.
Observer refresh is explicit, not a full Ghidra trace/timeline synchronization
plugin. Native Ghidra/GDB UI integration has not been exercised here because
the local GDB dependency is absent.

## 4. Extract files and dump runtime regions

Single file: `ftp_download`. Several selected files: `ftp_extract` with
`paths: ["/data/first", "/data/second"]`. Paths must be real observed files;
these examples are not claims that such files exist.

Extraction produces per-file hashes and a manifest retaining original remote
paths, total bytes and explicit `complete`/`error` fields. It stops on failure
without retrying a partially completed transfer. It does not recursively follow
remote symlinks, parse ambiguous UNIX listings, decrypt SELF files or install PKGs.

Use `memory_peek` for small live views with no artifact churn. Use
`memory_region_dump` for a larger, explicitly selected readable range: it validates
map coverage, reads bounded chunks, preserves partial captures and provenance,
and reports completion. Dumps are **raw memory**, not reconstructed ELF/SELF.
The configured transfer/memory/time limits still apply; captures are non-atomic.

## 5. Payloads and recovery

Use the manifest/import/qualification flow in `QUALIFICATION.md`. Payload sending
is blocked while a debug session is attached. BIN, ELF, PRX and PKG remain distinct;
the workbench does not silently convert them or send ELF to your BinLoader.
Successful TCP transfer is not proof of payload execution.

The shared event pump owns the callback and retains 1024 events with sequence
numbers, session IDs and reception timestamps. Each MCP/client has its own
cursor. Lost events and callback EOF are explicit errors, not fabricated stops.

`session_state` identifies the current controller. A failed attach retains its
lease until its client explicitly calls `session_release`; release does not
repair or guarantee console state. CLI `remote-call` uses stable identity `cli`
by default; supply `--client-id` to deliberately address your existing lease.
Clients sharing the token are one trusted local user, not separate security
principals; identities prevent accidental contention, not malicious impersonation.

Closing a proxy does not detach the broker's active session. Detach explicitly
before ending work. Broker shutdown attempts cleanup, but uncertain state is
never a reason to automatically resend a payload, repeat a write or resume a
target. Inspect the console and saved audit records first.

## 6. Live debugging loop (debug_control permission + qualification required)

Attach with `debug_attach` (`pid`, `listen_address` = the PC's LAN IPv4; the
console calls back on TCP 755). Then, in any order:

- `module_list`, `disassemble` (breakpoint bytes masked, branch targets annotated),
  `debug_eval` (expressions like `[rsp+8]`, `rax == 1`, `eboot.bin+0x1000`),
  `debug_registers` / `debug_registers_fpu` / `debug_registers_dr`.
- `debug_breakpoint` (optional `condition`, `log`, `stop_after`; `debug_breakpoint_list`
  shows hit counts), `debug_watchpoint`.
- `debug_step` (`into`/`over`/`out`), `debug_run` (optional `target_address`,
  `condition`, `max_stops`, `timeout_seconds`), `debug_stack` for a call-stack
  unwind, `debug_registers_set` to patch registers (readback-verified),
  `debug_control` for halt/resume, `debug_events` / `session_events` for stops.
- `debug_detach` when done; payload sending stays blocked while attached.

All-stop semantics: `resume`/`debug_run` continue every thread. After every stop
the live registers are re-read (the pinned server steps past a breakpoint
instruction before reporting, so event registers can be stale). `step over/out`
and run-to-address use a temporary internal breakpoint when a single step cannot
produce the stop; the report says when that happened.

For static work on extracted files (no console needed): `artifact_info` (ELF64
structure / SELF-PKG identification), `artifact_disasm`, `artifact_strings`,
`pattern_scan`, plus the IDA/Ghidra agents above for decompilation and xrefs.

## 7. Connection stability (no server restarts needed)

- Invalid payloads are rejected **before any byte is sent** (container magic,
  size, uniform-fill and text heuristics, manifest hash and allowlist), so the
  BinLoader/PayLoader never receives garbage and does not need a restart.
  Sends are single-attempt, rate-limited and closed with a clean EOF; they are
  never retried automatically.
- FTP: extraction reuses one session (NOOP-revalidated); single-shot transfers
  open a fresh connection and retry idempotent reads up to 3 times; sessions are
  closed with QUIT. `ftp_extract` stops on first failure without retrying partial
  transfers.
- Klog: dropped log streams are re-established (up to 3 reconnects) instead of
  silently truncating the capture.
- Debugger: read-only commands reconnect once after a transient drop; losing an
  attachment is reported explicitly (console state uncertain) rather than
  silently cleared.
- `link_status` (optionally with `probe: true`) reports per-service health,
  consecutive failures and retry counts. Nothing probes in the background.

## Verification boundary

See `VALIDATION.md`. The exact installed IDA native debugger and Ghidra Java
static agent have been exercised against generated/local fixtures. **The PS4 at
192.168.86.25 has not been contacted.** Actual 14.00/Afterglow/HEN/debugger
qualification remains mandatory and is not a 100%-compatibility certification.
