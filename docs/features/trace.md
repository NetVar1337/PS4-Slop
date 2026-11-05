# Tracing and coverage

Five tools built on the pinned ps4debug-NG software-breakpoint model. Four of them
resume the target, so they are `debug_control` tools: they need a qualified
debugger, an active `debug_attach`, and they write audit records
(`debug_control_intent` and `debug_control_result`/`_uncertain`). `coverage_diff`
works offline.

| Tool | Purpose | Output |
|---|---|---|
| `debug_trace_imports` | ltrace-like API trace of one module's PLT imports | JSONL artifact + summary |
| `debug_trace_syscalls` | trace libkernel syscall wrappers | JSONL artifact + summary |
| `debug_trace_function` | trace calls to chosen functions | JSONL artifact + summary |
| `debug_coverage` | one-shot breakpoint coverage | `ps4wb-coverage-v1` JSON + drcov v2 |
| `coverage_diff` | compare two coverage artifacts | lists only-A / only-B / both |

Code: `src/debugger/trace.rs` (engine), `src/tracekit.rs` (parsers, formats,
syscall names), `src/dyntrace.rs` (MCP dispatch), `src/catalog/trace.json` (schemas).

## Workflow

1. `debug_attach`. The target stops on attach; leave it halted.
2. Plan first. `dry_run: true` on imports, syscalls and coverage resolves the probes
   without arming or resuming anything.
3. Run the tool with a short `timeout_seconds` and a narrow `filter`, `names` or
   `targets` list.
4. Read the result. `first_events` and `summary.counts` come back inline. The full
   trace is the JSONL artifact (one event per line); use `artifact_read` to page
   through it.

Every run ends with the target halted and every internal breakpoint cleared. This
holds on timeout (the tool issues `halt`), at `max_events`, on a foreign stop, and
on errors. The result includes a `cleanup` report. If cleanup is incomplete, the
tool returns an error that names the saved artifact and states that the console is
in an uncertain state.

## Examples

```jsonc
// What does the game call in libSceSaveData?
{"name":"debug_trace_imports","arguments":{"filter":"SaveData","timeout_seconds":20,"capture_returns":true}}

// Which files are opened?
{"name":"debug_trace_syscalls","arguments":{"names":["open"],"string_bytes":128,"max_events":200}}

// Arguments and return values of one function
{"name":"debug_trace_function","arguments":{"targets":["eboot.bin+0x1a2b30"],"capture_returns":true,"backtrace_frames":8}}

// Coverage while pressing X, compared with an idle baseline
{"name":"debug_coverage","arguments":{"blocks_artifact":"blocks-....json","timeout_seconds":60}}
{"name":"coverage_diff","arguments":{"a":"coverage-pressX.json","b":"coverage-idle.json"}}
```

## How hits are read

The pinned server steps the thread over the instruction under a breakpoint
**before** it reports the hit. So the live registers show the state after the
probed instruction, and the event's register block may be stale (taken before the
step). For every hit, the tool decodes the original instruction at the probe:

- Registers that the instruction does not write are read live (`source: "live"`).
- Registers that it writes are taken from the event snapshot
  (`source: "event_snapshot"`).
- `rsp` at entry is recovered from the live `rsp` plus the instruction's stack
  effect (`push`, `sub rsp, imm`, and so on). If that effect cannot be derived,
  the event snapshot is used.
- The caller is the value at `[rsp_at_entry]`, accepted only when it lands in an
  executable mapping.

How each tool places its probes:

- **Imports.** A PLT stub (`jmp [rip+GOT]`) writes only `rip`, so its arguments
  and `[rsp]` are exact. The default `probe_at: "plt"` catches calls made by this
  module only. `"target"` breakpoints the bound function itself instead, which
  catches calls from every module.
- **Syscalls.** The probe is the wrapper's `mov rax, N`. At that point `rcx` still
  holds argument 4 (`mov r10, rcx` has not run), and this is reported as `r10`. A
  bare `syscall` site (`include_unrecognized`) has already executed when the hit
  is reported, so all of its values come from the event snapshot.
- **Return capture.** A temporary breakpoint is set on the return address. A
  return hit is matched to its call by thread and by `rsp == rsp_at_entry + 8`;
  if no `rsp` match exists, the most recent call on that thread is used.
  `host_elapsed_ms` includes debugger round trips. It is not the function's real
  run time.

## Import resolution

The tool tries these sources in order:

1. **`elf_artifact`**: a decrypted ELF of the module. Tables are located through
   `PT_DYNAMIC` and `PT_SCE_DYNLIBDATA` file offsets.
2. **The in-memory ELF header at the module base.** `PT_DYNAMIC` is read from the
   process. Orbis `DT_SCE_*` table values are offsets into `PT_SCE_DYNLIBDATA`,
   which is often not mapped in user memory. When it is missing, the tool adds a
   note and moves on.
3. **Unnamed lazy PLT stubs** (`FF 25 .. 68 .. E9`). These are labelled
   `plt_<index>-><target module+offset>`.

`R_X86_64_JUMP_SLOT` relocations give the GOT slots. Symbols named `NID#lib#mod`
are demangled through the built-in NID corpus (`src/nid.rs`). The parser is
intentionally small and tolerant: anything missing becomes a note, not an error.

## Syscall names

- FreeBSD 9 native numbers from `sys/kern/syscalls.master` (releng/9.x).
  Compatibility and obsolete slots are omitted.
- Orbis `dynlib_*` syscalls 589–595, which are used by the public payload SDKs and
  listed on psdevwiki.
- Everything else prints as `sys_<n>`.

Orbis can repurpose slots, so treat the names as hints. To supply your own names,
pass `dictionary_artifact`: a JSON object `{"<number>": "name"}` with decimal or
`0x` keys. Its entries override the built-in names.

## Coverage

### Input blocks

The blocks artifact uses the agreed format:

```json
{"format":"ps4wb-blocks-v1","module":"eboot.bin","module_sha256":null,"image_base":"0x0",
 "blocks":[{"start":"0x1a2b30","size":12}],"functions":[{"start":"0x1a2b30","end":"0x1a2c00","name":"f"}]}
```

- RVAs are relative to `image_base` and are rebased onto the live module base.
- Blocks outside the module's executable maps are dropped and reported.
- If `blocks` is empty, function starts are used instead (`function_entry`
  granularity).

Without a blocks artifact, function entries are derived live. The tool uses
`.eh_frame` FDEs, found through the in-memory ELF's `PT_GNU_EH_FRAME`. If those are
unavailable, it falls back to `push rbp; mov rbp, rsp` prologues on 16-byte
boundaries.

### How it runs

Breakpoints are armed in rotating batches:

1. Arm up to `max_breakpoints` blocks.
2. Resume.
3. On each hit, mark the block covered, disarm its slot, and arm the next unarmed
   block.

The run stops when every block has been armed and hit, or on timeout,
`max_events`, or a foreign stop. Blocks that were never armed count as uncovered.
`run.never_armed` and `stop_reason` show this.

### Outputs

- **`ps4wb-coverage-v1`**: `{"format","module","module_sha256","image_base","runtime_base","granularity","blocks":[{"rva","size","hits"}],"run"}`.
  `hits` is 0 or 1 because each breakpoint fires only once.
- **drcov version 2**: `DRCOV VERSION: 2`, a module table with
  `Columns: id, base, end, entry, checksum, timestamp, path`, and a binary BB table
  of `{u32 start, u16 size, u16 id}` entries. BB starts are module offsets. Load
  it in Lighthouse or Cartographer against the same module. At `function_entry`
  granularity the BB size is 1, so whole functions are not painted.

## Limits

- **Slot budget.** The server has 30 software breakpoint slots. One tool uses at
  most 28 at once, and only slots that are free. User breakpoints are never
  touched, and an address that already has a breakpoint is skipped. Imports,
  syscalls and functions need one slot per probe, plus one per outstanding return
  capture. If more probes are selected than the budget allows, the tool refuses
  and asks for a narrower filter. Only coverage rotates through slots.
- **All-stop overhead.** Every hit halts all threads and costs several network
  round trips (event, register read, optional memory reads, resume). Hot functions
  slow the game a lot, and timing-sensitive code may behave differently while
  traced. Keep filters narrow and timeouts short.
- **Bounds.** `timeout_seconds` is at most 300 and `max_events` at most 10 000
  (coverage: at most 200 000 hits). An internal stop cap of 4× `max_events`
  bounds return and filtered stops. Planning scans are capped by
  `scan_limit_bytes`, and string reads at 256 bytes within one readable map and
  page.
- **Memory safety.** The tools only read inside known readable maps, because a
  rejected read drops the debugger session. They never write process memory,
  except for what the breakpoint command itself writes.
- **Events.** Trace stops go to the artifact, not to `debug_events`. Only the
  halt stop and any unprocessed queued stops are left in `debug_events`.
- **Foreign stops** end the trace and leave the target halted. These include a
  user breakpoint, a fault, or any stop that is not one of the trace's own
  breakpoints.
- **Untested on hardware.** All of this was validated only against the in-process
  protocol fixture (`debugger::fake`). Behaviour on firmware 14.00 is unverified,
  including:
  - whether the in-memory ELF header and `PT_SCE_DYNLIBDATA` are mapped;
  - the exact libkernel wrapper shapes;
  - the staleness of event registers.

  Check the `notes` and `*_source` fields before trusting a result.
