# Access finding, crash triage, pointer scanning, struct inference and host scripts

Code: `src/debugger/access.rs` (live debugger side), `src/dynaccess.rs` (MCP
dispatch), `src/pointerscan.rs`, `src/structinfer.rs`, `src/hostscript.rs`
(pure, unit-tested), schemas in `src/catalog/access.json`.

| Tool | Permission | Resumes target |
|---|---|---|
| `debug_find_accesses` | `debug_control` | yes |
| `debug_crash_triage` | `debug_control` | only with `wait=true` |
| `debug_run_script` | `debug_control` | yes |
| `struct_infer` | none (read-only) | no |
| `memory_pointer_scan` | none (read-only) | no |
| `memory_pointer_rescan` | none (read-only) | no |

The control tools write `debug_control_intent` and `debug_control_result` (or
`debug_control_uncertain`) audit records, the same way `debug_run` does. Run loops
are capped at 300 s. They clear every watchpoint and internal breakpoint they set
on every exit path, and they leave the target **halted**: after a timeout they
send `halt` and consume the resulting stop. If cleanup fails, the error says
"cleanup uncertain".

## `debug_find_accesses`

This is Cheat Engine's "find out what writes/accesses this address".

* **Normal mode.** `address` and `length` (1 to 32 bytes) are split exactly into
  naturally aligned 1/2/4/8-byte slots. Only slots that `debug_watchpoint` is not
  already using are taken. If the exact split needs more slots than are free,
  the range is covered with aligned 8-byte slots, and hits that fall outside the
  requested range are dropped and counted in `outside_range_hits`.
* **Struct mode.** Pass `struct_span` (8 to 0x400 bytes). The span is covered
  with 8-byte slots that rotate across rounds, up to 4 slots × 8 bytes = 32 bytes
  per round. The time budget is split evenly between rounds.
* **Instruction recovery.** Data watchpoints trap *after* the access retires.
  The tool decodes every instruction that starts at `rip-15..rip-1` and ends
  exactly at `rip`. It evaluates each memory operand (iced-x86 `InstructionInfo`)
  with the live post-access registers plus fs/gs bases, and keeps the operands
  that overlap the watched slots. The longest decode wins, because shorter
  decodes are usually tails of it. Confidence values:
  * `exact`: one candidate.
  * `ambiguous`: several candidates; the rest are listed in `alternatives`.
  * `plausible`: the instruction overwrote its own base/index register, so the
    address cannot be re-evaluated.
  * `unknown`: nothing decodes, e.g. after `call [mem]`. The fired slot (`dr6`)
    is reported instead.
* **Samples.** Each sample has the registers, `old` (from a shadow copy of the
  watched bytes) and `new` (read live after the hit).
* **Artifact** (`access-log-*.json`):
  `{"format":"ps4wb-access-v1","base":"0x…","length":N,"span":N|null,"pid":…,
  "accesses":[{"instruction","location","disasm","address","offset","size",
  "kind":"read|write","count","confidence","samples","alternatives"}],
  "maps":[[start,end,prot,name]…]}`. `maps` lets `struct_infer` classify
  pointer values offline.
* **Stopping early.** A non-SIGTRAP signal (`unexpected_stop`) or a software
  breakpoint (`foreign_breakpoint`) ends the run with the target halted at that
  stop.

## `struct_infer`

Inputs:

* `access_artifacts`: rebased to `address`, or to the first log's base.
* Optional `snapshot_artifacts`: aligned through their sidecar
  `metadata.address`; their `metadata.maps` are also used.
* Optional `pid`: one read-only live read of the object.

Inference rules:

* **Size.** Field size is the most frequent operand size.
* **Floating point.** SSE scalar single/double instructions (`movss`, `addsd`,
  `cvtss2sd`, …, plus their VEX forms) give `float`/`double`. Packed single gives
  `float[4]`. `cvtsi2ss`/`cvtsi2sd` give integers.
* **Pointers.** If the values point into mapped memory, the type is `void*`.
  Pointers into executable memory count as code pointers. At offset 0, a pointer
  into read-only module data gives `void**` (vtable-like). `call`/`jmp [slot]`
  gives a code pointer.
* **Integers.** 0/1 bytes give `bool`. `movsx` gives signed widths, and so do
  values near `0xffffxxxx`.
* **Arrays.** One instruction touching three or more offsets at a stride equal
  to the element size gives `T[n]`.
* **Overlaps.** Overlapping accesses keep the field with more hits and note the
  overlap.

Output (`struct-*.json`), the exact format the analyzer consumes:
`{"format":"ps4wb-struct-v1","name","size","fields":[{"offset","size","name":"field_0x10","type","confidence","evidence":[…]}],"c_declaration":"struct X { … };"}`.
The C declaration includes explicit `_pad_0x…` members.

## `debug_crash_triage`

* **Which stop.** With `wait=false`, the tool analyzes the latest stop event
  (optionally filtered by `thread_id`). With `wait=true`, it resumes and waits
  for a stop whose FreeBSD wait status is not `SIGTRAP`. SIGTRAP stops are
  resumed past, up to `max_events`.
* **Report contents:**
  * signal name and decoded status
  * `trapno`, error code and decoded page-fault bits
  * registers
  * the faulting instruction (faults trap *before* retiring, so `rip` is the
    faulting instruction and registers are pre-fault)
  * each evaluated memory operand with its mapping and r/w/x flags, plus
    module+offset
  * `debug_stack` frames
  * bounded memory captures around rsp and the operands (`capture_bytes` ≤ 4096)
* **Classifications**, ranked by confidence:
  * `null_pointer_dereference`, `wild_read`/`wild_write`,
    `non_canonical_address`, `write_to_read_only`, `read_protected`
  * `execute_null_pointer`, `execute_unmapped`, `execute_non_executable`,
    `rip_outside_modules`
  * `stack_overflow` (an access just below the stack mapping or in the guard
    page), `stack_pointer_corrupt`
  * `int3_breakpoint`, `ud2_trap`, `abort`, `illegal_instruction`,
    `divide_error`, `bus_error`
  * `segv_unexplained`, `no_fault`
* **After the fault.** The target is never resumed; the full report is saved as
  `crash-report-*.json`.

## `memory_pointer_scan` / `memory_pointer_rescan`

* **Snapshot.** Writable, non-executable maps are captured, module data segments
  first and then heaps (`include_heap`). Capture is chunked by
  `limits.memory_bytes` and bounded by `budget_bytes` (default
  `limits.transfer_bytes`) and 150 s.
* **Index.** Every 8-byte aligned qword whose value points into a readable
  mapping goes into a sorted `(value, location)` index.
* **Search.** Breadth-first search runs backward from the target. Each level
  looks for values in `[t - max_offset, t]`. A location inside a named module
  image becomes a static root (`module+offset`); any other location becomes a
  target for the next level. Each address is expanded only once, at most 200k
  nodes are explored, and `max_depth` ≤ 6, `max_offset` ≤ 0x4000,
  `max_results` ≤ 10000.
* **Path meaning.** `[module+off] -> +o1 -> +o2` reads `[[module+off]+o1]+o2`:
  every offset except the last is dereferenced.
* **Artifact** (`ps4wb-pointers-v1`): target, module bases and `paths`, each with
  `base`, `module`, `module_offset`, `offsets` and `text`.
* **Rescan.** This resolves each saved path against the *current* module bases,
  by name, and against live memory. Pages are cached and the reads are bounded.
  It keeps the paths that reach `target_address` (for example the object's new
  address after a restart), reports `wrong_target` and `unresolved` counts, and
  saves the survivors as a new artifact.

## `debug_run_script`

Breakpoints come as `{address, name?}`. `address` can be a number, a label, or
an expression such as `eboot.bin + 0x1234`. The script must define
`fn on_stop(ctx)`. Its return value decides what happens next:

* `"continue"`, `false` or `()`: continue.
* `"stop"` or `true`: stop.
* Anything else, or any error: stop, with the error reported.

The `ctx` API is read-only:

* **Registers and memory.** `ctx.reg(name)`,
  `ctx.read_u8/u16/u32/i32/u64/f32/f64(addr)`, `ctx.read_bytes(addr, n ≤ 4096)`,
  `ctx.read_cstring(addr, max ≤ 4096)`.
* **Hit metadata.** `ctx.bp_name`, `ctx.bp_address`, `ctx.hits` (per
  breakpoint), `ctx.total_hits`, `ctx.thread_id`, `ctx.rip`, `ctx.location`.
* **State.** A persistent map in `ctx.state`. Write through the chain
  (`ctx.state.n += 1`) or use `ctx.get(k)` / `ctx.set(k, v)`.
* **Logging.** `log(msg)`, `ctx.log(msg)` and `print`, all captured. `hex(n)`
  formats a number.

Sandbox:

* Rhai is built with `no_module`, and `eval` is disabled.
* There are no filesystem, network or process functions, and no memory or
  register writes.
* `print`/`debug` are redirected into the log, never to stdout (the MCP
  transport).
* Limits: max operations per hit (default 1M), call depth 32, expression depth
  64/32, strings 64 KiB, arrays 4096, maps 1024. The per-hit wall time
  (`per_hit_ms`, default 250) is enforced through `on_progress`. Each hit may
  read up to 256 times and 64 KiB in total. Logs are capped at 2000 lines of up
  to 512 characters.
* Memory reads go through a provider that exists only while `on_stop` runs, so
  a `ctx` kept in state cannot read later.

Top-level statements run once at load time. Internal breakpoints are cleared on
exit, and the full log is saved as `script-log-*.json`.

## Limitations

* The recovered access instruction comes from back-decoding. Instructions that
  overwrite their own address registers (`mov rax, [rax]`, string ops,
  push/pop) are only `plausible`. A trap right after a branch through memory
  cannot be attributed.
* All-stop model: the other threads' accesses that happen during a round are
  serialized by the server. Hits are attributed by the event's thread.
* `dr6` is sticky on some kernels. It is used only as a fallback when decoding
  fails.
* The pointer scan uses positive offsets only. Paths through regions skipped
  because of the budget are missed (`snapshot.truncated`).
* Struct types are heuristics; check the `confidence` and `evidence` fields.
