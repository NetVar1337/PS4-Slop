# Native static analysis

The static-analysis tools work on ELF artifacts already in the local artifact
store, or on a live module (`pid` + `module`) that is read from process memory.
Live input only reads memory. Every tool is read-only, needs no permission
(`permission: null`) and works offline for artifacts. No external disassembler
or analyzer is needed: decoding uses iced-x86, and ELF, `.eh_frame` and
relocation parsing are written in Rust in this repository.

| Tool | Purpose |
| --- | --- |
| `artifact_functions` | Finds functions and saves the module blocks artifact |
| `artifact_cfg` | Builds the CFG of one function (JSON/DOT), or of the whole module (`mode: "module"`) |
| `artifact_callgraph` | Lists callers and callees, and finds shortest call paths |
| `binary_diff` | Matches functions between two builds |
| `annotation_port` | Moves names and comments from build A to build B |
| `signature_make` | Makes the shortest unique wildcarded AOB signature |
| `orbis_prototypes` | Builds or queries the Orbis prototype database |

Implementation: `src/binimage.rs` (image abstraction), `src/cfg.rs` (discovery,
CFG, call graph), `src/sigmaker.rs`, `src/bindiff.rs`, `src/prototypes.rs` and
`src/binstatic.rs` (tool dispatch). Schemas are in `src/catalog/binstatic.json`.

## Inputs

* `artifact`: an ELF64 image. Standard ELF and PS4 SCE-flavoured ELF are both
  supported: `PT_LOAD` and `PT_SCE_RELRO` segments, section and dynamic symbol
  tables, `DT_JMPREL`/`DT_RELA` and the `DT_SCE_*` tables in
  `PT_SCE_DYNLIBDATA`. NID symbol names (`NID#lib#mod`) are demangled with the
  built-in NID dictionary. SELF and PKG containers must first be decrypted or
  extracted elsewhere. Raw code (for example a memory dump) also works if you
  pass `base_address`.
* `pid` + `module`: every segment of the named module (from `module_list`) is
  read in `memory_bytes` chunks, up to `transfer_bytes` in total. Live modules
  have no ELF headers, so discovery uses call targets and, by default for live
  input, prologues. `module_sha256` is `null` for live input.

Addresses in arguments and results are virtual addresses, which are runtime
addresses for live input. RVAs are relative to `image_base`, the lowest
segment address.

## Function discovery (`artifact_functions`)

Seeds come from these sources, and each can be switched off:

* `eh_frame`: FDE ranges from `.eh_frame`, located through the section header
  or through `PT_GNU_EH_FRAME` → `eh_frame_ptr`. The FDE range is used as the
  function end.
* `symbols`: defined `FUNC`/`IFUNC` symbols in executable segments.
* `linear_sweep`: `call rel32` targets found by a linear sweep of the
  executable segments.
* `call_targets`: direct call targets found while doing recursive descent.
* `prologues` (opt-in for artifacts): `push rbp; mov rbp, rsp` on a 16-byte
  boundary after padding.
* Also the ELF entry point. A function whose first instruction is
  `jmp [rip+GOT]` is named after its import and marked `import_thunk`.

Seeds that come only from the sweep or prologue sources are dropped if they
fall inside an FDE or symbol-bounded function. Work is bounded by
`max_functions` (default 50 000), `max_instructions` per function (default
20 000) and 4 M decoded instructions in total. The `truncated` flag and
`notes` say when a bound was hit.

### Blocks artifact (`ps4wb-blocks-v1`)

Both `artifact_functions` (unless `save_blocks: false`) and `artifact_cfg`
with `mode: "module"` save this artifact:

```json
{"format":"ps4wb-blocks-v1","module":"<artifact path|module name>|null",
 "module_sha256":"<sha256 of the artifact>|null","image_base":"0x...",
 "blocks":[{"start":"0x<rva>","size":N}],
 "functions":[{"start":"0x<rva>","end":"0x<rva>","name":"...|null"}]}
```

Blocks are deduplicated by start address and sorted.

## CFG (`artifact_cfg`)

The CFG is built by recursive descent. Block terminators are `conditional`,
`jump`, `switch`, `indirect_jump`, `return`, `trap` (int3/ud2/hlt/int),
`tail_call` and `fallthrough`. If a block ends early because decoding failed,
or because the instruction cap was reached, its terminator is
`invalid_or_unmapped` or `truncated`.

A direct jump counts as a tail call if it goes to another known function start
or leaves the function's FDE/symbol range.

Jump tables are recovered on a best-effort basis for two patterns:

* Clang's relative table:
  `lea B,[rip+T]; movsxd R,[B+I*4]; add R,B; jmp R`
* Absolute `jmp [B+I*8]` / `jmp [T+I*8]` tables

Each recovered table records `bounded_by`. `cmp` means the bound came from a
preceding `cmp reg, imm`. `heuristic` means entries were read until one did
not point into executable memory, with a cap of 256. Indirect jumps that are
not recovered are counted in `unresolved_indirect_jumps`. `format: "dot"` or
`"both"` adds Graphviz output.

## Call graph (`artifact_callgraph`)

The call graph includes:

* direct calls
* tail calls
* calls through import thunks
* `call [rip+GOT]` calls, resolved through `R_X86_64_JUMP_SLOT`/`GLOB_DAT`
  relocations to import names

`to_address` or `to_name` (a function or import name) runs a breadth-first
search from `address`. It is bounded by `max_depth` (≤16) and visits at most
200 000 nodes. It returns up to `max_paths` shortest paths. Indirect calls are
not followed.

## Binary diff (`binary_diff`)

For every function, the diff computes:

* a masked byte hash: rel32 branch targets, RIP-relative displacements and
  absolute in-image addresses are zeroed
* a mnemonic-sequence hash
* the CFG shape: blocks, edges and calls
* constants and referenced strings
* direct callees

Matching runs in passes. Each pass pairs only keys that are unique on both
sides:

| Pass | Confidence |
| --- | --- |
| `symbol` | 1.0 |
| `exact_bytes` | 1.0 |
| `mnemonics` | 0.9 |
| `constants_strings` | 0.8 |
| `cfg_shape` (≥3 blocks) | 0.7 |

After these passes, `callgraph` propagation pairs the unmatched callees and
callers of matched pairs, using mnemonic-trigram similarity. Its confidence is
between 0.4 and 0.7.

The `ps4wb-bindiff-v1` artifact holds:

* both modules (name, sha256, image_base)
* `summary`
* every match: `a`/`b` RVAs, method, confidence, `identical`, `similarity`
* `unmatched_a`/`unmatched_b`
* the full function lists

`changed` means matched but not `identical`.

## Annotation porting (`annotation_port`)

Accepted source artifacts:

* `annotation_save` evidence. Its `module_sha256` must equal module A's
  SHA-256 unless `allow_hash_mismatch` is set.
* `debug_label_save` exports. These need `label_base`, the runtime base of
  module A.
* Earlier `ps4wb-ported-annotations-v1` sets, so ports can be chained
  1.00 → 1.01 → 1.02.
* Plain `{"0x<rva>": "name"}` JSON.

How an item is mapped:

* At a function start: it moves with the function match.
* Inside an identical function: it keeps the same offset.
* Inside a changed function: this needs `artifact_a`/`artifact_b`. An LCS
  alignment of the two mnemonic sequences (≤4000 instructions) maps the
  instruction, at confidence × 0.8.

Items in data, or in unmatched or unaligned code, are listed under `unported`
with a reason.

The output is a new `ps4wb-ported-annotations-v1` artifact whose
`module_sha256` is module B's. With `runtime_base_b`, the tool also writes a
`{"version":1,"labels":[...]}` document for `debug_label_load`. Source
artifacts are never changed.

## Signatures (`signature_make`)

Instructions are decoded from the target onward. Using iced-x86 constant
offsets, these bytes are wildcarded:

* rel32 branch/call displacements
* RIP-relative displacements
* 32/64-bit values that are addresses inside the image (only when the image
  base is ≥ 0x10000)
* with `wildcard_operands`, every 32/64-bit displacement and immediate

The pattern grows one instruction at a time until it matches only once in the
executable segments. Growth stops at the end of the code path (ret, jmp, trap)
rather than running into padding. A binary search then trims the pattern to
the shortest unique prefix (not shorter than `min_length`). The final pattern
is checked again with the shared `pattern_scan` engine.

The output uses `pattern_scan`/`memory_search` syntax (`48 8B ?? ??`).

`via_reference` (`auto` | `never` | `only`) adds a fallback. The tool finds
rel32 call/jmp and RIP-relative references to the target, makes a unique
signature at the reference site, and returns the resolve formula
`target = match + len + int32_le(match + operand_offset)`, checked against
the real bytes.

## Prototypes (`orbis_prototypes`)

Sources, highest precedence first. Merging is keyed by NID:

1. `dictionary`: a user JSON artifact. It can be a database, a list of
   `{name, declaration}` or prototype objects, or `{name: "declaration;"}`.
   Entries get `"source":"user"`.
2. `headers`: header artifacts.
3. `include_dir`: a host directory. Without it, `$OO_PS4_TOOLCHAIN/include`
   is used, the same variable `sdk_status` reports, unless `use_sdk: false`.
   The scan is recursive and read-only: `*.h`/`*.hpp`/`*.hh`, ≤8192 files,
   ≤2 MiB each, ≤128 MiB in total. `source` is the header path.
4. Built-ins (`include_builtin`, default true). These are ISO C libc
   declarations plus `int sceKernelUsleep(unsigned int)`, marked
   `"source":"builtin"`.

The declaration scanner handles:

* comments and preprocessor lines (with continuations)
* `extern "C"` and namespace blocks
* `__attribute__`, `__declspec`, `asm` and `[[...]]`
* common qualifier macros, and `*_API`/`*_EXPORT`-style macros
* pointers, `const`, arrays, variadics and function-pointer parameters

It skips typedefs, inline bodies, initialised variables and macro
invocations. Parameters without a name get `"name": null`; names are never
invented. NIDs are computed with `nid::encode_nid`.

Database format:

```json
{"format":"ps4wb-prototypes-v1","prototypes":[{"name":"...","nid":"...","library":null,
 "declaration":"...;","return":"...","params":[{"name":"...|null","type":"..."}],
 "source":"<header path>|builtin|user"}]}
```

Actions:

* `build` saves the database.
* `lookup` takes `names` or `nids`.
* `imports` lists an ELF's undefined symbols with their matched prototypes.

`library` is `null` unless a user dictionary supplies it, because headers do
not record which library exports a function.

## Limitations

* No data-flow analysis. Indirect calls and virtual dispatch are not resolved,
  and jump-table bounds are heuristic.
* Functions reached only through indirect calls are missing unless an FDE,
  symbol or prologue covers them.
* Instructions that overlap, or jumps into the middle of an instruction, are
  decoded at both addresses, so the blocks may overlap.
* Diff confidences are fixed per method and are not calibrated
  probabilities. Each pass pairs only keys that are unique on both sides, so
  duplicated small functions stay unmatched.
* The header scanner is not a C preprocessor. Declarations hidden behind
  macros that expand to declarations are missed.
