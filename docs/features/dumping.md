# Dumping: ELF rebuild, process dumps, core files, snapshot timeline

All tools in this area are **read-only toward the console**: they only list
maps/modules, read process memory and, when a debugger session is *already*
attached, read thread registers. Nothing writes to the target. Nothing decrypts SELF/PKG
containers or uses keys; the tools only process memory that is already loaded
and decrypted, or ELF artifacts you already have. Every read is chunked by
`limits.memory_bytes`, and every dump has a byte budget (`max_total_bytes`,
defaulting to `limits.transfer_bytes`). When an item fails, the tool records the
failure and continues with the rest of the dump.

| Tool | Purpose |
|------|---------|
| `elf_rebuild` | Turn an ELF artifact (e.g. `memory_elf_dump` output) into an analyzer-friendly ELF; optionally unresolve live GOT values. |
| `process_dump` | Dump every module (ELF reconstruction + rebuild), readable maps and thread state in one call, with a manifest. |
| `process_core_dump` | Write a FreeBSD-style ELF64 core (`ET_CORE`) for gdb/IDA. |
| `memory_snapshot_capture` | Content-addressed, deduplicated memory snapshot (4 KiB SHA-256 chunks). |
| `memory_snapshot_list` | List stored snapshots. |
| `memory_snapshot_timeline` | Diff snapshots in order: changed pages/regions, value changes, change frequency. |

Code: `src/dumping.rs` (tool glue), `src/orbisdyn.rs` (reusable Orbis dynamic
parser), `src/elfrebuild.rs`, `src/coredump.rs`, `src/snapstore.rs`.

## elf_rebuild

```json
{"artifact": "elfdump-<id>.elf", "pid": 77, "module": "eboot.bin",
 "image_base": "0x400000", "restore_relocations": false, "normalize_type": true,
 "nid_dictionary": "nids.txt",
 "export_artifacts": [{"module": "libkernel.sprx", "artifact": "libkernel.elf"}]}
```

The tool copies the input bytes unchanged and appends new data:

* **Dynamic parsing** (`orbisdyn`): `PT_DYNAMIC` plus the Orbis
  `PT_SCE_DYNLIBDATA` (0x61000000) blob. Supported tags include the standard `DT_*`
  tags and `DT_SCE_{STRTAB,STRSZ,SYMTAB,SYMTABSZ,SYMENT,RELA,RELASZ,RELAENT,JMPREL,PLTRELSZ,PLTREL,PLTGOT,HASH,HASHSZ}`,
  `DT_SCE_{MODULE_INFO,NEEDED_MODULE,EXPORT_LIB,IMPORT_LIB,*_ATTR,FINGERPRINT,ORIGINAL_FILENAME}`.
  The tag values and their packing are listed with sources (OpenOrbis create-fself,
  ps4libdoc, psdevwiki, GhidraOrbis) at the top of `src/orbisdyn.rs`. The table
  offsets of `DT_SCE_*` are relative to the start of the dynlib blob.
* **NID demangling**: `.dynsym` names of the form `<nid>#<lib>#<mod>` become real
  names when `src/nid.rs` (or the optional `nid_dictionary`) knows the NID. Otherwise
  the raw NID name is kept. The library and module ids are decoded and resolved
  against `DT_SCE_IMPORT_LIB`/`DT_SCE_NEEDED_MODULE`.
* **Sections**: the tool builds `.text`/`.rodata`/`.data` from `PT_LOAD` flags and
  `.bss` from `memsz > filesz` tails. It also adds every table whose location it
  can derive: `.got.plt` (JMPREL slots, starting at `DT_PLTGOT`), `.got`
  (`GLOB_DAT` slots), `.init_array`/`.fini_array`/`.preinit_array`, and
  `.eh_frame_hdr`/`.eh_frame` (from `PT_GNU_EH_FRAME`, with CIE/FDE records walked
  up to the terminator). The original Orbis tables are kept as `.sce_dynlibdata`
  and `.sce_dynamic`. Allocated sections never overlap.
* **Standard dynamic table**: the tool adds a new read-only `PT_LOAD` after the
  highest segment. It holds `.dynamic`, `.dynstr`, `.dynsym`, `.hash` (a SysV hash
  rebuilt over the new names), `.rela.dyn` and `.rela.plt`. `PT_DYNAMIC` is
  repointed at this table, so IDA, Ghidra and gdb can apply relocations and show
  imports without an Orbis plugin. The program header table is rewritten at the end
  of the file, and `PT_PHDR` becomes `PT_NULL`.
* **`.symtab`**: contains demangled exports, `__imp_<name>` labels on each GOT slot
  and `_entry`.
* `normalize_type` (default true) maps `ET_SCE_EXEC` to `ET_EXEC` and
  `ET_SCE_DYNEXEC`, `ET_SCE_DYNAMIC`, `ET_SCE_RELEXEC` and `ET_SCE_STUBLIB` to `ET_DYN`.
* `image_base` shifts every VA in the headers and tables, plus `RELATIVE` addends,
  so that the lowest `PT_LOAD` starts at the given address.
  Pointer *contents* in data are only rewritten when `restore_relocations` is true.
  In that case, `RELATIVE` slots become `image_base + addend` and
  `JUMP_SLOT`/`GLOB_DAT`/`R_X86_64_64` slots become `0`.
* **GOT unresolution** (with `pid`): the tool reads the live GOT slots, maps each
  value to `module+offset` through the module list, and then to the exporting
  symbol. Status per import: `resolved_export`, `module_only`, `self_lazy_or_local`
  (the slot still points into the module's own PLT stub), `unmapped`, `null`.
  `name_matches_export` cross-checks the import NID against the export. An import
  with an unknown NID is renamed when the export side has a real name.
  Export tables come from `export_artifacts` (already-decrypted module ELFs you
  supply) or from the module's in-memory ELF header. The in-memory path only works
  when the module's dynamic data lies inside a loaded segment.

Output: an `elfrebuild-*.elf` artifact plus an `elfrebuild-report-*.json` with
every import row. The inline JSON summary lists sections created, resolved and
unresolved counts (for NIDs and live bindings), and warnings.

## process_dump

```json
{"pid": 77, "include": ["heap", "<anon>"], "exclude": ["shm"], "protection": "rw",
 "max_total_bytes": 268435456, "max_region_bytes": 67108864,
 "modules": true, "rebuild_modules": true, "regions": true, "threads": true}
```

* **Modules** (`module_list`, i.e. named maps with an executable segment): each one
  goes through `memory_elf_dump`, then `elf_rebuild` with live GOT unresolution.
  When the module has no ELF header at its base, the tool records the item as
  `elf_reconstruction_failed` and dumps its readable map segments raw instead.
* **Regions**: these are readable maps that are not covered by a dumped module.
  `include`/`exclude` match name substrings case-insensitively, and `<anon>` matches
  unnamed maps. `protection` lists the required bits, and read access is always
  required. The tool streams each region into `procregion-*.bin`. Unreadable chunks
  are zero-filled and listed in `failures`, and the item status becomes `partial`.
* **Threads**: captured only if the session is already attached to `pid`. For each
  thread the tool records registers, FPU state, TLS bases and info. The dump never
  attaches by itself.
* **Manifest** (`procdump-*.json`): one entry per item with `kind`, `name`,
  `start`/`end`, `path`, `sha256`, `size`, `status` (`complete`, `partial`,
  `skipped_budget`, `skipped_region_limit`, `failed` or
  `elf_reconstruction_failed`) and the error. Module items carry an
  `address_rebase` block (`artifact`, `pid`, `module`) that you can pass directly to
  `address_rebase`.

## process_core_dump

```json
{"pid": 77, "include": ["eboot", "heap"], "protection": "r", "max_total_bytes": 536870912}
```

The tool writes `coredump-*.core`. The file is ELF64, `ET_CORE`, `EM_X86_64` and
`ELFOSABI_FREEBSD`, with one `PT_NOTE` and one `PT_LOAD` per selected map. Maps
beyond the budget keep `memsz` with `filesz = 0`. The note layouts follow FreeBSD
amd64 (`sys/sys/procfs.h`, `sys/amd64/include/reg.h`, `sys/kern/imgact_elf.c`):

| Note | Size | Content |
|------|------|---------|
| `NT_PRPSINFO` (3) | 120 | `prpsinfo_t` v1: process name (16 chars), path as args, pid |
| `NT_PRSTATUS` (1) | 224 | `prstatus_t` v1: `pr_pid` = LWP id, `pr_reg` = the 176-byte ps4debug GP block (identical to FreeBSD `struct reg`) |
| `NT_FPREGSET` (2) | 512 | first 512 bytes (FXSAVE) of the 832-byte `savefpu_ymm` |
| `NT_THRMISC` (7) | 24 | thread name |
| `NT_X86_XSTATE` (0x202) | 832 | full XSAVE area; XCR0 at offset 464 (gdb `I386_FBSD_XSAVE_XCR0_OFFSET`) |

Thread notes are only written when the session is attached to `pid`. Otherwise the
core is memory-only, and the result `mode` says so. `pr_osreldate` and
`pr_cursig` are written as 0 because ps4debug exposes neither. Usage:
`gdb rebuilt-eboot.elf coredump-<id>.core`.

## Snapshot timeline

* `memory_snapshot_capture {"pid", "ranges":[{"address","length"}] | include/exclude/protection (default rw), "label", "max_total_bytes"}`.
  Ranges are split at absolute 4 KiB boundaries. Each page is stored once as
  `snapshots/chunks/<aa>/<sha256>.bin`, and the snapshot itself is
  `snapshots/manifests/<id>.json`. The result reports `new_chunks`, `reused_chunks`
  and `new_bytes_written`; repeated captures of unchanged memory write nothing but
  the manifest. Pages that fail to read are listed in `failed`. Captures are
  non-atomic, and each one stops after 300 s or when the budget is used up
  (`truncated_*` range status).
* `memory_snapshot_list {"pid", "label", "limit"}` lists snapshots oldest first.
* `memory_snapshot_timeline {"snapshots":[ids in order], "address", "length", ...}`
  reports, for each step, changed, added and removed pages and the changed byte
  regions. For small changes (8 bytes or less) it gives before/after
  `u8`/`u32`/`f32`/`u64` values. Across the whole series it reports a change
  frequency over aligned 4-byte words (`changed_in` N of M transitions, a histogram,
  `changed_every_transition` and the top addresses), plus `value_series` (u32/f32
  per snapshot) for the most frequently changing words. Chunk hashes are verified
  on read.

## Limits and what is untested on hardware

* All tests are offline: they use the ps4debug fixture (`src/debugger.rs`
  `fake`) and synthetic Orbis-style ELFs (`orbisdyn::testelf`). **None of these
  tools has been run against a PS4 yet.**
* The Orbis dynamic layout (tag values, id packing, dynlib-relative offsets) comes
  from community documentation. The parser is tolerant and records warnings, but
  real firmware 14.00 images may differ in details.
* On real consoles, `PT_SCE_DYNLIBDATA` is not a loaded segment, and the module's
  ELF header may not be mapped at its base. A pure memory dump therefore usually
  has **no symbol or relocation tables**. In that case `elf_rebuild` still emits
  sections from the loads and `.eh_frame`, but it cannot name GOT slots unless the
  dynamic data is present in the artifact. Supply an artifact that contains the
  dynamic data, or `export_artifacts` for the exporting modules. Live export
  discovery from process memory works only when a module's dynamic tables are
  inside a loaded segment (homebrew/OpenOrbis builds, the fixture).
* Lazy-bound PLT slots point back into the importing module and are reported as
  `self_lazy_or_local`, not resolved.
* All dumps are non-atomic: the target keeps running unless you halt it yourself.
* The core file has not been loaded in gdb or IDA. Its layout follows the FreeBSD
  sources cited above, and the tests check it structurally.
