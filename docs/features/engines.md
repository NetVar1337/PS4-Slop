# Engine & metadata recovery

Five read-only tools (permission `null`) that recover runtime metadata from
offline artifacts or live process memory. Code: `src/engines.rs` (dispatch),
`src/bytesource.rs` (shared byte source), `src/il2cpp.rs`, `src/unreal.rs`,
`src/rtti.rs`, `src/yara.rs`, `src/cryptoscan.rs`; schemas in
`src/catalog/engines.json`.

## Targets and bounds

All tools read through one byte-source abstraction:

| Target | Arguments | Addressing |
|---|---|---|
| Artifact, file mode (`yara_scan`, `crypto_scan`) | `artifact` | file offsets (YARA semantics); an ELF's PT_LOAD VA is added as `va` when it maps the offset |
| Artifact, mapped mode (`rtti_recover`, `il2cpp_dump` binary, `unreal_dump`) | `artifact` (+ `base` for raw dumps) | ELF64: PT_LOAD segments mapped, `R_X86_64_RELATIVE` and defined-symbol `64/GLOB_DAT/JUMP_SLOT` relocations applied (standard `DT_RELA`/`DT_JMPREL` or Orbis `DT_SCE_RELA`/`DT_SCE_JMPREL` in `PT_SCE_DYNLIBDATA`), imports recorded per slot. Non-ELF: raw dump placed at `base`, treated as rwx |
| Live | `pid` + `module` and/or `address`+`length` | VAs; results add `module` + `module_offset` |

* Offline artifacts are capped at 512 MiB (and ELF mappings at 512 MiB total).
* Live reads go through `Debugger::read_memory` (each request ≤ `memory_bytes`).
  Total live bytes are charged to a budget: `max_bytes`, clamped to the
  profile's `transfer_bytes` (default = `transfer_bytes`). Random reads are
  cached in 16 KiB blocks; heuristic probes fetch only the bytes needed.
  Results report `bytes_fetched`, `budget_exhausted` and `read_failures`.
* Large JSON results are written as artifacts; the tool result returns paths,
  counts and a short preview.

## `il2cpp_dump`

Parses Unity `global-metadata.dat` (magic `0xFAB11BAF`, versions 24.0–29).

* Source: `metadata_artifact`, or `pid` (searches readable non-executable maps
  for the magic at 4-byte alignment and validates the header table spans), or
  `pid` + `metadata_address`.
* Layouts are derived per version from Il2CppDumper's `MetadataClass.cs`
  field/version table (type definition 104/100/92/88 bytes for 24.0/24.1/24.2+/27+,
  method definition 56/52/32, etc.). v24 sub-version: `stringLiteralOffset == 264`
  ⇒ 24.2, otherwise image tokens decide 24.0 vs 24.1 (Il2CppDumper rule). Every
  table is size/index-validated and alternative layouts are tried; `version`
  forces a layout.
* Optional binary (`binary_artifact` [+ `binary_base`] or `pid` + `module`):
  * v24.2+: `Il2CppCodeRegistration.codeGenModules` found via the
    `"mscorlib.dll"` → `Il2CppCodeGenModule.moduleName` → module array preceded
    by the image count pointer chain; method VA =
    `module.methodPointers[(token & 0xFFFFFF) - 1]` for the method's image.
    Override: `code_gen_modules`.
  * ≤24.1: global `methodPointers[methodIndex]`, found as a qword equal to the
    method-pointer count followed by a pointer to an executable-pointer array.
    Override: `method_pointers`.
  * Type names (fields, parameters, returns) from
    `Il2CppMetadataRegistration.types` (found where `typeDefinitionsSizesCount`
    and `fieldOffsetsCount` both equal the type count). Override:
    `metadata_registration`. Without it, types print as `type#N`.
* Outputs: `il2cpp-*.json`
  `{"format":"ps4wb-il2cpp-v1","metadata_version","image_base","images","types","methods":[{"rva","va","name","class","namespace","signature","token","image"}],"string_literals","registration","stats","notes"}`
  (`rva` is null when unresolved) and `il2cpp-dump-*.cs` (dump.cs-style text,
  `// RVA:` per method; disable with `include_dump_cs: false`).
* Limits: no generic method instantiation tables, attributes, properties/events
  or field offsets; nested-type names come from the `nestedTypes` table.

## `unreal_dump`

Finds GNames and GObjects, lists names/objects and a best-effort SDK.

* GNames (auto, or `gnames` + `gnames_kind`):
  * `name_pool` (4.23+/UE5 `FNamePool`): a writable-data slot whose previous
    qword looks like `{CurrentBlock, CurrentByteCursor}` and whose block 0
    starts with entries `"None"`, `"ByteProperty"` (header `Len:10 | hash:5 |
    wide:1`). `gnames` = address of `Blocks[0]`.
  * `name_array` (<4.23 `TNameEntryArray`): array (inline or behind a global
    pointer) with consistent `NumElements/NumChunks` at +0x400 and chunk 0
    entries `"None"`, `"ByteProperty"`; the string offset in `FNameEntry` is
    detected (0x10 default) or set via `offsets.name_entry_string`.
* GObjects (auto, or `gobjects` = `FUObjectArray` address):
  `FChunkedFixedUObjectArray` at +0x10 (`offsets.objobjects`) with consistent
  counts, objects 0 and 1 having `InternalIndex` 0 and 1; the older
  `FFixedUObjectArray` is tried too (`version` < 4.20 skips the chunked form).
* Objects: name, class, outer and outer-path (`UObjectBase` 0x10/0x18/0x20).
* SDK (`sdk`, default true): for `Class`/`ScriptStruct`/`BlueprintGeneratedClass`
  objects, super, size and properties (FField chain for 4.25+, UField chain
  before). Defaults per `version` hint (4.25 assumed); every offset can be
  overridden via `offsets`. Best-effort: validate against a known class.
* Outputs: `unreal-*.json` (`format: ps4wb-unreal-v1`, `gnames`, `gobjects`,
  `names`, `objects`, `sdk`, `offsets` used, `heuristics`) and `unreal-sdk-*.txt`.
* Limits: `max_names` (100k), `max_objects` (50k), 200k candidate slots, live
  budget. Case-preserving (editor) name entries and encrypted/obfuscated name
  pools are not supported.

## `rtti_recover`

Itanium C++ ABI RTTI/vtable recovery (PS4 titles use Clang).

1. Mangled class names (`N…E`, `<len><id>`, `St…`) in non-executable data,
   validated by a demangler subset (nested/unscoped names, substitutions,
   template args incl. literals/packs, builtins, cv/pointer/reference, arrays,
   function and member-pointer types, anonymous namespaces; local names `Z…E`
   and expressions are left mangled / skipped).
2. `type_info` = 8-aligned slot pointing at a name, minus 8. The vptr must be an
   import of `__cxxabiv1::__{class,si,vmi}_class_type_info` vtables (by name or
   Orbis NID), an override (`class/si/vmi_typeinfo_vtable`), a mapped pointer
   (live), or a pointer-like value shared by several candidates.
3. Kind: import/override, else structure (si: base pointer is a type_info; vmi:
   flags ≤ 3, 1–64 well-formed base entries), else majority of the vptr cluster.
4. vtables: slots referencing a type_info outside type_info objects with a
   plausible offset-to-top; virtuals = following pointers into executable
   segments (or import slots), up to `max_virtuals`.

Output (`rtti-classes-*.json`), consumed by the analyzer-apply code:

```json
{"format":"ps4wb-classes-v1","image_base":"0x...","classes":[{"name","mangled","typeinfo":"0x<rva>",
 "vtable":"0x<rva>","bases":["Base"],"virtuals":[{"index":0,"target":"0x<rva>"}],
 "typeinfo_kind","kind_evidence","address_point","base_details","secondary_vtables","confidence"}]}
```

RVAs are relative to `image_base` (lowest PT_LOAD VA, raw `base`, or live
module base). `vtable` is the offset-to-top slot of the primary vtable
(`address_point` − 16); virtual-base offsets above it are not included.
Virtual targets outside the image have `target: null` plus `external`
(absolute VA) or `import` (relocation symbol).

## `yara_scan`

YARA subset; rules from `rules` or `rules_artifact` (≤ 1 MiB).

* Strings: text (`\" \\ \n \r \t \xHH`) with `nocase`, `wide`, `ascii`,
  `fullword`, `private`; hex with `??`, `4?`, `?4`, `~XX`, `[n]`, `[n-m]`
  (≤ 65536), `( a | b )`; regex `/…/is` (Rust `regex` syntax over bytes).
* Conditions: `and or not ( )`, `== != < <= > >=`, `+ - * \ %`, `filesize`,
  `$a`, `$a at N`, `$a in (A..B)`, `#a`, `#a in (A..B)`, `@a[i]`, `!a[i]`,
  `all|any|none|N|N% of them|($a, $b*)`, `true/false`, references to earlier
  rules, `private rule`, tags and `meta`.
* Rejected with an error: `import`/`include`, `global`, `for` loops,
  `xor`/`base64`, unbounded jumps `[n-]`, `uintXX()` reads, `entrypoint`,
  `matches`/`contains`, `wide` regexes.
* Live targets need `module` or `address`/`length`; chunks overlap by 4 KiB
  (longer matches across a chunk boundary can be missed). `filesize` is the
  file size or the total selected live bytes; offsets in conditions are
  relative to the target start. Matches are per start offset, ≤ 10,000 per
  string; `max_matches` caps reported matches.

## `crypto_scan`

FindCrypt-style constants, generated from their definitions (not typed in) and
pinned by tests against published values: AES S-box / inverse S-box / Te0–Te3 /
Td0–Td3 / rcon; SHA-1, SHA-224/256, SHA-384/512 initial states and SHA-256/512
K tables; MD5 T table; CRC-32 (reflected and MSB-first) and CRC-32C tables;
DEFLATE length/distance bases and code-length order; ChaCha/Salsa
`"expand 32/16-byte k"`; Blowfish P-array and S-box 0 (π digits via BBP);
PKCS#1 DigestInfo prefixes (SHA-1/256/512), rsaEncryption OID, PEM armor; sparse
"immediates" (SHA-1 K, SHA-256 H, MD5 T[1..4] within a 4 KiB window).

Matches are searched as bytes and as little/big-endian 16/32/64-bit words.
Confidence: `high` full table; `medium` full but short/generic constant or ≥ 50 %
of a table; `low` shorter partial or sparse immediates. Filter with
`min_confidence`; cap with `max_results`.

## `source_dump`

Source-engine runtime metadata: Valve Source and forks such as Respawn's engine
(Titanfall / Apex Legends). Live (`pid`, default module `eboot.bin`) or a mapped
artifact (an `elf_rebuild` / `memory_elf_dump` ELF, or a raw dump with `base`).

Recovered structures:

| Section | Structure | Output |
|---|---|---|
| `client_classes` | `ClientClass` linked list | name, class id, RecvTable name, address |
| `recv_tables` | `RecvTable` / `RecvProp` (nested via the data-table pointer) | prop name, offset, raw type, nested table |
| `datamaps` | `datamap_t` / `typedescription_t` | class, base class, field name, offset, raw type |
| `convars` | `ConCommandBase` linked list | name, help text (flags only when the layout is SDK 2013) |
| `interfaces` | `InterfaceReg` linked list | version name (`VClient018`), create function |

**Nothing about the layout is assumed.** Forks reorder and extend these structs,
and the PS4 builds have not been checked here, so every field offset is
inferred:

1. Classified identifier strings are indexed in the module's non-executable
   ranges (`C*` class names, `DT_*` tables, `m_*` members, cvar-style names,
   `Name###` interfaces), then aligned pointers to them are located.
2. Linked lists: every (name, next) offset pair is scored by how many valid
   links it produces from the anchors; whole chains (including non-anchor
   members such as `quit`) are then walked from their heads.
3. Pointer fields (RecvTable, nested table, base map, help text, create
   function) are chosen by what they point at; integer fields (class id, prop
   and field offsets, types) by value statistics (distinct, aligned, small enum).
4. Arrays (RecvProp, typedescription): stride and name offset are validated
   over whole arrays. Datamap layouts that validate equally when shifted are
   disambiguated by base-map pointers (which point at true struct starts).

`layouts` in the result reports every chosen offset with `confidence`, runner-up
`*_alternatives`, and `layout_matches_sdk2013` (the public Source SDK 2013 64-bit
layout, used only as a label). Pin any offset with `layout` (`cc_*`, `rt_*`,
`rp_*`, `dm_*`, `td_*`, `cv_*`, `if_*`); a pinned offset is used as given, never
replaced by inference. `heuristics` explains each decision.

Outputs: a `ps4wb-source-v1` JSON artifact and a text listing (classes, tables
with nested references, datamaps, convars, interfaces). Offsets in RecvTables
are relative to their own table; nested tables (`baseclass`, `m_Local`, …) are
listed separately rather than flattened.

Limits and caveats:

* Type values are raw: the SDK 2013 `SendPropType` names are shown only as a
  hint in the listing; forks use different enums.
* Live runs read the module's non-executable ranges twice (strings, then
  pointers), plus once more for datamaps, against `max_bytes` (clamped to
  `transfer_bytes`); check `source.budget_exhausted`.
* ConVar flags and default values are only reported for the SDK 2013 layout.
* Verified on synthetic images in the SDK 2013 layout and a reshuffled layout,
  and live through the protocol fixture; **not yet run against a real PS4 game**.
