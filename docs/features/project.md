# Project database, recipes and analyzer application

All three features are local-only: none of them talks to the console by itself.

## Per-game project index

Tools (permission `null`): `project_open`, `project_record`, `project_query`, `project_summary`.

Storage is plain files under the artifact directory, with no SQLite or C dependency:

```
<artifact_directory>/project-index/
  active.json                 {"id": "<current project>"}
  <project-id>/project.json   identity: title_id, name, app_version, content_id, tags
  <project-id>/records.jsonl  one record per line (append-only, capped at 64 MiB)
```

- `project_open`: give it `title_id` (and optionally `app_version`) or `name` to create or select a
  project. The id comes from those values, e.g. `CUSA12345` + `01.02` gives `CUSA12345-v01_02`.
  Use `project` to pick an existing id. With no arguments it lists the projects and shows which
  one is active.
- `project_record` accepts `artifacts`, `modules` (name/sha256/base/size), `notes`, `findings`,
  `questions`, `resolve_questions` (+ `resolution`) and `tags`.
  - For each artifact it reads the provenance sidecar and stores kind, sha256, size, tool, module,
    module_sha256, pid and address.
  - The same artifact path is only recorded once.
  - If `tags` is the only argument, the tags go on the project itself.
- `project_query` filters records by `type`, `kind`, `tool`, `tag`, `module`, `module_sha256`,
  `text`, `since` and `until` (ISO-8601 strings). It returns pages of at most 100 records with
  `next_offset`. Newest records come first unless you pass `order: "oldest"`.
- `project_summary` lists the modules and their hashes, then groups records into dumps, traces,
  coverage and annotations. It also returns findings, open questions, tag counts, artifact-kind
  counts and total bytes.

### Automatic recording

`crate::project::auto_record(store, tool, args, result)` searches a tool result for artifact
provenance objects (objects with a `path` and a 64-hex `sha256`). It records each new one in the
active project, along with call context such as pid, module and address. It does nothing when:

- no project is active,
- the tool is a `project_*` or `recipe_*` tool,
- the tool is a lookup (`artifact_list`, `artifact_info`, `artifact_read`, `artifact_bundle`), or
- the artifact is already recorded.

Hook: in `ToolRegistry::call`, right after `let result = crate::config::json_safe(...)?;`:

```rust
let _ = crate::project::auto_record(&self.workbench.store, name, &args, &result);
```

## Recipes

Tools: `recipe_list` lists the built-in recipes and whether each step's tool is available.
`recipe_run` runs a recipe. Pick it with **exactly one** of:

- `recipe`: a built-in recipe name
- `recipe_artifact`: a JSON file in the artifact directory
- `definition`: an inline recipe

Optional arguments: `inputs`, `dry_run`, `max_steps` (at most 32).

```json
{"format": "ps4wb-recipe-v1", "name": "my_recipe", "description": "...",
 "inputs": {"pid": {"type": "integer", "required": true}, "module": {"type": "string", "default": "eboot.bin"}},
 "steps": [{"tool": "memory_elf_dump", "arguments": {"pid": "${pid}", "module": "${module}"}},
           {"tool": "elf_rebuild", "arguments": {"artifact": "${steps.0.@artifact}"}}]}
```

### References

| Reference | Value |
| --- | --- |
| `${name}` or `${inputs.name}` | A recipe input |
| `${steps.N.a.b.0}` | A path into the result of step N (object keys and array indices) |
| `${steps.N.@artifact}` | The first artifact path in the result of step N |

- If a string is exactly one `${...}`, the value keeps its JSON type.
- If that reference points to an optional input that wasn't given, the argument is dropped.
- A reference embedded inside a longer string is converted to text.

### Policy

- Every step goes through `ToolRegistry::call`, so schema checks, local permissions and
  qualification apply exactly as for a direct call. A disabled tool fails its step.
- A recipe cannot call `recipe_*` tools, so recipes cannot nest.
- Execution stops at the first error. The result includes a summary for each step, the artifacts
  produced and the failure.
- A full run log is saved as a `recipe-run` artifact, and the run is written to the audit log.
- Through the shared broker, a recipe that contains any `CONTROL_TOOLS` step is refused unless the
  caller holds the debug lease.

### Built-in recipes

| Recipe | Steps |
| --- | --- |
| `dump_and_rebuild` | `memory_elf_dump` → `elf_rebuild` → `artifact_functions` |
| `static_triage` | `artifact_functions`, `rtti_recover`, `crypto_scan`, `orbis_prototypes` |
| `update_port` | `binary_diff` → `annotation_port` |
| `crash_capture` | `debug_crash_triage` → `process_core_dump` |
| `coverage_compare` | `debug_coverage` → `coverage_diff` |

`recipes::PLANNED_TOOLS` lists step tools that other feature areas haven't added yet. A unit test
checks that every built-in step names either a cataloged tool (with existing argument names) or a
planned tool. Delete the list once all of those tools are in the catalog.

## Analyzer application (`analysis_apply_*`, broker)

These tools change only the local analyzer database, never the console.

Common arguments:

- `target`: `ida`, `ghidra`, `binja` or `iaito`
- `artifact`: path of the JSON artifact, read with a 16 MiB limit
- `static_base`
- `dry_run`
- `allow_hash_mismatch`

How the broker handles a call:

1. It reads and validates the artifact. Invalid items are dropped and counted.
2. It rebases each RVA. With `static_base`, items carry an absolute `address`. Without it, items
   carry `rva` and the agent adds its own image base.
3. If the artifact has a `module_sha256` and it differs from the agent's registered input hash, the
   broker refuses unless `allow_hash_mismatch` is true.
4. It sends batches to the agent: up to 200 prototypes, 500 symbols or 2000 blocks per job.

| Tool | Artifact | Agent op |
| --- | --- | --- |
| `analysis_apply_prototypes` | `ps4wb-prototypes-v1` (declaration, or return+params) | `apply_prototypes` |
| `analysis_apply_struct` | `ps4wb-struct-v1` | `apply_struct` |
| `analysis_apply_coverage` | `ps4wb-coverage-v1` (`clear`, `color`, `comment`, `min_hits`, `max_blocks`) | `apply_coverage` |
| `analysis_apply_classes` | `ps4wb-classes-v1` → `vtable_for_X`/`typeinfo_for_X` labels, `X::vfN` for unnamed virtuals | `apply_symbols` |
| `analysis_apply_symbols` | `{rva: name}` map, or `symbols`/`annotations`/`ported`/`labels` arrays with `rva`/`new_rva`; inline `symbols` also accepted | `apply_symbols` |

### Validation

- Declarations must be a single function declaration: no `; { } # " ' \` or backtick, at most
  1024 characters.
- Names are reduced to the broker's rename character set.
- Struct fields must not overlap and must fit inside the struct size.

### Agent side

The shared logic lives in `ps4_workbench/adapters/base.py` (`ApplyMixin`). Each backend implements
these primitives: `image_base`, `find_function`, `set_prototype`, `name_at`, `set_name`,
`set_comment`, `define_struct` and `color_block`.

- Existing user-defined names are kept unless `overwrite` is set.
- A virtual function is named `X::vfN` only while it still has a default name.
- `clear` removes the coverage colour. It removes a comment only if that comment starts with
  `PS4 coverage hits=`.
- If a backend lacks a feature, it is reported in `unsupported`. If nothing was applied, the job
  fails with an error.

| Backend | Prototypes | Structs | Coverage colour | Names/comments |
| --- | --- | --- | --- | --- |
| IDA | `idc.SetType` | `idc.parse_decls` (artifact C, typed, then untyped fallback) | `idc.set_color` per head (BGR) | `ida_name` / `ida_bytes` |
| Ghidra (Python + Java) | `FunctionSignatureParser` + `ApplyFunctionSignatureCmd` | `StructureDataType` from the field layout (built-in types by size) | `ColorizingService`. Python needs `tool=`; Java uses `setBackgroundColor`. Unsupported headless | symbol table / EOL comments |
| Binary Ninja | `parse_type_string` + `set_user_type` | `parse_types_from_string` + `define_user_type` | `set_user_highlight` on the block (falls back to the instruction) | yes |
| iaito / r2 | `afs` (strict character whitelist) | `"td struct ..."` built from the untyped layout only | **unsupported** (use `comment=true`) | `afn`/`f`, `CCu base64:` |
