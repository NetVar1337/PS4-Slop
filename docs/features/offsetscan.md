# Offset scanning and dump integrity

## `offset_scan` (catalog `offsetscan`, read-only)

Verifies offsets against the running target instead of trusting a stale header:

- **Manifest mode** (`offsets`: a `ps4wb-offsets-v1` artifact from
  `project_export_offsets`): each entry's exact verify bytes are compared at
  `image_base + rva` → `verified` / `mismatch` / `read_error` / `no_fingerprint`.
- **Signature mode** (`signatures`: `[{symbol, rva, pattern}]` with `??`
  wildcards): the pattern is checked at its expected RVA. On mismatch and with
  `relocate` (default true), the module's executable maps are searched:
  exactly one hit → `relocated` (with the new address and `new_rva`), none →
  `missing`, several → `ambiguous`.

`module` defaults to `eboot.bin`; `image_base` is optional and otherwise derived
from the process maps. `max_matches` caps the relocation search per signature.

Typical use after a game update: feed the signatures that `signature_make`
proved unique, and let the scanner tell you which offsets survived and where the
others moved, before regenerating a target manifest.

## `module_integrity` (offline, read-only)

Diffs an in-memory ELF dump (`dump`, run `elf_rebuild` first for raw memory
dumps) against the on-disk ELF (`disk`) and reports changed executable-text
ranges with expected (file) vs actual (memory) bytes, plus unmapped bytes.
Use it to see exactly which regions were hooked or patched at runtime.
