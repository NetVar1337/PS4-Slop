# Encrypted PS4 SELF images

A retail PS4 `eboot.bin` (and most `.sprx`) is a **SELF**: a 0x20-byte header,
a table of 0x20-byte segment entries, then the embedded ELF header and program
headers. Each loadable program header's bytes live in a *blocked* SELF segment
(`flags & 0x800`) whose id (`flags >> 20`) is the program header index.

Retail builds flag those segments **encrypted** (`flags & 0x2`) and signed
(`flags & 0x4`). The decryption keys live in the console's secure module and
never leave it, so an encrypted SELF cannot be decrypted offline — not by this
tool, not by any host-side tool.

## What the engine does

`disasm.load` / `disasm.load_self` parse the SELF segment table before
touching the ELF. When any blocked segment carries the encrypted flag the load
fails immediately with an actionable error naming the segment, its program
header index, its file offset and its stored size, for example:

```
encrypted SELF: 3 of 5 data segments are encrypted (first: SELF segment 1 =
program header 1 at file offset 0x2000, 4096 bytes stored). Retail
eboot.bin/.sprx files are decrypted only on the console; ... call
target.ps4_dump_module {name, load:true} ... and load that file instead
```

Fake-signed / unencrypted SELFs (homebrew, devkit builds, and dumps that were
re-signed) load normally: the loader rebuilds a plain ELF from the segments,
inflating deflated ones.

## Getting a decrypted image

The decrypted bytes exist **in the console's memory** once the title is
running. Two supported sources:

### 1. Dump from live memory (recommended)

Requires a PS4/PS5 in a jailbreakable firmware running ps4debug-NG (or a
compatible payload) with the game launched.

```
target.ps4_connect  { "host": "192.168.1.50" }
target.ps4_auto     { "host": "192.168.1.50" }      # connect + attach
target.ps4_modules                                   # find eboot.bin's base
target.ps4_dump_module {
  "name": "eboot.bin",
  "path": "C:/dumps/eboot.bin",
  "load": true                                       # rebuild ELF + load it
}
```

`target.ps4_dump_module` reads the module's whole mapped range over the wire
and, with `load: true`, rebuilds an ELF64 with one `PT_LOAD` per console
segment at its runtime VA. The result loads straight into the disassembler with
addresses matching the live console, so breakpoints and static VAs agree.
`complete: false` in the reply means some pages were unreadable and were
zero-filled; re-dump after the title finishes loading if that matters.

### 2. Extract from an fpkg

An fpkg (`*.pkg`) built with a decrypted `eboot.bin` — or any tool that
produces the plain ELF (e.g. a homebrew dumper, or `pkg` tooling that decrypts
with console-side keys) — gives you a file you can load directly:

```
disasm.load_self {
  "path": "C:/games/CUSA00000/eboot.bin",   # the original SELF, for reference
  "decrypted_dump": "C:/dumps/eboot.elf"    # the decrypted image to analyze
}
```

or simply `disasm.load { "path": "C:/dumps/eboot.elf", "relocate": false }`
for a memory dump (dumps already carry the loader's relocations; pass
`relocate: false` so the engine does not apply them twice).

## Why not decrypt here

The SELF encryption is AES with per-title keys derived inside the console's
secure processor. The host never sees them. Any "decrypt" option in a PC tool
is either (a) operating on a fake-signed image that was never encrypted, or
(b) bundled console keys, which this project does not ship. The error path and
`docs/encrypted-self.md` exist so the workflow is explicit instead of silently
producing noise from ciphertext.

## Limits

- `disasm.load_self` inspects the SELF header/segment table only; the analysis
  always runs on the decrypted image.
- A memory dump's VAs match the console's runtime base. Keep the dump's base
  when loading (`base` omitted or the console base) so annotations and
  breakpoints line up.
- Encrypted `.sprx` modules follow the same flow: dump the module by name with
  `target.ps4_dump_module`.
