# SPDX-License-Identifier: GPL-3.0-only
"""ELF64 (x86-64) parsing from process memory.

On a jailbroken PS4, loaded modules are decrypted in memory, so a module's
ELF image can be parsed live with a handful of targeted reads - no file
access needed. This gives imports, exports, and packer/packing heuristics
for "packed" SELF-style modules (real .self headers are stripped by the
loader; what remains is the plain ELF image plus segment mappings).

All functions take a `read(address, length) -> bytes` callable so they work
against any transport (the debugger client in production, bytes backed by a
dict in tests).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

ELF_MAGIC = b"\x7fELF"
EM_X86_64 = 0x3E
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_DYNSYM = 11
SHN_UNDEF = 0
PF_X = 1
PF_W = 2
PF_R = 4


@dataclass
class Section:
    name: str
    sh_type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    entsize: int


@dataclass
class Symbol:
    name: str
    value: int
    size: int
    shndx: int
    got: int | None = None  # GOT entry VA (imports with a PLT relocation)


@dataclass
class ElfInfo:
    base: int
    entry: int
    elf_type: int
    sections: list[Section] = field(default_factory=list)
    exports: list[Symbol] = field(default_factory=list)
    imports: list[Symbol] = field(default_factory=list)
    is_packed: bool = False
    packer_hints: list[str] = field(default_factory=list)


class ElfError(Exception):
    pass


def _unpack(fmt, buf, off=0):
    return struct.unpack_from(fmt, buf, off)


def parse_elf(read, base: int) -> ElfInfo:
    """Parse the ELF header + section table + dynamic symbols at `base`."""
    ehdr = read(base, 64)
    if ehdr[:4] != ELF_MAGIC:
        raise ElfError(f"no ELF magic at {hex(base)}")
    if ehdr[4] != 2:
        raise ElfError("not a 64-bit ELF")
    (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags,
     e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = \
        _unpack("<HHIQQQIHHHHHH", ehdr, 16)
    if e_machine != EM_X86_64:
        raise ElfError(f"not x86-64 (e_machine={e_machine})")

    info = ElfInfo(base=base, entry=e_entry, elf_type=e_type)

    # Packing heuristics: encrypted/compressed SELF payloads or protected
    # binaries show a missing/implausible section table.
    if e_shoff == 0 or e_shnum == 0:
        info.is_packed = True
        info.packer_hints.append("section header table stripped (e_shnum=0)")
        return info
    if e_shstrndx >= e_shnum:
        info.is_packed = True
        info.packer_hints.append("bad e_shstrndx")
        return info

    shdrs = read(base + e_shoff, e_shentsize * e_shnum)
    raw_sections = []
    for i in range(e_shnum):
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link,
         _info, _align, sh_entsize) = _unpack("<IIQQQQIIQQ", shdrs, i * e_shentsize)
        raw_sections.append((sh_name, sh_type, sh_flags, sh_addr, sh_offset,
                             sh_size, sh_link, sh_entsize))

    shstr_off = raw_sections[e_shstrndx][4]
    shstr = read(base + shstr_off, raw_sections[e_shstrndx][5])

    def cstr(blob: bytes, off: int) -> str:
        end = blob.find(b"\0", off)
        return blob[off:end if end >= 0 else len(blob)].decode("ascii", "replace")

    for (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link,
         sh_entsize) in raw_sections:
        info.sections.append(Section(
            name=cstr(shstr, sh_name) if sh_name < len(shstr) else "",
            sh_type=sh_type, flags=sh_flags, addr=sh_addr, offset=sh_offset,
            size=sh_size, link=sh_link, entsize=sh_entsize))

    # Dynamic symbols: imports (shndx == UND) and exports (defined).
    symtab_idx = next((i for i, s in enumerate(info.sections)
                       if s.sh_type == SHT_DYNSYM), None)
    if symtab_idx is not None:
        symtab = info.sections[symtab_idx]
        strtab = info.sections[symtab.link]
        names = read(base + strtab.offset, strtab.size)
        count = symtab.size // (symtab.entsize or 24)
        symbuf = read(base + symtab.offset, symtab.entsize * count)
        symbols: list[Symbol] = []
        for i in range(count):
            st_name, _info, _other, st_shndx, st_value, st_size = \
                _unpack("<IBBHQQ", symbuf, i * (symtab.entsize or 24))
            name = cstr(names, st_name) if st_name < len(names) else ""
            symbols.append(Symbol(name=name, value=st_value, size=st_size,
                                  shndx=st_shndx))

        # GOT addresses for imports from .rela.plt / .rela.dyn
        got_by_sym: dict[int, int] = {}
        for sec in info.sections:
            if sec.sh_type != SHT_RELA:
                continue
            n = sec.size // (sec.entsize or 24)
            rela = read(base + sec.offset, sec.entsize * n)
            for i in range(n):
                r_offset, r_info, _addend = _unpack("<QQq", rela, i * (sec.entsize or 24))
                sym_idx = r_info >> 32
                if sym_idx < len(symbols):
                    got_by_sym[sym_idx] = r_offset
        for i, sym in enumerate(symbols):
            if not sym.name:
                continue
            if sym.shndx == SHN_UNDEF:
                sym.got = got_by_sym.get(i)
                info.imports.append(sym)
            else:
                info.exports.append(sym)

    # More packing signals: exports look scrambled (high entropy values) or
    # suspiciously few symbols for a large text.
    text = next((s for s in info.sections if s.name == ".text"), None)
    if text and len(info.exports) < 5 and text.size > 0x100000:
        info.is_packed = True
        info.packer_hints.append(f"large .text ({hex(text.size)}) with <5 exports")
    return info


def read_backed(data: dict[int, bytes]):
    """Build a `read(address, length)` callable over {addr: bytes} chunks (tests)."""
    def read(address: int, length: int) -> bytes:
        out = bytearray()
        pos = address
        while len(out) < length:
            match = next(((base, blob) for base, blob in data.items()
                          if base <= pos < base + len(blob)), None)
            if match is None:
                raise ElfError(f"no test memory at {hex(pos)}")
            chunk_base, chunk = match
            take = min(length - len(out), len(chunk) - (pos - chunk_base))
            out += chunk[pos - chunk_base: pos - chunk_base + take]
            pos += take
        return bytes(out)
    return read
