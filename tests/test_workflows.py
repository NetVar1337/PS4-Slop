# SPDX-License-Identifier: GPL-3.0-only

import struct

from ps4debug_ng import elf as elf_mod
from ps4debug_ng import scans, workflows


class MemClient:
    """Fake client backed by {addr: bytes}."""

    def __init__(self, memory: dict[int, bytes]):
        self.memory = memory

    def read_memory(self, pid, address, length):
        out = bytearray()
        pos = address
        while len(out) < length:
            match = next(((b, d) for b, d in self.memory.items()
                          if b <= pos < b + len(d)), None)
            if match is None:
                raise RuntimeError(f"unmapped {hex(pos)}")
            base, blob = match
            take = min(length - len(out), len(blob) - (pos - base))
            out += blob[pos - base: pos - base + take]
            pos += take
        return bytes(out)


def test_pointer_chains_simple():
    # layout: region A (module) holds ptr to 0x4000+0x10; region B (heap) at
    # 0x4000 holds ptr to target 0x9000; chain: [0x2000] -> +0? verify tail.
    mem = {
        0x2000: struct.pack("<Q", 0x4010),          # module ptr -> 0x4010
        0x4000: (b"\0" * 0x10 + struct.pack("<Q", 0x9000)).ljust(0x20, b"\0"),
    }
    regions = [
        {"start": 0x2000, "end": 0x2008, "prot": 1, "name": "eboot.bin"},
        {"start": 0x4000, "end": 0x4020, "prot": 1, "name": ""},
    ]
    client = MemClient(mem)
    chains = workflows.find_pointer_chains(client, 1, 0x9000, regions,
                                           max_depth=2, max_offset=0x100)
    assert chains, "expected at least one chain"
    resolved = [c for c in chains
                if workflows.resolve_chain(client, 1, c["address"], c["offsets"]) == 0x9000]
    assert resolved, f"no chain resolved to target: {chains}"
    # the module-rooted chain (0x2000 -> 0x4010 -> 0x9000) must be flagged stable
    assert any(c["stable"] for c in resolved), resolved


def test_resolve_chain():
    mem = {0x1000: struct.pack("<Q", 0x2000), 0x2000: struct.pack("<Q", 0x3000)}
    client = MemClient(mem)
    # *(0x1000)=0x2000 +0 -> *(0x2000)=0x3000 +0x20
    assert workflows.resolve_chain(client, 1, 0x1000, [0, 0x20]) == 0x3020


def test_snapshot_diff_roundtrip(tmp_path):
    # tmp_path is a pytest-managed per-test temp dir; both snapshot files are
    # created here (no user input reaches the filesystem).
    a = tmp_path / "a.snap"
    b = tmp_path / "b.snap"
    data_a = struct.pack("<QQQ", 1, 0x1000, 64) + b"\xAA" * 64
    data_b = struct.pack("<QQQ", 1, 0x1000, 64) + b"\xAA" * 32 + b"\xBB" * 32
    a.write_bytes(data_a)
    b.write_bytes(data_b)
    diff = workflows.snapshot_diff(a, b)
    assert diff["changed"] == [32, 40, 48, 56]
    assert diff["unchanged_count"] == 4


def test_value_scan():
    mem = {0x1000: struct.pack("<II", 1337, 42)}
    client = MemClient(mem)
    regions = [{"start": 0x1000, "end": 0x1008, "prot": 1}]
    hits = scans.value_scan(client, 1, regions, 1337, "u32")
    assert hits == [0x1000]
    hits = scans.value_scan(client, 1, regions, 42, "u32")
    assert hits == [0x1004]


def test_diff_results():
    out = scans.diff_results([1, 2, 3], [2, 3, 4])
    assert out["stable"] == [2, 3]
    assert out["changed"] == [1]
    assert out["new"] == [4]


def test_list_modules():
    regions = [
        {"start": 0x1000, "end": 0x2000, "prot": 5, "name": "a.bin"},
        {"start": 0x2000, "end": 0x3000, "prot": 5, "name": "a.bin"},
        {"start": 0x4000, "end": 0x5000, "prot": 3, "name": ""},
    ]
    mods = workflows.list_modules(regions)
    assert mods[0]["name"] == "a.bin"
    assert mods[0]["base"] == 0x1000
    assert mods[0]["size"] == 0x2000
    assert mods[1]["name"].startswith("[anonymous:")


def _build_minimal_elf():
    """Craft a tiny ELF64 with a .dynsym of one import + one export."""
    base = 0x400000
    shstr = b"\0.dynsym\0.dynstr\0"
    dynstr = b"\0imported_func\0exported_func\0"
    # dynsym: [0] null, [1] imported (UND), [2] exported (shndx 1)
    dynsym = (b"\0" * 24
              + struct.pack("<IBBHQQ", 1, 0x10, 0, 0, 0, 0)
              + struct.pack("<IBBHQQ", 15, 0x12, 0, 1, 0x1234, 0x56))
    ehdr_rest = struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x1000,
                            0, 0x100, 0, 64, 0, 0, 64, 4, 3)
    ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8 + ehdr_rest
    # section headers at file offset 0x100: null, .dynsym, .dynstr, .shstrtab
    shdrs = b"\0" * 64
    shdrs += struct.pack("<IIQQQQIIQQ", 0, 11, 0, 0, 0x200, len(dynsym), 2, 0, 8, 24)
    shdrs += struct.pack("<IIQQQQIIQQ", 8, 3, 0, 0, 0x300, len(dynstr), 0, 0, 1, 0)
    shdrs += struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, 0x400, len(shstr), 0, 0, 1, 0)
    blob = bytearray(0x500)
    blob[0:64] = ehdr
    blob[0x100:0x100 + len(shdrs)] = shdrs
    blob[0x200:0x200 + len(dynsym)] = dynsym
    blob[0x300:0x300 + len(dynstr)] = dynstr
    blob[0x400:0x400 + len(shstr)] = shstr
    return base, bytes(blob)


def test_parse_elf_imports_exports():
    base, blob = _build_minimal_elf()
    read = elf_mod.read_backed({base: blob})
    info = elf_mod.parse_elf(read, base)
    assert [s.name for s in info.imports] == ["imported_func"]
    assert [(s.name, s.value, s.size) for s in info.exports] == [("exported_func", 0x1234, 0x56)]
    assert not info.is_packed


def test_parse_elf_packed_stripped_sections():
    base, blob = _build_minimal_elf()
    blob = bytearray(blob)
    struct.pack_into("<Q", blob, 40, 0)  # e_shoff = 0 -> stripped
    read = elf_mod.read_backed({base: bytes(blob)})
    info = elf_mod.parse_elf(read, base)
    assert info.is_packed
    assert info.packer_hints
