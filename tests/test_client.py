# SPDX-License-Identifier: GPL-3.0-only

import struct

import pytest

from ps4debug_ng import protocol as P
from ps4debug_ng.client import Ps4DebugClient, Ps4DebugError, _search_buffer


class FakeSocket:
    """Scripted socket: recv serves from a buffer, sendall is captured."""

    def __init__(self, script: bytes = b""):
        self.script = bytearray(script)
        self.sent = bytearray()

    def recv(self, n):
        if not self.script:
            return b""
        take = min(n, len(self.script))
        out = bytes(self.script[:take])
        del self.script[:take]
        return out

    def sendall(self, data):
        self.sent += data

    def settimeout(self, t):
        pass


def make_client(script: bytes = b"") -> tuple[Ps4DebugClient, FakeSocket]:
    c = Ps4DebugClient("10.0.0.5")
    fake = FakeSocket(script)
    c.sock = fake  # type: ignore[assignment]  (test stub)
    return c, fake


def test_version():
    body = b"1.3"
    script = struct.pack("<I", len(body)) + body
    c, _ = make_client(script)
    assert c.version() == "1.3"


def test_list_processes():
    entries = P.PROC_LIST_ENTRY.pack(b"SceGame\0".ljust(32, b"\0"), 123)
    entries += P.PROC_LIST_ENTRY.pack(b"SceShell\0".ljust(32, b"\0"), 1)
    script = struct.pack("<II", P.CMD_SUCCESS, 2) + entries
    c, _ = make_client(script)
    procs = c.list_processes()
    assert procs == [{"pid": 123, "name": "SceGame"}, {"pid": 1, "name": "SceShell"}]


def test_read_memory_chunked():
    payload = bytes(range(256)) * 0x100  # 64 KiB
    script = struct.pack("<I", P.CMD_SUCCESS) + payload + payload
    c, _ = make_client(script)
    data = c.read_memory(123, 0x1000, 2 * 0x10000)
    assert data == payload + payload


def test_write_memory_framing():
    c, fake = make_client(struct.pack("<II", P.CMD_SUCCESS, P.CMD_SUCCESS))
    c.write_memory(123, 0x4000, b"\x90\x90\xCC")
    sent = bytes(fake.sent)
    magic, cmd, datalen = struct.unpack_from("<III", sent, 0)
    assert magic == P.PACKET_MAGIC
    assert cmd == P.CMD_PROC_WRITE
    assert datalen == P.WRITE_PACKET.size
    pid, addr, length = P.WRITE_PACKET.unpack_from(sent, 12)
    assert (pid, addr, length) == (123, 0x4000, 3)
    assert sent[-3:] == b"\x90\x90\xCC"


def test_error_status_raises():
    c, _ = make_client(struct.pack("<I", P.CMD_DATA_NULL))
    with pytest.raises(Ps4DebugError) as excinfo:
        c.list_processes()
    assert "DATA_NULL" in str(excinfo.value)


def test_disassemble_sentinel_termination():
    entry = P.DISASM_ENTRY.pack(0x400000, 0x400100, 8, 5, P.KIND_CALL, 0, 0, 0, 0x33, 0)
    script = struct.pack("<I", P.CMD_SUCCESS) + entry + P.DISASM_SENTINEL
    c, _ = make_client(script)
    out = c.disassemble(123, 0x400000, 0x40)
    assert len(out) == 1
    assert out[0]["address"] == 0x400000
    assert out[0]["kind"] & P.KIND_CALL


def test_search_buffer_wildcard():
    buf = b"\x48\x8B\x05\x11\x22\x33\x44" * 3
    pattern = bytes([0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC])
    hits = _search_buffer(buf, 0x1000, pattern, wildcard=0xCC)
    assert hits == [0x1000, 0x1007, 0x100E]


def test_scan_aob_regions_skips_unreadable():
    c, _ = make_client()
    reads = []

    def fake_read(pid, address, length):
        reads.append(address)
        return b"\x48\x8B\x05\xAA\xBB\xCC\xDD"

    c.read_memory = fake_read  # type: ignore[method-assign]
    regions = [
        {"start": 0x1000, "end": 0x2000, "prot": 1},   # readable
        {"start": 0x3000, "end": 0x4000, "prot": 0},   # skipped
    ]
    pattern = bytes([0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC])
    hits = c.scan_aob(123, 0, 0x8000, pattern, regions=regions)
    assert hits == [0x1000]
    assert reads == [0x1000]
