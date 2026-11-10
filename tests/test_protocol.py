# SPDX-License-Identifier: GPL-3.0-only

import struct

from ps4debug_ng import protocol as P


def test_reg64_roundtrip():
    regs = {f: i + 1 for i, f in enumerate(P.REG64_FIELDS)}
    regs.update({"trapno": 7, "fs": 8, "gs": 9, "err": 10, "es": 11, "ds": 12})
    regs.update({f: 100 + i for i, f in enumerate(P.REG64_TRAIL)})
    buf = P.pack_reg64(regs)
    assert len(buf) == P.REG64_SIZE  # 176 (debug.c:768), not the 184 PROTOCOL.md claims
    parsed = P.parse_reg64(buf)
    for k, v in regs.items():
        assert parsed[k] == v, k


def test_fw_version_str():
    assert P.fw_version_str(500) == "5.00"   # 0x1F4, per payload README
    assert P.fw_version_str(1402) == "14.02"


def test_ip_roundtrip():
    assert P.u32_to_ip(P.ip_to_u32("192.168.1.10")) == "192.168.1.10"


def test_parse_interrupt_packet():
    buf = bytearray(P.DEBUG_INTERRUPT_PACKET_SIZE)
    struct.pack_into("<II", buf, 0, 1234, 0)
    buf[8:8 + 4] = b"SceGame\0"
    regs = {f: 0x1000 + i for i, f in enumerate(P.REG64_FIELDS)}
    regs["rip"] = 0xDEADBEEF
    buf[48:48 + 184] = P.pack_reg64(regs)
    event = P.parse_interrupt_packet(bytes(buf))
    assert event["lwpid"] == 1234
    assert event["thread_name"] == "SceGame"
    assert event["registers"]["rip"] == 0xDEADBEEF
    assert event["registers"]["rax"] == 0x1000 + 14


def test_disasm_entry_size_and_sentinel():
    assert P.DISASM_ENTRY.size == 32
    assert P.DISASM_SENTINEL == b"\xff" * 32
