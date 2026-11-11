# SPDX-License-Identifier: GPL-3.0-only

import json
import time

from ps4debug_ng import actions


class FakeDebugClient:
    """Scripted client for actions-layer tests."""

    def __init__(self):
        self.writes = []
        self.watchpoints = []
        self.events = []
        self.continues = 0

    def write_memory(self, pid, address, data):
        self.writes.append((pid, address, data))

    def set_watchpoint(self, index, address, length, breaktype, enabled=True):
        self.watchpoints.append((index, address, length, breaktype, enabled))

    def continue_(self, stop):
        self.continues += 1
        if self.events:
            self.events.pop(0)

    def wait_event(self, timeout=None):
        return {"lwpid": 7, "status": 0, "thread_name": "t",
                "registers": {"rip": 0x5000 + len(self.watchpoints)}} if self.continues == 1 else None

    def read_memory(self, pid, address, length):
        return b"\x00" * length

    def kernel_write(self, address, data):
        self.writes.append(("kernel", address, data))

    def set_breakpoint(self, index, address, enabled=True):
        pass


def test_find_what_writes():
    c = FakeDebugClient()
    events = actions.find_what_writes(c, 0x9000, 8, 1, max_events=5, timeout=1.0)
    assert len(events) == 1
    assert events[0]["rip"] == 0x5001  # rip offset by watchpoint count in fake
    # watchpoint was disabled afterwards
    assert c.watchpoints[-1][4] is False


def test_freeze_writes_until_stopped():
    c = FakeDebugClient()
    fz = actions.Freeze(c, 1, 0x1000, b"\x90\x90", interval_ms=20)
    fz.start()
    time.sleep(0.12)
    fz.stop()
    assert fz.writes >= 3
    assert all(w[2] == b"\x90\x90" for w in c.writes)


def test_cheat_roundtrip(tmp_path):
    path = tmp_path / "cheat.json"
    pokes = [{"name": "ammo", "pid": 1, "address": "0x1000", "hex": "ff"}]
    chains = [{"name": "hp", "pid": 1, "address": "0x2000",
               "offsets": [0x10, 0x20], "value_hex": "64", "value_type": "u32"}]
    actions.cheat_export(path, pokes, chains, "test")
    doc = actions.cheat_import(path)
    assert doc["pokes"] == pokes
    assert doc["chains"][0]["offsets"] == [0x10, 0x20]


def test_cheat_rejects_foreign_format(tmp_path):
    path = tmp_path / "other.json"
    path.write_text(json.dumps({"format": "someone-else", "version": 1}))
    try:
        actions.cheat_import(path)
        raise AssertionError("should have raised")
    except ValueError as e:
        assert "not a ps4cheat file" in str(e)


def test_replay_audit(tmp_path):
    log = tmp_path / "audit.jsonl"
    entries = [
        {"ts": "t", "tool": "ps4_read_memory", "args": {}, "result": "16 bytes"},
        {"ts": "t", "tool": "ps4_write_memory",
         "args": {"pid": 3, "address": "0x1000", "hex": "90"}, "result": "ok"},
        {"ts": "t", "tool": "ps4_kernel_write",
         "args": {"address": "0xffff", "hex": "cc"}, "result": "ok"},
        {"ts": "t", "tool": "ps4_write_memory",
         "args": {"pid": 3, "address": "0x1000", "hex": "90"}, "result": "ERROR"},
    ]
    log.write_text("\n".join(json.dumps(e) for e in entries))
    c = FakeDebugClient()
    done = actions.replay_audit(c, log)
    assert done == ["ps4_write_memory", "ps4_kernel_write"]
    assert len(c.writes) == 2
    assert c.writes[0] == (3, 0x1000, b"\x90")
    assert c.writes[1] == ("kernel", 0xFFFF, b"\xcc")


def test_replay_audit_tolerates_torn_line(tmp_path):
    log = tmp_path / "audit.jsonl"
    log.write_text('{"tool": "ps4_write_memory", "args": {"pid": 1, "address": "0x1", "hex": "ff"}, "result": "ok"}\n{bad json')
    c = FakeDebugClient()
    done = actions.replay_audit(c, log)
    assert done == ["ps4_write_memory"]
