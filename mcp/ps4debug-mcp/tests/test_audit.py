# SPDX-License-Identifier: GPL-3.0-only

import json

from ps4debug_ng.audit import AuditLog


def test_audit_log_writes_jsonl(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("ps4_read_memory", {"pid": 123, "address": "0x4000"}, "16 bytes")
    log.record("ps4_write_memory", {"pid": 123}, "ok")
    lines = path.read_text().strip().split("\n")
    assert len(lines) == 2
    entry = json.loads(lines[0])
    assert entry["tool"] == "ps4_read_memory"
    assert entry["args"]["pid"] == 123
    assert entry["result"] == "16 bytes"
    assert "ts" in entry


def test_audit_log_disabled_without_path():
    log = AuditLog(None)
    log.record("x", {}, "ok")  # must not raise
