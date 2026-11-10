# SPDX-License-Identifier: GPL-3.0-only
"""Watchpoint-driven workflows, freeze loop, cheat files, and audit replay.

find_what_writes answers the classic RE question ("what code writes this
address?") with a hardware watchpoint. freeze_value implements the
Cheat Engine-style poke loop. Cheat files are a documented JSON format
(ps4cheat v1). replay_audit re-applies the mutating actions from an MCP
audit log (session record/replay).
"""

from __future__ import annotations

import contextlib
import json
import threading
import time
from pathlib import Path
from typing import Protocol

from .client import Ps4DebugError


class RuntimeClient(Protocol):
    """Minimal client surface used here (tests fake this)."""

    def write_memory(self, pid: int, address: int, data: bytes) -> None: ...
    def set_watchpoint(self, index: int, address: int, length: int,
                       breaktype: int, enabled: bool = True) -> None: ...
    def continue_(self, stop: int) -> None: ...
    def wait_event(self, timeout: float | None = None) -> dict | None: ...
    def read_memory(self, pid: int, address: int, length: int) -> bytes: ...
    def kernel_write(self, address: int, data: bytes) -> None: ...
    def set_breakpoint(self, index: int, address: int,
                       enabled: bool = True) -> None: ...

# ------------------------------------------------------------- what writes

def find_what_writes(client: RuntimeClient, address: int, length: int = 8,
                     breaktype: int = 1, max_events: int = 20,
                     timeout: float = 10.0) -> list[dict]:
    """Set a hardware watchpoint on [address, +length) and capture each hit:
    {rip, registers, lwpid}. breaktype: 1=write, 3=read/write, 0=exec.

    Requires an attached session; leaves the process stopped after the last
    hit so the caller can inspect (call continue_ to resume).
    """
    events: list[dict] = []
    client.set_watchpoint(0, address, length, breaktype)
    try:
        client.continue_(0)
        for i in range(max_events):
            event = client.wait_event(timeout if i == 0 else 2.0)
            if event is None:
                break
            regs = event["registers"]
            events.append({"hit": i, "lwpid": event["lwpid"], "rip": regs["rip"],
                           "registers": regs})
            if i < max_events - 1:
                client.continue_(0)
    finally:
        with contextlib.suppress(Ps4DebugError, OSError, ConnectionError):
            client.set_watchpoint(0, address, length, breaktype, enabled=False)
    return events


# ------------------------------------------------------------------ freeze

class Freeze:
    """Background poke loop: re-write `data` to `address` every `interval_ms`
    until stopped. Mirror of Cheat Engine's freeze."""

    def __init__(self, client: RuntimeClient, pid: int, address: int,
                 data: bytes, interval_ms: int = 250):
        self.client = client
        self.pid = pid
        self.address = address
        self.data = data
        self.interval_ms = interval_ms
        self.writes = 0
        self.errors: list[str] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name=f"freeze-{hex(address)}")

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2.0)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.client.write_memory(self.pid, self.address, self.data)
                self.writes += 1
            except (Ps4DebugError, OSError, ConnectionError) as e:
                self.errors.append(str(e))
                if len(self.errors) > 5:
                    break
            self._stop.wait(self.interval_ms / 1000.0)


# -------------------------------------------------------------- cheat files

CHEAT_FORMAT = "ps4cheat"
CHEAT_VERSION = 1


def cheat_export(path: str | Path, pokes: list[dict], chains: list[dict],
                 note: str = "") -> Path:
    """Write a ps4cheat v1 file.

    pokes: [{name, pid, address, hex}] - one-shot writes.
    chains: [{name, pid, address, offsets, value_hex, value_type}] - pointer
    chains (CE convention, resolves via workflows.resolve_chain) with the
    frozen value.
    """
    doc = {
        "format": CHEAT_FORMAT,
        "version": CHEAT_VERSION,
        "note": note,
        "pokes": pokes,
        "chains": chains,
    }
    path = Path(path)
    path.write_text(json.dumps(doc, indent=2))
    return path


def cheat_import(path: str | Path) -> dict:
    """Parse a ps4cheat v1 file; raises ValueError on unknown formats."""
    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"cannot read cheat file {path}: {e}") from e
    if doc.get("format") != CHEAT_FORMAT:
        raise ValueError(f"not a {CHEAT_FORMAT} file: {doc.get('format')!r}")
    if doc.get("version") != CHEAT_VERSION:
        raise ValueError(f"unsupported version: {doc.get('version')!r}")
    return doc


def cheat_apply_pokes(client: RuntimeClient, pokes: list[dict]) -> list[str]:
    """Apply one-shot pokes from a cheat file. Returns per-poke results."""
    results = []
    for p in pokes:
        client.write_memory(int(p["pid"]), int(p["address"]),
                            bytes.fromhex(p["hex"]))
        results.append(f"{p.get('name', hex(p['address']))}: ok")
    return results


# ------------------------------------------------------------- audit replay

def replay_audit(client: RuntimeClient, log_path: str | Path,
                 limit: int = 0) -> list[str]:
    """Re-apply the mutating actions recorded in an MCP audit JSONL log.

    Replays ps4_write_memory, ps4_kernel_write, and ps4_set_breakpoint
    entries in recorded order. Read-only entries are skipped. `limit`
    bounds the number of replayed actions (0 = all).
    """
    replayable = {"ps4_write_memory", "ps4_kernel_write", "ps4_set_breakpoint"}
    actions = []
    try:
        lines = Path(log_path).read_text().strip().splitlines()
    except OSError as e:
        raise ValueError(f"cannot read audit log {log_path}: {e}") from e
    for line in lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue  # tolerate a torn final line
        if entry.get("tool") in replayable and entry.get("result") == "ok":
            actions.append(entry)
    if limit:
        actions = actions[:limit]

    done = []
    for entry in actions:
        args = entry["args"]
        tool = entry["tool"]
        if tool == "ps4_write_memory":
            client.write_memory(int(args["pid"]), int(args["address"], 16),
                                bytes.fromhex(args["hex"]))
        elif tool == "ps4_kernel_write":
            client.kernel_write(int(args["address"], 16),
                                bytes.fromhex(args["hex"]))
        elif tool == "ps4_set_breakpoint" and args.get("enabled", True):
            client.set_breakpoint(int(args["index"]), int(args["address"], 16), True)
        done.append(tool)
        time.sleep(0.05)  # keep the payload's per-client pacing comfortable
    return done
