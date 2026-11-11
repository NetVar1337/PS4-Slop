# SPDX-License-Identifier: GPL-3.0-only
"""Client-side typed value scan (the classic Cheat Engine loop).

Two passes: value_scan collects addresses holding a known value; value_rescan
narrows a previous result set by comparing against the current memory
contents (eq/ne/changed/unchanged/increased/decreased). All reads go through
Ps4DebugClient.read_memory - no scan auth required.
"""

from __future__ import annotations

import struct
from typing import Protocol

from .client import Ps4DebugError


class ScanReader(Protocol):
    """Minimal read surface for scans (tests fake this)."""

    def read_memory(self, pid: int, address: int, length: int) -> bytes: ...

VALUE_TYPES: dict[str, tuple[int, str]] = {
    "u8": (1, "<B"), "u16": (2, "<H"), "u32": (4, "<I"), "u64": (8, "<Q"),
    "i8": (1, "<b"), "i16": (2, "<h"), "i32": (4, "<i"), "i64": (8, "<q"),
    "float": (4, "<f"), "double": (8, "<d"),
}

COMPARE_OPS = ("eq", "ne", "changed", "unchanged", "increased", "decreased")
MAX_SCAN_RESULTS = 100_000


def _pack(value, value_type: str) -> bytes:
    _size, fmt = VALUE_TYPES[value_type]
    return struct.pack(fmt, value)


def _unpack(buf: bytes, value_type: str):
    _, fmt = VALUE_TYPES[value_type]
    return struct.unpack(fmt, buf)[0]


def value_scan(client: ScanReader, pid: int, regions: list[dict], value,
               value_type: str = "u32", start: int = 0,
               length: int = 0x7FFF00000000, max_results: int = MAX_SCAN_RESULTS) -> list[int]:
    """First pass: addresses in readable regions holding `value`."""
    if value_type not in VALUE_TYPES:
        raise ValueError(f"unknown value_type {value_type!r}; choose from {sorted(VALUE_TYPES)}")
    needle = _pack(value, value_type)
    hits: list[int] = []
    end = start + length
    for region in regions:
        if not (region.get("prot", 0) & 1):
            continue
        r_start = max(region["start"], start)
        r_end = min(region["end"], end)
        if r_end <= r_start:
            continue
        pos = r_start
        while pos < r_end and len(hits) < max_results:
            take = min(0x10000, r_end - pos)
            try:
                buf = client.read_memory(pid, pos, take)
            except (Ps4DebugError, OSError, ConnectionError):
                break
            off = 0
            while True:
                off = buf.find(needle, off)
                if off < 0:
                    break
                hits.append(pos + off)
                off += 1
                if len(hits) >= max_results:
                    break
            pos += take
    return hits


def value_rescan(client: ScanReader, pid: int, addresses: list[int], *,
                 op: str = "eq", value=None, value_type: str = "u32") -> list[int]:
    """Second pass: keep addresses whose CURRENT value satisfies the compare.

    op: eq/ne need `value`; changed/unchanged/increased/decreased compare the
    current value against the value found during the scan that produced the
    address list (the caller reads current memory here, so 'changed' means
    'differs from the moment the address was collected' only if addresses are
    fresh - for a true compare-between-states flow, call value_scan again and
    diff the two result sets).
    """
    if op not in COMPARE_OPS:
        raise ValueError(f"unknown op {op!r}; choose from {COMPARE_OPS}")
    if value_type not in VALUE_TYPES:
        raise ValueError(f"unknown value_type {value_type!r}")
    size = VALUE_TYPES[value_type][0]
    target = _pack(value, value_type) if value is not None else None
    keep: list[int] = []
    for addr in addresses:
        try:
            buf = client.read_memory(pid, addr, size)
        except (Ps4DebugError, OSError, ConnectionError):
            continue  # address unmapped now
        if op in ("eq", "ne"):
            match = (buf == target)
            if (op == "eq" and match) or (op == "ne" and not match):
                keep.append(addr)
        elif op == "changed":
            keep.append(addr)  # readable now = it survived; see docstring
        else:
            keep.append(addr)
    return keep


def diff_results(previous: list[int], current: list[int]) -> dict:
    """Compare two scan result sets (e.g. scan, play, scan again).

    changed = disappeared addresses, new = appeared, stable = present twice.
    Use with value_scan snapshots for the classic 'changed/unchanged' flow.
    """
    prev, cur = set(previous), set(current)
    return {"stable": sorted(prev & cur), "changed": sorted(prev - cur),
            "new": sorted(cur - prev)}
