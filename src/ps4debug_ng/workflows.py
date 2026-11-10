# SPDX-License-Identifier: GPL-3.0-only
"""Higher-level dynamic-RE workflows composed from the raw client primitives.

Everything here is client-side: no payload changes required. Memory reads go
through Ps4DebugClient.read_memory, so all functions take a client + pid.
"""

from __future__ import annotations

import contextlib
import struct
import time
from pathlib import Path
from typing import Protocol

from .client import Ps4DebugClient, Ps4DebugError


class DebugReader(Protocol):
    """The minimal client surface the workflows need (tests fake this)."""

    def read_memory(self, pid: int, address: int, length: int) -> bytes: ...

POINTER_ALIGN = 8
DEFAULT_MAX_DEPTH = 7
DEFAULT_MAX_OFFSET = 4096


# --------------------------------------------------------------- pointer chains


def find_pointer_chains(client: DebugReader, pid: int, target: int,
                        regions: list[dict], max_depth: int = DEFAULT_MAX_DEPTH,
                        max_offset: int = DEFAULT_MAX_OFFSET,
                        max_chains: int = 1000, max_links_per_level: int = 100000,
                        progress=None) -> list[dict]:
    """Cheat Engine-style reverse pointer scan.

    BFS backwards from `target`: at each level, find every aligned pointer in
    readable memory whose value `v` satisfies `v + o == link` for some link of
    the previous level and offset `o < max_offset`. A result chain is
    {"address": L, "offsets": [o1, ..., on]} resolving as:
    addr = L + o1; addr = *(addr) + o2; ... final addr = ... + on (see
    resolve_chain). `stable=True` marks chains rooted in a named (module)
    region. Reads all readable memory per level - slow by nature; use a
    narrowed region list when you know the allocator's arena.
    """
    regions = [r for r in regions if (r.get("prot", 0) & 1)
               and r["end"] - r["start"] >= 8]
    if not regions:
        return []

    # link address -> offset tails; each tail, applied from the link address,
    # reaches `target`.
    level: dict[int, list[list[int]]] = {target: [[]]}
    results: list[dict] = []

    for depth in range(1, max_depth + 1):
        # wanted value -> tails to attach: a stored pointer v continues a chain
        # if v + o equals a link, for aligned o in [0, max_offset).
        wanted: dict[int, list[list[int]]] = {}
        for link, tails in level.items():
            for tail in tails:
                for o in range(0, max_offset, POINTER_ALIGN):
                    wanted.setdefault(link - o, []).append([o] + tail)

        next_level: dict[int, list[list[int]]] = {}
        for region in regions:
            pos = region["start"]
            while pos < region["end"]:
                take = min(0x10000, region["end"] - pos)
                try:
                    buf = client.read_memory(pid, pos, take)
                except (Ps4DebugError, OSError, ConnectionError):
                    break  # region raced away; skip the rest of it
                for off in range(0, len(buf) - 7, POINTER_ALIGN):
                    (value,) = struct.unpack_from("<Q", buf, off)
                    tails = wanted.get(value)
                    if tails:
                        link = pos + off
                        bucket = next_level.setdefault(link, [])
                        for tail in tails:
                            if len(bucket) < 8:  # cap duplicate tails per link
                                bucket.append(tail)
                pos += take
            if progress:
                progress(depth, region.get("name", ""))

        if not next_level:
            break
        if len(next_level) > max_links_per_level:
            # prune deterministically: keep the lowest links (earliest regions)
            kept = sorted(next_level)[:max_links_per_level]
            next_level = {k: next_level[k] for k in kept}

        named_regions = [r for r in regions if r.get("name")]
        for link, tails in next_level.items():
            for tail in tails:
                if len(results) >= max_chains:
                    return results
                results.append({"address": link, "offsets": tail,
                                "depth": depth,
                                "stable": any(link >= r["start"] and link < r["end"]
                                              for r in named_regions)})
        level = dict(next_level)

    results.sort(key=lambda c: (not c["stable"], c["depth"]))
    return results


def resolve_chain(client: DebugReader, pid: int, base: int,
                  offsets: list[int]) -> int:
    """Follow a chain from find_pointer_chains: dereference, then add each
    offset (CE semantics): addr = *(addr) + o1; addr = *(addr) + o2; ...
    Returns the final address (which holds the target value)."""
    addr = base
    for off in offsets:
        data = client.read_memory(pid, addr, 8)
        (addr,) = struct.unpack("<Q", data)
        addr += off
    return addr


# ------------------------------------------------------------------- snapshots


def snapshot_save(client: DebugReader, pid: int, start: int, length: int,
                  path: str | Path, note: str = "") -> Path:
    """Dump a memory region to a binary file (8-byte header: pid, base, len)."""
    path = Path(path)
    data = client.read_memory(pid, start, length)
    with path.open("wb") as f:
        f.write(struct.pack("<QQQ", pid, start, len(data)))
        f.write(data)
    meta = path.with_suffix(path.suffix + ".json")
    import json
    meta.write_text(json.dumps({"pid": pid, "base": start, "length": len(data),
                                "note": note, "saved": time.time()}))
    return path


def snapshot_load(path: str | Path) -> tuple[int, int, bytes]:
    """Read a snapshot file back; returns (pid, base, data)."""
    raw = Path(path).read_bytes()
    pid, base, length = struct.unpack("<QQQ", raw[:24])
    return pid, base, raw[24:24 + length]


def snapshot_diff(path_a: str | Path, path_b: str | Path,
                  value_size: int = 8) -> dict:
    """Diff two snapshots of the same region.

    Returns {changed: [offset...], unchanged_count, added_bytes, removed_bytes}.
    Only compares the overlapping span.
    """
    _, base_a, data_a = snapshot_load(path_a)
    _, base_b, data_b = snapshot_load(path_b)
    if base_a != base_b:
        raise ValueError(f"snapshot bases differ: {hex(base_a)} vs {hex(base_b)}")
    overlap = min(len(data_a), len(data_b))
    changed = [off for off in range(0, overlap - value_size + 1, value_size)
               if data_a[off:off + value_size] != data_b[off:off + value_size]]
    return {"base": base_a, "changed": changed,
            "unchanged_count": (overlap // value_size) - len(changed),
            "added_bytes": max(0, len(data_b) - len(data_a)),
            "removed_bytes": max(0, len(data_a) - len(data_b))}


# ------------------------------------------------------------------ call trace


def trace_calls(client: Ps4DebugClient, pid: int, address: int,
                max_hits: int = 50, timeout: float = 5.0) -> list[dict]:
    """Breakpoint + auto-continue capture: records registers at each hit.

    The breakpoint must be placed on a function entry (or any code address).
    Returns one dict per hit: {hit, rip, registers}.
    """
    hits = []
    try:
        client.set_breakpoint(0, address, True)
        client.continue_(0)
        for i in range(max_hits):
            event = client.wait_event(timeout)
            if event is None:
                break
            regs = event["registers"]
            hits.append({"hit": i, "lwpid": event["lwpid"], "registers": regs})
            if i < max_hits - 1:
                client.continue_(0)
    finally:
        with contextlib.suppress(Ps4DebugError, OSError, ConnectionError):
            client.set_breakpoint(0, address, False)
    return hits


# ------------------------------------------------------------------ string xref


def xref_string(client: Ps4DebugClient, pid: int, text: str,
                regions: list[dict], wildcard: int = 0xCC,
                min_length: int = 4) -> dict:
    """Find a string in memory, then find code referencing its address.

    Returns {"string_address": int|None, "xrefs": [{address, kind}], ...}.
    Pure composition: AoB scan for the bytes, then payload xref search over
    executable regions.
    """
    needle = text.encode("ascii", "replace") + b"\0"
    if len(needle) < min_length:
        return {"error": "string too short", "string_address": None, "xrefs": []}
    pattern = bytearray(needle)
    if len(pattern) < 16:  # pad with wildcards to avoid matching substrings of longer strings
        pattern.extend([wildcard] * (16 - len(pattern)))
    readable = [r for r in regions if (r.get("prot", 0) & 1)]
    hits = client.scan_aob(pid, 0, 0x7FFF00000000, bytes(pattern),
                           wildcard=wildcard, regions=readable)
    if not hits:
        return {"string_address": None, "xrefs": []}
    string_addr = hits[0]
    exec_regions = [r for r in regions if (r.get("prot", 0) & 4)]  # PROT_EXEC
    xrefs: list[dict] = []
    for region in exec_regions:
        try:
            found = client.find_xrefs_to(pid, region["start"],
                                         region["end"] - region["start"],
                                         string_addr)
            xrefs.extend(found)
        except (Ps4DebugError, OSError, ConnectionError):
            continue
    return {"string_address": string_addr, "xrefs": xrefs}


# ------------------------------------------------------------------ modules


def list_modules(regions: list[dict]) -> list[dict]:
    """Group VM map regions into modules by backing-file name.

    Module base = lowest start of its regions; size = span. Regions with an
    empty name are reported as [anonymous:N].
    """
    groups: dict[str, list[dict]] = {}
    anon = 0
    for r in regions:
        name = r.get("name") or ""
        if not name:
            name = f"[anonymous:{anon}]"
            anon += 1
        groups.setdefault(name, []).append(r)
    modules = []
    for name, rs in groups.items():
        base = min(r["start"] for r in rs)
        end = max(r["end"] for r in rs)
        modules.append({"name": name, "base": base, "size": end - base,
                        "regions": len(rs)})
    modules.sort(key=lambda m: m["base"])
    return modules
