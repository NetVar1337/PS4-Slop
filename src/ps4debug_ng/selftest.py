# SPDX-License-Identifier: GPL-3.0-only
"""Guided real-hardware smoke test.

    python -m ps4debug_ng.selftest [host]

Read-only: connect, enumerate, read, and AoB-scan. Attach/breakpoint steps
require typing a pid and are clearly marked. Prints PASS/FAIL per step.
"""

from __future__ import annotations

import sys
from typing import Any

from .client import Ps4DebugClient


def check(name: str, fn) -> Any:
    """Run fn, print PASS/FAIL, return the result (None on failure)."""
    try:
        result = fn()
        summary = ""
        if isinstance(result, (str, int, float)):
            summary = f" -> {result}"
        elif isinstance(result, list):
            summary = f" -> {len(result)} entries"
        elif isinstance(result, dict):
            summary = f" -> {len(result)} keys"
        print(f"  PASS  {name}{summary}")
        return result
    except Exception as e:  # noqa: BLE001 - report anything the console throws
        print(f"  FAIL  {name}: {e}")
        return None


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else None
    print("ps4debug-mcp selftest (read-only; attach step asks first)\n")

    if not host:
        print("1. discovery (UDP broadcast)")

        def discover():
            found = Ps4DebugClient.discover()
            if not found:
                raise RuntimeError("no console answered the broadcast")
            return found

        host = check("broadcast discover", discover)
    else:
        print(f"1. using host {host}")

    c = Ps4DebugClient(host)
    check("tcp connect :744", c.connect)

    print("2. info")
    check("server_info", lambda: str(c.server_info()))
    check("firmware_version", c.firmware_version)
    check("ping", c.ping)

    print("3. process inspection")
    procs = check("list_processes", c.list_processes)
    if not procs:
        print("cannot continue without a process list")
        return 1
    shell = next((p for p in procs if "SceShellUI" in p["name"]), procs[0])
    pid = shell["pid"]
    print(f"  using pid {pid} ({shell['name']})")
    regions = check("list_regions", lambda: c.list_regions(pid))
    if not regions:
        return 1

    print("4. memory reads")
    readable = next((r for r in regions if (r["prot"] & 1) and r["end"] - r["start"] >= 16), None)
    if not readable:
        print("  FAIL  no readable region found")
        return 1
    probe = check("read 16 bytes", lambda: c.read_memory(pid, readable["start"], 16).hex())

    print("5. client-side AoB scan (reads back the probe bytes)")
    if probe:
        pattern = bytes.fromhex(probe)[:8]
        hits = check("scan_aob 8-byte pattern",
                     lambda: c.scan_aob(pid, 0, 0x7FFF00000000, pattern,
                                        regions=[readable]))
        if isinstance(hits, list):
            assert readable["start"] in hits, "probe address missing from scan results"

    print("6. kernel (read-only)")
    kbase = check("kernel_base", lambda: hex(c.kernel_base()))
    if kbase:
        check("kernel_read 16 bytes", lambda: c.kernel_read(int(kbase, 16), 16).hex())

    print("7. debug attach (optional, mutating: freezes the target process)")
    answer = input("   attach to a process to test breakpoints? type a pid, or Enter to skip: ").strip()
    if answer:
        tpid = int(answer, 0)
        if check("attach", lambda: c.attach(tpid) or "ok"):
            lw = check("thread_list", c.thread_list)
            if lw:
                check("get_registers", lambda: hex(c.get_registers(lw[0])["rip"]))
            check("detach", lambda: c.detach() or "ok")

    c.close()
    print("\ndone. Every line above should read PASS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
