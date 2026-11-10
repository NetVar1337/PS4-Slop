# SPDX-License-Identifier: GPL-3.0-only
"""MCP server exposing ps4debug-NG to AI agents.

Run over stdio (Claude Desktop, Cursor, pi, ...):
    python -m ps4debug_ng.mcp_server

Design:
- Read-only tools work out of the box once connected.
- Every mutating tool takes `confirm: bool = False` and refuses to act until
  called with confirm=True, so the agent must explicitly ask the operator.
- Every call that reaches the console is appended to a JSONL audit log
  (PS4DEBUG_AUDIT_LOG env var; default ./ps4debug_audit.jsonl).
"""

from __future__ import annotations

import os

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # mcp >= 2.0 renamed FastMCP to MCPServer
    from mcp.server.mcpserver import MCPServer as FastMCP

from .audit import AuditLog
from .client import Ps4DebugClient

mcp = FastMCP("ps4debug-ng")

_client: Ps4DebugClient | None = None
_audit = AuditLog(os.environ.get("PS4DEBUG_AUDIT_LOG", "ps4debug_audit.jsonl"))


def _connected() -> Ps4DebugClient:
    if _client is None:
        raise RuntimeError("not connected - call ps4_connect first")
    return _client


def _need_confirm(confirm: bool, action: str) -> str | None:
    if not confirm:
        return (f"REFUSED: {action} changes console state. Re-invoke with "
                f"confirm=True after the operator approves.")
    return None


def _record(tool: str, args: dict, result: str) -> None:
    _audit.record(tool, args, result)


# --------------------------------------------------------------- connection


@mcp.tool()
def ps4_discover(timeout: float = 2.0) -> str:
    """Find a PS4 running the ps4debug-NG payload on the local network (UDP broadcast).
    Returns the console IP or 'not found'."""
    ip = Ps4DebugClient.discover(timeout=timeout)
    return ip or "not found"


@mcp.tool()
def ps4_connect(host: str | None = None, port: int = 744) -> dict:
    """Connect to the console. If host is omitted, auto-discover via broadcast."""
    global _client
    if _client is not None:
        _client.close()
        _client = None
    if not host:
        host = Ps4DebugClient.discover()
        if not host:
            raise RuntimeError("no console answered the broadcast; pass host explicitly")
    _client = Ps4DebugClient(host, port)
    _client.connect()
    info = _client.server_info()
    _record("ps4_connect", {"host": host, "port": port}, "ok")
    return info


@mcp.tool()
def ps4_disconnect() -> str:
    """Close the connection (and detach any active debug session)."""
    global _client
    if _client:
        _client.close()
        _client = None
    return "disconnected"


# ---------------------------------------------------------------- processes


@mcp.tool()
def ps4_server_info() -> dict:
    """Payload version, branding, capability level, and console firmware."""
    return _connected().server_info()


@mcp.tool()
def ps4_list_processes() -> list[dict]:
    """List running processes (pid + name)."""
    return _connected().list_processes()


@mcp.tool()
def ps4_process_info(pid: int) -> dict:
    """Name, path, title id, and content id of a process."""
    return _connected().proc_info(pid)


@mcp.tool()
def ps4_list_regions(pid: int) -> list[dict]:
    """List virtual memory regions (start/end/prot/name) of a process."""
    return _connected().list_regions(pid)


# ------------------------------------------------------------------- memory


def _hexdump_preview(data: bytes, limit: int = 256) -> str:
    lines = []
    for off in range(0, min(len(data), limit), 16):
        chunk = data[off:off + 16]
        hexpart = " ".join(f"{b:02X}" for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08X}  {hexpart:<47}  {asciipart}")
    return "\n".join(lines)


@mcp.tool()
def ps4_read_memory(pid: int, address: int, length: int) -> dict:
    """Read process memory. Returns hex dump preview (first 256 bytes) + full hex string.
    Keep reads small and targeted; use ps4_list_regions to find valid ranges."""
    c = _connected()
    data = c.read_memory(pid, address, length)
    _record("ps4_read_memory", {"pid": pid, "address": hex(address), "length": length},
            f"{len(data)} bytes")
    return {"length": len(data), "hex": data.hex(),
            "preview": _hexdump_preview(data)}


@mcp.tool()
def ps4_write_memory(pid: int, address: int, hex_bytes: str, confirm: bool = False) -> str:
    """Write bytes (hex string, e.g. '4889C3') to process memory. Verified by the payload.
    Requires confirm=True."""
    if refuse := _need_confirm(confirm, f"write to pid {pid} @ {hex(address)}"):
        return refuse
    data = bytes.fromhex(hex_bytes)
    c = _connected()
    c.write_memory(pid, address, data)
    _record("ps4_write_memory", {"pid": pid, "address": hex(address), "hex": hex_bytes},
            "ok")
    return f"wrote {len(data)} bytes to pid {pid} @ {hex(address)}"


# ------------------------------------------------------------------------ RE


@mcp.tool()
def ps4_disassemble(pid: int, address: int, length: int = 256,
                    max_entries: int = 512) -> list[dict]:
    """Disassemble a code region. Entries carry address/length/kind bitmask and
    resolved RIP-relative targets. kind bits: 1=call 2=ret 4=jmp 8=jcc 16=mem
    32=rip-rel 64=read 128=write."""
    return _connected().disassemble(pid, address, length, max_entries)


@mcp.tool()
def ps4_assemble(base_addr: int, text: str, syntax: int = 0) -> dict:
    """Assemble x86-64 text (Keystone, in-payload) at a base address.
    Returns machine code as hex + instruction count."""
    code, count = _connected().assemble(base_addr, text, syntax)
    return {"hex": code.hex(), "byte_len": len(code), "instructions": count}


@mcp.tool()
def ps4_code_targets(pid: int, address: int, length: int) -> list[int]:
    """List deduplicated branch/call targets inside a code region (RIP-relative
    xrefs extracted server-side). Feed a module's .text range."""
    return _connected().code_targets(pid, address, length)


@mcp.tool()
def ps4_find_xrefs(pid: int, scan_address: int, scan_length: int,
                   target_address: int) -> list[dict]:
    """Find instructions referencing target_address inside [scan_address, +length).
    Each hit: {address, kind} with the disasm kind bitmask."""
    return _connected().find_xrefs_to(pid, scan_address, scan_length, target_address)


@mcp.tool()
def ps4_read_stack(pid: int, rbp: int, rsp: int, depth: int = 32) -> list[dict]:
    """Walk the RBP frame chain server-side. Get rbp/rsp from ps4_get_registers."""
    frames = _connected().read_stack(pid, rbp, rsp, depth)
    for f in frames:
        f["frame_locals"] = f["frame_locals"].hex()
        f["code"] = f["code"].hex()
    return frames


@mcp.tool()
def ps4_scan_aob(pid: int, pattern_hex: str, start: int = 0,
                 length: int = 0x7FFF00000000, wildcard: int = 0xCC,
                 prot_filter: bool = True) -> list[int]:
    """Client-side array-of-bytes scan over process memory (no scan auth needed).
    pattern_hex: hex string; wildcard byte (default CC) matches anything.
    prot_filter=True restricts to readable regions from ps4_list_regions.
    Returns matching addresses."""
    pattern = bytes.fromhex(pattern_hex)
    c = _connected()
    regions = c.list_regions(pid) if prot_filter else None
    if regions:
        # list_regions returns prot as the kernel's PROT_* bits
        regions = [r for r in regions if r["prot"] & 1]
    hits = c.scan_aob(pid, start, length, pattern, wildcard, regions)
    _record("ps4_scan_aob", {"pid": pid, "pattern": pattern_hex, "hits": len(hits)},
            f"{len(hits)} hits")
    return hits


# ------------------------------------------------------------------- debug


@mcp.tool()
def ps4_attach(pid: int) -> str:
    """Attach the debugger to a process. Starts listening for debug events on
    port 755; use ps4_wait_event to receive breakpoint/watchpoint hits."""
    _connected().attach(pid)
    _record("ps4_attach", {"pid": pid}, "ok")
    return f"attached to pid {pid}"


@mcp.tool()
def ps4_detach(confirm: bool = False) -> str:
    """Detach: clears breakpoints/watchpoints and resumes the target. Requires confirm=True."""
    if refuse := _need_confirm(confirm, "detach (resumes the debugged process)"):
        return refuse
    _connected().detach()
    _record("ps4_detach", {}, "ok")
    return "detached"


@mcp.tool()
def ps4_wait_event(timeout: float = 10.0) -> dict | str:
    """Wait for the next debug event (breakpoint/watchpoint/step hit).
    Returns register context incl. RIP. 'timeout' if none arrived."""
    event = _connected().wait_event(timeout)
    if event is None:
        return "timeout"
    return event


@mcp.tool()
def ps4_set_breakpoint(index: int, address: int, enabled: bool = True,
                       confirm: bool = False) -> str:
    """Set/clear a software breakpoint (0xCC patch; max 30). Requires confirm=True."""
    if refuse := _need_confirm(confirm, f"breakpoint {index} @ {hex(address)}"):
        return refuse
    _connected().set_breakpoint(index, address, enabled)
    _record("ps4_set_breakpoint", {"index": index, "address": hex(address),
                                   "enabled": enabled}, "ok")
    return f"breakpoint {index} {'set' if enabled else 'cleared'} @ {hex(address)}"


@mcp.tool()
def ps4_set_watchpoint(index: int, address: int, length: int, breaktype: int,
                       enabled: bool = True, confirm: bool = False) -> str:
    """Set/clear a hardware watchpoint (DR0-3; max 4). breaktype: 0=exec, 1=write,
    3=read/write; length in {1,2,4,8}. Requires confirm=True."""
    if refuse := _need_confirm(confirm, f"watchpoint {index} @ {hex(address)}"):
        return refuse
    _connected().set_watchpoint(index, address, length, breaktype, enabled)
    _record("ps4_set_watchpoint", {"index": index, "address": hex(address),
                                   "length": length, "breaktype": breaktype,
                                   "enabled": enabled}, "ok")
    return f"watchpoint {index} {'set' if enabled else 'cleared'} @ {hex(address)}"


@mcp.tool()
def ps4_list_threads() -> list[int]:
    """List thread ids (lwpids) of the attached process."""
    return _connected().thread_list()


@mcp.tool()
def ps4_thread_info(lwpid: int) -> dict:
    """Priority + name of a thread of the attached process."""
    return _connected().thread_info(lwpid)


@mcp.tool()
def ps4_suspend_thread(lwpid: int, confirm: bool = False) -> str:
    """Suspend a thread. Requires confirm=True."""
    if refuse := _need_confirm(confirm, f"suspend thread {lwpid}"):
        return refuse
    _connected().suspend_thread(lwpid)
    _record("ps4_suspend_thread", {"lwpid": lwpid}, "ok")
    return f"thread {lwpid} suspended"


@mcp.tool()
def ps4_resume_thread(lwpid: int, confirm: bool = False) -> str:
    """Resume a thread. Requires confirm=True."""
    if refuse := _need_confirm(confirm, f"resume thread {lwpid}"):
        return refuse
    _connected().resume_thread(lwpid)
    _record("ps4_resume_thread", {"lwpid": lwpid}, "ok")
    return f"thread {lwpid} resumed"


@mcp.tool()
def ps4_get_registers(lwpid: int) -> dict:
    """General-purpose registers of a thread (rax..r15, rip, rsp, rflags, ...)."""
    return _connected().get_registers(lwpid)


@mcp.tool()
def ps4_set_registers(lwpid: int, registers: dict, confirm: bool = False) -> str:
    """Write GP registers (subset of ps4_get_registers keys). Requires confirm=True."""
    if refuse := _need_confirm(confirm, f"set registers of thread {lwpid}"):
        return refuse
    _connected().set_registers(lwpid, registers)
    _record("ps4_set_registers", {"lwpid": lwpid,
                                  "keys": sorted(registers)}, "ok")
    return f"registers updated for thread {lwpid}"


@mcp.tool()
def ps4_get_debug_registers(lwpid: int) -> list[int]:
    """DR0-DR15 of a thread (hardware breakpoint state)."""
    return _connected().get_debug_registers(lwpid)


@mcp.tool()
def ps4_get_fsgsbase(lwpid: int) -> dict:
    """FSBASE/GSBASE of a thread (TLS anchors - useful for finding thread-local structs)."""
    return _connected().get_fsgsbase(lwpid)


@mcp.tool()
def ps4_continue(stop: int = 0, confirm: bool = False) -> str:
    """Resume the debugged process. stop=1 enters single-step/halted mode. Requires confirm=True."""
    if refuse := _need_confirm(confirm, "continue execution"):
        return refuse
    _connected().continue_(stop)
    _record("ps4_continue", {"stop": stop}, "ok")
    return "continued"


@mcp.tool()
def ps4_step(confirm: bool = False) -> str:
    """Single-step all threads of the debugged process. Requires confirm=True."""
    if refuse := _need_confirm(confirm, "single-step"):
        return refuse
    _connected().step()
    _record("ps4_step", {}, "ok")
    return "stepped"


@mcp.tool()
def ps4_step_thread(lwpid: int, confirm: bool = False) -> str:
    """Single-step one thread. Requires confirm=True."""
    if refuse := _need_confirm(confirm, f"step thread {lwpid}"):
        return refuse
    _connected().step_thread(lwpid)
    _record("ps4_step_thread", {"lwpid": lwpid}, "ok")
    return f"thread {lwpid} stepped"


@mcp.tool()
def ps4_stop_process(pid: int, state: int, confirm: bool = False) -> str:
    """Signal a process: 0=resume, 1=stop, 2=KILL (cannot be caught). Requires confirm=True."""
    if refuse := _need_confirm(confirm, f"signal {state} pid {pid}"):
        return refuse
    _connected().proc_stop(pid, state)
    _record("ps4_stop_process", {"pid": pid, "state": state}, "ok")
    return f"pid {pid} signalled ({state})"


# ------------------------------------------------------------------- kernel


@mcp.tool()
def ps4_kernel_base() -> int:
    """Base address of the running kernel."""
    return _connected().kernel_base()


@mcp.tool()
def ps4_kernel_read(address: int, length: int) -> dict:
    """Read kernel memory. Hex dump preview + full hex string."""
    data = _connected().kernel_read(address, length)
    _record("ps4_kernel_read", {"address": hex(address), "length": length},
            f"{len(data)} bytes")
    return {"length": len(data), "hex": data.hex(), "preview": _hexdump_preview(data)}


@mcp.tool()
def ps4_kernel_write(address: int, hex_bytes: str, confirm: bool = False) -> str:
    """Write kernel memory (bypasses CR0.WP in the payload). Requires confirm=True."""
    if refuse := _need_confirm(confirm, f"kernel write @ {hex(address)}"):
        return refuse
    data = bytes.fromhex(hex_bytes)
    _connected().kernel_write(address, data)
    _record("ps4_kernel_write", {"address": hex(address), "hex": hex_bytes}, "ok")
    return f"wrote {len(data)} kernel bytes @ {hex(address)}"


# ------------------------------------------------------------------ console


@mcp.tool()
def ps4_notify(message: str, message_type: int = 222, confirm: bool = False) -> str:
    """Show a system notification on the console screen. Requires confirm=True."""
    if refuse := _need_confirm(confirm, "console notification"):
        return refuse
    _connected().notify(message, message_type)
    _record("ps4_notify", {"message": message}, "ok")
    return "notification sent"


# --------------------------------------------------------------------- main


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
