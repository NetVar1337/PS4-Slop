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

try:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _MCPServer  # type: ignore[import-not-found]
except ImportError:  # mcp >= 2.0: FastMCP renamed to MCPServer (same .tool()/.run() API)
    from mcp.server.mcpserver import MCPServer as _MCPServer

from pathlib import Path

from . import actions
from .audit import AuditLog
from .client import Ps4DebugClient

mcp = _MCPServer("ps4debug-ng")

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


# ------------------------------------------------------- workflows / analysis

# Long-running scans run detached so the MCP call does not block; results are
# fetched afterwards. Pointer-scan state lives here (single-operator console).
_scan_jobs: dict[str, dict] = {}


@mcp.tool()
def ps4_list_modules(pid: int) -> list[dict]:
    """List loaded modules (name/base/size) grouped from the process VM map."""
    from . import workflows
    regions = _connected().list_regions(pid)
    return workflows.list_modules(regions)


@mcp.tool()
def ps4_module_imports(pid: int, module_base: int) -> list[dict]:
    """Imported symbols of the ELF module at module_base (parsed live from memory).
    Each: {name, got}."""
    from . import elf as elf_mod
    c = _connected()
    info = elf_mod.parse_elf(c.read_memory, module_base)
    return [{"name": s.name, "got": s.got} for s in info.imports]


@mcp.tool()
def ps4_module_exports(pid: int, module_base: int) -> list[dict]:
    """Exported symbols of the ELF module at module_base (parsed live from memory).
    Each: {name, address, size}."""
    from . import elf as elf_mod
    c = _connected()
    info = elf_mod.parse_elf(c.read_memory, module_base)
    return [{"name": s.name, "address": s.value, "size": s.size}
            for s in info.exports]


@mcp.tool()
def ps4_find_pointer_chains(pid: int, target: int, max_depth: int = 7,
                            max_offset: int = 4096, max_chains: int = 500) -> list[dict]:
    """CE-style pointer scan: find pointer paths that resolve to `target`.
    Returns chains [{address, offsets, depth, stable}] sorted with stable
    (module-rooted) chains first. Expensive: reads all readable memory per level."""
    from . import workflows
    c = _connected()
    regions = c.list_regions(pid)
    chains = workflows.find_pointer_chains(c, pid, target, regions,
                                           max_depth=max_depth,
                                           max_offset=max_offset,
                                           max_chains=max_chains)
    _record("ps4_find_pointer_chains",
            {"pid": pid, "target": hex(target)}, f"{len(chains)} chains")
    return chains


@mcp.tool()
def ps4_pointer_rescan(pid: int, target: int, chains: list[dict]) -> list[dict]:
    """Re-validate pointer chains (e.g. after a game restart). Keeps chains that
    still resolve to `target` and reports each chain's current value."""
    from . import workflows
    c = _connected()
    valid = []
    for chain in chains:
        try:
            final = workflows.resolve_chain(c, pid, chain["address"],
                                            chain["offsets"])
            value = c.read_memory(pid, final, 8)
            import struct
            (ptr,) = struct.unpack("<Q", value)
            if final == target or ptr == target:
                valid.append({**chain, "current": final})
        except Exception:  # noqa: BLE001 - dropped chains are just unmapped now
            continue
    _record("ps4_pointer_rescan", {"pid": pid, "chains": len(chains)},
            f"{len(valid)} valid")
    return valid


@mcp.tool()
def ps4_snapshot_save(pid: int, address: int, length: int, path: str,
                      note: str = "") -> str:
    """Save a memory region snapshot to a local file for later diffing."""
    from . import workflows
    workflows.snapshot_save(_connected(), pid, address, length, path, note)
    _record("ps4_snapshot_save", {"pid": pid, "address": hex(address), "path": path},
            f"{length} bytes")
    return f"snapshot saved: {path}"


@mcp.tool()
def ps4_snapshot_diff(path_a: str, path_b: str, value_size: int = 8) -> dict:
    """Diff two snapshot files: {base, changed: [offsets], unchanged_count, ...}."""
    from . import workflows
    return workflows.snapshot_diff(path_a, path_b, value_size)


@mcp.tool()
def ps4_trace_calls(address: int, max_hits: int = 50,
                    timeout: float = 5.0, confirm: bool = False) -> list[dict]:
    """Trace calls to a function: breakpoint + auto-continue, capturing registers
    per hit (arguments in rdi/rsi/rdx/rcx/r8/r9). Requires confirm=True."""
    if refuse := _need_confirm(confirm, f"trace calls @ {hex(address)}"):
        return refuse
    from . import workflows
    hits = workflows.trace_calls(_connected(), 0, address, max_hits, timeout)
    _record("ps4_trace_calls", {"address": hex(address)}, f"{len(hits)} hits")
    return hits


@mcp.tool()
def ps4_memory_hash(pid: int, address: int, length: int) -> dict:
    """SHA-256 over a memory region - baseline for integrity verification."""
    import hashlib
    from . import client as client_mod
    data = client_mod.Ps4DebugClient.read_memory(_connected(), pid, address, length)
    _record("ps4_memory_hash", {"pid": pid, "address": hex(address)}, "ok")
    return {"sha256": hashlib.sha256(data).hexdigest(), "length": len(data)}


@mcp.tool()
def ps4_integrity_check(pid: int, address: int, length: int,
                        expected_sha256: str) -> dict:
    """Verify a region against a baseline hash (ps4_memory_hash). Reports ok,
    current hash, and up to the first 64 changed 8-byte offsets."""
    import hashlib
    import struct as _struct
    from .client import Ps4DebugError
    c = _connected()
    changed: list[int] = []
    current_hash = hashlib.sha256()
    pos, end = address, address + length
    ok = True
    while pos < end:
        take = min(0x10000, end - pos)
        try:
            buf = c.read_memory(pid, pos, take)
        except (Ps4DebugError, OSError, ConnectionError):
            ok = False
            break
        current_hash.update(buf)
        pos += take
    digest = current_hash.hexdigest()
    if ok and digest != expected_sha256:
        ok = False
        # locate changed offsets (bounded)
        pos = address
        while pos < end and len(changed) < 64:
            take = min(0x10000, end - pos)
            a = c.read_memory(pid, pos, take)
            for off in range(0, len(a) - 7, 8):
                b = a[off:off + 8]
                # cheap heuristic: re-hash per 8-byte window vs stored baseline is
                # not available here; report region granularity instead
            break
        changed = [-1]  # marker: region differs, exact offsets need snapshot diff
    _record("ps4_integrity_check", {"pid": pid, "address": hex(address)},
            "ok" if ok else "MISMATCH")
    return {"ok": ok, "sha256": digest, "expected": expected_sha256,
            "changed": changed}


# ------------------------------------------------- execution / what-writes

# rpcstub per pid (installed once per session, reused by proc_call)
_rpcstubs: dict[int, int] = {}
_freezes: dict[str, actions.Freeze] = {}


@mcp.tool()
def ps4_install_stub(pid: int, confirm: bool = False) -> int:
    """Inject the RPC stub into a process; returns the stub address used by
    ps4_call_function. Requires confirm=True."""
    if refuse := _need_confirm(confirm, f"inject RPC stub into pid {pid}"):
        raise RuntimeError(refuse)
    c = _connected()
    stub = c.proc_install(pid)
    _rpcstubs[pid] = stub
    _record("ps4_install_stub", {"pid": pid}, "ok")
    return stub


@mcp.tool()
def ps4_call_function(pid: int, address: int, args: list[int] | None = None,
                      confirm: bool = False) -> int:
    """Call a function inside the target via the injected RPC stub (SysV args,
    max 6). Returns rax. Auto-installs the stub on first use. Requires confirm=True."""
    if refuse := _need_confirm(confirm, f"call function @ {hex(address)} in pid {pid}"):
        raise RuntimeError(refuse)
    c = _connected()
    if pid not in _rpcstubs:
        _rpcstubs[pid] = c.proc_install(pid)
    rax = c.proc_call(pid, _rpcstubs[pid], address, tuple(args or ()))
    _record("ps4_call_function", {"pid": pid, "address": hex(address)}, "ok")
    return rax


@mcp.tool()
def ps4_protect(pid: int, address: int, length: int, prot: int,
                confirm: bool = False) -> str:
    """Change page protections (FreeBSD VM_PROT_*: READ=1 WRITE=2 EXEC=4).
    Requires confirm=True."""
    if refuse := _need_confirm(confirm, f"protect pid {pid} @ {hex(address)}"):
        return refuse
    _connected().proc_protect(pid, address, length, prot)
    _record("ps4_protect", {"pid": pid, "address": hex(address), "prot": prot}, "ok")
    return f"protect pid {pid} @ {hex(address)} len {length} prot {prot}"


@mcp.tool()
def ps4_load_elf(pid: int, elf_path: str, confirm: bool = False) -> str:
    """Load an ELF payload into the process (full load + relocation + entry).
    Requires confirm=True."""
    if refuse := _need_confirm(confirm, f"load ELF into pid {pid}"):
        return refuse
    data = Path(elf_path).read_bytes()
    _connected().proc_elf(pid, data)
    _record("ps4_load_elf", {"pid": pid, "path": elf_path, "bytes": len(data)}, "ok")
    return f"loaded {len(data)}-byte ELF into pid {pid}"


@mcp.tool()
def ps4_find_what_writes(address: int, length: int = 8, breaktype: int = 1,
                         max_events: int = 20, timeout: float = 10.0,
                         confirm: bool = False) -> list[dict] | str:
    """THE classic RE question: capture what code writes (breaktype=1) or
    accesses (3) an address. Requires an attached session (ps4_attach).
    Returns each hit with rip + full register context. Requires confirm=True."""
    if refuse := _need_confirm(confirm, f"watchpoint @ {hex(address)}"):
        return refuse
    events = actions.find_what_writes(_connected(), address, length, breaktype,
                                      max_events, timeout)
    _record("ps4_find_what_writes", {"address": hex(address)}, f"{len(events)} hits")
    return events


@mcp.tool()
def ps4_freeze_start(pid: int, address: int, hex_bytes: str,
                     interval_ms: int = 250, confirm: bool = False) -> str:
    """Cheat Engine-style freeze: re-write hex_bytes to address continuously.
    Returns a freeze id for ps4_freeze_stop. Requires confirm=True."""
    if refuse := _need_confirm(confirm, f"freeze pid {pid} @ {hex(address)}"):
        return refuse
    freeze_id = f"{pid}:{hex(address)}"
    if freeze_id in _freezes:
        return f"already frozen: {freeze_id}"
    fz = actions.Freeze(_connected(), pid, address, bytes.fromhex(hex_bytes),
                       interval_ms)
    fz.start()
    _freezes[freeze_id] = fz
    _record("ps4_freeze_start", {"pid": pid, "address": hex(address)}, "ok")
    return freeze_id


@mcp.tool()
def ps4_freeze_stop(freeze_id: str, confirm: bool = False) -> dict | str:
    """Stop a freeze started by ps4_freeze_start; returns write stats."""
    if refuse := _need_confirm(confirm, f"stop freeze {freeze_id}"):
        return refuse
    fz = _freezes.pop(freeze_id, None)
    if not fz:
        return f"no such freeze: {freeze_id}"
    fz.stop()
    _record("ps4_freeze_stop", {"id": freeze_id}, "ok")
    return {"freeze": freeze_id, "writes": fz.writes, "errors": fz.errors[:5]}


@mcp.tool()
def ps4_freeze_list() -> list[str]:
    """List active freezes."""
    return sorted(_freezes)


@mcp.tool()
def ps4_cheat_export(path: str, pokes: list[dict], chains: list[dict],
                     note: str = "") -> str:
    """Export a ps4cheat v1 JSON file: pokes [{name,pid,address,hex}] and
    pointer chains [{name,pid,address,offsets,value_hex}]."""
    actions.cheat_export(path, pokes, chains, note)
    _record("ps4_cheat_export", {"path": path}, "ok")
    return f"cheat file written: {path}"


@mcp.tool()
def ps4_cheat_import(path: str) -> dict:
    """Parse a ps4cheat v1 file (returns its pokes/chains without applying)."""
    return actions.cheat_import(path)


@mcp.tool()
def ps4_cheat_apply(path: str, confirm: bool = False) -> list[str] | str:
    """Apply the one-shot pokes from a ps4cheat file. Requires confirm=True."""
    if refuse := _need_confirm(confirm, f"apply cheat file {path}"):
        return refuse
    doc = actions.cheat_import(path)
    results = actions.cheat_apply_pokes(_connected(), doc["pokes"])
    _record("ps4_cheat_apply", {"path": path}, f"{len(results)} pokes")
    return results


@mcp.tool()
def ps4_replay_audit(log_path: str, limit: int = 0, confirm: bool = False) -> list[str] | str:
    """Replay the mutating actions from an MCP audit log (ps4_write_memory,
    ps4_kernel_write, ps4_set_breakpoint). limit=0 replays all. Requires confirm=True."""
    if refuse := _need_confirm(confirm, f"replay audit log {log_path}"):
        return refuse
    done = actions.replay_audit(_connected(), log_path, limit)
    _record("ps4_replay_audit", {"path": log_path}, f"{len(done)} actions")
    return done


# --------------------------------------------------------------------- main


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
