# SPDX-License-Identifier: GPL-3.0-only
"""TCP client for the ps4debug-NG payload (port 744).

Implements the read-only RE command set plus confirm-gated mutating commands.
Scans are performed client-side over proc_read so they need no scan auth
(PROTOCOL.md §1.8). The classic debug event channel (port 755, §1.9) is
listened on while attached; events are queued for wait_event().
"""

from __future__ import annotations

import contextlib
import queue
import socket
import struct
import threading
import time

from . import protocol as P

CHUNK = 0x10000


class Ps4DebugError(Exception):
    """Raised when the payload answers with a non-success status."""

    def __init__(self, status: int, context: str = ""):
        self.status = status
        name = P.STATUS_NAMES.get(status, f"0x{status:08X}")
        super().__init__(f"{context}: payload returned {name}".strip(": "))


class Ps4DebugClient:
    def __init__(self, host: str, port: int = P.SERVER_PORT, timeout: float = 15.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self._lock = threading.Lock()
        self._event_listener: socket.socket | None = None
        self._event_thread: threading.Thread | None = None
        self._events: queue.Queue[dict] = queue.Queue()
        self._events_closed = threading.Event()

    # ------------------------------------------------------------------ conn

    def connect(self) -> None:
        if self.sock:
            return
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)

    def close(self) -> None:
        with self._lock:
            if self.sock:
                try:
                    self.sock.close()
                finally:
                    self.sock = None
        self._stop_event_listener()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    @staticmethod
    def discover(timeout: float = 2.0, broadcast_addr: str = "255.255.255.255") -> str | None:
        """Return the first console IP answering the UDP broadcast probe."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.settimeout(timeout)
            s.sendto(struct.pack("<I", P.BROADCAST_MAGIC), (broadcast_addr, P.BROADCAST_PORT))
            try:
                data, (addr, _) = s.recvfrom(4)
            except TimeoutError:
                return None
            if data == struct.pack("<I", P.BROADCAST_MAGIC):
                return addr
            return None

    # ------------------------------------------------------------- transport

    def _send(self, data: bytes) -> None:
        assert self.sock is not None, "not connected"
        self.sock.sendall(data)

    def _recv_exact(self, n: int) -> bytes:
        assert self.sock is not None, "not connected"
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("payload closed the connection")
            buf += chunk
        return buf

    def _request(self, cmd: int, body: bytes = b"", trailing: bytes = b"") -> None:
        header = struct.pack("<III", P.PACKET_MAGIC, cmd, len(body))
        self._send(header + body + trailing)

    def _status(self, context: str) -> int:
        (status,) = struct.unpack("<I", self._recv_exact(4))
        if status != P.CMD_SUCCESS:
            raise Ps4DebugError(status, context)
        return status

    # ------------------------------------------------------------- info/ping

    def version(self) -> str:
        with self._lock:
            self._request(P.CMD_VERSION)
            (n,) = struct.unpack("<I", self._recv_exact(4))
            return self._recv_exact(n).decode("ascii", "replace")

    def branding(self) -> tuple[str, str]:
        with self._lock:
            self._request(P.CMD_BRANDING)
            (n,) = struct.unpack("<I", self._recv_exact(4))
            raw = self._recv_exact(n)
        parts = raw.split(b"\0", 1)
        brand = parts[0].decode("ascii", "replace")
        level = parts[1].decode("ascii", "replace") if len(parts) > 1 else "1.0"
        return brand, level

    def firmware_version(self) -> str:
        with self._lock:
            self._request(P.CMD_FW_VERSION)
            (v,) = struct.unpack("<H", self._recv_exact(2))
        return P.fw_version_str(v)

    def ping(self) -> bool:
        with self._lock:
            self._request(P.CMD_PROC_NOP)
            try:
                self._status("ping")
                return True
            except Ps4DebugError:
                return False

    def server_info(self) -> dict:
        brand, level = self.branding()
        return {"host": self.host, "version": self.version(), "branding": brand,
                "capability": level, "firmware": self.firmware_version()}

    # ------------------------------------------------------------------ proc

    def list_processes(self) -> list[dict]:
        with self._lock:
            self._request(P.CMD_PROC_LIST)
            self._status("proc_list")
            (num,) = struct.unpack("<I", self._recv_exact(4))
            entries = self._recv_exact(num * P.PROC_LIST_ENTRY.size)
        out = []
        for i in range(num):
            name, pid = P.PROC_LIST_ENTRY.unpack_from(entries, i * P.PROC_LIST_ENTRY.size)
            out.append({"pid": pid, "name": name.split(b"\0", 1)[0].decode("ascii", "replace")})
        return out

    def proc_info(self, pid: int) -> dict:
        with self._lock:
            self._request(P.CMD_PROC_INFO, P.INFO_PACKET.pack(pid))
            self._status("proc_info")
            raw = self._recv_exact(188)
        pid, name, path, titleid, contentid = struct.unpack("<i40s64s16s64s", raw)
        return {
            "pid": pid,
            "name": name.split(b"\0", 1)[0].decode("ascii", "replace"),
            "path": path.split(b"\0", 1)[0].decode("ascii", "replace"),
            "title_id": titleid.split(b"\0", 1)[0].decode("ascii", "replace"),
            "content_id": contentid.split(b"\0", 1)[0].decode("ascii", "replace"),
        }

    def list_regions(self, pid: int) -> list[dict]:
        with self._lock:
            self._request(P.CMD_PROC_MAPS, P.MAPS_PACKET.pack(pid))
            self._status("proc_maps")
            (num,) = struct.unpack("<I", self._recv_exact(4))
            raw = self._recv_exact(num * P.VM_MAP_ENTRY.size)
        out = []
        for i in range(num):
            start, end, offset, prot, name = P.VM_MAP_ENTRY.unpack_from(
                raw, i * P.VM_MAP_ENTRY.size)
            out.append({"start": start, "end": end, "offset": offset, "prot": prot,
                        "name": name.split(b"\0", 1)[0].decode("ascii", "replace")})
        return out

    def read_memory(self, pid: int, address: int, length: int) -> bytes:
        if length < 0:
            raise ValueError("length must be >= 0")
        out = bytearray()
        with self._lock:
            self._request(P.CMD_PROC_READ, P.READ_PACKET.pack(pid, address, length))
            self._status("proc_read")
            remaining = length
            while remaining > 0:
                take = min(remaining, CHUNK)
                chunk = self._recv_exact(take)
                out += chunk
                remaining -= take
        return bytes(out)

    def write_memory(self, pid: int, address: int, data: bytes) -> None:
        with self._lock:
            self._request(P.CMD_PROC_WRITE,
                          P.WRITE_PACKET.pack(pid, address, len(data)))
            self._status("proc_write ack")
            self._send(data)
            self._status("proc_write verify")

    # -------------------------------------------------------- disasm / asm

    def disassemble(self, pid: int, address: int, length: int,
                    max_entries: int = 512) -> list[dict]:
        with self._lock:
            self._request(P.CMD_PROC_DISASM_REGION,
                          P.DISASM_PACKET.pack(pid, address, length, max_entries))
            self._status("disasm")
            out = []
            while True:
                entry = self._recv_exact(P.DISASM_ENTRY.size)
                if entry == P.DISASM_SENTINEL:
                    break
                addr, rip_rel, disp, ilen, kind, base_r, idx_r, scale, mnem, _pad = \
                    P.DISASM_ENTRY.unpack(entry)
                out.append({
                    "address": addr, "length": ilen, "kind": kind,
                    "rip_rel_target": rip_rel, "mem_disp": disp,
                    "mem_base_reg": base_r, "mem_index_reg": idx_r, "mem_scale": scale,
                    "mnemonic_lo": mnem,
                })
            return out

    def code_targets(self, pid: int, address: int, length: int,
                     max_entries: int = 0x10000) -> list[int]:
        with self._lock:
            self._request(P.CMD_PROC_EXTRACT_CODE_XREFS,
                          P.DISASM_PACKET.pack(pid, address, length, max_entries))
            self._status("extract_code_xrefs")
            (num,) = struct.unpack("<I", self._recv_exact(4))
            raw = self._recv_exact(num * 8)
        return [struct.unpack_from("<Q", raw, i * 8)[0] for i in range(num)]

    def find_xrefs_to(self, pid: int, scan_address: int, scan_length: int,
                      target_address: int, limit: int = 4096) -> list[dict]:
        with self._lock:
            self._request(P.CMD_PROC_FIND_XREFS_TO,
                          P.XREF_TO_PACKET.pack(pid, scan_address, scan_length, target_address))
            self._status("find_xrefs_to")
            (num,) = struct.unpack("<I", self._recv_exact(4))
            raw = self._recv_exact(num * 9)
        out = []
        for i in range(min(num, limit)):
            addr, kind = struct.unpack_from("<QB", raw, i * 9)
            out.append({"address": addr, "kind": kind})
        return out

    def assemble(self, base_addr: int, text: str, syntax: int = 0) -> tuple[bytes, int]:
        body = P.ASSEMBLE_HDR.pack(base_addr, syntax) + text.encode("ascii")
        with self._lock:
            self._request(P.CMD_PROC_ASSEMBLE, body)
            try:
                self._status("assemble")
            except Ps4DebugError as e:
                ks_errno, msg_len = struct.unpack("<II", self._recv_exact(8))
                msg = self._recv_exact(msg_len).decode("ascii", "replace")
                raise Ps4DebugError(e.status, f"assemble failed: {msg}") from None
            byte_len, insn_count = struct.unpack("<II", self._recv_exact(8))
            code = self._recv_exact(byte_len)
        return code, insn_count

    # ----------------------------------------------------------------- stack

    def read_stack(self, pid: int, rbp: int, rsp: int, depth: int = 32) -> list[dict]:
        with self._lock:
            self._request(P.CMD_PROC_READ_STACK,
                          P.READ_STACK_PACKET.pack(pid, rbp, rsp, depth))
            self._status("read_stack")
            (bundle_len,) = struct.unpack("<I", self._recv_exact(4))
            bundle = self._recv_exact(bundle_len)
        (n_frames,) = struct.unpack_from("<I", bundle, 0)
        frames = []
        off = 4
        for _ in range(n_frames):
            rbp_v, rsp_v, saved_rbp, ret, flags, locals_len, code_len = \
                struct.unpack_from("<QQQIIII", bundle, off)
            off += 36
            locals_ = bundle[off:off + locals_len]
            off += locals_len
            code = bundle[off:off + code_len]
            off += code_len
            frames.append({"rbp": rbp_v, "rsp": rsp_v, "saved_rbp": saved_rbp,
                           "ret_addr": ret, "flags": flags,
                           "locals_omitted": bool(flags & 1),
                           "frame_locals": locals_, "code": code})
        return frames

    # ----------------------------------------------------------------- debug

    def _start_event_listener(self) -> None:
        self._stop_event_listener()
        self._events = queue.Queue()
        self._events_closed.clear()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", P.EVENT_PORT))  # noqa: S104 - must accept the console's outbound event connection on any interface
        listener.listen(1)
        listener.settimeout(5.0)
        self._event_listener = listener

        def run():
            try:
                conn, _ = listener.accept()
                conn.settimeout(None)
                with conn:
                    while not self._events_closed.is_set():
                        buf = b""
                        while len(buf) < P.DEBUG_INTERRUPT_PACKET_SIZE:
                            chunk = conn.recv(P.DEBUG_INTERRUPT_PACKET_SIZE - len(buf))
                            if not chunk:
                                return
                            buf += chunk
                        self._events.put(P.parse_interrupt_packet(buf))
            except (OSError, TimeoutError):
                pass
            finally:
                self._events_closed.set()

        self._event_thread = threading.Thread(target=run, daemon=True, name="ps4debug-events")
        self._event_thread.start()

    def _stop_event_listener(self) -> None:
        self._events_closed.set()
        if self._event_listener:
            with contextlib.suppress(OSError):
                self._event_listener.close()
            self._event_listener = None
        self._event_thread = None

    def attach(self, pid: int) -> None:
        self._start_event_listener()
        time.sleep(0.1)  # let the listener get into accept()
        with self._lock:
            assert self.sock is not None, "not connected"
            self._request(P.CMD_DEBUG_ATTACH,
                          P.ATTACH_PACKET.pack(pid, P.ip_to_u32(self.sock.getsockname()[0])))
            try:
                self._status("attach")
            except Exception:
                self._stop_event_listener()
                raise

    def detach(self) -> None:
        with self._lock:
            self._request(P.CMD_DEBUG_DETACH)
            self._status("detach")
        self._stop_event_listener()

    def wait_event(self, timeout: float | None = None) -> dict | None:
        """Pop the next debug event (breakpoint/watchpoint/step). None on timeout."""
        try:
            return self._events.get(timeout=timeout)
        except queue.Empty:
            return None

    def set_breakpoint(self, index: int, address: int, enabled: bool = True) -> None:
        with self._lock:
            self._request(P.CMD_DEBUG_SET_BREAKPOINT,
                          P.BREAKPT_PACKET.pack(index, int(enabled), address))
            self._status("set_breakpoint")

    def set_watchpoint(self, index: int, address: int, length: int,
                       breaktype: int, enabled: bool = True) -> None:
        # breaktype: 0=exec, 1=write, 3=read/write (DBREG_DR7_* encoding)
        with self._lock:
            self._request(P.CMD_DEBUG_SET_WATCHPOINT,
                          P.WATCHPT_PACKET.pack(index, int(enabled), length, breaktype, address))
            self._status("set_watchpoint")

    def thread_list(self) -> list[int]:
        with self._lock:
            self._request(P.CMD_DEBUG_GET_THREAD_LIST)
            self._status("thread_list")
            (num,) = struct.unpack("<I", self._recv_exact(4))
            raw = self._recv_exact(num * 4)
        return [struct.unpack_from("<I", raw, i * 4)[0] for i in range(num)]

    def thread_info(self, lwpid: int) -> dict:
        with self._lock:
            self._request(P.CMD_DEBUG_THREAD_INFO, P.STOPGO_PACKET.pack(lwpid))
            self._status("thread_info")
            lwpid, priority, name = struct.unpack("<II32s", self._recv_exact(40))
        return {"lwpid": lwpid, "priority": priority,
                "name": name.split(b"\0", 1)[0].decode("ascii", "replace")}

    def suspend_thread(self, lwpid: int) -> None:
        with self._lock:
            self._request(P.CMD_DEBUG_SUSPEND_THREAD, P.STOPGO_PACKET.pack(lwpid))
            self._status("suspend_thread")

    def resume_thread(self, lwpid: int) -> None:
        with self._lock:
            self._request(P.CMD_DEBUG_RESUME_THREAD, P.STOPGO_PACKET.pack(lwpid))
            self._status("resume_thread")

    def get_registers(self, lwpid: int) -> dict:
        with self._lock:
            self._request(P.CMD_DEBUG_GETREGS, P.STOPGO_PACKET.pack(lwpid))
            self._status("getregs")
            return P.parse_reg64(self._recv_exact(P.REG64_SIZE))

    def set_registers(self, lwpid: int, registers: dict) -> None:
        body = P.STOPGO_PACKET.pack(lwpid) + struct.pack("<I", P.REG64_SIZE)
        with self._lock:
            self._request(P.CMD_DEBUG_SETREGS, body)
            self._status("setregs ack")
            self._send(P.pack_reg64(registers))
            self._status("setregs")

    def get_debug_registers(self, lwpid: int) -> list[int]:
        with self._lock:
            self._request(P.CMD_DEBUG_GETDBREGS, P.STOPGO_PACKET.pack(lwpid))
            self._status("getdbregs")
            raw = self._recv_exact(128)
        return [struct.unpack_from("<Q", raw, i * 8)[0] for i in range(16)]

    def get_fsgsbase(self, lwpid: int) -> dict:
        with self._lock:
            self._request(P.CMD_DEBUG_GETFSGSBASE, P.STOPGO_PACKET.pack(lwpid))
            self._status("getfsgsbase")
            fsbase, gsbase = struct.unpack("<QQ", self._recv_exact(16))
        return {"fsbase": fsbase, "gsbase": gsbase}

    def continue_(self, stop: int = 0) -> None:
        with self._lock:
            self._request(P.CMD_DEBUG_CONTINUE, P.STOPGO_PACKET.pack(stop))
            self._status("continue")

    def step(self) -> None:
        with self._lock:
            self._request(P.CMD_DEBUG_STEP)
            self._status("step")

    def step_thread(self, lwpid: int) -> None:
        with self._lock:
            self._request(P.CMD_DEBUG_STEP_THREAD, P.STOPGO_PACKET.pack(lwpid))
            self._status("step_thread")

    def proc_stop(self, pid: int, state: int) -> None:
        """state: 0=resume, 1=stop, 2=kill."""
        with self._lock:
            self._request(P.CMD_DEBUG_PROCESS_STOP, P.PROC_STOP_RAW.pack(pid, state))
            self._status("proc_stop")

    # ---------------------------------------------------------------- kernel

    def kernel_base(self) -> int:
        with self._lock:
            self._request(P.CMD_KERN_BASE)
            self._status("kern_base")
            (base,) = struct.unpack("<Q", self._recv_exact(8))
        return base

    def kernel_read(self, address: int, length: int) -> bytes:
        with self._lock:
            self._request(P.CMD_KERN_READ, P.KERN_RW_PACKET.pack(address, length))
            self._status("kern_read")
            return self._recv_exact(length)

    def kernel_write(self, address: int, data: bytes) -> None:
        with self._lock:
            self._request(P.CMD_KERN_WRITE, P.KERN_RW_PACKET.pack(address, len(data)))
            self._status("kern_write ack")
            self._send(data)
            self._status("kern_write")  # second status, sent after the write (PROTOCOL.md §2.4)

    # --------------------------------------------------------------- console

    def notify(self, message: str, message_type: int = 222) -> None:
        body = P.NOTIFY_PACKET.pack(message_type, len(message) + 1)
        with self._lock:
            self._request(P.CMD_CONSOLE_NOTIFY, body)
            self._status("notify ack")
            self._send(message.encode("ascii", "replace") + b"\0")
            self._status("notify")

    # ------------------------------------------------------------ client scan

    def scan_aob(self, pid: int, start: int, length: int,
                 pattern: bytes, wildcard: int = 0xCC,
                 regions: list[dict] | None = None) -> list[int]:
        """Client-side AoB scan over proc_read; needs no scan auth.

        `wildcard` marks pattern bytes to skip. `regions` (from list_regions)
        restricts the scan to mapped ranges inside [start, start+length).
        """
        hits: list[int] = []
        if not pattern:
            return hits
        end = start + length
        spans = regions or [{"start": start, "end": end}]
        for region in spans:
            r_start = max(region["start"], start)
            r_end = min(region["end"], end)
            if r_end <= r_start:
                continue
            if (region.get("prot", 0) & 1) == 0:  # not readable
                continue
            pos = r_start
            while pos < r_end:
                take = min(CHUNK, r_end - pos)
                try:
                    buf = self.read_memory(pid, pos, take)
                except (Ps4DebugError, ConnectionError, OSError):
                    break  # unmapped race; skip rest of region
                hits.extend(_search_buffer(buf, pos, pattern, wildcard))
                pos += take
        return hits


def _search_buffer(buf: bytes, base: int, pattern: bytes, wildcard: int) -> list[int]:
    mask = bytes(0 if b == wildcard else 0xFF for b in pattern)
    hits = []
    plen = len(pattern)
    for i in range(max(0, len(buf) - plen + 1)):
        match = True
        for j in range(plen):
            if mask[j] and buf[i + j] != pattern[j]:
                match = False
                break
        if match:
            hits.append(base + i)
    return hits
