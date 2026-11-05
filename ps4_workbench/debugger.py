import socket
import struct
import time
from contextlib import contextmanager

from .config import WorkbenchError, require_integer


MAGIC = 0xFFAABBCC
SUCCESS = 0x80000000
REGISTER_FORMAT = "<15QIHHIHH5Q"
REGISTER_NAMES = ("r15", "r14", "r13", "r12", "r11", "r10", "r9", "r8", "rdi", "rsi", "rbp",
                  "rbx", "rdx", "rcx", "rax", "trapno", "fs", "gs", "err", "es", "ds", "rip", "cs", "rflags", "rsp", "ss")
EVENT_SIZE = 1184


def cstring(data):
    return data.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def registers(data):
    return {name: hex(value) for name, value in zip(REGISTER_NAMES, struct.unpack(REGISTER_FORMAT, data))}


def address_range(address, length, maximum):
    require_integer(address, "address", 0, 0xFFFFFFFFFFFFFFFF)
    require_integer(length, "length", 1, maximum)
    if address + length > 0x10000000000000000:
        raise WorkbenchError("Address range overflows uint64")


class Debugger:
    def __init__(self, profile):
        self.profile = profile
        self.connection = None
        self.identity = None
        self.attached_pid = None
        self.listener = None
        self.events = None
        self.event_buffer = bytearray()
        self.deadline = None

    def _close_sockets(self):
        for stream in (self.events, self.listener, self.connection):
            if stream is not None:
                stream.close()
        self.events = self.listener = self.connection = None
        self.identity = None
        self.attached_pid = None
        self.event_buffer.clear()

    def close(self):
        if self.attached_pid is not None and self.connection is not None:
            try:
                self.deadline = time.monotonic() + self.profile.timeout
                self._packet(0xBDBB0002)
                self._status()
            finally:
                self._close_sockets()
        else:
            self._close_sockets()

    def _remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise WorkbenchError("Debugger exchange deadline exceeded; state may be uncertain")
        self.connection.settimeout(remaining)

    def _read(self, length):
        result = bytearray()
        while len(result) < length:
            self._remaining()
            chunk = self.connection.recv(length - len(result))
            if not chunk:
                raise WorkbenchError("Debugger disconnected mid-response")
            result.extend(chunk)
        return bytes(result)

    def _packet(self, command, body=b""):
        self._remaining()
        self.connection.sendall(struct.pack("<III", MAGIC, command, len(body)) + body)

    def _status(self):
        status = struct.unpack("<I", self._read(4))[0]
        if status != SUCCESS:
            raise WorkbenchError(f"Debugger rejected command: 0x{status:08x}")

    def _text(self):
        length = struct.unpack("<I", self._read(4))[0]
        require_integer(length, "identity length", 1, 1024)
        return self._read(length).decode("utf-8", errors="strict")

    def _connect(self):
        if self.connection is not None:
            return
        self.connection = socket.create_connection((self.profile.host, self.profile.data["ports"]["debug"]), self.profile.timeout)
        self._packet(0xBD000001)
        version = self._text().rstrip("\0")
        if version != self.profile.data["debugger"]["protocol"]:
            raise WorkbenchError(f"Unsupported debugger protocol: {version}")
        self._packet(0xBD000501)
        brand, _, capability = self._text().partition("\0")
        if not brand.startswith("ps4debug-NG by Pharaoh2k v"):
            raise WorkbenchError("Unknown debugger branding; no legacy backend fallback")
        expected = self.profile.data["debugger"].get("expected_brand")
        if expected and brand != expected:
            raise WorkbenchError("Debugger brand does not match the pinned profile")
        self._packet(0xBD000500)
        encoded = struct.unpack("<H", self._read(2))[0]
        firmware = f"{encoded // 100}.{encoded % 100:02d}"
        if firmware != self.profile.data["firmware"]:
            raise WorkbenchError(f"Debugger firmware mismatch: {firmware}; expected 14.00")
        self._packet(0xBD000502)
        platform = struct.unpack("<H", self._read(2))[0]
        if platform != 4:
            raise WorkbenchError("Debugger does not identify as PS4")
        self.identity = {"brand": brand, "protocol": version, "capability": capability.rstrip("\0"),
                         "firmware": firmware, "firmware_encoding": "decimal_major_times_100",
                         "platform": platform, "binary_hash_remotely_verified": False,
                         "hardware_compatibility_guaranteed": False}

    @contextmanager
    def exchange(self):
        self.deadline = time.monotonic() + self.profile.timeout
        try:
            self._connect()
            yield
        except Exception:
            self._close_sockets()
            raise

    def info(self):
        with self.exchange():
            self._packet(0xBDAACC06)
            self._status()
            return dict(self.identity)

    def kernel_base(self):
        self.require_qualified_debugger("kernel_read")
        with self.exchange():
            self._packet(0xBDCC0001)
            self._status()
            return {"kernel_base": hex(struct.unpack("<Q", self._read(8))[0])}

    def _list(self, command, body, entry_size, decode):
        with self.exchange():
            self._packet(command, body)
            self._status()
            count = struct.unpack("<I", self._read(4))[0]
            require_integer(count, "server entry count", 0, self.profile.limit("list_entries"))
            return [decode(self._read(entry_size)) for _ in range(count)]

    def processes(self):
        def decode(data):
            name, pid = struct.unpack("<32sI", data)
            return {"pid": pid, "name": cstring(name)}
        return self._list(0xBDAA0001, b"", 36, decode)

    def maps(self, pid):
        require_integer(pid, "pid", 1, 0x7FFFFFFF)

        def decode(data):
            start, end, offset, protection, name = struct.unpack("<QQQQ32s", data)
            if end < start:
                raise WorkbenchError("Invalid memory map range")
            return {"start": start, "end": end, "offset": offset, "protection": protection, "name": cstring(name)}
        return self._list(0xBDAA0004, struct.pack("<I", pid), 64, decode)

    def process_info(self, pid):
        require_integer(pid, "pid", 1, 0x7FFFFFFF)
        with self.exchange():
            self._packet(0xBDAA000A, struct.pack("<I", pid))
            self._status()
            values = struct.unpack("<I40s64s16s64s", self._read(188))
            return {"pid": values[0], **{name: cstring(value) for name, value in zip(("name", "path", "title_id", "content_id"), values[1:])}}

    def read_memory(self, pid, address, length, kernel=False):
        address_range(address, length, self.profile.limit("memory_bytes"))
        if kernel:
            self.require_qualified_debugger("kernel_read")
            command, body = 0xBDCC0002, struct.pack("<QI", address, length)
        else:
            require_integer(pid, "pid", 1, 0x7FFFFFFF)
            command, body = 0xBDAA0002, struct.pack("<IQI", pid, address, length)
        with self.exchange():
            self._packet(command, body)
            self._status()
            return self._read(length)

    def require_qualified_debugger(self, permission):
        qualification = self.profile.require(permission)
        settings = self.profile.data["debugger"]
        if not settings.get("expected_brand") or not settings.get("payload_sha256"):
            raise WorkbenchError("Pin expected_brand and payload_sha256 before debugger mutations")
        if qualification.get("debugger_payload_sha256") != settings["payload_sha256"]:
            raise WorkbenchError("Debugger binary hash differs from hardware qualification")

    def write_memory(self, pid, address, content, kernel=False):
        self.require_qualified_debugger("kernel_write" if kernel else "process_write")
        address_range(address, len(content), self.profile.limit("memory_bytes"))
        if kernel:
            command, body = 0xBDCC0003, struct.pack("<QI", address, len(content))
        else:
            require_integer(pid, "pid", 1, 0x7FFFFFFF)
            command, body = 0xBDAA0003, struct.pack("<IQI", pid, address, len(content))
        with self.exchange():
            if not kernel and self.identity["capability"] != "1.1":
                raise WorkbenchError("Process writes require exactly capability 1.1 verified-write semantics")
            self._packet(command, body)
            self._status()
            self._remaining()
            self.connection.sendall(content)
            self._status()

    def _session_required(self):
        if self.attached_pid is None:
            raise WorkbenchError("No active debug session; attach first in this MCP process")

    def attach(self, pid, listen_address):
        self.require_qualified_debugger("debug_control")
        require_integer(pid, "pid", 1, 0x7FFFFFFF)
        if self.attached_pid is not None:
            raise WorkbenchError("Already attached; detach before selecting another process")
        socket.inet_pton(socket.AF_INET, listen_address)
        if listen_address in ("0.0.0.0", "255.255.255.255"):
            raise WorkbenchError("Bind the callback to an explicit local IPv4 interface")
        with self.exchange():
            self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener.bind((listen_address, 755))
            self.listener.listen(1)
            self.listener.settimeout(self.profile.timeout)
            self._packet(0xBDBB0001, struct.pack("<I", pid) + socket.inet_aton(listen_address))
            self._status()
            self.attached_pid = pid
            self.events, peer = self.listener.accept()
            if peer[0] != self.profile.host:
                raise WorkbenchError("Rejected debugger callback from unexpected peer")
            self.events.setblocking(False)
            self.listener.close()
            self.listener = None
            return {"pid": pid, "callback_port": 755, "attached": True}

    def detach(self):
        self._session_required()
        with self.exchange():
            self._packet(0xBDBB0002)
            self._status()
        self._close_sockets()
        return {"detached": True}

    def threads(self):
        self._session_required()
        return self._list(0xBDBB0005, b"", 4, lambda data: struct.unpack("<I", data)[0])

    def get_registers(self, thread_id):
        self._session_required()
        require_integer(thread_id, "thread_id", 1, 0x7FFFFFFF)
        with self.exchange():
            self._packet(0xBDBB0008, struct.pack("<I", thread_id))
            self._status()
            return registers(self._read(struct.calcsize(REGISTER_FORMAT)))

    def control(self, action, thread_id=0):
        self.require_qualified_debugger("debug_control")
        self._session_required()
        if action in ("resume", "halt"):
            command, body = 0xBDBB0010, struct.pack("<I", int(action == "halt"))
        elif action == "step":
            command, body = 0xBDBB0012, b""
        elif action in ("step_thread", "suspend_thread", "resume_thread"):
            require_integer(thread_id, "thread_id", 1, 0x7FFFFFFF)
            command = {"step_thread": 0xBDBB0013, "suspend_thread": 0xBDBB0006, "resume_thread": 0xBDBB0007}[action]
            body = struct.pack("<I", thread_id)
        else:
            raise WorkbenchError("Unsupported debug action")
        with self.exchange():
            self._packet(command, body)
            self._status()
        return {"action": action, "acknowledged": True}

    def breakpoint(self, index, address, enabled=True):
        self.require_qualified_debugger("debug_control")
        self._session_required()
        require_integer(index, "index", 0, 29)
        address_range(address, 1, 1)
        with self.exchange():
            self._packet(0xBDBB0003, struct.pack("<IIQ", index, int(enabled), address))
            self._status()
        return {"index": index, "address": hex(address), "enabled": enabled}

    def watchpoint(self, index, address, length, access, enabled=True):
        self.require_qualified_debugger("debug_control")
        self._session_required()
        require_integer(index, "index", 0, 3)
        if length not in (1, 2, 4, 8) or access not in ("execute", "write", "read_write"):
            raise WorkbenchError("Invalid watchpoint length or access")
        address_range(address, length, 8)
        if address % length or (access == "execute" and length != 1):
            raise WorkbenchError("Watchpoint must be aligned; execute requires length 1")
        with self.exchange():
            self._packet(0xBDBB0004, struct.pack("<IIIIQ", index, int(enabled), {1: 0, 2: 1, 4: 3, 8: 2}[length],
                                               {"execute": 0, "write": 1, "read_write": 3}[access], address))
            self._status()
        return {"index": index, "enabled": enabled}

    def poll_events(self):
        self._session_required()
        result = []
        while len(result) < 16:
            while len(self.event_buffer) < EVENT_SIZE:
                try:
                    chunk = self.events.recv(EVENT_SIZE - len(self.event_buffer))
                except BlockingIOError:
                    return result
                if not chunk:
                    raise WorkbenchError("Debug callback disconnected; detach and inspect console state")
                self.event_buffer.extend(chunk)
            data = bytes(self.event_buffer)
            self.event_buffer.clear()
            thread_id, status = struct.unpack_from("<II", data)
            result.append({"thread_id": thread_id, "status": status, "name": cstring(data[8:48]),
                           "registers": registers(data[48:224]), "raw_hex": data.hex()})
        return result
