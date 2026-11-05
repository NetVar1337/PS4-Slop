import select
import socketserver
import sys
import uuid

from .client import BrokerClient
from .config import WorkbenchError, require_integer


CORE_NAMES = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs")
REGISTER_LAYOUT = [(name, 64 if index < 17 else 32) for index, name in enumerate(CORE_NAMES)]
REGISTER_LAYOUT += [("st" + str(index), 80) for index in range(8)]
REGISTER_LAYOUT += [(name, 32) for name in ("fctrl", "fstat", "ftag", "fiseg", "fioff", "foseg", "fooff", "fop")]
TARGET_XML = ('<?xml version="1.0"?><!DOCTYPE target SYSTEM "gdb-target.dtd"><target>'
              '<architecture>i386:x86-64</architecture><osabi>FreeBSD</osabi>'
              '<feature name="org.gnu.gdb.i386.core">' + ''.join(
                  f'<reg name="{name}" bitsize="{bits}" regnum="{index}" type="{"i387_ext" if bits == 80 else "int"}"/>'
                  for index, (name, bits) in enumerate(REGISTER_LAYOUT)) + '</feature></target>').encode()
MAX_PACKET = 16384


def numeric(value):
    return int(value, 0) if isinstance(value, str) else value


def memory_map_xml(mappings):
    regions = []
    for entry in mappings:
        if entry["protection"] & 1:
            regions.append(f'<memory type="ram" start="{hex(numeric(entry["start"]))}" length="{hex(numeric(entry["end"]) - numeric(entry["start"]))}"/>')
    return ('<?xml version="1.0"?><memory-map>' + ''.join(regions) + '</memory-map>').encode()


def frame(payload):
    encoded = bytearray()
    for value in payload:
        if value in (35, 36, 42, 125):
            encoded.extend((125, value ^ 32))
        else:
            encoded.append(value)
    return b"$" + encoded + b"#" + f"{sum(encoded) & 255:02x}".encode()


def register_bytes(values):
    output = []
    for name, bits in REGISTER_LAYOUT:
        source = "rflags" if name == "eflags" else name
        value = values.get(source)
        if value is None:
            output.append("xx" * (bits // 8))
        else:
            number = int(value, 16) & ((1 << bits) - 1)
            output.append(number.to_bytes(bits // 8, "little").hex())
    return "".join(output).encode()


class PacketDecoder:
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data):
        self.buffer.extend(data)
        messages = []
        while self.buffer:
            first = self.buffer[0]
            if first in (3, 43, 45):
                messages.append(("interrupt" if first == 3 else "ack" if first == 43 else "nak", b""))
                del self.buffer[0]
                continue
            if first != 36:
                raise WorkbenchError("Invalid RSP framing")
            delimiter = self.buffer.find(b"#", 1)
            if delimiter < 0:
                if len(self.buffer) > MAX_PACKET:
                    raise WorkbenchError("RSP packet exceeds limit")
                break
            if delimiter > MAX_PACKET:
                raise WorkbenchError("RSP packet exceeds limit")
            if len(self.buffer) < delimiter + 3:
                break
            encoded = bytes(self.buffer[1:delimiter])
            try:
                checksum = int(bytes(self.buffer[delimiter + 1:delimiter + 3]), 16)
            except ValueError:
                checksum = -1
            del self.buffer[:delimiter + 3]
            if checksum != sum(encoded) & 255:
                messages.append(("bad_checksum", b""))
                continue
            decoded = bytearray()
            escaped = False
            for value in encoded:
                if escaped:
                    decoded.append(value ^ 32)
                    escaped = False
                elif value == 125:
                    escaped = True
                elif value == 42:
                    raise WorkbenchError("Client-side RSP run-length encoding unsupported")
                else:
                    decoded.append(value)
            if escaped:
                raise WorkbenchError("Truncated RSP escape")
            messages.append(("packet", bytes(decoded)))
        return messages


class RspSession:
    def __init__(self, client, pid, listen_address, observer=False):
        require_integer(pid, "pid", 1, 0x7FFFFFFF)
        self.client = client
        self.pid = pid
        self.listen_address = listen_address
        self.observer = observer
        self.thread_id = None
        self.continue_thread = None
        self.cursor = client.state()["event_cursor"]
        self.last_stop = None
        self.awaiting_stop = False
        self.attached_here = False
        self.breakpoints = {}
        self.finished = False
        self.no_ack = False
        self.session_id = None
        self.map_xml = None

    def ensure_attached(self):
        state = self.client.state()
        if state["attached_pid"] is None:
            if self.observer:
                raise WorkbenchError("Observer requires an existing attached session")
            self.client.call("debug_attach", pid=self.pid, listen_address=self.listen_address)
            self.attached_here = True
        elif state["attached_pid"] != self.pid:
            raise WorkbenchError("Another process is already attached")
        elif not self.observer and state["controller"] != self.client.client:
            raise WorkbenchError("Another client owns the session; use a separate observer bridge")
        self.session_id = self.client.state()["session_id"]

    def require_control(self):
        if self.observer:
            raise WorkbenchError("Observer debugger cannot mutate or resume the target")
        self.ensure_attached()

    def current_thread(self):
        self.ensure_attached()
        if self.thread_id is None:
            threads = self.client.call("debug_threads")
            if not threads:
                raise WorkbenchError("No thread available")
            self.thread_id = threads[0]
        return self.thread_id

    def stop_reply(self, event):
        thread_id = event["thread_id"]
        self.thread_id = thread_id
        status = event["status"]
        if status & 255 != 127:
            raise WorkbenchError("Unsupported non-stop wait status; inspect broker event journal")
        signal = (status >> 8) & 255
        mapping = {2: 2, 4: 4, 5: 5, 8: 8, 10: 10, 11: 11, 17: 17, 19: 17}
        if signal not in mapping:
            raise WorkbenchError("Unmapped FreeBSD stop signal; inspect broker event journal")
        return f"T{mapping[signal]:02x}thread:{thread_id:x};".encode()

    def poll_stop(self):
        events = self.client.events(self.cursor)
        self.cursor = events["cursor"]
        if events["lost_events"]:
            raise WorkbenchError("Debug events were lost; target state is uncertain")
        reply = None
        for event in events["events"]:
            if event["type"] in ("session_error", "detached"):
                raise WorkbenchError("Shared debugger state changed or failed; inspect broker")
            if event["type"] == "stop":
                if event.get("session_id") != self.session_id:
                    continue
                self.last_stop = self.stop_reply(event)
                reply = self.last_stop
        if self.awaiting_stop and reply is not None:
            self.awaiting_stop = False
            return reply
        return None

    def read_memory(self, address, length):
        self.ensure_attached()
        require_integer(length, "RSP memory length", 0, MAX_PACKET // 2)
        if length == 0:
            return b""
        result = self.client.call("memory_peek", pid=self.pid, address=hex(address), length=length)
        content = bytes.fromhex(result["hex"])
        if len(content) != length:
            raise WorkbenchError("Short broker memory capture")
        return content.hex().encode()

    def set_breakpoint(self, command):
        self.require_control()
        kind_text, address_text, length_text = command[1:].split(",")
        kind, address, length = int(kind_text, 16), int(address_text, 16), int(length_text, 16)
        if kind not in (0, 1, 2, 4):
            return b""
        if kind == 0 and length != 1:
            raise WorkbenchError("x86 software breakpoints require one-byte kind")
        key = (kind, address, length)
        if command[0] == "z":
            if key not in self.breakpoints:
                return b"OK"
            index = self.breakpoints[key]
            enabled = False
        else:
            if key in self.breakpoints:
                return b"OK"
            used = {index for (other_kind, _, _), index in self.breakpoints.items() if (other_kind == 0) == (kind == 0)}
            index = next((slot for slot in range(30 if kind == 0 else 4) if slot not in used), None)
            if index is None:
                raise WorkbenchError("No breakpoint slots available")
            enabled = True
        if kind == 0:
            self.client.call("debug_breakpoint", index=index, address=hex(address), enabled=enabled)
        else:
            self.client.call("debug_watchpoint", index=index, address=hex(address), length=length,
                             access={1: "execute", 2: "write", 4: "read_write"}[kind], enabled=enabled)
        if enabled:
            self.breakpoints[key] = index
        else:
            del self.breakpoints[key]
        return b"OK"

    def resume(self, step=False, thread_id=None):
        self.require_control()
        if self.last_stop is None:
            raise WorkbenchError("Wait for a real stop event before resuming or stepping")
        self.cursor = self.client.state()["event_cursor"]
        if step:
            selected = thread_id or self.continue_thread or self.current_thread()
            self.client.call("debug_control", action="step_thread", thread_id=selected)
        else:
            if thread_id is not None:
                raise WorkbenchError("Thread-specific continue is not implemented; use all-stop continue")
            self.client.call("debug_control", action="resume")
        self.last_stop = None
        self.awaiting_stop = True
        return None

    def handle(self, payload):
        command = payload.decode("ascii")
        if command.startswith("qSupported"):
            return b"PacketSize=4000;qXfer:features:read+;qXfer:memory-map:read+;QStartNoAckMode+"
        if command == "QStartNoAckMode":
            self.no_ack = True
            return b"OK"
        if command.startswith("qXfer:features:read:target.xml:"):
            offset, length = (int(value, 16) for value in command.rsplit(":", 1)[1].split(","))
            require_integer(offset, "XML offset", 0, 0xFFFFFFFF)
            require_integer(length, "XML chunk", 1, MAX_PACKET - 1)
            return (b"l" if offset + length >= len(TARGET_XML) else b"m") + TARGET_XML[offset:offset + length]
        if command.startswith("qXfer:memory-map:read::"):
            self.ensure_attached()
            offset, length = (int(value, 16) for value in command.rsplit(":", 1)[1].split(","))
            require_integer(offset, "map XML offset", 0, 0xFFFFFFFF)
            require_integer(length, "map XML chunk", 1, MAX_PACKET - 1)
            if offset == 0:
                mappings = self.client.call("process_maps", pid=self.pid)
                if not isinstance(mappings, list):
                    raise WorkbenchError("Large map list requires artifact inspection")
                self.map_xml = memory_map_xml(mappings)
            if self.map_xml is None:
                raise WorkbenchError("Begin a memory map transfer at offset zero")
            content = self.map_xml
            return (b"l" if offset + length >= len(content) else b"m") + content[offset:offset + length]
        if command == "?":
            self.ensure_attached()
            state = self.client.state()
            if self.last_stop is not None and state["execution_state"] == "stopped":
                return self.last_stop
            if self.observer:
                if state["execution_state"] != "stopped":
                    raise WorkbenchError("Observer requires the controller to stop the target first")
                event = state.get("last_stop")
                if event is not None and event.get("session_id") == self.session_id:
                    self.last_stop = self.stop_reply(event)
                if self.last_stop is not None:
                    return self.last_stop
            self.awaiting_stop = True
            return self.poll_stop()
        if command.startswith("vAttach;"):
            if int(command.split(";", 1)[1], 16) != self.pid:
                raise WorkbenchError("Attach PID differs from explicitly configured PID")
            return self.handle(b"?")
        if command == "qAttached":
            return b"1"
        if command == "qC":
            return f"QC{self.current_thread():x}".encode()
        if command == "qfThreadInfo":
            self.ensure_attached()
            threads = self.client.call("debug_threads")
            return ("m" + ",".join(f"{thread_id:x}" for thread_id in threads)).encode() if threads else b"l"
        if command == "qsThreadInfo":
            return b"l"
        if command.startswith(("Hg", "Hc")):
            selected = int(command[2:], 16)
            thread_id = None if selected in (-1, 0) else selected
            if thread_id is not None and thread_id not in self.client.call("debug_threads"):
                raise WorkbenchError("Unknown thread")
            if command[1] == "g":
                self.thread_id = thread_id
            else:
                self.continue_thread = thread_id
            return b"OK"
        if command.startswith("T"):
            return b"OK" if int(command[1:], 16) in self.client.call("debug_threads") else b"E01"
        if command == "g" or command.startswith("p"):
            values = self.client.call("debug_registers", thread_id=self.current_thread())
            content = register_bytes(values)
            if command == "g":
                return content
            index = int(command[1:], 16)
            require_integer(index, "register index", 0, len(REGISTER_LAYOUT) - 1)
            offset = sum(bits // 4 for _, bits in REGISTER_LAYOUT[:index])
            return content[offset:offset + REGISTER_LAYOUT[index][1] // 4]
        if command.startswith("m"):
            address, length = (int(value, 16) for value in command[1:].split(","))
            return self.read_memory(address, length)
        if command.startswith(("Z", "z")):
            return self.set_breakpoint(command)
        if command == "vCont?":
            return b"vCont;c;s"
        if command.startswith("vCont;"):
            actions = command.split(";")[1:]
            if len(actions) != 1:
                raise WorkbenchError("Mixed per-thread vCont actions are unsupported")
            action, _, selected = actions[0].partition(":")
            if action not in ("c", "s"):
                return b""
            return self.resume(step=action == "s", thread_id=int(selected, 16) if selected else None)
        if command in ("c", "s"):
            return self.resume(step=command == "s")
        if command in ("D", f"D;{self.pid:x}"):
            self.cleanup()
            self.finished = True
            return b"OK"
        if command.startswith(("M", "X", "G", "P", "k", "vKill", "R", "vRun", "qRcmd")):
            return b"E01"
        return b""

    def interrupt(self):
        self.require_control()
        self.client.call("debug_control", action="halt")
        self.awaiting_stop = True

    def cleanup(self):
        if self.attached_here:
            self.client.call("debug_detach")
            self.attached_here = False


class RspServer(socketserver.TCPServer):
    allow_reuse_address = False

    def __init__(self, url, token_path, pid, listen_address, port=1234, observer=False, expected_profile=None):
        self.url = url
        self.token_path = token_path
        self.pid = pid
        self.listen_address = listen_address
        self.observer = observer
        self.expected_profile = expected_profile
        super().__init__(("127.0.0.1", port), RspHandler)


class RspHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client = BrokerClient(self.server.url, self.server.token_path, "gdb-" + uuid.uuid4().hex,
                              expected_profile=self.server.expected_profile)
        session = RspSession(client, self.server.pid, self.server.listen_address, self.server.observer)
        decoder = PacketDecoder()
        last_frame = None
        last_request = None
        unacknowledged = False
        try:
            while not session.finished:
                readable, _, _ = select.select([self.request], [], [], 0.05)
                if readable:
                    data = self.request.recv(16384)
                    if not data:
                        break
                    for kind, payload in decoder.feed(data):
                        if kind == "ack":
                            unacknowledged = False
                            continue
                        if kind == "nak":
                            if last_frame:
                                self.request.sendall(last_frame)
                            continue
                        if kind == "bad_checksum":
                            if not session.no_ack:
                                self.request.sendall(b"-")
                            continue
                        if kind == "packet" and not session.no_ack:
                            self.request.sendall(b"+")
                        if kind == "packet" and payload == last_request and unacknowledged:
                            if last_frame:
                                self.request.sendall(last_frame)
                            continue
                        try:
                            if kind == "interrupt":
                                session.interrupt()
                                response = None
                            else:
                                if session.awaiting_stop and payload == last_request:
                                    continue
                                response = session.handle(payload)
                                last_request = payload
                        except (WorkbenchError, ValueError, KeyError, UnicodeError) as error:
                            print(f"RSP command failed: {error}", file=sys.stderr)
                            response = b"E01"
                        if response is not None:
                            last_frame = frame(response)
                            self.request.sendall(last_frame)
                            unacknowledged = not session.no_ack
                if session.awaiting_stop:
                    try:
                        response = session.poll_stop()
                    except WorkbenchError as error:
                        print(f"RSP event failure: {error}", file=sys.stderr)
                        session.awaiting_stop = False
                        response = b"E01"
                    if response is not None:
                        last_frame = frame(response)
                        self.request.sendall(last_frame)
                        unacknowledged = not session.no_ack
        except (OSError, WorkbenchError) as error:
            print(f"RSP connection ended: {error}", file=sys.stderr)
        finally:
            try:
                session.cleanup()
            except WorkbenchError as error:
                print(f"RSP cleanup uncertain: {error}", file=sys.stderr)
