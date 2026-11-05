import collections
import hmac
import json
import os
import re
import secrets
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .artifacts import utc_now
from .agents import AnalysisAgents
from .config import WorkbenchError, require_integer


MAX_BODY = 1048576
CONTROL_TOOLS = {
    "debug_attach", "debug_control", "debug_breakpoint", "debug_watchpoint",
    "memory_write", "kernel_write", "debug_detach", "debug_step", "debug_run",
    "debug_registers_set", "debug_registers_fpu_set", "debug_tls_set",
    "debug_breakpoint_load", "memory_patch", "patch_restore", "memory_alloc",
    "memory_free", "memory_protect",
}


def token_file(profile):
    return profile.path.parent / "broker-token.local"


def load_token(path, create=False):
    path = Path(path).resolve()
    if create and not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(secrets.token_hex(32) + "\n")
    token = path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise WorkbenchError("Broker token file must contain exactly 64 lowercase hex characters")
    return token


class SessionHub:
    def __init__(self, registry):
        self.registry = registry
        self.debug_lock = threading.RLock()
        self.controller = None
        self.journal = collections.deque(maxlen=1024)
        self.sequence = 0
        self.event_failure = False
        self.stopping = threading.Event()
        self.worker = None
        self.session_id = None
        self.analysis = AnalysisAgents()
        self.execution_state = "detached"
        self.last_stop = None

    def publish(self, event):
        self.sequence += 1
        self.journal.append({"sequence": self.sequence, "received_at": utc_now(), **event})

    def events_since(self, cursor, limit=1024):
        require_integer(cursor, "cursor", 0, 9007199254740991)
        require_integer(limit, "event limit", 1, 1024)
        with self.debug_lock:
            if cursor > self.sequence:
                raise WorkbenchError("Event cursor is ahead of this broker; reconnect explicitly after a restart")
            oldest = self.journal[0]["sequence"] if self.journal else self.sequence + 1
            selected = [entry for entry in self.journal if entry["sequence"] > cursor][:limit]
            return {"events": selected, "cursor": selected[-1]["sequence"] if selected else self.sequence,
                    "latest_cursor": self.sequence, "lost_events": max(0, oldest - cursor - 1)}

    def pump(self):
        with self.debug_lock:
            debugger = self.registry.workbench.debugger
            if debugger.attached_pid is None or self.event_failure:
                return
            try:
                for event in debugger.poll_events():
                    self.execution_state = "stopped"
                    self.publish({"type": "stop", "pid": debugger.attached_pid, "session_id": self.session_id, **event})
                    self.last_stop = {"thread_id": event["thread_id"], "status": event["status"],
                                      "session_id": self.session_id, "sequence": self.sequence}
            except Exception as error:
                self.event_failure = True
                self.execution_state = "uncertain"
                self.publish({"type": "session_error", "error": str(error), "console_state": "uncertain"})

    def start(self):
        def run():
            while not self.stopping.wait(0.05):
                self.pump()
        self.worker = threading.Thread(target=run, name="ps4-event-pump", daemon=True)
        self.worker.start()

    def close(self):
        self.stopping.set()
        if self.worker:
            self.worker.join(timeout=2)
        with self.debug_lock:
            self.registry.workbench.close()

    def state(self):
        with self.debug_lock:
            return {"controller": self.controller, "attached_pid": self.registry.workbench.debugger.attached_pid,
                    "profile_sha256": self.registry.workbench.profile.fingerprint,
                    "host": self.registry.workbench.profile.host,
                    "event_cursor": self.sequence, "event_channel_failed": self.event_failure,
                    "session_id": self.session_id,
                    "execution_state": self.execution_state,
                    "last_stop": self.last_stop,
                    "hardware_compatibility_guaranteed": False}

    def _resolve_runtime_base(self, pid=None, module=None, runtime_addr=None):
        debugger = self.registry.workbench.debugger
        target_pid = pid if pid is not None else debugger.attached_pid
        if target_pid is None:
            return None, module
        mappings = debugger.maps(target_pid)
        if not isinstance(mappings, list) or not mappings:
            return None, module
        from .rsp import numeric
        by_mod = {}
        for entry in mappings:
            name = str(entry.get("name") or "anonymous")
            start, end = numeric(entry["start"]), numeric(entry["end"])
            if name not in by_mod:
                by_mod[name] = [start, end]
            else:
                by_mod[name][0] = min(by_mod[name][0], start)
                by_mod[name][1] = max(by_mod[name][1], end)
        if module:
            needle = module.lower()
            for name, (start, _) in by_mod.items():
                if name.lower() == needle or needle in name.lower():
                    return start, name
        if runtime_addr is not None:
            for name, (start, end) in by_mod.items():
                if start <= runtime_addr < end:
                    return start, name
        if "eboot.bin" in by_mod:
            return by_mod["eboot.bin"][0], "eboot.bin"
        first_name = next(iter(by_mod))
        return by_mod[first_name][0], first_name

    def _analysis_call(self, name, arguments):
        from .tools import parse_address, validate
        description = next((tool for tool in analysis_tools() if tool["name"] == name), None)
        if description is None:
            raise WorkbenchError("Unknown static-analysis tool")
        validate(arguments, description["inputSchema"])
        if name == "analysis_status":
            return self.analysis.status()
        if name == "analysis_sync_annotations":
            target = arguments["target"]
            direction = arguments.get("direction", "bidirectional")
            static_base = parse_address(arguments.get("static_base", "0x0"))
            max_items = arguments.get("max_items", 100)
            rt_base, mod_name = self._resolve_runtime_base(arguments.get("pid"), arguments.get("module"))
            effective_rt = rt_base if rt_base is not None else static_base
            debugger = self.registry.workbench.debugger
            labels = getattr(debugger, "labels", None)
            if labels is None:
                labels = {}
                debugger.labels = labels
            imported = 0
            exported_renames = 0
            if direction in ("import_from_static", "bidirectional"):
                funcs = self.analysis.submit(target, "functions", {"offset": 0, "limit": min(max_items, 100)}) or []
                for fn in funcs[:max_items]:
                    fn_name = str(fn.get("name", ""))
                    if not fn_name or fn_name.startswith(("sub_", "FUN_", "fcn.", "loc_")):
                        continue
                    st_addr = parse_address(str(fn["address"]))
                    if st_addr >= static_base:
                        labels[fn_name] = effective_rt + (st_addr - static_base)
                        imported += 1
            if direction in ("export_to_static", "bidirectional"):
                for lbl_name, rt_addr in list(labels.items())[:max_items]:
                    if rt_addr >= effective_rt:
                        st_addr = static_base + (rt_addr - effective_rt)
                        self.analysis.submit(target, "rename", {"address": hex(st_addr), "name": lbl_name})
                        exported_renames += 1
            return {
                "target": target,
                "direction": direction,
                "module": mod_name,
                "runtime_base": hex(effective_rt),
                "static_base": hex(static_base),
                "imported_labels": imported,
                "exported_renames": exported_renames,
            }
        fields = {k: v for k, v in arguments.items() if k not in ("target", "runtime_address", "pid", "module", "static_base")}
        if "address" not in fields and "runtime_address" in arguments:
            rt_addr = parse_address(arguments["runtime_address"])
            st_base = parse_address(arguments.get("static_base", "0x0"))
            rt_base, _ = self._resolve_runtime_base(arguments.get("pid"), arguments.get("module"), rt_addr)
            if rt_base is None or rt_addr < rt_base:
                raise WorkbenchError("Cannot rebase runtime_address without a matching live process module")
            fields["address"] = hex(st_base + (rt_addr - rt_base))
        result = self.analysis.submit(arguments["target"], name.removeprefix("analysis_"), fields)
        encoded = json.dumps(result, ensure_ascii=True, allow_nan=False).encode()
        if len(encoded) > 24576:
            return {"result_saved": self.registry.workbench.store.save("static-analysis", encoded, {"tool": name}, "json")}
        return result

    def call(self, client, name, arguments):
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,96}", client):
            raise WorkbenchError("Use a simple unique broker client identifier")
        if name == "debug_events":
            raise WorkbenchError("Shared events use events_since(cursor); draining the callback is broker-owned")
        if name.startswith("analysis_"):
            return self._analysis_call(name, arguments)
        shared = (
            name.startswith(("debug_", "process_", "memory_", "kernel_", "patch_"))
            or name in ("debugger_info", "address_correlate", "address_rebase", "disassemble", "module_list", "code_xrefs", "payload_execute")
        )
        if not shared:
            return self.registry.call(name, arguments)
        with self.debug_lock:
            if name == "payload_execute" and self.registry.workbench.debugger.attached_pid is not None:
                raise WorkbenchError("Detach the active debug session before sending a payload")
            from .tools import validate
            tool = self.registry.tools.get(name)
            if tool is None or tool not in self.registry.available():
                raise WorkbenchError("Unknown or locally disabled tool: " + name)
            validate(arguments, tool.schema)
            if tool.permission:
                self.registry.workbench.profile.require(tool.permission)
            if name in CONTROL_TOOLS and self.controller not in (None, client):
                raise WorkbenchError("Another client owns debug control; observers may still read memory and events")
            claimed = name == "debug_attach" and self.controller is None
            if claimed:
                self.controller = client
                self.session_id = uuid.uuid4().hex
                self.execution_state = "attaching"
                self.last_stop = None
            try:
                result = self.registry.call(name, arguments)
            except Exception:
                if name in CONTROL_TOOLS or (self.registry.workbench.debugger.attached_pid is None and self.controller is not None):
                    self.execution_state = "uncertain"
                if claimed:
                    self.publish({"type": "session_error", "error": "Attach failed; inspect console before retrying", "console_state": "uncertain"})
                raise
            if name in ("debug_attach", "debug_detach"):
                self.event_failure = False
            if name == "debug_detach":
                self.controller = None
                self.publish({"type": "detached"})
                self.session_id = None
                self.execution_state = "detached"
                self.last_stop = None
            elif name == "debug_control":
                self.execution_state = "halting" if arguments.get("action") == "halt" else "running" if arguments.get("action") in ("resume", "step", "step_thread") else self.execution_state
            return result

    def dispatch(self, client, operation, arguments):
        if operation == "tools":
            tools = [tool.describe() for tool in self.registry.available() if tool.name != "debug_events"]
            return tools + analysis_tools()
        if operation == "call":
            if not isinstance(arguments.get("name"), str) or not isinstance(arguments.get("arguments", {}), dict):
                raise WorkbenchError("call requires name and object arguments")
            return self.call(client, arguments["name"], arguments.get("arguments", {}))
        if operation == "events":
            limit = require_integer(arguments.get("limit", 64), "event page limit", 1, 64)
            return self.events_since(arguments.get("cursor", 0), limit)
        if operation == "state":
            return self.state()
        if operation == "agent_register":
            return self.analysis.register(client, arguments["target"], arguments["program"])
        if operation == "agent_poll":
            return self.analysis.poll(client, arguments["target"])
        if operation == "agent_unregister":
            return self.analysis.unregister(client, arguments["target"])
        if operation == "agent_result":
            return self.analysis.complete(client, arguments["identifier"], arguments.get("result"), arguments.get("error"))
        if operation == "release":
            with self.debug_lock:
                if self.controller != client:
                    raise WorkbenchError("Only the controlling client can release its lease")
                if self.registry.workbench.debugger.attached_pid is not None:
                    raise WorkbenchError("Detach before releasing debug control")
                self.controller = None
                return self.state()
        raise WorkbenchError("Unknown broker operation")


def analysis_tools():
    from .tools import ADDRESS, PID, integer, text
    target = text("Live static-analysis application", enum=["ida", "ghidra", "binja", "iaito"])
    rebase_fields = {
        "runtime_address": ADDRESS,
        "pid": PID,
        "module": text("Module name for runtime_address rebasing", 256, minLength=1),
        "static_base": ADDRESS,
    }
    operations = [
        ("analysis_status", "Connected IDA/Ghidra/Binary Ninja/iaito analysis agents; no application is launched automatically.", {}, [], True),
        ("analysis_decompile", "Decompile a function in a connected IDA/Ghidra/Binary Ninja/iaito database (supply static address or runtime_address).",
         {"target": target, "address": ADDRESS, **rebase_fields}, ["target"], True),
        ("analysis_functions", "List a bounded page of functions from a connected static-analysis database.",
         {"target": target, "offset": integer(0, 1000000), "limit": integer(1, 100), "filter": text("Substring filter", 256, minLength=1)}, ["target"], True),
        ("analysis_xrefs", "List bounded references to/from a static database address.",
         {"target": target, "address": ADDRESS, **rebase_fields, "limit": integer(1, 100),
          "direction": text("Reference direction", enum=["to", "from", "both"])}, ["target"], True),
        ("analysis_disasm", "Disassemble instructions at a static database address.",
         {"target": target, "address": ADDRESS, **rebase_fields, "count": integer(1, 256)}, ["target"], True),
        ("analysis_strings", "List strings in a connected static-analysis database.",
         {"target": target, "offset": integer(0, 1000000), "limit": integer(1, 100),
          "filter": text("Substring filter", 256, minLength=1), "min_length": integer(1, 256)}, ["target"], True),
        ("analysis_imports", "List imported symbols in a connected static-analysis database (with Orbis NID demangling when available).",
         {"target": target, "offset": integer(0, 1000000), "limit": integer(1, 100),
          "filter": text("Substring filter", 256, minLength=1)}, ["target"], True),
        ("analysis_rename", "Rename a function or label in a connected static-analysis database (does not touch console).",
         {"target": target, "address": ADDRESS, **rebase_fields, "name": text("New symbol name", 256, minLength=1)}, ["target", "name"], False),
        ("analysis_comment", "Set or clear an address comment in a connected static-analysis database (does not touch console).",
         {"target": target, "address": ADDRESS, **rebase_fields, "text": text("Comment text", 2048)}, ["target", "text"], False),
        ("analysis_sync_annotations", "Synchronize debugger labels/breakpoints and static-analysis function names/comments with automatic ASLR rebasing.",
         {"target": target, "direction": text("Sync direction", enum=["import_from_static", "export_to_static", "bidirectional"]),
          "pid": PID, "module": text("Module name", 256, minLength=1), "static_base": ADDRESS, "max_items": integer(1, 500)}, ["target"], False),
    ]
    return [{"name": name, "description": description,
             "inputSchema": {"type": "object", "properties": properties, "required": required, "additionalProperties": False},
             "annotations": {"readOnlyHint": read_only, "destructiveHint": False, "openWorldHint": True}}
            for name, description, properties, required, read_only in operations]


class BrokerServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = False

    def __init__(self, hub, token, port=8765):
        require_integer(port, "broker port", 0, 65535)
        self.hub = hub
        self.token = token
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(("127.0.0.1", port), BrokerHandler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class BrokerHandler(BaseHTTPRequestHandler):
    server_version = "PS4Workbench"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *arguments):
        pass

    def respond(self, status, value):
        content = json.dumps(value, ensure_ascii=True, allow_nan=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self):
        expected_host = f"127.0.0.1:{self.server.server_port}"
        authorization = self.headers.get("Authorization", "")
        if self.headers.get("Host") != expected_host or self.headers.get("Origin") is not None:
            self.respond(403, {"error": "Loopback native clients only; browser origins are forbidden"})
            return
        if not authorization.isascii() or not hmac.compare_digest(authorization, "Bearer " + self.server.token):
            self.respond(401, {"error": "Broker authentication required"})
            return
        try:
            if self.path != "/rpc" or self.headers.get("Transfer-Encoding") is not None:
                raise WorkbenchError("Use POST /rpc with Content-Length")
            length = int(self.headers.get("Content-Length", "0"))
            require_integer(length, "body length", 1, MAX_BODY)
            content = self.rfile.read(length)
            if len(content) != length:
                raise WorkbenchError("Truncated request body")
            request = json.loads(content)
            if not isinstance(request, dict) or not isinstance(request.get("arguments", {}), dict):
                raise WorkbenchError("Request must be an operation/arguments object")
            expected_profile = request.get("profile_sha256")
            if expected_profile != self.server.hub.registry.workbench.profile.fingerprint:
                if expected_profile is not None or request.get("operation") != "state":
                    raise WorkbenchError("Broker profile mismatch; reconnect explicitly to the intended console profile")
            client = self.headers.get("X-PS4-Client", "")
            if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,96}", client):
                raise WorkbenchError("Missing or invalid client identity")
            result = self.server.hub.dispatch(client, request.get("operation"), request.get("arguments", {}))
            self.respond(200, {"result": result})
        except (WorkbenchError, ValueError, KeyError, TypeError, OSError, RecursionError) as error:
            self.respond(400, {"error": str(error)})
        except Exception:
            self.respond(500, {"error": "Internal broker failure; no automatic retry"})
