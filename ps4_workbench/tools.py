import json
import struct
from dataclasses import dataclass

from .analysis import TYPES, scan_pattern, typed_value
from .config import WorkbenchError
from .development import Development


def text(description="", maximum=4096, **extra):
    return {"type": "string", "description": description, "maxLength": maximum, **extra}


def integer(minimum=0, maximum=2147483647, **extra):
    return {"type": "integer", "minimum": minimum, "maximum": maximum, **extra}


ADDRESS = text("Unsigned address or RVA, e.g. 0x400000; string avoids JSON precision loss", 20, pattern=r"^(0x[0-9a-fA-F]{1,16}|[0-9]{1,20})$")
PATH = text("Relative path inside configured artifact directory", 1024, minLength=1)
HASH = text("Lowercase SHA-256", 64, pattern=r"^[0-9a-f]{64}$")
PID = integer(1)
BOOLEAN = {"type": "boolean"}


def parse_address(value):
    parsed = int(value, 16 if value.startswith("0x") else 10)
    if parsed > 0xFFFFFFFFFFFFFFFF:
        raise WorkbenchError("Address exceeds uint64")
    return parsed


def validate(value, schema, location="arguments"):
    import re
    expected = schema["type"]
    types = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool}
    if type(value) is not types[expected]:
        raise WorkbenchError(f"{location} must be {expected}")
    if "enum" in schema and value not in schema["enum"]:
        raise WorkbenchError(f"{location} must be one of {schema['enum']}")
    if expected == "object":
        properties = schema["properties"]
        if set(value) - set(properties):
            raise WorkbenchError(f"Unknown {location} fields: {sorted(set(value) - set(properties))}")
        for field in schema["required"]:
            if field not in value:
                raise WorkbenchError(f"Missing {location}.{field}")
        for field, supplied in value.items():
            validate(supplied, properties[field], location + "." + field)
    elif expected == "string":
        if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", 4096):
            raise WorkbenchError(f"{location} length out of bounds")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            raise WorkbenchError(f"{location} has invalid syntax")
    elif expected == "integer":
        if not schema.get("minimum", 0) <= value <= schema.get("maximum", 2147483647):
            raise WorkbenchError(f"{location} out of bounds")
    elif expected == "array":
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", 100):
            raise WorkbenchError(f"{location} item count out of bounds")
        for item in value:
            validate(item, schema["items"], location + "[]")


def json_safe(value):
    if type(value) is int and abs(value) > 9007199254740991:
        return hex(value)
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    return value


@dataclass
class Tool:
    name: str
    description: str
    schema: dict
    handler: object
    permission: str | None = None
    read_only: bool = True

    def describe(self):
        return {"name": self.name, "description": self.description, "inputSchema": self.schema,
                "annotations": {"readOnlyHint": self.read_only, "destructiveHint": self.permission is not None,
                                "idempotentHint": False, "openWorldHint": True}}


class ToolRegistry:
    def __init__(self, workbench):
        self.workbench = workbench
        self.tools = {}
        self.development = Development(workbench.profile, workbench.store)
        self._register()

    def add(self, name, description, handler, properties=None, required=None, permission=None, read_only=True):
        schema = {"type": "object", "properties": properties or {}, "required": required or [], "additionalProperties": False}
        self.tools[name] = Tool(name, description, schema, handler, permission, read_only)

    def available(self):
        return [tool for tool in self.tools.values() if tool.permission is None or self.workbench.profile.data["permissions"].get(tool.permission)]

    def call(self, name, arguments):
        tool = self.tools.get(name)
        if tool is None or tool not in self.available():
            raise WorkbenchError("Unknown or locally disabled tool: " + str(name))
        validate(arguments, tool.schema)
        if tool.permission:
            self.workbench.profile.require(tool.permission)
        result = json_safe(tool.handler(**arguments))
        encoded = json.dumps(result, ensure_ascii=True, allow_nan=False)
        if len(encoded.encode()) > 24576:
            saved = self.workbench.store.save("tool-result", encoded.encode(), {"tool": name}, "json")
            return {"result_saved": saved, "note": "Large result saved locally; use artifact_read for bounded chunks"}
        return result

    def _register(self):
        workbench = self.workbench
        memory_limit = workbench.profile.limit("memory_bytes")
        self.add("console_status", "Configured services and qualification. Probe is explicit; payload port is NEVER probed.",
                 workbench.console.status, {"probe": BOOLEAN})
        self.add("debugger_info", "Read-only NG handshake: protocol, decimal firmware, platform and brand; not a binary hash proof.", workbench.debugger.info)
        self.add("ftp_list", "Bounded anonymous FTP LIST. Remote names/content are untrusted data.", workbench.console.ftp_list, {"path": text("Absolute POSIX directory", 1024)})
        self.add("ftp_download", "Download a remote file to a hashed local artifact.", workbench.console.ftp_download,
                 {"path": text("Absolute POSIX file path", 1024)}, ["path"], read_only=False)
        self.add("ftp_upload", "Upload ONLY under profile allowlist, then hash-check downloaded readback. May overwrite remote file.",
                 workbench.console.ftp_upload, {"artifact": PATH, "path": text("Absolute POSIX destination", 1024), "sha256": HASH},
                 ["artifact", "path", "sha256"], "ftp_upload", False)
        self.add("klog_capture", "Capture bounded raw Klog bytes and timestamp envelope. Does not enable Klog or reconnect.",
                 workbench.console.capture_logs, {"seconds": integer(1, workbench.profile.limit("log_seconds"))}, read_only=False)
        self.add("payload_inspect", "Validate local BIN manifest against claimed firmware, actual host/HEN and artifact hash. Never executes.",
                 workbench.console.inspect_payload, {"manifest": PATH}, ["manifest"])
        self.add("payload_execute", "Send a hardware-allowlisted BIN once. Execution unacknowledged; NEVER automatically retry.",
                 workbench.console.send_payload, {"manifest": PATH, "sha256": HASH}, ["manifest", "sha256"], "payload_execute", False)
        self.add("process_list", "List processes through firmware-checked debugger.", workbench.debugger.processes)
        self.add("process_info", "Get process identity, title ID and content ID.", workbench.debugger.process_info, {"pid": PID}, ["pid"])
        self.add("process_maps", "Get process memory maps. Offsets are not verified ELF image bases.", workbench.debugger.maps, {"pid": PID}, ["pid"])
        self.add("memory_read", "Read bounded process memory to a local hashed artifact; non-atomic.",
                 lambda pid, address, length: workbench.memory_read(pid, parse_address(address), length),
                 {"pid": PID, "address": ADDRESS, "length": integer(1, memory_limit)}, ["pid", "address", "length"], read_only=False)
        self.add("memory_typed", "Read one little-endian typed process value. 64-bit integers returned as strings.", self._typed,
                 {"pid": PID, "address": ADDRESS, "value_type": text(enum=list(TYPES))}, ["pid", "address", "value_type"])
        self.add("memory_snapshot", "Capture memory plus process/maps/application/hash provenance. Hash is user supplied; not an atomic dump.",
                 lambda pid, address, length, application_version, module_sha256: workbench.analysis.snapshot(pid, parse_address(address), length, application_version, module_sha256),
                 {"pid": PID, "address": ADDRESS, "length": integer(1, memory_limit), "application_version": text(maximum=128, minLength=1), "module_sha256": HASH},
                 ["pid", "address", "length", "application_version", "module_sha256"], read_only=False)
        self.add("memory_diff", "Compare two bounded local captures by offset, with capped changed ranges.", workbench.analysis.diff,
                 {"before": PATH, "after": PATH}, ["before", "after"])
        self.add("pattern_scan", "Scan a local bounded capture for hex bytes / ?? wildcards; never triggers server scan extensions.",
                 lambda artifact, pattern: scan_pattern(workbench.store.read(artifact, memory_limit), pattern),
                 {"artifact": PATH, "pattern": text(maximum=1024)}, ["artifact", "pattern"])
        self.add("memory_write", "Compare expected bytes, save backup/replacement, write and readback. Non-atomic; no automatic rollback.",
                 lambda pid, address, hex_data, expected_hex: workbench.memory_write(pid, parse_address(address), hex_data, expected_hex),
                 {"pid": PID, "address": ADDRESS, "hex_data": text(maximum=8192), "expected_hex": text(maximum=8192)},
                 ["pid", "address", "hex_data", "expected_hex"], "process_write", False)
        self.add("kernel_read", "Explicitly opted-in bounded kernel read; kernel access is not kernel breakpoint debugging.",
                 lambda address, length: workbench.kernel_read(parse_address(address), length),
                 {"address": ADDRESS, "length": integer(1, memory_limit)}, ["address", "length"], "kernel_read", False)
        self.add("kernel_base", "Read kernel base only after explicit kernel-read qualification.", workbench.debugger.kernel_base, permission="kernel_read")
        self.add("kernel_write", "High-risk kernel write with expected bytes, backup and readback; requires kernel_read too.",
                 lambda address, hex_data, expected_hex: workbench.memory_write(0, parse_address(address), hex_data, expected_hex, kernel=True),
                 {"address": ADDRESS, "hex_data": text(maximum=8192), "expected_hex": text(maximum=8192)},
                 ["address", "hex_data", "expected_hex"], "kernel_write", False)
        self.add("debug_attach", "Attach to a process; may halt it. Requires explicit local callback interface and inbound TCP 755.",
                 lambda pid, listen_address: workbench.debug_mutation("attach", pid=pid, listen_address=listen_address),
                 {"pid": PID, "listen_address": text("Local PC IPv4 reachable from console", 15)}, ["pid", "listen_address"], "debug_control", False)
        self.add("debug_detach", "Detach/resume and clear backend breakpoints for this session. Available for cleanup.",
                 lambda: workbench.debug_mutation("detach"), read_only=False)
        self.add("debug_threads", "List threads of the attached process. Requires a persistent MCP session.", workbench.debugger.threads)
        self.add("debug_registers", "Read exact pinned-source 176-byte GP register layout (not protocol doc's 184).", workbench.debugger.get_registers,
                 {"thread_id": PID}, ["thread_id"])
        self.add("debug_events", "Poll up to 16 asynchronous 1184-byte event packets without blocking.", workbench.debugger.poll_events)
        self.add("debug_control", "Halt/resume/step or suspend/resume a thread. No process kill or reboot command exposed.",
                 lambda action, thread_id=0: workbench.debug_mutation("control", action=action, thread_id=thread_id),
                 {"action": text(enum=["resume", "halt", "step", "step_thread", "suspend_thread", "resume_thread"]), "thread_id": integer()},
                 ["action"], "debug_control", False)
        self.add("debug_breakpoint", "Set/clear one of 30 software breakpoint slots; changes target instruction bytes.",
                 lambda index, address, enabled=True: workbench.debug_mutation("breakpoint", index=index, address=parse_address(address), enabled=enabled),
                 {"index": integer(0, 29), "address": ADDRESS, "enabled": BOOLEAN}, ["index", "address"], "debug_control", False)
        self.add("debug_watchpoint", "Set/clear one of four aligned hardware watchpoint slots.",
                 lambda index, address, length, access, enabled=True: workbench.debug_mutation("watchpoint", index=index, address=parse_address(address), length=length, access=access, enabled=enabled),
                 {"index": integer(0, 3), "address": ADDRESS, "length": integer(1, 8), "access": text(enum=["execute", "write", "read_write"]), "enabled": BOOLEAN},
                 ["index", "address", "length", "access"], "debug_control", False)
        self.add("address_correlate", "Correlate runtime address to mapping and estimated image RVA; manually verify ELF layout.",
                 lambda pid, address, module_sha256, application_version: workbench.analysis.correlate(pid, parse_address(address), module_sha256, application_version),
                 {"pid": PID, "address": ADDRESS, "module_sha256": HASH, "application_version": text(maximum=128)},
                 ["pid", "address", "module_sha256", "application_version"])
        self.add("annotation_save", "Save local evidence-backed module/RVA comment or symbol for analysis handoff; does not mutate Ghidra.",
                 lambda artifact, module_sha256, rva, text, symbol="": workbench.analysis.annotate(artifact, module_sha256, parse_address(rva), text, symbol),
                 {"artifact": PATH, "module_sha256": HASH, "rva": ADDRESS, "text": text(maximum=8192), "symbol": text(maximum=128)},
                 ["artifact", "module_sha256", "rva", "text"], read_only=False)
        self.add("ghidra_export", "Create a Ghidra handoff bundle with raw artifact and requested image base. Not reconstructed ELF.",
                 lambda artifact, image_base, module_sha256: workbench.analysis.ghidra_export(artifact, parse_address(image_base), module_sha256),
                 {"artifact": PATH, "image_base": ADDRESS, "module_sha256": HASH}, ["artifact", "image_base", "module_sha256"], read_only=False)
        self.add("artifact_list", "List bounded capture metadata; local files may contain sensitive console data.", workbench.store.inventory)
        self.add("artifact_read", "Read up to 4096 bytes of a local artifact by offset, as hex and UTF-8 preview.", self._artifact_read,
                 {"artifact": PATH, "offset": integer(0, 67108864), "length": integer(1, 4096)}, ["artifact"])
        self.add("experiment_bundle", "Archive selected artifacts, metadata and profile; no network export.", workbench.store.bundle,
                 {"paths": {"type": "array", "items": PATH, "minItems": 1, "maxItems": 100}, "notes": text(maximum=8192)}, ["paths", "notes"], read_only=False)
        self.add("sdk_status", "Discover local toolchain paths/executables without running or installing them.", self.development.status)
        self.add("sdk_scaffold", "Create SDK recipe/reference workspace. Requires a pinned upstream sample before build; no fake offsets or APIs.",
                 self.development.scaffold, {"kind": text(enum=["homebrew", "plugin", "payload"]), "name": text(maximum=64)}, ["kind", "name"], read_only=False)
        self.add("sdk_build", "Run a locally hash-allowlisted build recipe with bounded logs/time; never deploy automatically.",
                 self.development.build, {"recipe": PATH, "sha256": HASH}, ["recipe", "sha256"], "build", False)

    def _typed(self, pid, address, value_type):
        length = struct.calcsize("<" + TYPES[value_type])
        return typed_value(self.workbench.debugger.read_memory(pid, parse_address(address), length), value_type)

    def _artifact_read(self, artifact, offset=0, length=256):
        with self.workbench.store.path(artifact).open("rb") as stream:
            stream.seek(offset)
            content = stream.read(length)
        return {"offset": offset, "length": len(content), "hex": content.hex(), "utf8": content.decode("utf-8", errors="replace")}
