import hashlib

from .analysis import Analysis
from .artifacts import ArtifactStore
from .config import WorkbenchError
from .debugger import Debugger
from .transports import ConsoleTransports


class Workbench:
    def __init__(self, profile):
        self.profile = profile
        self.store = ArtifactStore(profile)
        self.debugger = Debugger(profile)
        self.console = ConsoleTransports(profile, self.store)
        self.analysis = Analysis(profile, self.store, self.debugger)

    def close(self):
        try:
            self.debugger.close()
        except Exception as error:
            self.store.audit("debug_cleanup_failure", error=str(error), console_state="uncertain")

    def memory_read(self, pid, address, length):
        content = self.debugger.read_memory(pid, address, length)
        result = self.store.save("memory", content, {"pid": pid, "address": address,
                                 "runtime_identity": self.debugger.identity, "atomic_snapshot": False})
        if length <= 256:
            result["hex"] = content.hex()
        return result

    def memory_peek(self, pid, address, length):
        content = self.debugger.read_memory(pid, address, length)
        return {"pid": pid, "address": hex(address), "length": len(content), "hex": content.hex(),
                "atomic_snapshot": False, "runtime_identity": self.debugger.identity}

    def region_dump(self, pid, address, length):
        import time
        from .debugger import address_range
        address_range(address, length, self.profile.limit("transfer_bytes"))
        maps = self.debugger.maps(pid)
        position = address
        for entry in sorted(maps, key=lambda item: item["start"]):
            if entry["start"] <= position < entry["end"] and entry["protection"] & 1:
                position = min(address + length, entry["end"])
        if position != address + length:
            raise WorkbenchError("Requested dump crosses an unmapped or unreadable region")
        process = self.debugger.process_info(pid)
        identity = dict(self.debugger.identity or {})
        content = bytearray()
        deadline = time.monotonic() + 60
        error_text = None
        try:
            while len(content) < length:
                if time.monotonic() >= deadline:
                    raise WorkbenchError("Region dump exceeded 60-second deadline")
                count = min(self.profile.limit("memory_bytes"), length - len(content))
                chunk = self.debugger.read_memory(pid, address + len(content), count)
                if len(chunk) != count:
                    raise WorkbenchError("Short region read")
                content.extend(chunk)
        except Exception as error:
            error_text = str(error)
        artifact = self.store.save("region", bytes(content), {"pid": pid, "address": address,
                                    "requested_length": length, "complete": len(content) == length,
                                    "error": error_text, "process": process, "maps": maps,
                                    "runtime_identity": identity, "atomic_snapshot": False,
                                    "format": "raw_memory_not_reconstructed_elf"})
        return {"artifact": artifact, "complete": len(content) == length, "error": error_text}

    def kernel_read(self, address, length):
        content = self.debugger.read_memory(0, address, length, kernel=True)
        return self.store.save("kernel", content, {"address": address, "runtime_identity": self.debugger.identity})

    def memory_write(self, pid, address, hex_data, expected_hex, kernel=False):
        self.debugger.require_qualified_debugger("kernel_write" if kernel else "process_write")
        if kernel:
            self.profile.require("kernel_read")
        try:
            content, expected = bytes.fromhex(hex_data), bytes.fromhex(expected_hex)
        except ValueError as error:
            raise WorkbenchError("Invalid hex bytes") from error
        if not content or len(content) != len(expected):
            raise WorkbenchError("Supply equal nonempty replacement and expected-original byte counts")
        original = self.debugger.read_memory(pid, address, len(content), kernel=kernel)
        if original != expected:
            raise WorkbenchError("Original bytes differ; no write attempted")
        backup = self.store.save("prewrite", original, {"pid": pid, "address": address, "kernel": kernel})
        replacement = self.store.save("replacement", content, {"pid": pid, "address": address, "kernel": kernel})
        self.store.audit("memory_write_intent", pid=pid, address=address, kernel=kernel, backup=backup,
                         replacement=replacement, replacement_sha256=hashlib.sha256(content).hexdigest())
        try:
            self.debugger.write_memory(pid, address, content, kernel=kernel)
            actual = self.debugger.read_memory(pid, address, len(content), kernel=kernel)
            verified = actual == content
            readback = self.store.save("readback", actual, {"pid": pid, "address": address, "kernel": kernel})
            self.store.audit("memory_write_result", verified=verified, backup=backup["path"], readback=readback)
            if not verified:
                raise WorkbenchError("Write readback mismatch; no automatic rollback or retry")
            return {"verified": True, "backup": backup, "replacement": replacement, "readback": readback,
                    "warning": "Non-atomic compare/write/readback; target may change concurrently"}
        except Exception as error:
            self.store.audit("memory_write_uncertain", error=str(error), backup=backup["path"],
                             warning="Do not retry automatically; inspect console")
            raise

    def debug_mutation(self, method, **arguments):
        if method != "detach":
            self.debugger.require_qualified_debugger("debug_control")
        self.store.audit("debug_control_intent", method=method, arguments=arguments)
        try:
            result = getattr(self.debugger, method)(**arguments)
            self.store.audit("debug_control_result", method=method, result=result)
            return result
        except Exception as error:
            self.store.audit("debug_control_failure", method=method, error=str(error), console_state="uncertain")
            raise
