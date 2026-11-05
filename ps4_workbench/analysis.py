import hashlib
import json
import struct

from .config import WorkbenchError, require_hash
from .debugger import address_range


TYPES = {"u8": "B", "i8": "b", "u16": "H", "i16": "h", "u32": "I", "i32": "i",
         "u64": "Q", "i64": "q", "f32": "f", "f64": "d"}


def typed_value(content, value_type):
    if value_type not in TYPES:
        raise WorkbenchError("Unsupported value type")
    encoding = "<" + TYPES[value_type]
    if len(content) != struct.calcsize(encoding):
        raise WorkbenchError("Byte count does not match requested value type")
    value = struct.unpack(encoding, content)[0]
    if value_type in ("u64", "i64"):
        value = str(value)
    if isinstance(value, float):
        import math
        if not math.isfinite(value):
            value = str(value)
    return {"type": value_type, "value": value, "endianness": "little", "hex": content.hex()}


def scan_pattern(content, pattern, base=0, max_results=256):
    import re
    tokens = pattern.split()
    if not 1 <= len(tokens) <= 256:
        raise WorkbenchError("Pattern must have 1 to 256 space-separated hex bytes / ?? wildcards")
    try:
        signature = [None if token == "??" else int(token, 16) for token in tokens]
    except ValueError as error:
        raise WorkbenchError("Invalid byte pattern") from error
    if any(token != "??" and not re.fullmatch(r"[0-9a-fA-F]{2}", token) for token in tokens):
        raise WorkbenchError("Pattern bytes must be exactly two hex characters")
    found = []
    truncated = False
    for offset in range(len(content) - len(signature) + 1):
        if all(value is None or content[offset + index] == value for index, value in enumerate(signature)):
            if len(found) == max_results:
                truncated = True
                break
            found.append(hex(base + offset))
    return {"matches": found, "truncated": truncated, "scanned_bytes": len(content)}


class Analysis:
    def __init__(self, profile, store, debugger):
        self.profile = profile
        self.store = store
        self.debugger = debugger

    def snapshot(self, pid, address, length, application_version, module_sha256):
        require_hash(module_sha256, "module_sha256")
        info = self.debugger.process_info(pid)
        maps = self.debugger.maps(pid)
        content = self.debugger.read_memory(pid, address, length)
        return self.store.save("memory", content, {"pid": pid, "address": address, "length": length,
                               "application_version": application_version, "module_sha256": module_sha256,
                               "process": info, "maps": maps, "runtime_identity": self.debugger.identity,
                               "atomic_snapshot": False, "module_hash_source": "user_supplied"})

    def diff(self, before, after):
        left = self.store.read(before, self.profile.limit("memory_bytes"))
        right = self.store.read(after, self.profile.limit("memory_bytes"))
        ranges = []
        begin = None
        changed = 0
        for offset in range(max(len(left), len(right))):
            different = left[offset:offset + 1] != right[offset:offset + 1]
            if different:
                changed += 1
                if begin is None:
                    begin = offset
            elif begin is not None:
                if len(ranges) < 256:
                    ranges.append({"offset": begin, "length": offset - begin})
                begin = None
        if begin is not None and len(ranges) < 256:
            ranges.append({"offset": begin, "length": max(len(left), len(right)) - begin})
        return {"before_size": len(left), "after_size": len(right), "changed_bytes": changed,
                "ranges": ranges, "ranges_may_be_truncated": len(ranges) == 256,
                "warning": "Offset comparison only; ensure same process/module/range and application version"}

    def correlate(self, pid, address, module_sha256, application_version):
        require_hash(module_sha256, "module_sha256")
        address_range(address, 1, 1)
        maps = self.debugger.maps(pid)
        selected = next((entry for entry in maps if entry["start"] <= address < entry["end"]), None)
        if selected is None:
            raise WorkbenchError("Address is not in the captured process maps")
        base = selected["start"] - selected["offset"]
        return {"pid": pid, "module_name": selected["name"], "module_sha256": module_sha256,
                "application_version": application_version, "absolute_address": hex(address),
                "mapping_base": hex(selected["start"]), "mapping_relative_offset": hex(address - selected["start"]),
                "estimated_image_base": hex(base), "estimated_rva": hex(address - base),
                "warning": "Image base is estimated from map offset; verify ELF PT_LOAD layout in Ghidra"}

    def annotate(self, artifact, module_sha256, rva, text, symbol=""):
        require_hash(module_sha256, "module_sha256")
        address_range(rva, 1, 1)
        source = self.store.read(artifact)
        entry = {"artifact": artifact, "artifact_sha256": hashlib.sha256(source).hexdigest(),
                 "module_sha256": module_sha256, "rva": hex(rva), "comment": text, "symbol": symbol}
        return self.store.save("annotation", json.dumps(entry, indent=2).encode(), extension="json")

    def ghidra_export(self, artifact, image_base, module_sha256):
        require_hash(module_sha256, "module_sha256")
        address_range(image_base, 1, 1)
        content = self.store.read(artifact)
        metadata = {"artifact": artifact, "sha256": hashlib.sha256(content).hexdigest(),
                    "module_sha256": module_sha256, "requested_image_base": hex(image_base),
                    "instruction": "Import as raw x86:LE:64:default if not ELF. Set image base explicitly. Dumps are not reconstructed ELF files."}
        return self.store.bundle([artifact], json.dumps(metadata, indent=2))
