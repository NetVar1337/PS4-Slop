from ..client import BrokerClient
from ..config import WorkbenchError, parse_address, require_hash, require_integer

# --- Analyzer application (analysis_apply_* broker tools) -------------------------------------------
#
# The broker validates artifacts and sends compact batches; items carry either an absolute static
# ``address`` (static_base supplied) or an ``rva`` that the adapter rebases onto its own image base.
# Backends implement the primitive hooks of ApplyMixin; anything a backend cannot do raises
# ``Unsupported`` and is reported per feature instead of faking success.

APPLY_OPERATIONS = ("apply_prototypes", "apply_struct", "apply_coverage", "apply_symbols")
DEFAULT_NAME_PREFIXES = ("sub_", "FUN_", "fcn.", "loc_", "LAB_", "nullsub_", "j_", "unk_", "DAT_", "off_",
                         "func_", "thunk_", "byte_", "word_", "dword_", "qword_")
COVERAGE_COMMENT = "PS4 coverage hits="
MAX_REPORTED_ERRORS = 20
_SIZED_TYPES = {1: "unsigned char", 2: "unsigned short", 4: "unsigned int", 8: "unsigned long long"}


class Unsupported(WorkbenchError):
    """A backend cannot perform one apply feature (e.g. block colouring in radare2)."""

    def __init__(self, feature, detail=""):
        self.feature = feature
        super().__init__(f"{feature} is unsupported by this analyzer backend" + (f": {detail}" if detail else ""))


def is_default_name(name):
    return not name or str(name).startswith(DEFAULT_NAME_PREFIXES)


def struct_c_declaration(struct, typed=True):
    """Backend-neutral C text for a validated ps4wb-struct-v1 definition, with explicit padding."""
    lines, cursor = [], 0
    for field in sorted(struct["fields"], key=lambda item: item["offset"]):
        offset, size, name = int(field["offset"]), int(field["size"]), field["name"]
        if offset > cursor:
            lines.append(f"  unsigned char _pad_{cursor:x}[{offset - cursor}];")
        kind = field.get("type") if typed else None
        if kind and kind.rstrip().endswith("]") and "[" in kind:
            base, _, suffix = kind.partition("[")
            lines.append(f"  {base.strip()} {name}[{suffix.strip()};")
        elif kind:
            lines.append(f"  {kind} {name};")
        elif size in _SIZED_TYPES:
            lines.append(f"  {_SIZED_TYPES[size]} {name};")
        else:
            lines.append(f"  unsigned char {name}[{size}];")
        cursor = offset + size
    if struct["size"] > cursor:
        lines.append(f"  unsigned char _pad_{cursor:x}[{struct['size'] - cursor}];")
    return "struct " + struct["name"] + " {\n" + "\n".join(lines) + "\n};"


class ApplyReport:
    def __init__(self):
        self.applied = self.skipped = self.failed = 0
        self.errors, self.unsupported = [], []

    def error(self, where, exception):
        self.failed += 1
        if len(self.errors) < MAX_REPORTED_ERRORS:
            self.errors.append({"at": str(where)[:64], "error": str(exception)[:256]})

    def lacks(self, feature):
        return feature in self.unsupported

    def mark_unsupported(self, exception):
        if exception.feature not in self.unsupported:
            self.unsupported.append(exception.feature)

    def result(self):
        if not self.applied and self.unsupported:
            raise Unsupported(", ".join(self.unsupported))
        return {"applied": self.applied, "skipped": self.skipped, "failed": self.failed,
                "errors": self.errors, "unsupported": self.unsupported}


class ApplyMixin:
    """Shared analyzer-application logic; backends override the primitive hooks."""

    # Primitive hooks ------------------------------------------------------------------------------
    def image_base(self):
        raise Unsupported("image_base")

    def find_function(self, name):
        """Opaque handle for a function/import named ``name``, or None."""
        raise Unsupported("prototypes")

    def has_user_type(self, handle):
        return False

    def set_prototype(self, handle, declaration):
        raise Unsupported("prototypes")

    def name_at(self, address):
        raise Unsupported("names")

    def set_name(self, address, name):
        raise Unsupported("names")

    def comment_at(self, address):
        return None

    def set_comment(self, address, text):
        raise Unsupported("comments")

    def type_exists(self, name):
        return False

    def define_struct(self, struct, declaration):
        """Create/replace ``struct``; ``declaration`` is the artifact's optional C text."""
        raise Unsupported("structs")

    def color_block(self, address, size, rgb):
        """Colour [address, address+size) with 0xRRGGBB, or clear it when rgb is None."""
        raise Unsupported("color")

    # Generic drivers -------------------------------------------------------------------------------
    def apply(self, operation, arguments):
        handlers = {"apply_prototypes": self._apply_prototypes, "apply_struct": self._apply_struct,
                    "apply_coverage": self._apply_coverage, "apply_symbols": self._apply_symbols}
        if operation not in handlers:
            raise WorkbenchError("Unsupported apply operation")
        self.__dict__.pop("_cached_image_base", None)
        return handlers[operation](arguments)

    def item_address(self, item):
        if "address" in item:
            return parse_address(item["address"])
        if "_cached_image_base" not in self.__dict__:
            self._cached_image_base = int(self.image_base())
        return (self._cached_image_base + parse_address(item["rva"])) & 0xFFFFFFFFFFFFFFFF

    @staticmethod
    def _guard(report, call, where):
        """Run one primitive and return (ok, value); unsupported features are recorded once."""
        try:
            return True, call()
        except Unsupported as exception:
            report.mark_unsupported(exception)
            return False, None
        except Exception as exception:  # noqa: BLE001 - per-item failures are reported, not fatal
            report.error(where, exception)
            return False, None

    def _apply_symbols(self, arguments):
        report, overwrite = ApplyReport(), bool(arguments.get("overwrite"))
        for item in arguments.get("symbols", []):
            ok, address = self._guard(report, lambda: self.item_address(item), item.get("rva", item.get("address")))
            if not ok:
                continue
            changed = False
            name = item.get("name")
            if name and not report.lacks("names"):
                ok, current = self._guard(report, lambda: self.name_at(address), hex(address))
                if ok:
                    user_named = not is_default_name(current)
                    keep = current == name or (user_named and (item.get("only_if_unnamed") or not overwrite))
                    if not keep:
                        ok, done = self._guard(report, lambda: self.set_name(address, name), hex(address))
                        changed |= bool(ok and done)
            text = item.get("comment")
            if text and not report.lacks("comments"):
                ok, done = self._guard(report, lambda: self.set_comment(address, text), hex(address))
                changed |= bool(ok and done)
            if changed:
                report.applied += 1
            else:
                report.skipped += 1
        return report.result()

    def _apply_prototypes(self, arguments):
        report, overwrite = ApplyReport(), bool(arguments.get("overwrite"))
        for item in arguments.get("prototypes", []):
            if report.lacks("prototypes"):
                break
            handle = None
            for candidate in (item["name"], item.get("nid")):
                if candidate and handle is None:
                    _, handle = self._guard(report, lambda: self.find_function(candidate), candidate)
            if report.lacks("prototypes"):
                break
            if handle is None:
                report.skipped += 1
                continue
            if not overwrite and self.has_user_type(handle):
                report.skipped += 1
                continue
            ok, done = self._guard(report, lambda: self.set_prototype(handle, item["declaration"]), item["name"])
            if ok and done:
                report.applied += 1
            elif ok:
                report.error(item["name"], "declaration was not accepted")
        return report.result()

    def _apply_struct(self, arguments):
        report, struct = ApplyReport(), arguments["struct"]
        if not arguments.get("overwrite") and self.type_exists(struct["name"]):
            report.skipped += 1
        else:
            ok, done = self._guard(report, lambda: self.define_struct(struct, struct.get("c_declaration")), struct["name"])
            if ok and done:
                report.applied += 1
            elif ok:
                report.error(struct["name"], "type definition was not accepted")
        result = report.result()
        result["fields"] = len(struct["fields"])
        return result

    def _apply_coverage(self, arguments):
        report = ApplyReport()
        clear, comment = bool(arguments.get("clear")), bool(arguments.get("comment"))
        rgb = int(arguments.get("color", "0xC8F0C8"), 16)
        for block in arguments.get("blocks", []):
            ok, address = self._guard(report, lambda: self.item_address(block), block.get("rva", block.get("address")))
            if not ok:
                continue
            changed = False
            if not report.lacks("color"):
                ok, done = self._guard(report, lambda: self.color_block(address, int(block["size"]), None if clear else rgb),
                                       hex(address))
                changed |= bool(ok and done is not False)
            if comment and not report.lacks("comments"):
                if clear:
                    existing = self.comment_at(address) or ""
                    if existing.startswith(COVERAGE_COMMENT):
                        ok, _ = self._guard(report, lambda: self.set_comment(address, ""), hex(address))
                        changed |= ok
                else:
                    text = COVERAGE_COMMENT + str(block.get("hits", 1))
                    ok, done = self._guard(report, lambda: self.set_comment(address, text), hex(address))
                    changed |= bool(ok and done is not False)
            if changed:
                report.applied += 1
            else:
                report.skipped += 1
        return report.result()


class LiveAnalysis(ApplyMixin):
    target = None

    def __init__(self, url, token_path):
        self.client = BrokerClient(url, token_path)
        self.cursor = self.client.state()["event_cursor"]
        self.worker = None
        self.expected_program_hash = None

    def events(self):
        result = self.client.events(self.cursor)
        self.cursor = result["cursor"]
        return result

    def read_live(self, pid, rva, runtime_base, length, module_sha256):
        require_hash(module_sha256, "module_sha256")
        require_integer(rva, "rva", 0, 0x7FFFFFFFFFFFFFFF)
        require_integer(runtime_base, "runtime_base", 0, 0xFFFFFFFFFFFFFFFF)
        require_integer(length, "length", 1, 8192)
        if self.input_hash() != module_sha256:
            raise WorkbenchError("Static input SHA-256 mismatch; refusing address correlation")
        result = self.client.call("memory_peek", pid=pid, address=hex(runtime_base + rva), length=length)
        content = bytes.fromhex(result["hex"])
        if len(content) != length:
            raise WorkbenchError("Short live read")
        return content

    def extract(self, remote_path):
        return self.client.call("ftp_download", path=remote_path)

    def payload(self, manifest, sha256):
        return self.client.call("payload_execute", manifest=manifest, sha256=sha256)

    def start_analysis(self):
        from ..agents import AnalysisWorker
        if self.worker is not None:
            raise WorkbenchError("Analysis agent already started")
        self.expected_program_hash = self.input_hash()
        self.worker = AnalysisWorker(self.client, self.target, self.analyze, self.expected_program_hash).start()
        return self.worker

    def close(self):
        if self.worker:
            self.worker.stop()


def clipped(text):
    text = str(text)
    return {"text": text[:32768], "truncated": len(text) > 32768}
