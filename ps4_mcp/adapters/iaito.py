"""radare2 / iaito analysis-agent adapter for the PS4-MCP broker.

iaito is the radare2 GUI; this adapter drives the same r2 engine headlessly
through r2pipe, so it works with either an iaito installation or a plain r2
on PATH::

    python integrations/iaito/ps4_connect.py D:/dumps/eboot.bin

Requires the ``r2pipe`` Python package and the ``r2`` binary. ``aaa`` runs
once at startup (can be slow on large binaries). The agent answers
analysis_decompile / analysis_functions / analysis_xrefs jobs from the shared
broker. Addresses are STATIC addresses as shown by r2 (image base + offset).
"""

import re

from .base import APPLY_OPERATIONS, LiveAnalysis, Unsupported, clipped, struct_c_declaration
from ..config import WorkbenchError

# radare2 treats ; | @ ` > < ~ $ ! " specially; only plain C declaration characters may reach a command.
_R2_DECLARATION = re.compile(r"[A-Za-z0-9_ *,()\[\]]{1,1024}")
_R2_IDENTIFIER = re.compile(r"[A-Za-z0-9_.$@?:+-]{1,256}")
_R2_FLAG = re.compile(r"[A-Za-z0-9_.]{1,256}")


def _sha256_file(path, maximum=1 << 30):
    import hashlib
    digest = hashlib.sha256()
    read = 0
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(1 << 20)
            if not chunk:
                break
            read += len(chunk)
            if read > maximum:
                raise WorkbenchError("iaito input exceeds the hashing bound")
            digest.update(chunk)
    return digest.hexdigest()


class IaitoWorkbench(LiveAnalysis):
    target = "iaito"

    def __init__(self, url, token_path, path, r2=None):
        if r2 is None:
            try:
                import r2pipe
            except ImportError as error:
                raise WorkbenchError("r2pipe is required (pip install r2pipe); r2 must be on PATH") from error
            r2 = r2pipe.open(path)
            r2.cmd("e scr.color=0")
            r2.cmd("e anal.hasnext=true")
            r2.cmd("aaa")
        self.r2 = r2
        self.path = path
        self.program = str(path)
        super().__init__(url, token_path)

    def input_hash(self):
        return _sha256_file(self.path)

    def analyze(self, operation, arguments):
        import base64
        import re
        from ..config import parse_address
        expected = getattr(self, "expected_program_hash", None)
        digest = self.input_hash()
        if expected and digest != expected:
            raise WorkbenchError("iaito input file changed; stop and restart its analysis agent")
        if operation in APPLY_OPERATIONS:
            return self.apply(operation, arguments)
        flt = (arguments.get("filter") or "").lower()
        if operation == "functions":
            offset, limit = arguments.get("offset", 0), arguments.get("limit", 100)
            functions = self.r2.cmdj("aflj") or []
            items = [
                {"address": hex(int(entry.get("offset", 0))), "name": str(entry.get("name", ""))[:256]}
                for entry in functions
                if not flt or flt in str(entry.get("name", "")).lower()
            ]
            return items[offset:offset + limit]
        if operation == "strings":
            offset, limit = arguments.get("offset", 0), arguments.get("limit", 100)
            min_len = arguments.get("min_length", 4)
            entries = self.r2.cmdj("izj") or []
            items = []
            for entry in entries:
                val = str(entry.get("string", ""))
                length = int(entry.get("length", len(val)))
                if length < min_len or (flt and flt not in val.lower()):
                    continue
                items.append({
                    "address": hex(int(entry.get("vaddr", entry.get("paddr", 0)))),
                    "length": length,
                    "value": val[:512],
                })
            return items[offset:offset + limit]
        if operation == "imports":
            offset, limit = arguments.get("offset", 0), arguments.get("limit", 100)
            entries = self.r2.cmdj("iij") or []
            items = []
            for entry in entries:
                sym_name = str(entry.get("name", ""))
                lib_name = str(entry.get("libname", ""))
                if flt and flt not in sym_name.lower() and flt not in lib_name.lower():
                    continue
                items.append({
                    "address": hex(int(entry.get("plt", 0))),
                    "name": sym_name[:256],
                    "library": lib_name[:128],
                    "ordinal": int(entry.get("ordinal", 0)),
                })
            return items[offset:offset + limit]
        address = parse_address(arguments["address"])
        where = hex(address)
        if operation == "decompile":
            text = self.r2.cmd(f"pdc @ {where}")
            if not text or not text.strip():
                text = self.r2.cmd(f"pdf @ {where}")
            if not text or not text.strip():
                raise WorkbenchError("r2 produced no output at this address (run aaa first)")
            return {"address": where, **clipped(text)}
        if operation == "xrefs":
            limit = arguments.get("limit", 100)
            direction = arguments.get("direction", "to")
            out = []
            if direction in ("to", "both"):
                refs = self.r2.cmdj(f"axtj @ {where}") or []
                for ref in refs[:limit]:
                    out.append({"from": hex(int(ref.get("from", 0))), "to": hex(int(ref.get("to", address))),
                                "type": str(ref.get("type", "")), "direction": "to"})
            if direction in ("from", "both") and len(out) < limit:
                refs = self.r2.cmdj(f"axfj @ {where}") or []
                for ref in refs[:limit - len(out)]:
                    out.append({"from": hex(int(ref.get("from", address))), "to": hex(int(ref.get("to", 0))),
                                "type": str(ref.get("type", "")), "direction": "from"})
            return out
        if operation == "disasm":
            count = int(arguments.get("count", 32))
            entries = self.r2.cmdj(f"pdj {count} @ {where}") or []
            insns = [
                {
                    "address": hex(int(entry.get("offset", 0))),
                    "size": int(entry.get("size", 0)),
                    "text": str(entry.get("disasm", entry.get("opcode", "")))[:256],
                }
                for entry in entries
            ]
            return {"address": where, "instructions": insns}
        if operation == "rename":
            name = arguments["name"]
            if not re.fullmatch(r"[A-Za-z0-9_.$@?:+-]{1,256}", name):
                raise WorkbenchError("Invalid r2 identifier")
            self.r2.cmd(f"afn {name} @ {where}")
            return {"address": where, "name": name, "applied": True}
        if operation == "comment":
            text = arguments["text"]
            if text:
                encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
                self.r2.cmd(f"CCu base64:{encoded} @ {where}")
            else:
                self.r2.cmd(f"CC- @ {where}")
            return {"address": where, "text": text, "applied": True}
        raise WorkbenchError("Unsupported iaito analysis operation")

    # Apply primitives (best effort over r2 commands) -------------------------------------------------
    def image_base(self):
        info = self.r2.cmdj("ij") or {}
        return int(info.get("bin", {}).get("baddr", 0))

    def find_function(self, name):
        if not _R2_FLAG.fullmatch(name):
            return None
        for flag in (name, "sym." + name, "sym.imp." + name, "fcn." + name):
            entries = self.r2.cmdj(f"afij @ {flag}") or []
            if entries:
                return int(entries[0].get("offset", 0)) or None
        return None

    def set_prototype(self, handle, declaration):
        declaration = declaration.rstrip(";")
        if not _R2_DECLARATION.fullmatch(declaration):
            raise WorkbenchError("Declaration contains characters radare2 cannot take safely")
        self.r2.cmd(f"afs {declaration} @ {hex(handle)}")
        return True

    def name_at(self, address):
        entries = self.r2.cmdj(f"afij @ {hex(address)}") or []
        if entries and int(entries[0].get("offset", -1)) == address:
            return str(entries[0].get("name", ""))
        return str(self.r2.cmd(f"fd. @ {hex(address)}") or "").strip()

    def set_name(self, address, name):
        if not _R2_IDENTIFIER.fullmatch(name):
            raise WorkbenchError("Invalid r2 identifier")
        entries = self.r2.cmdj(f"afij @ {hex(address)}") or []
        if entries and int(entries[0].get("offset", -1)) == address:
            self.r2.cmd(f"afn {name} @ {hex(address)}")
        else:
            self.r2.cmd(f"f {name} 1 @ {hex(address)}")
        return True

    def comment_at(self, address):
        return str(self.r2.cmd(f"CC. @ {hex(address)}") or "").strip() or None

    def set_comment(self, address, text):
        import base64
        if text:
            encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
            self.r2.cmd(f"CCu base64:{encoded} @ {hex(address)}")
        else:
            self.r2.cmd(f"CC- @ {hex(address)}")
        return True

    def type_exists(self, name):
        return name in (self.r2.cmd("ts") or "").split()

    def define_struct(self, struct, declaration):
        # The artifact's free-form c_declaration is never passed to r2; only the validated field layout is.
        text = struct_c_declaration(struct, typed=False).replace("\n", " ")
        if not re.fullmatch(r"[A-Za-z0-9_ *;{}\[\]]+", text):
            raise WorkbenchError("Struct layout contains characters radare2 cannot take safely")
        self.r2.cmd(f'"td {text}"')
        return struct["name"] in (self.r2.cmd("ts") or "").split()

    def color_block(self, address, size, rgb):
        raise Unsupported("color", "radare2/iaito keeps no persistent block highlight; use comment=true")
