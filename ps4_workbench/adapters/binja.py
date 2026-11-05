"""Binary Ninja analysis-agent adapter for the PS4 workbench broker.

Two ways to use it:

1. Inside Binary Ninja's own Python (plugin or Script Manager context, where
   the open BinaryView is the global ``bv``)::

       exec(open(r"C:/.../integrations/binja/ps4_connect.py").read())

2. Headless with Binary Ninja's bundled Python::

       import binaryninja
       bv = binaryninja.load(r"D:/dumps/eboot.bin")
       from ps4_workbench.adapters.binja import BinjaWorkbench
       ps4 = BinjaWorkbench("http://127.0.0.1:8765",
                           r"C:/.../profiles/broker-token.local", bv=bv)
       ps4.start_analysis()

The agent answers analysis_decompile / analysis_functions / analysis_xrefs
jobs from the shared broker. Addresses are STATIC database addresses.
"""

from .base import LiveAnalysis, clipped
from ..config import WorkbenchError


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
                raise WorkbenchError("Binary Ninja input exceeds the hashing bound")
            digest.update(chunk)
    return digest.hexdigest()


class BinjaWorkbench(LiveAnalysis):
    target = "binja"

    def __init__(self, url, token_path, bv=None):
        if bv is None:
            bv = globals().get("bv")
        if bv is None:
            raise WorkbenchError("Pass bv= (open BinaryView) or run inside Binary Ninja")
        self.bv = bv
        self.program = str(getattr(getattr(bv, "file", None), "filename", "binaryninja-view"))
        super().__init__(url, token_path)

    def input_hash(self):
        metadata = getattr(self.bv, "file", None)
        digest = getattr(metadata, "hash", None)
        if digest:
            return str(digest).lower()
        filename = getattr(metadata, "filename", None)
        if filename:
            return _sha256_file(filename)
        raise WorkbenchError("Binary Ninja input SHA-256 is unavailable")

    def analyze(self, operation, arguments):
        from ..config import parse_address
        expected = getattr(self, "expected_program_hash", None)
        digest = self.input_hash()
        if expected and digest != expected:
            raise WorkbenchError("Binary Ninja database changed; stop and restart its analysis agent")
        flt = (arguments.get("filter") or "").lower()
        if operation == "functions":
            offset, limit = arguments.get("offset", 0), arguments.get("limit", 100)
            functions = [
                {"address": hex(function.start), "name": str(function.name)[:256]}
                for function in self.bv.functions
                if not flt or flt in str(function.name).lower()
            ]
            return functions[offset:offset + limit]
        if operation == "strings":
            offset, limit = arguments.get("offset", 0), arguments.get("limit", 100)
            min_len = arguments.get("min_length", 4)
            matched = [
                {"address": hex(int(s.start)), "length": int(s.length), "value": str(s.value)[:512]}
                for s in getattr(self.bv, "strings", [])
                if int(s.length) >= min_len and (not flt or flt in str(s.value).lower())
            ]
            return matched[offset:offset + limit]
        if operation == "imports":
            offset, limit = arguments.get("offset", 0), arguments.get("limit", 100)
            collected = []
            raw_syms = getattr(self.bv, "symbols", {})
            sym_lists = raw_syms.values() if isinstance(raw_syms, dict) else []
            for entry in sym_lists:
                items = entry if isinstance(entry, list) else [entry]
                for sym in items:
                    kind = str(getattr(sym, "type", ""))
                    if "Import" not in kind and "External" not in kind:
                        continue
                    sym_name = str(getattr(sym, "full_name", None) or getattr(sym, "name", ""))
                    ns = str(getattr(sym, "namespace", "") or "")
                    if flt and flt not in sym_name.lower() and flt not in ns.lower():
                        continue
                    collected.append({
                        "address": hex(int(getattr(sym, "address", 0))),
                        "name": sym_name[:256],
                        "library": ns[:128],
                    })
            return collected[offset:offset + limit]
        address = parse_address(arguments["address"])
        if operation == "decompile":
            function = self.bv.get_function_at(address)
            if function is None:
                containing = self.bv.get_function_containing(address)
                if containing is None:
                    raise WorkbenchError("No function at static address")
                function = containing
            text = ""
            for attribute in ("hlil", "mlil", "llil"):
                il = getattr(function, attribute, None)
                if il is not None:
                    text = str(il)
                    if text.strip():
                        break
            if not text.strip():
                raise WorkbenchError("Binary Ninja produced no IL for this function")
            return {"address": hex(function.start), **clipped(text)}
        if operation == "xrefs":
            limit = arguments.get("limit", 100)
            direction = arguments.get("direction", "to")
            result = []
            if direction in ("to", "both"):
                for reference in list(self.bv.get_code_refs(address))[:limit] if hasattr(self.bv, "get_code_refs") and not hasattr(self.bv, "get_code_refs_to") else list(self.bv.get_code_refs_to(address))[:limit]:
                    kind = getattr(reference, "ref_type", None) or getattr(reference, "type", "")
                    result.append({"from": hex(reference.address), "to": hex(address), "type": str(kind), "direction": "to"})
            if direction in ("from", "both") and len(result) < limit and hasattr(self.bv, "get_code_refs_from"):
                for dst in list(self.bv.get_code_refs_from(address))[:limit - len(result)]:
                    target_addr = dst if isinstance(dst, int) else getattr(dst, "address", 0)
                    result.append({"from": hex(address), "to": hex(int(target_addr)), "type": "code", "direction": "from"})
            return result
        if operation == "disasm":
            count = arguments.get("count", 32)
            cur = address
            insns = []
            for _ in range(count):
                sz = self.bv.get_instruction_length(cur)
                if not sz or sz <= 0:
                    break
                line = self.bv.get_disassembly(cur) or ""
                insns.append({"address": hex(cur), "size": int(sz), "text": str(line)[:256]})
                cur += sz
            return {"address": hex(address), "instructions": insns}
        if operation == "rename":
            name = arguments["name"]
            fn = self.bv.get_function_at(address)
            if fn is not None:
                fn.name = name
            else:
                import binaryninja
                self.bv.define_user_symbol(binaryninja.Symbol(binaryninja.SymbolType.DataSymbol, address, name))
            return {"address": hex(address), "name": name, "applied": True}
        if operation == "comment":
            text = arguments["text"]
            if hasattr(self.bv, "set_comment_at"):
                self.bv.set_comment_at(address, text)
            elif (fn := self.bv.get_function_containing(address)) is not None:
                fn.set_comment_at(address, text)
            return {"address": hex(address), "text": text, "applied": True}
        raise WorkbenchError("Unsupported Binary Ninja analysis operation")
