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
        from ..tools import parse_address
        expected = getattr(self, "expected_program_hash", None)
        digest = self.input_hash()
        if expected and digest != expected:
            raise WorkbenchError("Binary Ninja database changed; stop and restart its analysis agent")
        if operation == "functions":
            offset, limit = arguments.get("offset", 0), arguments.get("limit", 100)
            functions = list(self.bv.functions)
            return [{"address": hex(function.start), "name": str(function.name)[:256]}
                    for function in functions[offset:offset + limit]]
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
            refs = self.bv.get_code_refs_to(address)
            result = []
            for reference in refs[:limit]:
                kind = getattr(reference, "ref_type", None) or getattr(reference, "type", "")
                result.append({"from": hex(reference.address), "to": hex(address), "type": str(kind)})
            return result
        raise WorkbenchError("Unsupported Binary Ninja analysis operation")
