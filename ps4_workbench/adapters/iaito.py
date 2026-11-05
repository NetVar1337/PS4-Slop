"""radare2 / iaito analysis-agent adapter for the PS4 workbench broker.

iaito is the radare2 GUI; this adapter drives the same r2 engine headlessly
through r2pipe, so it works with either an iaito installation or a plain r2
on PATH::

    python integrations/iaito/ps4_connect.py D:/dumps/eboot.bin

Requires the ``r2pipe`` Python package and the ``r2`` binary. ``aaa`` runs
once at startup (can be slow on large binaries). The agent answers
analysis_decompile / analysis_functions / analysis_xrefs jobs from the shared
broker. Addresses are STATIC addresses as shown by r2 (image base + offset).
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
        from ..tools import parse_address
        expected = getattr(self, "expected_program_hash", None)
        digest = self.input_hash()
        if expected and digest != expected:
            raise WorkbenchError("iaito input file changed; stop and restart its analysis agent")
        if operation == "functions":
            offset, limit = arguments.get("offset", 0), arguments.get("limit", 100)
            functions = self.r2.cmdj("aflj") or []
            return [{"address": hex(int(entry.get("offset", 0))), "name": str(entry.get("name", ""))[:256]}
                    for entry in functions[offset:offset + limit]]
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
            refs = self.r2.cmdj(f"axtj @ {where}") or []
            return [{"from": hex(int(ref.get("from", 0))), "to": hex(int(ref.get("to", address))),
                     "type": str(ref.get("type", ""))} for ref in refs[:limit]]
        raise WorkbenchError("Unsupported iaito analysis operation")
