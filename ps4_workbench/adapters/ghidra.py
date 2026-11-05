from .base import LiveAnalysis, clipped
from ..config import WorkbenchError


class GhidraWorkbench(LiveAnalysis):
    target = "ghidra"

    def __init__(self, program, url, token_path):
        self.program = program
        super().__init__(url, token_path)

    def input_hash(self):
        digest = self.program.getExecutableSHA256()
        if digest is None:
            raise WorkbenchError("Ghidra executable SHA-256 is unavailable")
        return str(digest).lower()

    def analyze(self, operation, arguments):
        import itertools
        from ..config import parse_address
        manager = self.program.getFunctionManager()
        flt = (arguments.get("filter") or "").lower()
        if operation == "functions":
            offset, limit = arguments.get("offset", 0), arguments.get("limit", 100)
            items = (
                {"address": "0x" + str(function.getEntryPoint()), "name": str(function.getName())[:256]}
                for function in manager.getFunctions(True)
            )
            if flt:
                items = (item for item in items if flt in item["name"].lower())
            return list(itertools.islice(items, offset, offset + limit))
        if operation == "strings":
            from ghidra.program.util import DefinedDataIterator
            offset, limit = arguments.get("offset", 0), arguments.get("limit", 100)
            min_len = arguments.get("min_length", 4)
            out = []
            skipped = 0
            for data in DefinedDataIterator.definedStrings(self.program):
                val = str(data.getValue() or "")
                if len(val) < min_len or (flt and flt not in val.lower()):
                    continue
                if skipped < offset:
                    skipped += 1
                    continue
                out.append({"address": "0x" + str(data.getAddress()), "length": int(data.getLength()), "value": val[:512]})
                if len(out) >= limit:
                    break
            return out
        if operation == "imports":
            offset, limit = arguments.get("offset", 0), arguments.get("limit", 100)
            out = []
            skipped = 0
            for sym in self.program.getSymbolTable().getExternalSymbols():
                sym_name = str(sym.getName())
                lib_name = str(sym.getParentNamespace().getName())
                if flt and flt not in sym_name.lower() and flt not in lib_name.lower():
                    continue
                if skipped < offset:
                    skipped += 1
                    continue
                out.append({
                    "address": "0x" + str(sym.getAddress()),
                    "name": sym_name[:256],
                    "library": lib_name[:128],
                })
                if len(out) >= limit:
                    break
            return out
        address = self.program.getAddressFactory().getDefaultAddressSpace().getAddress(hex(parse_address(arguments["address"])))
        if operation == "decompile":
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import TaskMonitor
            function = manager.getFunctionContaining(address)
            if function is None:
                raise WorkbenchError("No function at static address")
            decompiler = DecompInterface()
            try:
                if not decompiler.openProgram(self.program):
                    raise WorkbenchError("Ghidra decompiler could not open program")
                result = decompiler.decompileFunction(function, 10, TaskMonitor.DUMMY)
                if not result.decompileCompleted():
                    raise WorkbenchError(str(result.getErrorMessage()))
                return {"address": "0x" + str(function.getEntryPoint()), **clipped(result.getDecompiledFunction().getC())}
            finally:
                decompiler.dispose()
        if operation == "xrefs":
            limit = arguments.get("limit", 100)
            direction = arguments.get("direction", "to")
            ref_mgr = self.program.getReferenceManager()
            refs = []
            if direction in ("to", "both"):
                for reference in itertools.islice(ref_mgr.getReferencesTo(address), limit):
                    refs.append({"from": "0x" + str(reference.getFromAddress()), "to": "0x" + str(reference.getToAddress()),
                                 "type": str(reference.getReferenceType()), "direction": "to"})
            if direction in ("from", "both") and len(refs) < limit:
                for reference in itertools.islice(ref_mgr.getReferencesFrom(address), limit - len(refs)):
                    refs.append({"from": "0x" + str(reference.getFromAddress()), "to": "0x" + str(reference.getToAddress()),
                                 "type": str(reference.getReferenceType()), "direction": "from"})
            return refs
        if operation == "disasm":
            count = arguments.get("count", 32)
            insns = []
            for ins in itertools.islice(self.program.getListing().getInstructions(address, True), count):
                insns.append({"address": "0x" + str(ins.getAddress()), "size": int(ins.getLength()), "text": str(ins)[:256]})
            return {"address": "0x" + str(address), "instructions": insns}
        if operation == "rename":
            from ghidra.program.model.symbol import SourceType
            name = arguments["name"]
            tx = self.program.startTransaction("PS4 rename")
            ok = False
            try:
                fn = manager.getFunctionAt(address)
                if fn is not None:
                    fn.setName(name, SourceType.USER_DEFINED)
                else:
                    self.program.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED)
                ok = True
            finally:
                self.program.endTransaction(tx, ok)
            return {"address": "0x" + str(address), "name": name, "applied": ok}
        if operation == "comment":
            from ghidra.program.model.listing import CodeUnit
            text = arguments["text"]
            tx = self.program.startTransaction("PS4 comment")
            ok = False
            try:
                self.program.getListing().setComment(address, CodeUnit.EOL_COMMENT, text or None)
                ok = True
            finally:
                self.program.endTransaction(tx, ok)
            return {"address": "0x" + str(address), "text": text, "applied": ok}
        raise WorkbenchError("Unsupported Ghidra analysis operation")

    def refresh_shadow(self, pid, rva, runtime_base, length, module_sha256, apply=False):
        content = self.read_live(pid, rva, runtime_base, length, module_sha256)
        if not apply:
            return {"hex": content.hex(), "database_changed": False}
        import jpype
        address = self.program.getImageBase().addNoWrap(rva)
        block = self.program.getMemory().getBlock(address)
        if block is None or not block.contains(address.addNoWrap(length - 1)):
            raise WorkbenchError("Static address range is outside one Ghidra memory block")
        transaction = self.program.startTransaction("PS4 live memory shadow")
        success = False
        try:
            values = jpype.JArray(jpype.JByte)([value if value < 128 else value - 256 for value in content])
            self.program.getMemory().setBytes(address, values)
            success = True
        finally:
            self.program.endTransaction(transaction, success)
        return {"address": "0x" + str(address), "database_changed": True, "console_changed": False}
