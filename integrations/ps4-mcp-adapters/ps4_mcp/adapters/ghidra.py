from .base import APPLY_OPERATIONS, LiveAnalysis, Unsupported, clipped
from ..config import WorkbenchError


def _sized_data_type(kind, size):
    """Best-effort Ghidra built-in data type for a struct field."""
    from ghidra.program.model.data import (ArrayDataType, ByteDataType, DoubleDataType, DWordDataType, FloatDataType,
                                           PointerDataType, QWordDataType, WordDataType)
    text = (kind or "").replace(" ", "").lower()
    if "*" in text and size == 8:
        return PointerDataType()
    if text == "float" and size == 4:
        return FloatDataType()
    if text == "double" and size == 8:
        return DoubleDataType()
    sized = {1: ByteDataType, 2: WordDataType, 4: DWordDataType, 8: QWordDataType}
    if size in sized:
        return sized[size]()
    return ArrayDataType(ByteDataType(), size, 1)


class GhidraWorkbench(LiveAnalysis):
    target = "ghidra"

    def __init__(self, program, url, token_path, tool=None):
        """``tool`` (the PluginTool, e.g. ``state.getTool()``) enables block colouring via ColorizingService."""
        self.program = program
        self.tool = tool
        super().__init__(url, token_path)

    # Apply primitives (run inside a program transaction from analyze()) -----------------------------
    def _address(self, value):
        return self.program.getAddressFactory().getDefaultAddressSpace().getAddress(hex(value))

    def image_base(self):
        return int(self.program.getImageBase().getOffset())

    def find_function(self, name):
        manager = self.program.getFunctionManager()
        for symbol in self.program.getSymbolTable().getSymbols(name):
            candidate = symbol.getObject()
            if candidate is not None and hasattr(candidate, "getSignatureSource"):
                return candidate
            function = manager.getFunctionAt(symbol.getAddress())
            if function is not None:
                return function
        return None

    def has_user_type(self, handle):
        return str(handle.getSignatureSource()) == "USER_DEFINED"

    def set_prototype(self, handle, declaration):
        from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
        from ghidra.app.util.parser import FunctionSignatureParser
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import TaskMonitor
        parser = FunctionSignatureParser(self.program.getDataTypeManager(), None)
        signature = parser.parse(handle.getSignature(), declaration)
        command = ApplyFunctionSignatureCmd(handle.getEntryPoint(), signature, SourceType.USER_DEFINED)
        return bool(command.applyTo(self.program, TaskMonitor.DUMMY))

    def name_at(self, address):
        symbol = self.program.getSymbolTable().getPrimarySymbol(self._address(address))
        if symbol is None or str(symbol.getSource()) == "DEFAULT":
            return ""
        return str(symbol.getName())

    def set_name(self, address, name):
        from ghidra.program.model.symbol import SourceType
        location = self._address(address)
        function = self.program.getFunctionManager().getFunctionAt(location)
        if function is not None:
            function.setName(name, SourceType.USER_DEFINED)
        else:
            self.program.getSymbolTable().createLabel(location, name, SourceType.USER_DEFINED)
        return True

    def comment_at(self, address):
        from ghidra.program.model.listing import CodeUnit
        return self.program.getListing().getComment(CodeUnit.EOL_COMMENT, self._address(address))

    def set_comment(self, address, text):
        from ghidra.program.model.listing import CodeUnit
        self.program.getListing().setComment(self._address(address), CodeUnit.EOL_COMMENT, text or None)
        return True

    def type_exists(self, name):
        return self.program.getDataTypeManager().getDataType("/" + name) is not None

    def define_struct(self, struct, declaration):
        from ghidra.program.model.data import DataTypeConflictHandler, StructureDataType
        definition = StructureDataType(struct["name"], int(struct["size"]))
        for field in struct["fields"]:
            size = int(field["size"])
            definition.replaceAtOffset(int(field["offset"]), _sized_data_type(field.get("type"), size), size,
                                       field["name"], field.get("comment"))
        manager = self.program.getDataTypeManager()
        return manager.addDataType(definition, DataTypeConflictHandler.REPLACE_HANDLER) is not None

    def color_block(self, address, size, rgb):
        if self.tool is None:
            raise Unsupported("color", "pass tool=state.getTool() to GhidraWorkbench (unavailable headless)")
        from ghidra.app.plugin.core.colorizer import ColorizingService
        from java.awt import Color
        service = self.tool.getService(ColorizingService)
        if service is None:
            raise Unsupported("color", "ColorizingService is not available in this tool")
        start, end = self._address(address), self._address(address + max(size, 1) - 1)
        if rgb is None:
            service.clearBackgroundColor(start, end)
        else:
            service.setBackgroundColor(start, end, Color((rgb >> 16) & 0xFF, (rgb >> 8) & 0xFF, rgb & 0xFF))
        return True

    def input_hash(self):
        digest = self.program.getExecutableSHA256()
        if digest is None:
            raise WorkbenchError("Ghidra executable SHA-256 is unavailable")
        return str(digest).lower()

    def analyze(self, operation, arguments):
        import itertools
        from ..config import parse_address
        if operation in APPLY_OPERATIONS:
            transaction = self.program.startTransaction("PS4 " + operation)
            committed = False
            try:
                result = self.apply(operation, arguments)
                committed = True
                return result
            finally:
                self.program.endTransaction(transaction, committed)
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
