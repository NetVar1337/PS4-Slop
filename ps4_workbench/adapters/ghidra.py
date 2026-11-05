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
        from ..tools import parse_address
        manager = self.program.getFunctionManager()
        if operation == "functions":
            import itertools
            offset, limit = arguments.get("offset", 0), arguments.get("limit", 100)
            return [{"address": "0x" + str(function.getEntryPoint()), "name": str(function.getName())[:256]}
                    for function in itertools.islice(manager.getFunctions(True), offset, offset + limit)]
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
            import itertools
            return [{"from": "0x" + str(reference.getFromAddress()), "to": "0x" + str(reference.getToAddress()),
                     "type": str(reference.getReferenceType())}
                    for reference in itertools.islice(self.program.getReferenceManager().getReferencesTo(address), arguments.get("limit", 100))]
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
