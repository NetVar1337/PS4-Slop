import json
import sys
from pathlib import Path

import ida_auto
import ida_pro
import idc


sys.path.insert(0, idc.ARGV[1])
from ps4_mcp.adapters.ida import IDAWorkbench
from ps4_mcp.config import WorkbenchError

try:
    ida_auto.auto_wait()
    adapter = IDAWorkbench.__new__(IDAWorkbench)
    functions = adapter.analyze("functions", {"limit": 10})
    if not functions:
        raise RuntimeError("No functions analyzed in ELF fixture")
    decompilation = adapter.analyze("decompile", {"address": functions[0]["address"]})
    adapter.expected_program_hash = "0" * 64
    try:
        adapter.analyze("functions", {"limit": 1})
        raise RuntimeError("IDA database identity guard did not reject a hash mismatch")
    except WorkbenchError as error:
        if "database changed" not in str(error):
            raise
    result = {"passed": True, "sha256": adapter.input_hash(), "functions": functions,
              "decompilation": decompilation, "database_identity_guard": True}
    status = 0
except Exception as error:
    result = {"passed": False, "error": str(error)}
    status = 1
Path(idc.ARGV[2]).write_text(json.dumps(result, indent=2), encoding="utf-8")
ida_pro.qexit(status)
