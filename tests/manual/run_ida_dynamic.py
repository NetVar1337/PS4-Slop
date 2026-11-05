"""Installed IDA 9.5 Remote GDB -> ps4-workbench gdb-server -> broker -> ps4debug fixture.

Every hop is the shipped Rust binary; only the console is replaced by the loopback
protocol fixture. Requires IDA Professional 9.5 and a release build with
``--features fixture``.
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tests.manual.rust_stack import NO_WINDOW, RustStack


def main(ida="C:/Program Files/IDA Professional 9.5"):
    with RustStack() as stack:
        port = stack.gdb_server()
        report = stack.directory / "ida-dynamic.json"
        script = ROOT / "tests/manual/ida_dynamic_smoke.py"
        command = [str(Path(ida) / "idat.exe"), "-A", "-c", "-L" + str(stack.directory / "ida.log"),
                   f'-S"{script}" {port} "{report}" "{ROOT}" "{stack.url}" "{stack.token}"', str(stack.image)]
        process = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                 errors="replace", timeout=90, creationflags=NO_WINDOW)
        if report.exists():
            result = json.loads(report.read_text())
        else:
            result = {"passed": False, "error": "No report", "exit_code": process.returncode}
        result["path"] = "IDA Remote GDB -> Rust gdb-server -> Rust broker -> ps4debug-NG protocol fixture"
        if not result["passed"]:
            logs = stack.logs()
            logs = {name: re.sub(r"(?im)^.*license:.*$", "[application license metadata omitted]", text)
                    for name, text in logs.items()}
            result["logs"] = logs
        print(json.dumps(result, indent=2))
        return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:2]))
