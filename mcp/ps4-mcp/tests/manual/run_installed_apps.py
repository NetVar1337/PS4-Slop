import argparse
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


def elf_fixture():
    identity = b"\x7fELF\x02\x01\x01\x09" + bytes(8)
    header = struct.pack("<16sHHIQQQIHHHHHH", identity, 2, 62, 1, 0x400100, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    segment = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 0x106, 0x106, 0x1000)
    return (header + segment).ljust(0x100, b"\0") + b"\xb8\x2a\x00\x00\x00\xc3"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ida", default="C:/Program Files/IDA Professional 9.5")
    parser.add_argument("--ghidra", default="C:/Users/Admin/Desktop/Ghidra")
    parser.add_argument("--only", choices=("ida", "ghidra"))
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = Path(tempfile.mkdtemp(prefix="ps4-installed-app-tests-"))
    fixture = output / "fixture.elf"
    fixture.write_bytes(elf_fixture())
    report = {"fixture": str(fixture), "console_contacted": False, "results": {}}
    for target in ("ida", "ghidra"):
        if arguments.only and arguments.only != target:
            continue
        result_path = output / (target + ".json")
        if target == "ida":
            script = root / "tests/manual/ida_static_smoke.py"
            script_argument = f'-S"{script}" "{root}" "{result_path}"'
            command = [str(Path(arguments.ida) / "idat.exe"), "-A", "-c", "-L" + str(output / "ida.log"),
                       script_argument, str(fixture)]
        else:
            command = ["cmd.exe", "/d", "/c", str(Path(arguments.ghidra) / "support/analyzeHeadless.bat"),
                       str(output), "FixtureProject", "-import", str(fixture),
                       "-scriptPath", str(root / "tests/manual"), "-postScript", "InstalledStaticSmoke.java", str(result_path),
                       "-max-cpu", "1", "-analysisTimeoutPerFile", "30"]
        try:
            process = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                     errors="replace", timeout=150,
                                     creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            (output / (target + "-process.log")).write_text(process.stdout + process.stderr, encoding="utf-8")
            if result_path.exists():
                result = json.loads(result_path.read_text(encoding="utf-8"))
            else:
                result = {"passed": False, "error": "Application did not produce a report", "exit_code": process.returncode}
        except Exception as error:
            result = {"passed": False, "error": str(error)}
        report["results"][target] = result
    report["log_directory"] = str(output)
    print(json.dumps(report, indent=2))
    return 0 if all(result["passed"] for result in report["results"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
