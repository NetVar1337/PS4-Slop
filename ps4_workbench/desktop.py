import os
import shutil
from pathlib import Path


def desktop_status():
    ida = Path(os.environ.get("PS4_IDA_DIRECTORY", "C:/Program Files/IDA Professional 9.5"))
    ghidra = Path(os.environ.get("PS4_GHIDRA_DIRECTORY", "C:/Users/Admin/Desktop/Ghidra"))
    properties = ghidra / "Ghidra/application.properties"
    version = None
    if properties.is_file():
        with properties.open(encoding="utf-8") as stream:
            content = stream.read(65536)
        version = next((line.partition("=")[2].strip() for line in content.splitlines()
                        if line.startswith("application.version=")), None)
    binja = Path(os.environ.get("PS4_BINJA_DIRECTORY", "C:/Program Files/Vector 35/Binary Ninja"))
    iaito = Path(os.environ.get("PS4_IAITO_DIRECTORY", "C:/Program Files/radare2"))
    gdb = shutil.which("gdb")
    if gdb is None:
        for candidate in ("C:/msys64/ucrt64/bin/gdb.exe", "C:/msys64/mingw64/bin/gdb.exe", "C:/msys64/usr/bin/gdb.exe"):
            if Path(candidate).is_file():
                gdb = candidate
                break
    return {"ida": {"directory": str(ida), "installed": (ida / "ida.exe").is_file(),
                    "gdb_plugin_present": (ida / "plugins/gdb_user.dll").is_file(),
                    "supported_adapter": "IDA Pro 9.5 / IDAPython"},
            "ghidra": {"directory": str(ghidra), "version": version,
                       "installed": properties.is_file(), "supported_adapter": "Ghidra 12.2 / PyGhidra",
                       "native_debugger_requires": "GDB with Python and the Ghidra trace-agent dependencies"},
            "binja": {"directory": str(binja),
                      "installed": (binja / "binaryninja.exe").is_file(),
                      "supported_adapter": "Binary Ninja Python (plugin context or headless binaryninja.load)"},
            "iaito": {"directory": str(iaito),
                      "installed": any((iaito / name).is_file() for name in ("iaito.exe", "r2.exe", "radare2.exe")),
                      "r2_on_path": shutil.which("r2") is not None,
                      "supported_adapter": "radare2/iaito via r2pipe (aflj/pdc/axtj)"},
            "gdb_executable": gdb, "java_executable": shutil.which("java"),
            "note": "Discovery only; no application launch, console connection, or license inspection"}
