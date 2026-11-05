import json
import os
import subprocess
import sys
import threading
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ps4_workbench.rsp import RspServer
from tests.test_broker import BrokerCase
from tests.manual.run_installed_apps import elf_fixture


def main():
    case = BrokerCase()
    case.setUp()
    try:
        debugger = case.workbench.debugger
        pending = []
        original_attach = debugger.attach.side_effect

        def attach(pid, listen_address):
            result = original_attach(pid, listen_address)
            pending.append({"thread_id": 72, "status": 0x57F, "registers": {"rip": "0x400100"}, "name": "fixture", "raw_hex": "00"})
            return result
        debugger.attach.side_effect = attach
        def control(action, thread_id=0):
            if action == "step_thread":
                debugger.get_registers.return_value["rip"] = "0x400105"
                pending.append({"thread_id": 72, "status": 0x57F, "registers": {"rip": "0x400105"}, "name": "fixture", "raw_hex": "00"})
            return {"acknowledged": True}
        debugger.control.side_effect = control
        debugger.poll_events.side_effect = lambda: [pending.pop(0)] if pending else []
        debugger.get_registers.return_value.update(rip="0x400100", cs="0x43", ss="0x3b")
        debugger.maps.return_value = [{"start": 0x400000, "end": 0x401000, "protection": 5, "offset": 0, "name": "fixture.elf"}]
        content = elf_fixture().ljust(4096, b"\0")
        debugger.read_memory.side_effect = lambda pid, address, length: content[address - 0x400000:address - 0x400000 + length]
        fixture = case.directory / "native-fixture.elf"
        fixture.write_bytes(elf_fixture())
        report = case.directory / "ida-dynamic.json"
        case.hub.start()
        with case.broker() as url, RspServer(url, case.secret_path, 71, "127.0.0.1", port=0) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
            thread.start()
            try:
                script = ROOT / "tests/manual/ida_dynamic_smoke.py"
                command = ["C:/Program Files/IDA Professional 9.5/idat.exe", "-A", "-c", "-L" + str(case.directory / "ida.log"),
                           f'-S"{script}" {server.server_address[1]} "{report}" "{ROOT}" "{url}" "{case.secret_path}"', str(fixture)]
                process = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                         errors="replace", timeout=50,
                                         creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
                if report.exists():
                    result = json.loads(report.read_text())
                else:
                    result = {"passed": False, "error": "No report", "exit_code": process.returncode}
                if not result["passed"]:
                    log = case.directory / "ida.log"
                    import re
                    text = log.read_text(errors="replace")[-12000:] if log.exists() else process.stderr[-12000:]
                    result["log_tail"] = re.sub(r"(?im)^.*license:.*$", "[application license metadata omitted]", text)
                print(json.dumps(result, indent=2))
                return 0 if result["passed"] else 1
            finally:
                server.shutdown()
                thread.join(timeout=2)
    finally:
        case.doCleanups()


if __name__ == "__main__":
    raise SystemExit(main())
