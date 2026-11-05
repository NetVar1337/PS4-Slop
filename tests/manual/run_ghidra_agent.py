import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ps4_workbench.client import BrokerClient, RemoteRegistry
from ps4_workbench.mcp import MCPServer
from tests.test_broker import BrokerCase
from tests.manual.run_installed_apps import elf_fixture


def main():
    case = BrokerCase()
    case.setUp()
    process = None
    try:
        fixture = case.directory / "ghidra-agent-fixture.elf"
        fixture.write_bytes(elf_fixture())
        log = case.directory / "ghidra-agent.log"
        with case.broker() as url, log.open("w", encoding="utf-8") as output:
            command = ["cmd.exe", "/d", "/c", "C:/Users/Admin/Desktop/Ghidra/support/analyzeHeadless.bat",
                       str(case.directory), "AgentFixture", "-import", str(fixture),
                       "-scriptPath", str(ROOT / "integrations/ghidra"), "-postScript", "PS4Workbench.java",
                       "--agent", url, str(case.secret_path), "--once", "-max-cpu", "1"]
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                       creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            client = BrokerClient(url, case.secret_path, "mcp-smoke")
            deadline = time.monotonic() + 60
            registered = False
            while time.monotonic() < deadline and process.poll() is None:
                status = client.call("analysis_status")
                if status.get("ghidra", {}).get("connected"):
                    registered = True
                    break
                threading.Event().wait(0.1)
            if not registered:
                raise RuntimeError("Ghidra static agent did not register")
            server = MCPServer(RemoteRegistry(client))
            server.dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {}}})
            server.dispatch({"jsonrpc": "2.0", "method": "notifications/initialized"})
            response = server.dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "analysis_decompile", "arguments": {"target": "ghidra", "address": "0x400100"}}})
            result = response["result"]
            if result["isError"]:
                raise RuntimeError(result["content"][0]["text"])
            decompilation = json.loads(result["content"][0]["text"])
            if "return" not in decompilation["text"]:
                raise RuntimeError("Ghidra decompilation did not contain fixture return")
            process.wait(timeout=20)
            print(json.dumps({"passed": True, "console_contacted": False,
                              "path": "MCP -> authenticated broker -> installed Ghidra 12.2 Java agent -> decompiler",
                              "decompilation": decompilation}, indent=2))
            return 0
    except Exception as error:
        if process and process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        log_path = case.directory / "ghidra-agent.log"
        print(json.dumps({"passed": False, "error": str(error), "log_tail": log_path.read_text(errors="replace")[-16000:] if log_path.exists() else ""}, indent=2))
        return 1
    finally:
        case.doCleanups()


if __name__ == "__main__":
    raise SystemExit(main())
