"""MCP (``ps4-mcp serve --broker``) -> Rust broker -> installed Ghidra 12.2 Java agent.

Requires Ghidra 12.2 and a release build with ``--features fixture``.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tests.manual.rust_stack import NO_WINDOW, RustStack


class McpClient:
    """Minimal newline-delimited JSON-RPC client for the stdio MCP server."""

    def __init__(self, arguments, stderr):
        self.process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr,
                                        text=True, encoding="utf-8", creationflags=NO_WINDOW)
        self.next_id = 1

    def send(self, method, params=None, notify=False):
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        if not notify:
            message["id"] = self.next_id
            self.next_id += 1
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()
        if notify:
            return None
        while True:
            line = self.process.stdout.readline()
            if not line:
                raise RuntimeError("MCP server closed stdout")
            response = json.loads(line)
            if response.get("id") == message["id"]:
                if "error" in response:
                    raise RuntimeError(json.dumps(response["error"]))
                return response["result"]

    def close(self):
        self.process.stdin.close()
        self.process.wait(timeout=10)
        self.process.stdout.close()


def main(ghidra="C:/Users/Admin/Desktop/Ghidra"):
    with RustStack(debug_control=False) as stack:
        log = (stack.directory / "ghidra-agent.log").open("w", encoding="utf-8")
        stack.handles.append(log)
        command = ["cmd.exe", "/d", "/c", str(Path(ghidra) / "support/analyzeHeadless.bat"),
                   str(stack.directory), "AgentFixture", "-import", str(stack.image),
                   "-scriptPath", str(ROOT / "integrations/ghidra"), "-postScript", "PS4Mcp.java",
                   "--agent", stack.url, str(stack.token), "--once", "-max-cpu", "1"]
        agent = stack.spawn(command, stdout=log, stderr=subprocess.STDOUT)
        mcp_log = (stack.directory / "mcp.log").open("w", encoding="utf-8")
        stack.handles.append(mcp_log)
        mcp = McpClient(stack.workbench("serve", "--broker", stack.url, "--token-file", str(stack.token),
                                        "--client-id", "mcp-smoke"), mcp_log)
        try:
            mcp.send("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                    "clientInfo": {"name": "ghidra-smoke", "version": "1"}})
            mcp.send("notifications/initialized", notify=True)
            deadline = time.monotonic() + 90
            while True:
                status = mcp.send("tools/call", {"name": "analysis_status", "arguments": {}})
                data = status.get("structuredContent", {}).get("data") or json.loads(status["content"][0]["text"])
                if data.get("ghidra", {}).get("connected"):
                    break
                if time.monotonic() > deadline or agent.poll() is not None:
                    raise RuntimeError("Ghidra static agent did not register")
                time.sleep(0.2)
            result = mcp.send("tools/call", {"name": "analysis_decompile",
                                             "arguments": {"target": "ghidra", "address": "0x400100"}})
            if result.get("isError"):
                raise RuntimeError(result["content"][0]["text"])
            decompilation = result.get("structuredContent", {}).get("data") or json.loads(result["content"][0]["text"])
            if "return" not in decompilation["text"]:
                raise RuntimeError("Ghidra decompilation did not contain fixture return")
            agent.wait(timeout=60)
            print(json.dumps({"passed": True, "console_contacted": False,
                              "path": "Rust MCP serve -> Rust broker -> installed Ghidra Java agent -> decompiler",
                              "decompilation": decompilation}, indent=2))
            return 0
        except Exception as error:
            print(json.dumps({"passed": False, "error": str(error), "logs": stack.logs()}, indent=2))
            return 1
        finally:
            mcp.close()


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:2]))
