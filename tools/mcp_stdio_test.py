"""Smoke test for `reverse-slop-engine --stdio`: initialize, a notification,
tools/list and a tool call over stdin/stdout; every stdout line must be one
JSON-RPC reply, and closing stdin must end the engine.

    python tools/mcp_stdio_test.py [--engine path]
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--engine", default=str(Path(__file__).resolve().parent.parent
                                        / "build/src/engine/reverse-slop-engine.exe"))
args = ap.parse_args()

msgs = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
     "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "stdio-test", "version": "0"}}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
     "params": {"name": "target", "arguments": {"action": "status"}}},
]
stdin = "".join(json.dumps(m) + "\n" for m in msgs)
p = subprocess.run([args.engine, "--stdio", "--port", "0"], input=stdin, capture_output=True,
                   text=True, timeout=180)

lines = [ln for ln in p.stdout.splitlines() if ln.strip()]
fail = []
replies = {}
for ln in lines:
    try:
        r = json.loads(ln)
        replies[r.get("id")] = r
    except json.JSONDecodeError:
        fail.append(f"non-JSON stdout line: {ln[:120]!r}")
if sorted(replies) != [1, 2, 3]:
    fail.append(f"expected replies for ids 1,2,3 (none for the notification), got {sorted(replies)}")
if replies.get(1, {}).get("result", {}).get("serverInfo", {}).get("name") != "slopstation":
    fail.append(f"initialize: {replies.get(1)}")
tools = {t["name"] for t in replies.get(2, {}).get("result", {}).get("tools", [])}
if "target" not in tools:
    fail.append(f"tools/list missing 'target': {sorted(tools)[:10]}")
if "error" in replies.get(3, {}) or replies.get(3, {}).get("result", {}).get("isError"):
    fail.append(f"target.status failed: {replies.get(3)}")

for f in fail:
    print("FAIL", f)
if fail:
    print("--- stderr tail ---\n" + "\n".join(p.stderr.splitlines()[-20:]))
    sys.exit(1)
print(f"PASS stdio: {len(lines)} replies, {len(tools)} tools, engine exit {p.returncode}")
