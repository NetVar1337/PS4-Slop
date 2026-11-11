# SPDX-License-Identifier: GPL-3.0-only
"""JSONL audit log for MCP tool actions.

Every tool call that reaches the console is appended as one JSON line:
{ts, tool, args, result}. The log lets a user replay exactly what an AI
agent did to their console.
"""

from __future__ import annotations

import json
import time
from pathlib import Path


class AuditLog:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None

    def record(self, tool: str, args: dict, result: str) -> None:
        if not self.path:
            return
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "tool": tool,
                 "args": args, "result": result}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
