"""HTTP client for the PS4-Slop built-in MCP server (C++, ``src/core/mcp``).

PS4-MCP's adapters were written against the Rust broker's custom ``/rpc``
protocol. PS4-Slop instead exposes the same capabilities as standard MCP
(JSON-RPC 2.0) at ``http://127.0.0.1:8765/mcp``, so this module keeps the
``BrokerClient`` interface the adapters use (``request`` / ``call`` /
``state`` / ``events`` / ``release``) and maps the handful of broker
operations onto PS4-Slop MCP tools:

  broker op          PS4-Slop MCP tool.action
  ---------          ------------------------
  state              target.status            (synthesized broker-state view)
  events             debugger.ps4_events      (console stop-event drain)
  release            (local no-op, returns ok)
  memory_peek        memory.read              (live console read, hex out)
  process_maps       target.regions           (console memory map)
  ftp_download       target.ps4_dump_module   (dump module over ps4debug-NG)
  payload_execute    debugger.ps4_elf_load    (load a homebrew ELF payload)
  agent_register/    local no-ops: PS4-Slop runs analysis in the analyzer
  agent_poll/        itself (the MCP agent loop), so the poll returns None
  agent_result/
  agent_unregister

No bearer token is required by PS4-Slop's loopback MCP server; ``token_path``
is accepted for drop-in compatibility and only used as an Authorization header
when the file exists.
"""

import hashlib
import json
import os
import re
import tempfile
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from .config import WorkbenchError

MAX_RESPONSE = 8 * 1024 * 1024

# broker op -> (slop tool, action)
_OP_TABLE = {
    "memory_peek": ("memory", "read"),
    "process_maps": ("target", "regions"),
    "ftp_download": ("target", "ps4_dump_module"),
    "payload_execute": ("debugger", "ps4_elf_load"),
}


class BrokerClient:
    """Drop-in replacement speaking MCP JSON-RPC to PS4-Slop's server."""

    def __init__(self, url, token_path=None, client=None, timeout=150, expected_profile=None):
        parsed = urlsplit(url)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username:
            raise WorkbenchError("Server URL must be http://127.0.0.1:PORT, without credentials or paths")
        self.url = url.rstrip("/") + "/mcp"
        self.client = client or "client-" + uuid.uuid4().hex
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,96}", self.client):
            raise WorkbenchError("Invalid client identity")
        self.timeout = timeout
        self.opener = build_opener(ProxyHandler({}))
        self.token = None
        if token_path and os.path.exists(token_path):
            self.token = Path(token_path).read_text(encoding="ascii").strip()
        self.expected_profile = expected_profile
        self._id = 0

    # -- MCP JSON-RPC plumbing -------------------------------------------------

    def _rpc(self, method, params):
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method,
                           "params": params}, allow_nan=False).encode()
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = Request(self.url, data=body, headers=headers, method="POST")
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                content = response.read(MAX_RESPONSE + 1)
        except HTTPError as error:
            try:
                payload = json.loads(error.read(65536))
                message = payload.get("error", {}).get("message") or payload.get("error") or str(error)
            except ValueError:
                message = str(error)
            finally:
                error.close()
            raise WorkbenchError(str(message)) from error
        except (URLError, OSError) as error:
            raise WorkbenchError("PS4-Slop MCP server unreachable at " + self.url +
                                 " (start the app or engine with the MCP server enabled): " + str(error)) from error
        if len(content) > MAX_RESPONSE:
            raise WorkbenchError("Server response exceeds 8 MiB")
        reply = json.loads(content)
        if "error" in reply and reply["error"] is not None:
            raise WorkbenchError(str(reply["error"].get("message", reply["error"])))
        return reply.get("result", {})

    def _tool(self, tool, **arguments):
        result = self._rpc("tools/call", {"name": tool, "arguments": arguments})
        if result.get("isError"):
            text = result.get("content", [{}])[0].get("text", "tool error")
            raise WorkbenchError(f"{tool}: {text}")
        content = result.get("content") or []
        if not content:
            return {}
        return json.loads(content[0].get("text", "{}"))

    # -- broker-op mapping ------------------------------------------------------

    def request(self, operation, **arguments):
        if operation == "state":
            status = self._tool("target", action="status")
            return {"event_cursor": 0, "profile_sha256": self.expected_profile or "",
                    "server": "ps4-slop-mcp", "status": status}
        if operation == "events":
            drained = self._tool("debugger", action="ps4_events",
                                 max=int(arguments.get("limit", 64)), clear=True)
            events = drained.get("events", [])
            return {"cursor": int(arguments.get("cursor", 0)) + len(events),
                    "events": events, "pending": drained.get("pending", 0)}
        if operation == "release":
            return {"ok": True}
        if operation == "agent_register":
            return {"registered": True, "note": "ps4-slop runs analysis agents through its own MCP loop"}
        if operation == "agent_unregister":
            return {"ok": True}
        if operation == "agent_poll":
            return None  # no server-side jobs; analysis operations run inside the analyzer
        if operation == "agent_result":
            return {"accepted": True}
        if operation == "call":
            return self._dispatch_call(arguments.get("name"), arguments.get("arguments") or {})
        raise WorkbenchError("Unsupported broker operation for ps4-slop: " + operation)

    def _dispatch_call(self, name, arguments):
        if name not in _OP_TABLE:
            raise WorkbenchError(
                f"broker op '{name}' has no PS4-Slop MCP equivalent; available: "
                + ", ".join(sorted(_OP_TABLE)))
        tool, action = _OP_TABLE[name]
        if name == "memory_peek":
            out = self._tool(tool, action=action,
                             addr=arguments.get("address"), len=int(arguments.get("length", 256)))
            return {"hex": out.get("hex", ""), "len": out.get("len", 0)}
        if name == "process_maps":
            regions = self._tool(tool, action=action)
            items = regions.get("regions", regions if isinstance(regions, list) else [])
            modules = {}
            try:
                mods = self._tool("target", action="modules")
                for m in mods.get("modules", []):
                    modules[int(m.get("base", 0), 0) if isinstance(m.get("base"), str) else m.get("base", 0)] = m.get("name", "")
            except WorkbenchError:
                pass
            maps = []
            for r in items:
                base = int(r.get("base", 0), 0) if isinstance(r.get("base"), str) else r.get("base", 0)
                size = int(r.get("size", 0), 0) if isinstance(r.get("size"), str) else r.get("size", 0)
                maps.append({"start": base, "end": base + size,
                             "name": modules.get(base, hex(base)),
                             "protection": r.get("protect", 0)})
            return maps
        if name == "ftp_download":
            remote = arguments.get("path", "")
            local = os.path.join(tempfile.gettempdir(), os.path.basename(remote) or "ps4_module.bin")
            out = self._tool(tool, action=action, path=local, name=os.path.basename(remote),
                             format="elf")
            digest = ""
            if os.path.exists(local):
                digest = hashlib.sha256(Path(local).read_bytes()).hexdigest()
            return {"path": local, "remote": remote, "sha256": out.get("sha256", digest),
                    "size": out.get("size", os.path.getsize(local) if os.path.exists(local) else 0)}
        if name == "payload_execute":
            manifest = arguments.get("manifest", "")
            expected = arguments.get("sha256", "")
            if expected:
                actual = hashlib.sha256(Path(manifest).read_bytes()).hexdigest()
                if actual != expected:
                    raise WorkbenchError("payload sha256 mismatch; refusing to load")
            out = self._tool(tool, action=action, path=manifest)
            return {"loaded": True, "result": out}
        raise WorkbenchError("Unhandled broker op: " + str(name))

    # -- original BrokerClient surface ------------------------------------------

    def call(self, name, **arguments):
        return self.request("call", name=name, arguments=arguments)

    def state(self):
        return self.request("state")

    def events(self, cursor=0, limit=64):
        return self.request("events", cursor=cursor, limit=limit)

    def release(self):
        return self.request("release")
