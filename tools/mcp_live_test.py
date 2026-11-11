#!/usr/bin/env python3
"""Live MCP battery against a real reverse-slop engine.

By default it spawns build/src/engine/reverse-slop-engine.exe on a free port
with a fresh bearer token, waits for the SLOP_ENGINE_READY handshake, checks
/health, loads SlopTarget.exe as the shared image, waits for Hyperion, then
drives every MCP tool. Negative cases (bad actions, unmapped reads, SSRF to
loopback, ...) must fail; everything else must succeed. Exit code: 0 all
passed, 1 at least one case failed, 2 setup failed (engine/health/image).

Every path comes from argv or the environment, nothing is machine-specific:
  --engine   / SLOP_ENGINE_EXE   engine executable to spawn
  --target   / SLOP_TARGET_EXE   PE fixture to load (SlopTarget.exe)
  --url      / SLOP_MCP_URL      use an already-running engine instead
  --token    / SLOP_MCP_TOKEN    bearer token (generated when spawning)
  --workdir                      scratch dir for fs/persist cases (temp dir)
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PROTOCOL = "2025-06-18"


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--engine", default=os.environ.get("SLOP_ENGINE_EXE",
                    str(REPO / "build" / "src" / "engine" / "reverse-slop-engine.exe")))
    ap.add_argument("--target", default=os.environ.get("SLOP_TARGET_EXE",
                    str(REPO / "build" / "src" / "app" / "SlopTarget.exe")))
    ap.add_argument("--url", default=os.environ.get("SLOP_MCP_URL", ""),
                    help="base URL of a running engine (e.g. http://127.0.0.1:8765); skips spawning")
    ap.add_argument("--token", default=os.environ.get("SLOP_MCP_TOKEN", ""))
    ap.add_argument("--port", type=int, default=int(os.environ.get("SLOP_MCP_PORT", "0") or 0),
                    help="port for the spawned engine (default: a free port)")
    ap.add_argument("--workdir", default="", help="scratch directory (default: a new temp dir, removed after)")
    ap.add_argument("--results", default="", help="write per-case JSON results here")
    ap.add_argument("--startup-timeout", type=float, default=60.0)
    ap.add_argument("--ready-timeout", type=float, default=180.0, help="seconds to wait for hype.ready")
    ap.add_argument("--allow-existing", action="store_true",
                    help="accept a handover to an engine that is already running (it gets mutated)")
    return ap.parse_args()


class Engine:
    """Spawned engine process with stdout handshake and stderr capture."""

    def __init__(self, exe: str, port: int, token: str, log_path: Path):
        self.log_path = log_path
        env = dict(os.environ, SLOP_MCP_TOKEN=token)
        args = [exe, "--no-onboard", "--port", str(port), "--parent-pid", str(os.getpid())]
        self.log = open(log_path, "w", encoding="utf-8", errors="replace")
        self.proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=self.log, env=env,
                                     text=True, encoding="utf-8", errors="replace",
                                     creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        self.lines: list[str] = []
        self._ready = threading.Event()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self.lines.append(line.rstrip("\n"))
            if line.startswith(("SLOP_ENGINE_READY", "SLOP_ENGINE_FAILED")):
                self._ready.set()
        self._ready.set()

    def wait_ready(self, timeout: float) -> tuple[int, bool]:
        """Returns (port, existing) from the handshake or raises."""
        if not self._ready.wait(timeout):
            raise RuntimeError(f"no SLOP_ENGINE_READY within {timeout:.0f}s (log: {self.log_path})")
        time.sleep(0.2)  # let a following SLOP_ENGINE_EXISTING line arrive
        ready = next((l for l in self.lines if l.startswith("SLOP_ENGINE_READY")), None)
        if ready is None:
            failed = next((l for l in self.lines if l.startswith("SLOP_ENGINE_FAILED")), "engine exited")
            raise RuntimeError(f"{failed} (exit={self.proc.poll()}, log: {self.log_path})")
        port = int(ready.split()[1])
        return port, any(l.startswith("SLOP_ENGINE_EXISTING") for l in self.lines)

    def stop(self) -> None:
        if self.proc.poll() is None:
            # ctrl-break reaches the engine's console handler -> clean shutdown
            try:
                self.proc.send_signal(getattr(__import__("signal"), "CTRL_BREAK_EVENT"))
                self.proc.wait(timeout=15)
            except Exception:
                self.proc.kill()
                self.proc.wait(timeout=10)
        self.log.close()


class Client:
    def __init__(self, base: str, token: str):
        self.base = base.rstrip("/")
        self.token = token
        self.session = ""
        self.next_id = 1

    def _post(self, body: dict, timeout: float) -> tuple[dict | None, dict]:
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "MCP-Protocol-Version": PROTOCOL}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        req = urllib.request.Request(self.base + "/mcp", data=json.dumps(body).encode(), headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return (json.loads(raw) if raw.strip() else None), dict(r.headers)

    def health(self, timeout: float = 5.0) -> dict:
        with urllib.request.urlopen(self.base + "/health", timeout=timeout) as r:
            return json.loads(r.read())

    def initialize(self) -> dict:
        d, headers = self._post({"jsonrpc": "2.0", "id": self._id(), "method": "initialize",
                                 "params": {"protocolVersion": PROTOCOL, "capabilities": {},
                                            "clientInfo": {"name": "mcp_live_test", "version": "1"}}}, 30)
        if not d or "result" not in d:
            raise RuntimeError(f"initialize failed: {d}")
        self.session = next((v for k, v in headers.items() if k.lower() == "mcp-session-id"), "")
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"}, 30)
        return d["result"]

    def _id(self) -> int:
        self.next_id += 1
        return self.next_id

    def call(self, name: str, params: dict, timeout: float = 60) -> dict:
        t0 = time.time()
        try:
            d, _ = self._post({"jsonrpc": "2.0", "id": self._id(), "method": "tools/call",
                               "params": {"name": name, "arguments": params}}, timeout)
            d = d or {}
            res = d.get("result", {})
            content = res.get("content", [])
            text = content[0].get("text", "") if content else ""
            try:
                payload = json.loads(text) if text else {}
            except json.JSONDecodeError:
                payload = {"_raw": text[:500]}
            if "error" in d:
                payload = {"rpc_error": d["error"]}
            err = bool(res.get("isError")) or "error" in d or (isinstance(payload, dict) and "error" in payload)
            return {"ok": not err, "dt": round(time.time() - t0, 2), "payload": payload}
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")[:300]
            return {"ok": False, "dt": round(time.time() - t0, 2), "payload": {"http": e.code, "body": body}}
        except Exception as e:  # timeouts, refused connections
            return {"ok": False, "dt": round(time.time() - t0, 2), "payload": {"exception": str(e)[:300]}}


class Battery:
    def __init__(self, client: Client):
        self.c = client
        self.results: list[dict] = []

    def case(self, label: str, tool: str, params: dict, check=None, expect: str = "ok",
             timeout: float = 60) -> dict:
        """expect: 'ok' (must succeed), 'error' (must fail), 'any' (only `check` decides)."""
        r = self.c.call(tool, params, timeout)
        passed = {"ok": r["ok"], "error": not r["ok"], "any": True}[expect]
        note = ""
        if passed and check is not None:
            try:
                verdict = check(r["payload"])
                if verdict is False:
                    passed, note = False, "check failed"
                elif isinstance(verdict, str):
                    note = verdict
            except Exception as e:
                passed, note = False, f"check threw: {e!s:.200}"
        self.results.append({"label": label, "tool": tool, "params": params, "expect": expect,
                             "passed": passed, "call_ok": r["ok"], "dt": r["dt"], "note": note,
                             "brief": json.dumps(r["payload"])[:300]})
        print(f"[{'PASS' if passed else 'FAIL'}] {label} ({r['dt']}s) {note}")
        if not passed:
            print("   ->", json.dumps(r["payload"])[:250])
        return r


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_battery(b: Battery, target: str, work: Path, port: int) -> None:
    call = b.c.call
    st = call("target", {"action": "status"})
    image = st["payload"].get("image", {}) if st["ok"] else {}
    base, entry = image.get("base"), image.get("entry_va")
    if not base or not entry:
        raise RuntimeError(f"target.status has no image base/entry: {json.dumps(st['payload'])[:300]}")
    print("base=%X entry=%X hype.ready=%s" % (base, entry, (image.get("hype") or {}).get("ready")))

    # target
    b.case("target.status", "target", {"action": "status"}, lambda p: p["image"]["ready"] is True)
    b.case("target.list", "target", {"action": "list"})
    b.case("target.modules (no attach)", "target", {"action": "modules"}, expect="any")
    b.case("target.bad action", "target", {"action": "nope"}, expect="error")

    # disasm
    b.case("disasm.loaded", "disasm", {"action": "loaded"}, lambda p: p.get("ready") is True)
    b.case("disasm.pe", "disasm", {"action": "pe"}, lambda p: "%d sections" % len(p["sections"]))
    fns = b.case("disasm.functions", "disasm", {"action": "functions", "limit": 50},
                 lambda p: "total=%s" % p["total"] if p["functions"] else False)
    fn0 = fns["payload"]["functions"][0]["va"] if fns["ok"] and fns["payload"].get("functions") else entry
    b.case("disasm.disassemble at entry", "disasm", {"action": "disassemble", "addr": entry, "count": 8},
           lambda p: "got %d insns, first=%s" % (p["count"], p["instructions"][0]["text"]))
    b.case("disasm.disassemble garbage addr", "disasm", {"action": "disassemble", "addr": "0x1400", "count": 4},
           expect="any")
    b.case("disasm.xrefs at entry", "disasm", {"action": "xrefs", "addr": entry}, lambda p: "count=%d" % p["count"])
    b.case("disasm.blocks at fn", "disasm", {"action": "blocks", "addr": fn0}, lambda p: "%d blocks" % p["count"])
    b.case("disasm.vtables", "disasm", {"action": "vtables"}, lambda p: "%d vtables" % p["count"])
    b.case("disasm.globals", "disasm", {"action": "globals"}, lambda p: "%d globals" % p["count"])
    b.case("disasm.strings", "disasm", {"action": "strings", "limit": 20},
           lambda p: "%d strings" % len(p["strings"]) if p["strings"] else False)
    b.case("disasm.symbols", "disasm", {"action": "symbols"}, lambda p: "%d symbols" % p["count"])
    b.case("disasm.assemble", "disasm", {"action": "assemble", "text": "mov rax, rbx"},
           lambda p: "bytes=%s" % p["bytes"])
    b.case("disasm.assemble bad", "disasm", {"action": "assemble", "text": "frobnicate rax"}, expect="error")
    b.case("disasm.unknown action", "disasm", {"action": "zzz"}, expect="error")

    # decomp
    b.case("decomp.function at fn0", "decomp", {"action": "function", "addr": fn0},
           lambda p: "lines=%d vars=%d" % (len(p["lines"]), len(p["vars"])), timeout=120)
    b.case("decomp.function bad addr", "decomp", {"action": "function", "addr": "0x12345678"}, expect="error")
    b.case("decomp bad action", "decomp", {"action": "nope"}, expect="error")

    # re
    r = b.case("re.rtti_scan", "re", {"action": "rtti_scan"}, lambda p: "classes=%d" % p["count"])
    vt_va = (r["payload"].get("classes") or [{}])[0].get("vtable_va") if r["ok"] else None
    if vt_va:
        b.case("re.vftable", "re", {"action": "vftable", "addr": vt_va}, lambda p: "count=%d" % p["count"])
    shared = b.case("re.danger", "re", {"action": "danger"}, lambda p: "%d hits" % p["count"])
    b.case("re.danger with explicit path", "re", {"action": "danger", "path": target},
           lambda p: (p["count"] == shared["payload"].get("count")) or
           f"path hits {p['count']} != shared {shared['payload'].get('count')}")
    b.case("re.libsig bad", "re", {"action": "libsig", "sigset": "{}"}, expect="error")

    # analyze
    b.case("analyze.packer", "analyze", {"action": "packer"}, lambda p: "packed=%s" % p.get("packed"))
    b.case("analyze.signatures", "analyze", {"action": "signatures"}, lambda p: "count=%s" % p.get("count"))
    b.case("analyze.diff self", "analyze", {"action": "diff", "path_a": target, "path_b": target},
           lambda p: "totals=%s" % json.dumps(p.get("totals")), timeout=300)

    # xray
    for action in ("cfg", "complexity", "cff", "obfuscation", "indirect_calls", "anti_analysis", "strings_recon"):
        b.case(f"xray.{action} at fn0", "xray", {"action": action, "addr": fn0})
    b.case("xray.hooks", "xray", {"action": "hooks"})
    b.case("xray.syscalls", "xray", {"action": "syscalls"})
    b.case("xray.apihash ror13", "xray", {"action": "apihash", "hash": "0xC2B9DBB1", "algorithm": "ror13"})
    b.case("xray.entropy", "xray", {"action": "entropy", "addr": entry, "size": 2048},
           lambda p: "verdict=%s" % p.get("verdict"))
    b.case("xray.pages", "xray", {"action": "pages", "addr": entry, "size": 8192})
    b.case("xray.crypto_range", "xray", {"action": "crypto_range", "addr": base, "size": 65536})
    b.case("xray.gadgets", "xray", {"action": "gadgets", "limit": 20}, lambda p: "count=%d" % p["count"])

    # types
    b.case("types.declare struct", "types",
           {"action": "declare", "decl": "struct LiveTestHdr { u32 magic; u32 len; char tag[8]; } packed;"})
    b.case("types.get_struct", "types", {"action": "get_struct", "name": "LiveTestHdr"})
    b.case("types.list_structs", "types", {"action": "list_structs"})
    b.case("types.read_field (image)", "types",
           {"action": "read_field", "struct": "LiveTestHdr", "field": "magic", "addr": base})
    b.case("types.format_at", "types", {"action": "format_at", "type": "LiveTestHdr", "addr": base, "size": 16})
    b.case("types.create_enum", "types", {"action": "create_enum", "name": "LiveTestTag",
                                          "values": [{"name": "A", "value": 1}, {"name": "B", "value": 2}]})
    b.case("types.get_enum", "types", {"action": "get_enum", "name": "LiveTestTag"})
    b.case("types.remove_struct", "types", {"action": "remove_struct", "name": "LiveTestHdr"})

    # notes (every mutation is undone)
    b.case("notes.set_comment", "notes", {"action": "set_comment", "addr": entry, "text": "mcp live test"})
    b.case("notes.get_comment", "notes", {"action": "get_comment", "addr": entry},
           lambda p: p.get("comment") == "mcp live test")
    b.case("notes.comments", "notes", {"action": "comments"})
    b.case("notes.bookmark_toggle", "notes", {"action": "bookmark_toggle", "addr": entry})
    b.case("notes.bookmarks", "notes", {"action": "bookmarks"})
    b.case("notes.bookmark_toggle (undo)", "notes", {"action": "bookmark_toggle", "addr": entry})
    b.case("notes.set_comment (clear)", "notes", {"action": "set_comment", "addr": entry, "text": ""})

    # persist
    ps = b.case("persist.save", "persist", {"action": "save", "name": "mcp_live_test", "data": {"foo": "bar"}})
    pid_ = ps["payload"].get("id") if ps["ok"] else None
    b.case("persist.list", "persist", {"action": "list"})
    if pid_:
        b.case("persist.load", "persist", {"action": "load", "id": pid_})
    b.case("persist.kv_set", "persist", {"action": "kv_set", "key": "mcp_live_test", "value": {"x": 1}})
    b.case("persist.kv_get", "persist", {"action": "kv_get", "key": "mcp_live_test"})
    if pid_:
        b.case("persist.delete", "persist", {"action": "delete", "id": pid_})
    hdb = work / "hdb"
    b.case("persist.hype_save", "persist", {"action": "hype_save", "dir": str(hdb)}, timeout=120)
    b.case("persist.hype_load", "persist", {"action": "hype_load", "dir": str(hdb)}, timeout=120)

    # emulate
    b.case("emulate.run hex", "emulate", {"action": "run", "hex": "B839050000C3", "count": 16},
           lambda p: "reason=%s rax=%s" % (p.get("stopped_reason"), (p.get("regs") or {}).get("rax")))
    b.case("emulate.run file_addr", "emulate", {"action": "run", "file_addr": entry, "code_len": 64, "count": 32},
           lambda p: "stopped_reason" in p or p.get("ok") is True, expect="any")
    b.case("emulate.run taint", "emulate",
           {"action": "run", "hex": "8B0425AABBCCDD", "count": 8, "taint": [{"addr": "0xAABBCCDD", "len": 4}]},
           expect="any")

    # memory (no target attached: image fallback)
    b.case("memory.read hex @entry", "memory", {"action": "read", "addr": entry, "len": 32},
           lambda p: "len=%s" % p.get("len"))
    b.case("memory.read utf8", "memory", {"action": "read", "addr": entry, "len": 16, "format": "utf8"})
    b.case("memory.read u32", "memory", {"action": "read", "addr": base, "len": 16, "format": "u32"})
    b.case("memory.read unmapped", "memory", {"action": "read", "addr": "0xFFFFFFFFFFF00000", "len": 16},
           expect="error")
    b.case("memory.scan (no target)", "memory", {"action": "scan", "value": 42}, expect="error")
    b.case("memory.snapshots", "memory", {"action": "snapshots"})

    # patch (journal only)
    b.case("patch.journal", "patch", {"action": "journal"})
    b.case("patch.nop_junk fn0", "patch", {"action": "nop_junk", "addr": fn0, "aggressive": False}, expect="any")

    # devirt
    b.case("devirt.iat_audit", "devirt", {"action": "iat_audit"})
    b.case("devirt.identify at fn0", "devirt", {"action": "identify", "addr": fn0}, expect="any")
    b.case("devirt.prove_predicates fn0", "devirt", {"action": "prove_predicates", "addr": fn0, "runs": 2},
           expect="any", timeout=120)
    b.case("devirt.invariants fn0", "devirt", {"action": "invariants", "addr": fn0, "runs": 2},
           expect="any", timeout=120)

    # network / proxy
    for action in ("status", "packets", "connections", "stats"):
        b.case(f"network.{action}", "network", {"action": action})
    b.case("network.bad action", "network", {"action": "zzz"}, expect="error")
    b.case("proxy.status", "proxy", {"action": "status"})
    b.case("proxy.entries", "proxy", {"action": "entries"})

    # debugger (no console connected)
    b.case("debugger.status", "debugger", {"action": "status"})
    b.case("debugger.ps4_wait (no console)", "debugger", {"action": "ps4_wait"}, expect="error")

    # fs, confined to the scratch dir
    scratch = work / "fs_case.txt"
    b.case("fs.write_file", "fs", {"action": "write_file", "path": str(scratch), "text": "hello from mcp"})
    b.case("fs.read_file", "fs", {"action": "read_file", "path": str(scratch)},
           lambda p: "hello from mcp" in json.dumps(p))
    b.case("fs.list_directory", "fs", {"action": "list_directory", "path": str(work)},
           lambda p: "fs_case.txt" in json.dumps(p))
    b.case("fs.grep_in_files", "fs", {"action": "grep_in_files", "root": str(work), "needle": "hello from",
                                      "suffix": ".txt", "limit": 5}, lambda p: "fs_case.txt" in json.dumps(p))
    b.case("fs.delete_path", "fs", {"action": "delete_path", "path": str(scratch)},
           lambda p: not scratch.exists())

    # web: loopback / unresolvable hosts are refused (SSRF guard)
    b.case("web.fetch loopback refused", "web",
           {"action": "fetch", "url": f"http://127.0.0.1:{port}/health", "timeout_ms": 5000}, expect="error")
    b.case("web.fetch bad host", "web", {"action": "fetch", "url": "http://nonexistent.invalid/x"}, expect="error")

    # script
    b.case("script.run", "script", {"action": "run", "code": "return 'hello from lua'"},
           lambda p: "hello from lua" in p.get("output", ""))
    b.case("script.run infinite (timeout)", "script",
           {"action": "run", "code": "while true do end", "timeout_ms": 2000},
           lambda p: p.get("ok") is not True, expect="any", timeout=30)
    b.case("script sandbox blocks os.execute", "script",
           {"action": "run", "code": "return os.execute == nil and io == nil"},
           lambda p: "return: true" in p.get("output", ""))

    # unknown tool
    b.case("unknown tool", "zzztool", {"action": "x"}, expect="error")


def wait_hype_ready(client: Client, timeout: float) -> None:
    deadline = time.time() + timeout
    last = {}
    while time.time() < deadline:
        r = client.call("disasm", {"action": "loaded"}, timeout=15)
        last = r["payload"]
        hype = (last.get("hype") or {}) if isinstance(last, dict) else {}
        if hype.get("ready"):
            return
        if hype.get("error"):
            raise RuntimeError(f"hyperion analysis failed: {hype['error']}")
        time.sleep(1)
    raise RuntimeError(f"hype not ready after {timeout:.0f}s: {json.dumps(last)[:300]}")


def main() -> int:
    args = parse_args()
    target = str(Path(args.target).resolve())
    if not Path(target).is_file():
        print(f"setup: target fixture not found: {target} (--target / SLOP_TARGET_EXE)", file=sys.stderr)
        return 2

    own_work = not args.workdir
    work = Path(args.workdir or tempfile.mkdtemp(prefix="slop-mcp-live-"))
    work.mkdir(parents=True, exist_ok=True)
    engine = None
    try:
        if args.url:
            base, token = args.url, args.token
        else:
            exe = Path(args.engine)
            if not exe.is_file():
                print(f"setup: engine not found: {exe} (--engine / SLOP_ENGINE_EXE)", file=sys.stderr)
                return 2
            token = args.token or secrets.token_hex(32)
            engine = Engine(str(exe), args.port or free_port(), token, work / "engine.log")
            port, existing = engine.wait_ready(args.startup_timeout)
            if existing and not args.allow_existing:
                print(f"setup: an engine is already running on port {port}; refusing to mutate it "
                      "(close it or pass --allow-existing)", file=sys.stderr)
                return 2
            base = f"http://127.0.0.1:{port}"
        client = Client(base, token)
        port = int(base.rsplit(":", 1)[1].split("/")[0])

        health = client.health()
        if not health.get("ok"):
            raise RuntimeError(f"/health not ok: {health}")
        print(f"health: {health}")
        info = client.initialize()
        print(f"initialize: protocol={info.get('protocolVersion')} server={info.get('serverInfo')}")

        load = client.call("disasm", {"action": "load", "path": target}, timeout=120)
        if not load["ok"]:
            raise RuntimeError(f"disasm.load failed: {json.dumps(load['payload'])[:300]}")
        wait_hype_ready(client, args.ready_timeout)

        battery = Battery(client)
        run_battery(battery, target, work, port)
    except Exception as e:
        print(f"setup: {e}", file=sys.stderr)
        if engine is not None and engine.log_path.exists():
            engine.log.flush()
            print("--- engine log tail ---", file=sys.stderr)
            print("\n".join(engine.log_path.read_text("utf-8", "replace").splitlines()[-40:]), file=sys.stderr)
        return 2
    finally:
        if engine is not None:
            engine.stop()
        if own_work:
            shutil.rmtree(work, ignore_errors=True)

    if args.results:
        Path(args.results).write_text(json.dumps(battery.results, indent=1), encoding="utf-8")
    failed = [r for r in battery.results if not r["passed"]]
    print(f"\n=== SUMMARY: {len(battery.results) - len(failed)}/{len(battery.results)} passed ===")
    for r in failed:
        print(f"  FAILED: {r['label']} (expect {r['expect']}): {r['brief'][:160]}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
