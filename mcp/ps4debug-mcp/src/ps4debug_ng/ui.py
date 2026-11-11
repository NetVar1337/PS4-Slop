# SPDX-License-Identifier: GPL-3.0-only
"""x64dbg-style web UI for the ps4debug-NG payload.

    python -m ps4debug_ng.ui [host] [port]        # serves on 127.0.0.1:8337

Stdlib only (http.server + a single-page app). Tabs:
  Memory  - hex view with live auto-refresh (the live memory tracker)
  Debug   - disasm, registers, call stack, breakpoints/watchpoints
            (pause triggers), pause log with disasm+stack per pause (trace)
  Pointers- CE-style pointer scan + live chain revalidation
  Integrity - baseline hash + live mismatch badge

Every mutating route requires an explicit confirm=true (same safety model
as the MCP layer); the UI prompts before sending it.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import actions, workflows
from .client import Ps4DebugClient, Ps4DebugError

_lock = threading.RLock()
_client: Ps4DebugClient | None = None
_attached_pid: int | None = None
_freezes: dict[str, actions.Freeze] = {}
_integrity: dict[str, dict] = {}
_scan_job: dict = {"status": "idle", "result": None, "error": None, "chains": None}


def _require_client() -> Ps4DebugClient:
    if _client is None:
        raise RuntimeError("not connected - set the console host in the header bar")
    return _client


def _json(handler, obj, status=200):
    body = json.dumps(obj, default=lambda o: hex(o) if isinstance(o, int) else str(o)).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _route(handler, method: str, path: str, query: dict, body: dict):
    """Returns (status, obj). One case per route; keep it flat."""
    global _client, _attached_pid

    if path == "/api/connect" and method == "GET":
        host = (query.get("host") or [""])[0]
        if _client:
            _client.close()
        _client = Ps4DebugClient(host) if host else Ps4DebugClient(Ps4DebugClient.discover() or "")
        _client.connect()
        return 200, _client.server_info()

    if path == "/api/disconnect" and method == "GET":
        if _client:
            _client.close()
            _client = None
        return 200, "disconnected"

    c = _require_client()

    if path == "/api/procs" and method == "GET":
        return 200, c.list_processes()

    if path == "/api/regions" and method == "GET":
        return 200, c.list_regions(int(query["pid"][0]))

    if path == "/api/read" and method == "GET":
        data = c.read_memory(int(query["pid"][0], 0), int(query["addr"][0], 0),
                             int(query["len"][0]))
        return 200, {"hex": data.hex(), "len": len(data)}

    if path == "/api/write" and method == "POST":
        if not body.get("confirm"):
            return 403, "confirm=true required"
        c.write_memory(int(body["pid"]), int(body["address"], 0),
                       bytes.fromhex(body["hex"]))
        return 200, "ok"

    if path == "/api/disasm" and method == "GET":
        return 200, c.disassemble(int(query["pid"][0], 0), int(query["addr"][0], 0),
                                  int(query.get("len", ["256"])[0]))

    if path == "/api/modules" and method == "GET":
        return 200, workflows.list_modules(c.list_regions(int(query["pid"][0])))

    if path == "/api/attach" and method == "GET":
        pid = int(query["pid"][0])
        c.attach(pid)
        _attached_pid = pid
        return 200, f"attached {pid}"

    if path == "/api/detach" and method == "GET":
        if body.get("confirm") or query.get("confirm"):
            c.detach()
            _attached_pid = None
            return 200, "detached"
        return 403, "confirm=true required"

    if path == "/api/regs" and method == "GET":
        lw = int(query.get("lwpid", ["0"])[0])
        if not lw:
            threads = c.thread_list()
            lw = threads[0] if threads else 0
        return 200, c.get_registers(lw) if lw else {}

    if path == "/api/stack" and method == "GET":
        if _attached_pid is None:
            return 409, "attach first"
        regs = c.get_registers(int(query.get("lwpid", ["0"])[0]) or c.thread_list()[0])
        return 200, c.read_stack(_attached_pid, regs["rbp"], regs["rsp"], 16)

    if path == "/api/breakpoint" and method == "POST":
        if not body.get("confirm"):
            return 403, "confirm=true required"
        c.set_breakpoint(int(body["index"]), int(body["address"], 0),
                         bool(body.get("enabled", True)))
        return 200, "ok"

    if path == "/api/watchpoint" and method == "POST":
        if not body.get("confirm"):
            return 403, "confirm=true required"
        c.set_watchpoint(int(body["index"]), int(body["address"], 0),
                         int(body["length"]), int(body["breaktype"]),
                         bool(body.get("enabled", True)))
        return 200, "ok"

    if path == "/api/continue" and method == "GET":
        c.continue_(int(query.get("stop", ["0"])[0]))
        return 200, "continued"

    if path == "/api/step" and method == "GET":
        c.step()
        return 200, "stepped"

    if path == "/api/events" and method == "GET":
        return 200, c.wait_events(64)

    if path == "/api/pointer_scan" and method == "POST":
        if _scan_job["status"] == "running":
            return 409, "scan already running"
        pid, target = int(body["pid"]), int(body["target"], 0)
        regions = c.list_regions(pid)

        def run():
            _scan_job.update(status="running", result=None, error=None)
            try:
                chains = workflows.find_pointer_chains(
                    c, pid, target, regions,
                    max_depth=int(body.get("max_depth", 5)),
                    max_offset=int(body.get("max_offset", 2048)),
                    max_chains=int(body.get("max_chains", 300)))
                _scan_job.update(status="done", chains=chains)
            except Exception as e:  # noqa: BLE001 - surfaced in the UI
                _scan_job.update(status="error", error=str(e))

        threading.Thread(target=run, daemon=True).start()
        return 200, "started"

    if path == "/api/pointer_scan" and method == "GET":
        return 200, _scan_job

    if path == "/api/pointer_rescan" and method == "POST":
        if not _scan_job.get("chains"):
            return 409, "no scan to revalidate"
        pid, target = int(body["pid"]), int(body["target"], 0)
        valid, dropped = [], 0
        for chain in _scan_job["chains"]:
            try:
                final = workflows.resolve_chain(c, pid, chain["address"], chain["offsets"])
                if final == target:
                    valid.append({**chain, "current": final})
            except (Ps4DebugError, OSError, ConnectionError):
                dropped += 1  # chain root unmapped since the scan
        valid.append({"dropped": dropped}) if False else None
        _scan_job["dropped_on_rescan"] = dropped
        return 200, valid

    if path == "/api/integrity" and method == "POST":
        import hashlib
        pid = int(body["pid"])
        addr, length = int(body["address"], 0), int(body["length"])
        data = c.read_memory(pid, addr, length)
        key = f"{pid}:{hex(addr)}"
        _integrity[key] = {"sha256": hashlib.sha256(data).hexdigest(),
                           "length": length, "checked": 0, "mismatches": 0}
        return 200, key

    if path == "/api/integrity" and method == "GET":
        import hashlib
        key = query.get("key", [""])[0]
        base = _integrity.get(key)
        if not base:
            return 404, "no baseline"
        pid, addr = int(key.split(":")[0]), int(key.split(":")[1], 16)
        data = c.read_memory(pid, addr, base["length"])
        digest = hashlib.sha256(data).hexdigest()
        base["checked"] += 1
        ok = digest == base["sha256"]
        if not ok:
            base["mismatches"] += 1
        return 200, {"ok": ok, "sha256": digest, "checks": base["checked"],
                     "mismatches": base["mismatches"]}

    if path == "/api/freeze" and method == "POST":
        if not body.get("confirm"):
            return 403, "confirm=true required"
        fid = f'{int(body["pid"])}:{body["address"]}'
        if body.get("stop"):
            fz = _freezes.pop(fid, None)
            if fz:
                fz.stop()
            return 200, fid
        if fid in _freezes:
            return 409, "already frozen"
        fz = actions.Freeze(c, int(body["pid"]), int(body["address"], 0),
                            bytes.fromhex(body["hex"]), int(body.get("interval_ms", 250)))
        fz.start()
        _freezes[fid] = fz
        return 200, fid

    return 404, f"no route {method} {path}"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _handle(self, method):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        query = parse_qs(parsed.query)
        body = {}
        if method == "POST":
            length = int(self.headers.get("Content-Length", 0))
            if length:
                try:
                    body = json.loads(self.rfile.read(length) or b"{}")
                except json.JSONDecodeError:
                    _json(self, "invalid JSON body", 400)
                    return
        try:
            with _lock:
                status, obj = _route(self, method, parsed.path, query, body)
        except (RuntimeError, Ps4DebugError, OSError, ValueError, KeyError) as e:
            status, obj = 500, str(e)
        _json(self, obj, status)

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")


PAGE = r"""<!doctype html><meta charset=utf-8><title>ps4debug-ng</title>
<style>
:root{--bg:#1e1e1e;--pan:#252526;--fg:#d4d4d4;--acc:#007acc;--warn:#f48771;--ok:#89d185}
*{box-sizing:border-box;font:13px/1.4 Consolas,monospace;color:var(--fg);background:var(--bg)}
body{margin:0;display:flex;flex-direction:column;height:100vh}
#bar{display:flex;gap:8px;padding:6px;background:var(--pan);align-items:center;flex-wrap:wrap}
input,button,select{background:#3c3c3c;border:1px solid #555;color:var(--fg);padding:3px 6px}
button:hover{background:var(--acc)}
#tabs{display:flex;background:var(--pan)}
#tabs button{border:0;background:none;padding:6px 14px;cursor:pointer}
#tabs button.on{background:var(--acc);color:#fff}
.tab{display:none;flex:1;overflow:auto;padding:8px}
.tab.on{display:block}
pre{margin:4px 0;white-space:pre-wrap}
.addr{color:#4ec9b0}.val{color:#ce9178}.k{color:#9cdcfe}
#pauselog div{border-left:3px solid var(--acc);padding:2px 6px;margin:2px 0}
.badge{padding:1px 8px;border-radius:8px}.ok{background:#2d5a2d}.bad{background:#5a2d2d}
table{border-collapse:collapse}td,th{border:1px solid #444;padding:2px 8px}
</style>
<div id=bar>
  <b>ps4debug-ng</b>
  host <input id=host size=12 placeholder=auto>
  <button onclick=connect()>connect</button><span id=info></span>
  pid <input id=pid size=6> <button onclick=loadProcs()>procs</button><select id=procs onchange="pid.value=this.value"></select>
  <button onclick=attach()>attach</button><button onclick=detach()>detach</button>
  <span id=stat></span>
</div>
<div id=tabs>
 <button class=on onclick=show('mem',this)>Memory</button>
 <button onclick=show('dbg',this)>Debugger</button>
 <button onclick=show('ptr',this)>Pointer scan</button>
 <button onclick=show('integ',this)>Integrity</button>
</div>

<div class="tab on" id=mem>
 addr <input id=maddr value=0x400000 size=12> len <input id=mlen value=256 size=6>
 <button onclick=readmem()>read</button>
 <label><input type=checkbox id=live checked> live (1s)</label>
 <pre id=memout></pre>
</div>

<div class=tab id=dbg>
 <div style="display:flex;gap:16px">
  <div><b>disasm</b> <input id=daddr size=12 value=0x400000> <button onclick=disasm()>go</button>
    <button onclick=api('continue')>continue</button><button onclick=api('step')>step</button>
    <pre id=disout></pre></div>
  <div><b>registers</b><pre id=regs></pre><b>stack</b><pre id=stack></pre></div>
 </div>
 <div>
  bp# <input id=bpidx size=2 value=0> @ <input id=bpaddr size=12>
  <button onclick=bp(true)>set</button><button onclick=bp(false)>clear</button>
  wp# <input id=wpidx size=2 value=0> @ <input id=wpaddr size=12> len
  <select id=wplen><option>1<option>2<option>4<option selected>8</select>
  <select id=wpt><option value=1>write<option value=3>rw<option value=0>exec</select>
  <button onclick=wp(true)>set</button><button onclick=wp(false)>clear</button>
 </div>
 <b>pause log (trace)</b><div id=pauselog></div>
</div>

<div class=tab id=ptr>
 target <input id=ptarget size=12> depth <input id=pdepth value=5 size=2>
 offset <input id=poff value=2048 size=5> <button onclick=pscan()>scan</button>
 <button onclick=prescan()>revalidate</button><span id=pstatus></span>
 <table id=presults><tr><th>base</th><th>offsets</th><th>stable</th><th>current</th></tr></table>
</div>

<div class=tab id=integ>
 pid+addr+len <input id=ikey size=24 placeholder="1234 0x400000 4096">
 <button onclick=ibaseline()>baseline</button> <span id=istat></span>
 <label><input type=checkbox id=ilive> monitor (2s)</label>
</div>

<script>
let timer=null,poll=null;
async function j(path,opt){const r=await fetch(path,opt);const o=await r.json();if(!r.ok)stat(o);return o}
function stat(m){document.getElementById('stat').textContent=typeof m=='string'?m:JSON.stringify(m)}
function show(id,btn){document.querySelectorAll('.tab').forEach(t=>t.classList.remove('on'));document.getElementById(id).classList.add('on');
 document.querySelectorAll('#tabs button').forEach(b=>b.classList.remove('on'));btn.classList.add('on');
 clearInterval(timer);clearInterval(poll);
 if(id=='mem'&&document.getElementById('live').checked)timer=setInterval(readmem,1000);
 if(id=='dbg'){poll=setInterval(async()=>{const ev=await j('/api/events');ev.forEach(pause);
   if(ev.length){regsout();stackout();}},800)}
 if(id=='integ'&&document.getElementById('ilive').checked)poll=setInterval(icheck,2000)}
async function api(p){stat(await j('/api/'+p))}
async function connect(){const o=await j('/api/connect?host='+host.value);info.textContent=o.branding+' fw '+o.firmware}
async function loadProcs(){const l=await j('/api/procs');procs.innerHTML=l.map(p=>`<option value=${p.pid}>${p.pid} ${p.name}</option>`).join('')}
async function attach(){stat(await j('/api/attach?pid='+pid.value))}
async function detach(){if(confirm('detach?'))stat(await j('/api/detach?confirm=1'))}
function hx(b){let s='';for(let i=0;i<b.length;i+=16){s+=`<span class=addr>${(Number(maddr.value)+i).toString(16).padStart(8,'0')}</span> `;
 for(let x=i;x<i+16&&x<b.length;x++)s+=b[x].toString(16).padStart(2,'0')+' ';s+=' '+[...b.slice(i,i+16)].map(c=>c>31&&c<127?String.fromCharCode(c):'.').join('')+'\n'}return s}
async function readmem(){const o=await j(`/api/read?pid=${pid.value}&addr=${maddr.value}&len=${mlen.value}`);
 const b=new Uint8Array(o.hex.match(/../g).map(x=>parseInt(x,16)));memout.innerHTML=hx(b)}
async function disasm(){const l=await j(`/api/disasm?pid=${pid.value}&addr=${daddr.value}`);
 disout.innerHTML=l.map(e=>`<span class=addr>${e.address.toString(16)}</span> ${'kind '+e.kind} len ${e.length} ${e.rip_rel_target?'-> '+e.rip_rel_target.toString(16):''}`).join('\n')}
async function regsout(){regs.innerHTML=Object.entries(await j('/api/regs')).map(([k,v])=>`${k} <span class=val>${v.toString(16)}</span>`).join('\n')}
async function stackout(){try{const f=await j('/api/stack');stack.innerHTML=f.map(x=>`${x.ret_addr.toString(16)} rbp ${x.rbp.toString(16)}`).join('\n')}catch(e){}}
async function pause(ev){const r=ev.registers;pauselog.innerHTML=`<div>pause rip <span class=addr>${r.rip.toString(16)}</span> rax ${r.rax.toString(16)} thread ${ev.lwpid}</div>`+pauselog.innerHTML}
async function bp(en){stat(await j('/api/breakpoint',{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({index:+bpidx.value,address:bpaddr.value,enabled:en,confirm:true})}))}
async function wp(en){stat(await j('/api/watchpoint',{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({index:+wpidx.value,address:wpaddr.value,length:+wplen.value,breaktype:+wpt.value,enabled:en,confirm:true})}))}
async function pscan(){pstatus.textContent='scanning...';await j('/api/pointer_scan',{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({pid:+pid.value,target:ptarget.value,max_depth:+pdepth.value,max_offset:+poff.value})});
 const t=setInterval(async()=>{const o=await j('/api/pointer_scan');pstatus.textContent=o.status;
  if(o.status=='done'){clearInterval(t);presults.innerHTML='<tr><th>base</th><th>offsets</th><th>stable</th></tr>'+
   o.chains.map(c=>`<tr><td class=addr>${c.address.toString(16)}</td><td>${c.offsets.join(', ')}</td><td>${c.stable}</td></tr>`).join('')}
  if(o.status=='error'){clearInterval(t);pstatus.textContent=o.error}},1000)}
async function prescan(){const o=await j('/api/pointer_rescan',{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({pid:+pid.value,target:ptarget.value})});pstatus.textContent=o.length+' still valid'}
async function ibaseline(){const[a,b,c]=ikey.value.split(' ');ikey.dataset.key=await j('/api/integrity',{method:'POST',
 headers:{'Content-Type':'application/json'},body:JSON.stringify({pid:+a,address:b,length:+c})});istat.innerHTML='<span class="badge ok">baseline</span>'}
async function icheck(){const o=await j('/api/integrity?key='+ikey.dataset.key);
 istat.innerHTML=o.ok?'<span class="badge ok">ok ('+o.checks+')</span>':'<span class="badge bad">MISMATCH</span>'}
document.getElementById('live').onchange=()=>show('mem',document.querySelector('#tabs button'));
document.getElementById('ilive').onchange=()=>show('integ',document.querySelectorAll('#tabs button')[3]);
</script>"""


def main() -> None:
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8337
    print(f"ps4debug-ng UI on http://{host}:{port} (Ctrl+C to stop)")
    print("connect to your console from the header bar (or pass its IP as an argument).")
    ThreadingHTTPServer((host, port), _Handler).serve_forever()


if __name__ == "__main__":
    main()
