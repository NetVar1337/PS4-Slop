// app/src/components/panels/DebuggerView.tsx
// PS4 live-debug panel: attach state, run control, breakpoints/watchpoints,
// registers, callstack, event feed - every action goes over the ps4debug-NG
// wire via the debugger ps4_* MCP actions

import { useEffect, useState } from "react";
import { Ban, Play, Plus, ScanSearch, StepForward, Timer } from "lucide-react";
import { hex, useDisasm } from "@/store/disasm";
import { useDebugger } from "@/store/debugger";
import { useEngine } from "@/store/engine";

const kRegOrder = [
  "rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx",
  "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "flags",
];

export default function DebuggerView() {
  const target = useEngine((s) => s.target);
  const backend = useEngine((s) => s.backend);
  const {
    status, regs, regsLwpid, frames, events, breakpoints, watchpoints, scan, app, error, busy,
    refresh, attach, detach, cont, step, waitHalt, bpSet, bpClear, wpSet, wpClear,
    scanFirst, scanRescan, scanAob, scanReset, notify, dumpModule,
  } = useDebugger();
  const { gotoAddress } = useDisasm();
  const [bpAddr, setBpAddr] = useState("");
  const [wpAddr, setWpAddr] = useState("");
  const [wpType, setWpType] = useState(1);
  const [wpLen, setWpLen] = useState(8);
  const [lwp, setLwp] = useState("0");
  const [scAddr, setScAddr] = useState("");
  const [scLen, setScLen] = useState("0x10000");
  const [scType, setScType] = useState("u32");
  const [scCmp, setScCmp] = useState("exact");
  const [scVal, setScVal] = useState("");
  const [scAob, setScAob] = useState("");
  const [notifyMsg, setNotifyMsg] = useState("");
  const [dumpName, setDumpName] = useState("eboot.bin");
  const [dumpPath, setDumpPath] = useState("C:/dumps/eboot.bin");

  useEffect(() => {
    void refresh();
  }, [refresh, target.pid, backend.ps4]);

  const parseHex = (s: string) => Number.parseInt(s.replace(/^0x/i, ""), 16);
  const pid = target.pid ?? status.debug_pid;

  if (!backend.ps4) {
    return (
      <div className="empty">
        <div className="empty-glyph">
          <ScanSearch size={28} strokeWidth={1.5} />
        </div>
        <div className="empty-title">No PS4 console connected.</div>
        <div className="empty-hint">
          Connect one from the Targets panel (ps4 connect / ps4 auto), or over MCP with
          target.ps4_auto. This view then drives the live ps4debug-NG session on the console.
        </div>
      </div>
    );
  }

  const addBp = () => {
    const a = parseHex(bpAddr);
    if (Number.isFinite(a) && a !== 0) {
      void bpSet(a);
      setBpAddr("");
    }
  };
  const addWp = () => {
    const a = parseHex(wpAddr);
    if (Number.isFinite(a) && a !== 0) {
      void wpSet(a, wpType, wpLen);
      setWpAddr("");
    }
  };
  const lwpNum = parseHex(lwp) || 0;

  return (
    <div className="stack">
      <div className="view-bar">
        <span className="pill" style={{ color: status.debug_attached ? "var(--ok)" : undefined }}>
          {status.debug_attached ? `debug attached pid ${status.debug_pid}` : "debug not attached"}
        </span>
        {status.ps4_connected && <span className="faint mono" style={{ fontSize: 11 }}>ps4 · pending {status.pending_events}</span>}

        <div className="spacer" />

        {!status.debug_attached ? (
          <button
            className="row-action"
            disabled={pid === 0 || busy}
            onClick={() => pid !== 0 && void attach(pid)}
          >
            Attach debugger (ps4debug)
          </button>
        ) : (
          <>
            <button className="row-action" disabled={busy} onClick={() => void cont()} data-tip="continue">
              <Play size={11} />
            </button>
            <button className="row-action" disabled={busy} onClick={() => void step(lwpNum)} data-tip="step one lwp (0 = all threads)">
              <StepForward size={11} />
            </button>
            <button className="row-action" disabled={busy} onClick={() => void waitHalt(5000)} data-tip="wait for a stop event (5s)">
              <Timer size={11} />
            </button>
            <button className="row-action" onClick={() => void detach()}>
              <Ban size={11} /> Detach
            </button>
          </>
        )}
      </div>

      {error !== null && (
        <div className="empty-hint" style={{ padding: "var(--pad-sm) var(--pad-md)", color: "var(--danger)" }}>
          {error}
        </div>
      )}

      <div className="dbg">
        <div className="dbg-col">
          <div className="dbg-head">
            Registers
            <div className="spacer" />
            <input
              className="addr-input mono"
              style={{ width: 64 }}
              value={lwp}
              placeholder="lwpid"
              onChange={(e) => setLwp(e.target.value)}
            />
          </div>
          <div className="panel-body">
            {regs === null ? (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
                {status.debug_attached ? "stop the target (bp / wait) to read registers." : "not attached."}
              </div>
            ) : (
              <>
                <div className="faint" style={{ padding: "2px var(--pad-md)", fontSize: 11 }}>lwp {regsLwpid}</div>
                <table className="table">
                  <tbody>
                    {kRegOrder.map((name) => (
                      <tr key={name}>
                        <td className="mono faint" style={{ width: 52 }}>{name}</td>
                        <td>
                          <button className="mono link" onClick={() => void gotoAddress(regs[name] ?? 0)}>
                            {hex(regs[name] ?? 0)}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </div>
          <div className="dbg-head">Call stack</div>
          <div className="panel-body">
            {frames.length === 0 ? (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>no frames.</div>
            ) : (
              frames.map((f, i) => (
                <button
                  key={i}
                  className="fn-row"
                  style={{ position: "static", height: 20 }}
                  onClick={() => void gotoAddress(f.ret_addr ?? 0)}
                  data-tip={f.snippet !== undefined && f.snippet !== "" ? f.snippet : undefined}
                >
                  <span className="faint" style={{ width: 20 }}>{i}</span>
                  <span className="fn-name mono">{hex(f.ret_addr ?? 0)}</span>
                  {f.scanned === true && <span className="faint" style={{ fontSize: 10 }}>scan</span>}
                </button>
              ))
            )}
          </div>
        </div>

        <div className="dbg-col">
          <div className="dbg-head">
            Breakpoints
            <div className="spacer" />
            <input
              className="addr-input mono"
              style={{ width: 110 }}
              value={bpAddr}
              placeholder="address"
              onChange={(e) => setBpAddr(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && addBp()}
            />
            <button className="icon-button" onClick={addBp} disabled={!status.debug_attached}>
              <Plus size={13} />
            </button>
          </div>
          <div className="panel-body">
            {breakpoints.length === 0 ? (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>none set.</div>
            ) : (
              breakpoints.map((b) => (
                <div className="fn-row" style={{ position: "static", height: 20 }} key={b.addr}>
                  <span className="faint" style={{ width: 44 }}>slot {b.index}</span>
                  <span className="fn-name mono">{hex(b.addr)}</span>
                  <button className="icon-button" onClick={() => void bpClear(b.addr)}>
                    <Ban size={11} />
                  </button>
                </div>
              ))
            )}
            <div className="dbg-head" style={{ marginTop: "var(--pad-sm)" }}>
              Watchpoints (DR)
              <div className="spacer" />
              <input
                className="addr-input mono"
                style={{ width: 110 }}
                value={wpAddr}
                placeholder="address"
                onChange={(e) => setWpAddr(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && addWp()}
              />
              <select
                className="addr-input"
                style={{ width: 64 }}
                value={wpType}
                onChange={(e) => setWpType(Number(e.target.value))}
              >
                <option value={0}>exec</option>
                <option value={1}>write</option>
                <option value={3}>rdwr</option>
              </select>
              <select
                className="addr-input"
                style={{ width: 44 }}
                value={wpLen}
                onChange={(e) => setWpLen(Number(e.target.value))}
              >
                {[1, 2, 4, 8].map((n) => (
                  <option key={n} value={n}>{n}</option>
                ))}
              </select>
              <button className="icon-button" onClick={addWp} disabled={!status.debug_attached}>
                <Plus size={13} />
              </button>
            </div>
            {watchpoints.length === 0 ? (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>none set.</div>
            ) : (
              watchpoints.map((w) => (
                <div className="fn-row" style={{ position: "static", height: 20 }} key={w.addr}>
                  <span className="faint" style={{ width: 44 }}>DR{w.index}</span>
                  <span className="fn-name mono">{hex(w.addr)}</span>
                  <button className="icon-button" onClick={() => void wpClear(w.addr)}>
                    <Ban size={11} />
                  </button>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="dbg-col">
          <div className="dbg-head">
            Console scan (on-device)
            <div className="spacer" />
            <button className="row-action" disabled={busy} onClick={() => void scanReset()}>
              reset
            </button>
          </div>
          <div className="panel-body">
            <div style={{ display: "flex", gap: 4, flexWrap: "wrap", padding: "2px var(--pad-md)" }}>
              <input className="addr-input mono" style={{ width: 100 }} value={scAddr} placeholder="addr"
                onChange={(e) => setScAddr(e.target.value)} />
              <input className="addr-input mono" style={{ width: 64 }} value={scLen} placeholder="len"
                onChange={(e) => setScLen(e.target.value)} />
              <select className="addr-input" value={scType} onChange={(e) => setScType(e.target.value)}>
                {["u8", "i8", "u16", "i16", "u32", "i32", "u64", "i64", "f32", "f64"].map((w) => (
                  <option key={w} value={w}>{w}</option>
                ))}
              </select>
              <select className="addr-input" value={scCmp} onChange={(e) => setScCmp(e.target.value)}>
                {["exact", "bigger", "smaller", "between", "increased", "decreased", "changed", "unchanged", "unknown"].map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
              <input className="addr-input mono" style={{ width: 80 }} value={scVal} placeholder="value"
                onChange={(e) => setScVal(e.target.value)} />
              <button className="row-action" disabled={busy || !scAddr || !scVal}
                onClick={() => {
                  const a = parseHex(scAddr);
                  const l = parseHex(scLen);
                  const v = scVal.trim();
                  const num = Number(v);
                  void scanFirst({
                    addr: a, len: l, value_type: scType, compare: scCmp,
                    value: Number.isFinite(num) && v !== "" ? num : v,
                  });
                }}>
                scan
              </button>
              <button className="row-action" disabled={busy || !scan?.used}
                onClick={() => void scanRescan(scCmp === "exact" ? "changed" : scCmp,
                  scCmp === "exact" && scVal !== "" ? Number(scVal) : undefined)}>
                rescan
              </button>
            </div>
            <div style={{ display: "flex", gap: 4, padding: "2px var(--pad-md)" }}>
              <input className="addr-input mono" style={{ flex: 1 }} value={scAob}
                placeholder="aob pattern: 48 8B ?? ?? 90 (scan range above)"
                onChange={(e) => setScAob(e.target.value)} />
              <button className="row-action" disabled={busy || !scAddr || !scAob}
                onClick={() => {
                  void scanAob(parseHex(scAddr), parseHex(scLen), scAob);
                }}>
                aob
              </button>
            </div>
            {scan === null || !scan.used ? (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
                no native scan running - ps4_scan runs on the console (auth unlocked on connect).
              </div>
            ) : (
              <>
                <div className="faint mono" style={{ padding: "2px var(--pad-md)", fontSize: 11 }}>
                  base {scan.base_hex ?? hex(scan.base ?? 0)} · {scan.count ?? 0} hits{scan.truncated === true ? " (capped)" : ""}
                </div>
                {(scan.hits ?? []).slice(0, 100).map((h, i) => (
                  <div className="fn-row" style={{ position: "static", height: 20 }} key={i}>
                    <button className="fn-name mono" onClick={() => void gotoAddress(h.addr)}>
                      {h.addr_hex ?? hex(h.addr)}
                    </button>
                    <span className="faint mono" style={{ fontSize: 11 }}>{h.value_hex ?? ""}</span>
                  </div>
                ))}
              </>
            )}
          </div>
          <div className="dbg-head">Console</div>
          <div className="panel-body">
            <div className="faint" style={{ padding: "2px var(--pad-md)", fontSize: 11 }}>
              {app === null
                ? "foreground app unknown"
                : app.running === false || app.pid === 0
                  ? "no game in foreground"
                  : `foreground: ${app.name ?? "?"} ${app.titleid ?? ""} v${app.app_ver ?? "?"} (pid ${app.pid})`}
            </div>
            <div style={{ display: "flex", gap: 4, padding: "2px var(--pad-md)" }}>
              <input className="addr-input" style={{ flex: 1 }} value={notifyMsg}
                placeholder="notification text for the PS4 UI"
                onChange={(e) => setNotifyMsg(e.target.value)} />
              <button className="row-action" disabled={!notifyMsg}
                onClick={() => { void notify(notifyMsg); setNotifyMsg(""); }}>
                notify
              </button>
            </div>
            <div style={{ display: "flex", gap: 4, padding: "2px var(--pad-md)" }}>
              <input className="addr-input mono" style={{ width: 90 }} value={dumpName}
                onChange={(e) => setDumpName(e.target.value)} />
              <input className="addr-input mono" style={{ flex: 1 }} value={dumpPath}
                onChange={(e) => setDumpPath(e.target.value)} />
              <button className="row-action" disabled={busy || !dumpName || !dumpPath}
                onClick={() => void dumpModule(dumpName, dumpPath, true)}
                data-tip="dump the module's memory over the wire and load the ELF into disasm">
                dump+load
              </button>
            </div>
          </div>
        </div>

        <div className="dbg-col">
          <div className="dbg-head">Events</div>
          <div className="panel-body">
            {events.length === 0 ? (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
                no stop events yet - arm a bp, continue, wait.
              </div>
            ) : (
              events.slice(-40).map((e, i) => (
                <div className="log-row mono" key={i} style={{ padding: "1px var(--pad-md)", fontSize: 11 }}>
                  <span className="faint">lwp {e.lwpid}{e.thread !== undefined && e.thread !== "" ? ` (${e.thread})` : ""}</span>
                  <span style={{ color: e.signal !== 0 && e.signal !== 5 ? "var(--danger)" : undefined }}>
                    sig {e.signal}
                  </span>
                  {e.rip !== undefined && (
                    <button className="mono link" onClick={() => void gotoAddress(e.rip ?? 0)}>
                      {hex(e.rip, 12)}
                    </button>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
