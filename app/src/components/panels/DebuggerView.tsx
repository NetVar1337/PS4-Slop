// app/src/components/panels/DebuggerView.tsx
// PS4 live-debug panel: attach state, run control, breakpoints/watchpoints,
// registers, callstack, event feed - every action goes over the ps4debug-NG
// wire via the debugger ps4_* MCP actions

import { useEffect, useState } from "react";
import { Ban, FolderOpen, Gamepad2, Play, Plus, StepForward, Timer } from "lucide-react";
import { save } from "@tauri-apps/plugin-dialog";
import IconButton from "@/components/IconButton";
import { isTauri } from "@/lib/endpoint";
import { hex, parseAddress } from "@/lib/format";
import { showInDisassembly } from "@/lib/navigate";
import { kRegOrder, useDebugger } from "@/store/debugger";
import { useEngine } from "@/store/engine";
import { useUi } from "@/store/ui";

const kScanTypes = ["u8", "i8", "u16", "i16", "u32", "i32", "u64", "i64", "f32", "f64"];
const kCompares = [
  "exact",
  "bigger",
  "smaller",
  "between",
  "increased",
  "decreased",
  "changed",
  "unchanged",
  "unknown",
];
const kWaitMs = 5000;
/** Fallback poll while attached; the push stream is the primary source. */
const kFallbackPollMs = 15_000;

export default function DebuggerView() {
  const target = useEngine((s) => s.target);
  const backend = useEngine((s) => s.backend);
  const setRail = useUi((s) => s.setRail);
  const {
    status,
    regs,
    regsLwpid,
    frames,
    events,
    breakpoints,
    watchpoints,
    scan,
    app,
    error,
    waitNote,
    logs,
    busy,
    connectStream,
    refresh,
    attach,
    detach,
    cont,
    step,
    waitHalt,
    bpSet,
    bpClear,
    wpSet,
    wpClear,
    scanFirst,
    scanRescan,
    scanAob,
    scanReset,
    notify,
    dumpModule,
  } = useDebugger();
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
  const [dumpPath, setDumpPath] = useState("");
  const [inputError, setInputError] = useState<string | null>(null);

  useEffect(() => {
    void refresh();
    // stop events arrive over /events; the poll below is only a fallback for
    // a dropped stream (and catches state the engine does not push)
    const off = connectStream();
    const id = setInterval(() => {
      const s = useDebugger.getState().status;
      if (s.ps4_connected) void refresh();
    }, kFallbackPollMs);
    return () => {
      off();
      clearInterval(id);
    };
  }, [connectStream, refresh, target.pid, backend.ps4]);

  const pid = target.pid ?? status.debug_pid;

  if (!backend.ps4) {
    return (
      <div className="empty">
        <div className="empty-glyph">
          <Gamepad2 size={28} strokeWidth={1.5} />
        </div>
        <div className="empty-title">No PS4 console connected.</div>
        <div className="empty-hint">
          Connect one from the Targets panel, or over MCP with target.ps4_auto. This view then
          drives the live ps4debug-NG session on the console.
        </div>
        <button type="button" className="row-action" onClick={() => setRail("targets")}>
          Open Targets
        </button>
      </div>
    );
  }

  /** Parse an address field; reports instead of silently ignoring bad input. */
  const addrOf = (text: string, what: string): number | null => {
    const a = parseAddress(text);
    if (a === null || a === 0) {
      setInputError(`${what}: "${text}" is not a hex address`);
      return null;
    }
    setInputError(null);
    return a;
  };

  const addBp = () => {
    const a = addrOf(bpAddr, "breakpoint");
    if (a !== null) {
      void bpSet(a);
      setBpAddr("");
    }
  };
  const addWp = () => {
    const a = addrOf(wpAddr, "watchpoint");
    if (a !== null) {
      void wpSet(a, wpType, wpLen);
      setWpAddr("");
    }
  };
  // an empty box steps the thread that last stopped (the engine's lwpid 0
  // means all threads, which is rarely what the panel wants)
  const lwpNum = lwp.trim() === "" ? regsLwpid : (parseAddress(lwp) ?? 0);

  const pickDumpPath = async () => {
    if (!isTauri()) return;
    const picked = await save({
      title: `Dump ${dumpName}`,
      defaultPath: `${dumpName}.elf`,
      filters: [{ name: "ELF", extensions: ["elf", "bin", "prx"] }],
    });
    if (typeof picked === "string") setDumpPath(picked);
  };

  return (
    <div className="stack dbg-stack">
      <div className="view-bar">
        <span
          className="pill"
          style={{ color: status.debug_attached ? "var(--success)" : undefined }}
        >
          {status.debug_attached ? `debug attached pid ${status.debug_pid}` : "debug not attached"}
        </span>
        {status.ps4_connected && (
          <span className="faint mono" style={{ fontSize: 11 }}>
            ps4{status.fw !== undefined && status.fw !== "" ? ` · fw ${status.fw}` : ""} · pending{" "}
            {status.pending_events}
          </span>
        )}
        {(status.events_dropped ?? 0) > 0 && (
          <span
            className="pill warn-pill"
            data-tip="The engine's stop-event queue overflowed; older events were discarded"
          >
            {status.events_dropped} events dropped
          </span>
        )}

        <div className="spacer" />

        {!status.debug_attached ? (
          <button
            type="button"
            className="row-action"
            disabled={pid === 0 || busy}
            onClick={() => pid !== 0 && void attach(pid)}
          >
            {pid === 0 ? "Attach a process first" : "Attach debugger (ps4debug)"}
          </button>
        ) : (
          <>
            <IconButton tip="Continue" variant="row" disabled={busy} onClick={() => void cont()}>
              <Play size={11} />
            </IconButton>
            <IconButton
              tip="Step one lwp (empty = the thread that last stopped)"
              variant="row"
              disabled={busy}
              onClick={() => void step(lwpNum)}
            >
              <StepForward size={11} />
            </IconButton>
            <IconButton
              tip={`Wait for a stop event (${kWaitMs / 1000}s)`}
              variant="row"
              disabled={busy}
              onClick={() => void waitHalt(kWaitMs)}
            >
              <Timer size={11} />
            </IconButton>
            <button type="button" className="row-action" onClick={() => void detach()}>
              <Ban size={11} aria-hidden /> Detach
            </button>
          </>
        )}
      </div>

      {/* Always present: the view is a three-row grid (bar / notes / columns) */}
      <div className="dbg-notes">
        {waitNote !== null && (
          <div className="empty-hint" role="status">
            {waitNote}
          </div>
        )}
        {(error ?? inputError) !== null && (
          <div className="empty-hint error-text" role="alert">
            {error ?? inputError}
          </div>
        )}
      </div>

      <div className="dbg">
        <div className="dbg-col">
          <div className="dbg-head">
            Registers
            <div className="spacer" />
            <input
              className="addr-input mono"
              style={{ width: 64 }}
              aria-label="Thread (lwpid) for step"
              value={lwp}
              placeholder="lwpid"
              onChange={(e) => setLwp(e.target.value)}
            />
          </div>
          <div className="panel-body">
            {regs === null ? (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
                {status.debug_attached
                  ? "stop the target (bp / wait) to read registers."
                  : "not attached."}
              </div>
            ) : (
              <table className="table">
                <caption className="faint table-caption">lwp {regsLwpid}</caption>
                <thead className="sr-only">
                  <tr>
                    <th scope="col">Register</th>
                    <th scope="col">Value</th>
                  </tr>
                </thead>
                <tbody>
                  {kRegOrder.map((name) => (
                    <tr key={name}>
                      <th scope="row" className="mono faint reg-name">
                        {name}
                      </th>
                      <td>
                        <button
                          type="button"
                          className="mono link"
                          data-tip="show in disassembly"
                          onClick={() => showInDisassembly(regs[name] ?? 0)}
                        >
                          {hex(regs[name] ?? 0)}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
          <div className="dbg-head">Call stack</div>
          <div className="panel-body">
            {frames.length === 0 ? (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
                no frames.
              </div>
            ) : (
              <ol className="plain-list" aria-label="Call stack">
                {frames.map((f, i) => (
                  <li key={i}>
                    <button
                      type="button"
                      className="fn-row"
                      style={{ position: "static", height: 20 }}
                      onClick={() => showInDisassembly(f.ret_addr ?? 0)}
                      data-tip={f.snippet !== undefined && f.snippet !== "" ? f.snippet : undefined}
                    >
                      <span className="faint" style={{ width: 20 }}>
                        {i}
                      </span>
                      <span className="fn-name mono">{hex(f.ret_addr ?? 0)}</span>
                      {f.scanned === true && (
                        <span className="faint" style={{ fontSize: 10 }}>
                          scan
                        </span>
                      )}
                    </button>
                  </li>
                ))}
              </ol>
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
              aria-label="Breakpoint address"
              value={bpAddr}
              placeholder="address"
              onChange={(e) => setBpAddr(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && addBp()}
            />
            <IconButton tip="Set breakpoint" onClick={addBp} disabled={!status.debug_attached}>
              <Plus size={13} />
            </IconButton>
          </div>
          <div className="panel-body">
            {breakpoints.length === 0 ? (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
                none set.
              </div>
            ) : (
              breakpoints.map((b) => (
                <div className="fn-row" style={{ position: "static", height: 20 }} key={b.addr}>
                  <span className="faint" style={{ width: 44 }}>
                    slot {b.index}
                  </span>
                  <span className="fn-name mono">{hex(b.addr)}</span>
                  {(b.count ?? 0) > 0 && (
                    <span
                      className="faint mono"
                      style={{ fontSize: 10 }}
                      data-tip={
                        b.hits !== undefined && b.hits > 0
                          ? `stops on hit ${b.hits} (${b.hit_mode ?? "eq"})`
                          : "stops on every hit"
                      }
                    >
                      {b.count}
                      {b.hits !== undefined && b.hits > 0 ? `/${b.hits}` : ""}
                    </span>
                  )}
                  {b.owner !== undefined && b.owner !== "" && (
                    <span className="faint" style={{ fontSize: 10 }} data-tip="owning client">
                      {b.owner}
                    </span>
                  )}
                  <IconButton
                    tip={`Clear breakpoint ${hex(b.addr, 1)}`}
                    onClick={() => void bpClear(b.addr)}
                  >
                    <Ban size={11} />
                  </IconButton>
                </div>
              ))
            )}
            <div className="dbg-head" style={{ marginTop: "var(--pad-sm)" }}>
              Watchpoints (DR)
              <div className="spacer" />
              <input
                className="addr-input mono"
                style={{ width: 110 }}
                aria-label="Watchpoint address"
                value={wpAddr}
                placeholder="address"
                onChange={(e) => setWpAddr(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && addWp()}
              />
              <select
                className="addr-input"
                style={{ width: 64 }}
                aria-label="Watchpoint type"
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
                aria-label="Watchpoint length"
                value={wpLen}
                onChange={(e) => setWpLen(Number(e.target.value))}
              >
                {[1, 2, 4, 8].map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
              <IconButton tip="Set watchpoint" onClick={addWp} disabled={!status.debug_attached}>
                <Plus size={13} />
              </IconButton>
            </div>
            {watchpoints.length === 0 ? (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
                none set.
              </div>
            ) : (
              watchpoints.map((w) => (
                <div className="fn-row" style={{ position: "static", height: 20 }} key={w.addr}>
                  <span className="faint" style={{ width: 44 }}>
                    DR{w.index}
                  </span>
                  <span className="fn-name mono">{hex(w.addr)}</span>
                  <IconButton
                    tip={`Clear watchpoint ${hex(w.addr, 1)}`}
                    onClick={() => void wpClear(w.addr)}
                  >
                    <Ban size={11} />
                  </IconButton>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="dbg-col">
          <div className="dbg-head">
            Console scan (on-device)
            <div className="spacer" />
            <button
              type="button"
              className="row-action"
              disabled={busy}
              onClick={() => void scanReset()}
            >
              reset
            </button>
          </div>
          <div className="panel-body">
            <div className="dbg-form">
              <input
                className="addr-input mono"
                style={{ width: 100 }}
                aria-label="Scan start address"
                value={scAddr}
                placeholder="addr"
                onChange={(e) => setScAddr(e.target.value)}
              />
              <input
                className="addr-input mono"
                style={{ width: 64 }}
                aria-label="Scan length"
                value={scLen}
                placeholder="len"
                onChange={(e) => setScLen(e.target.value)}
              />
              <select
                className="addr-input"
                aria-label="Scan value type"
                value={scType}
                onChange={(e) => setScType(e.target.value)}
              >
                {kScanTypes.map((w) => (
                  <option key={w} value={w}>
                    {w}
                  </option>
                ))}
              </select>
              <select
                className="addr-input"
                aria-label="Scan comparison"
                value={scCmp}
                onChange={(e) => setScCmp(e.target.value)}
              >
                {kCompares.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
              <input
                className="addr-input mono"
                style={{ width: 80 }}
                aria-label="Scan value"
                value={scVal}
                placeholder="value"
                onChange={(e) => setScVal(e.target.value)}
              />
              <button
                type="button"
                className="row-action"
                disabled={busy || !scAddr || !scVal}
                onClick={() => {
                  const a = addrOf(scAddr, "scan start");
                  const l = parseAddress(scLen);
                  if (a === null || l === null) return;
                  const v = scVal.trim();
                  const num = Number(v);
                  void scanFirst({
                    addr: a,
                    len: l,
                    value_type: scType,
                    compare: scCmp,
                    value: Number.isFinite(num) && v !== "" ? num : v,
                  });
                }}
              >
                scan
              </button>
              <button
                type="button"
                className="row-action"
                disabled={busy || !scan?.used}
                onClick={() =>
                  void scanRescan(
                    scCmp === "exact" ? "changed" : scCmp,
                    scCmp === "exact" && scVal !== "" ? Number(scVal) : undefined,
                  )
                }
              >
                rescan
              </button>
            </div>
            <div className="dbg-form">
              <input
                className="addr-input mono"
                style={{ flex: 1 }}
                aria-label="AOB pattern"
                value={scAob}
                placeholder="aob pattern: 48 8B ?? ?? 90 (scan range above)"
                onChange={(e) => setScAob(e.target.value)}
              />
              <button
                type="button"
                className="row-action"
                disabled={busy || !scAddr || !scAob}
                onClick={() => {
                  const a = addrOf(scAddr, "scan start");
                  const l = parseAddress(scLen);
                  if (a !== null && l !== null) void scanAob(a, l, scAob);
                }}
              >
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
                  base {scan.base_hex ?? hex(scan.base ?? 0)} · {scan.count ?? 0} hits
                  {scan.truncated === true ? " (capped)" : ""}
                </div>
                {(scan.hits ?? []).slice(0, 100).map((h, i) => (
                  <div className="fn-row" style={{ position: "static", height: 20 }} key={i}>
                    <button
                      type="button"
                      className="fn-name mono link"
                      onClick={() => showInDisassembly(h.addr)}
                    >
                      {h.addr_hex ?? hex(h.addr)}
                    </button>
                    <span className="faint mono" style={{ fontSize: 11 }}>
                      {h.value_hex ?? ""}
                    </span>
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
            <div className="dbg-form">
              <input
                className="addr-input"
                style={{ flex: 1 }}
                aria-label="Notification text"
                value={notifyMsg}
                placeholder="notification text for the PS4 UI"
                onChange={(e) => setNotifyMsg(e.target.value)}
              />
              <button
                type="button"
                className="row-action"
                disabled={!notifyMsg}
                onClick={() => {
                  void notify(notifyMsg);
                  setNotifyMsg("");
                }}
              >
                notify
              </button>
            </div>
            <div className="dbg-form">
              <input
                className="addr-input mono"
                style={{ width: 90 }}
                aria-label="Module to dump"
                value={dumpName}
                onChange={(e) => setDumpName(e.target.value)}
              />
              <input
                className="addr-input mono"
                style={{ flex: 1 }}
                aria-label="Dump output path"
                value={dumpPath}
                placeholder="output file (Browse…)"
                onChange={(e) => setDumpPath(e.target.value)}
              />
              {isTauri() && (
                <IconButton tip="Browse for the output file" onClick={() => void pickDumpPath()}>
                  <FolderOpen size={12} />
                </IconButton>
              )}
              <button
                type="button"
                className="row-action"
                disabled={busy || !dumpName || !dumpPath}
                onClick={() => void dumpModule(dumpName, dumpPath, true)}
                data-tip="dump the module's memory over the wire and load the ELF into disasm"
              >
                dump+load
              </button>
            </div>
          </div>
        </div>

        <div className="dbg-col">
          <div className="dbg-head">Events</div>
          <div className="panel-body">
            {logs.length > 0 && (
              <ol className="plain-list" aria-label="Log breakpoint lines, newest first">
                {logs.slice(0, 20).map((line, i) => (
                  <li
                    className="log-row mono"
                    key={`log-${i}`}
                    style={{ padding: "1px var(--pad-md)", fontSize: 11 }}
                  >
                    {line}
                  </li>
                ))}
              </ol>
            )}
            {events.length === 0 ? (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
                no stop events yet - arm a bp, continue, wait.
              </div>
            ) : (
              <ol className="plain-list" aria-label="Stop events, newest first">
                {events.slice(0, 40).map((e, i) => (
                  <li
                    className="log-row mono"
                    key={i}
                    style={{ padding: "1px var(--pad-md)", fontSize: 11 }}
                  >
                    <span className="faint">
                      lwp {e.lwpid}
                      {e.thread !== undefined && e.thread !== "" ? ` (${e.thread})` : ""}
                    </span>
                    <span
                      style={{
                        color: e.signal !== 0 && e.signal !== 5 ? "var(--danger)" : undefined,
                      }}
                    >
                      sig {e.signal}
                    </span>
                    {e.rip !== undefined && (
                      <button
                        type="button"
                        className="mono link"
                        onClick={() => showInDisassembly(e.rip ?? 0)}
                      >
                        {hex(e.rip, 12)}
                      </button>
                    )}
                  </li>
                ))}
              </ol>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
