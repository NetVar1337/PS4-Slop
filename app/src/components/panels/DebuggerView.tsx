// app/src/components/panels/DebuggerView.tsx
// PS4 live-debug panel: attach state, run control, breakpoints/watchpoints,
// registers, callstack, event feed - every action goes over the ps4debug-NG
// wire via the debugger ps4_* MCP actions

import { useEffect, useState } from "react";
import { Ban, FolderOpen, Gamepad2, Play, Plus, StepForward, Timer } from "lucide-react";
import { save } from "@tauri-apps/plugin-dialog";
import IconButton from "@/components/IconButton";
import { useT } from "@/i18n";
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
  const t = useT();
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
        <div className="empty-title">{t("debugger.noConsole")}</div>
        <div className="empty-hint">{t("debugger.noConsoleHint")}</div>
        <button type="button" className="row-action" onClick={() => setRail("targets")}>
          {t("debugger.openTargets")}
        </button>
      </div>
    );
  }

  /** Parse an address field; reports instead of silently ignoring bad input. */
  const addrOf = (text: string, what: string): number | null => {
    const a = parseAddress(text);
    if (a === null || a === 0) {
      setInputError(t("debugger.badAddress", { what, text }));
      return null;
    }
    setInputError(null);
    return a;
  };

  const addBp = () => {
    const a = addrOf(bpAddr, t("debugger.breakpoint"));
    if (a !== null) {
      void bpSet(a);
      setBpAddr("");
    }
  };
  const addWp = () => {
    const a = addrOf(wpAddr, t("debugger.watchpoint"));
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
      title: t("modules.dumpTitle", { name: dumpName }),
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
          {status.debug_attached
            ? t("debugger.attached", { pid: status.debug_pid })
            : t("debugger.notAttached")}
        </span>
        {status.ps4_connected && (
          <span className="faint mono" style={{ fontSize: 11 }}>
            {t("debugger.ps4", {
              fw:
                status.fw !== undefined && status.fw !== ""
                  ? t("debugger.fw", { fw: status.fw })
                  : "",
              pending: status.pending_events,
            })}
          </span>
        )}
        {(status.events_dropped ?? 0) > 0 && (
          <span className="pill warn-pill" data-tip={t("debugger.droppedTip")}>
            {t("debugger.dropped", { count: status.events_dropped ?? 0 })}
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
            {pid === 0 ? t("debugger.attachFirst") : t("debugger.attach")}
          </button>
        ) : (
          <>
            <IconButton
              tip={t("debugger.continue")}
              variant="row"
              disabled={busy}
              onClick={() => void cont()}
            >
              <Play size={11} />
            </IconButton>
            <IconButton
              tip={t("debugger.step")}
              variant="row"
              disabled={busy}
              onClick={() => void step(lwpNum)}
            >
              <StepForward size={11} />
            </IconButton>
            <IconButton
              tip={t("debugger.wait", { seconds: kWaitMs / 1000 })}
              variant="row"
              disabled={busy}
              onClick={() => void waitHalt(kWaitMs)}
            >
              <Timer size={11} />
            </IconButton>
            <button type="button" className="row-action" onClick={() => void detach()}>
              <Ban size={11} aria-hidden /> {t("debugger.detach")}
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
            {t("debugger.registers")}
            <div className="spacer" />
            <input
              className="addr-input mono"
              style={{ width: 64 }}
              aria-label={t("debugger.thread")}
              value={lwp}
              placeholder={t("debugger.lwpidPlaceholder")}
              onChange={(e) => setLwp(e.target.value)}
            />
          </div>
          <div className="panel-body">
            {regs === null ? (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
                {status.debug_attached
                  ? t("debugger.registersHint")
                  : t("debugger.registersNotAttached")}
              </div>
            ) : (
              <table className="table">
                <caption className="faint table-caption">
                  {t("debugger.lwp", { lwpid: regsLwpid })}
                </caption>
                <thead className="sr-only">
                  <tr>
                    <th scope="col">{t("debugger.register")}</th>
                    <th scope="col">{t("debugger.value")}</th>
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
                          data-tip={t("debugger.showInDisasm")}
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
          <div className="dbg-head">{t("debugger.callStack")}</div>
          <div className="panel-body">
            {frames.length === 0 ? (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
                {t("debugger.noFrames")}
              </div>
            ) : (
              <ol className="plain-list" aria-label={t("debugger.callStack")}>
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
                          {t("debugger.scanMarker")}
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
            {t("debugger.breakpoints")}
            <div className="spacer" />
            <input
              className="addr-input mono"
              style={{ width: 110 }}
              aria-label={t("debugger.bpAddress")}
              value={bpAddr}
              placeholder={t("debugger.addressPlaceholder")}
              onChange={(e) => setBpAddr(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && addBp()}
            />
            <IconButton tip={t("debugger.setBp")} onClick={addBp} disabled={!status.debug_attached}>
              <Plus size={13} />
            </IconButton>
          </div>
          <div className="panel-body">
            {breakpoints.length === 0 ? (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
                {t("debugger.noneSet")}
              </div>
            ) : (
              breakpoints.map((b) => (
                <div className="fn-row" style={{ position: "static", height: 20 }} key={b.addr}>
                  <span className="faint" style={{ width: 44 }}>
                    {t("debugger.slot", { index: b.index })}
                  </span>
                  <span className="fn-name mono">{hex(b.addr)}</span>
                  {(b.count ?? 0) > 0 && (
                    <span
                      className="faint mono"
                      style={{ fontSize: 10 }}
                      data-tip={
                        b.hits !== undefined && b.hits > 0
                          ? t("debugger.hitOn", { hits: b.hits, mode: b.hit_mode ?? "eq" })
                          : t("debugger.hitEvery")
                      }
                    >
                      {b.count}
                      {b.hits !== undefined && b.hits > 0 ? `/${b.hits}` : ""}
                    </span>
                  )}
                  {b.owner !== undefined && b.owner !== "" && (
                    <span className="faint" style={{ fontSize: 10 }} data-tip={t("debugger.owner")}>
                      {b.owner}
                    </span>
                  )}
                  <IconButton
                    tip={t("debugger.clearBp", { addr: hex(b.addr, 1) })}
                    onClick={() => void bpClear(b.addr)}
                  >
                    <Ban size={11} />
                  </IconButton>
                </div>
              ))
            )}
            <div className="dbg-head" style={{ marginTop: "var(--pad-sm)" }}>
              {t("debugger.watchpoints")}
              <div className="spacer" />
              <input
                className="addr-input mono"
                style={{ width: 110 }}
                aria-label={t("debugger.wpAddress")}
                value={wpAddr}
                placeholder={t("debugger.addressPlaceholder")}
                onChange={(e) => setWpAddr(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && addWp()}
              />
              <select
                className="addr-input"
                style={{ width: 64 }}
                aria-label={t("debugger.wpType")}
                value={wpType}
                onChange={(e) => setWpType(Number(e.target.value))}
              >
                <option value={0}>{t("debugger.wpExec")}</option>
                <option value={1}>{t("debugger.wpWrite")}</option>
                <option value={3}>{t("debugger.wpRdwr")}</option>
              </select>
              <select
                className="addr-input"
                style={{ width: 44 }}
                aria-label={t("debugger.wpLength")}
                value={wpLen}
                onChange={(e) => setWpLen(Number(e.target.value))}
              >
                {[1, 2, 4, 8].map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
              <IconButton
                tip={t("debugger.setWp")}
                onClick={addWp}
                disabled={!status.debug_attached}
              >
                <Plus size={13} />
              </IconButton>
            </div>
            {watchpoints.length === 0 ? (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
                {t("debugger.noneSet")}
              </div>
            ) : (
              watchpoints.map((w) => (
                <div className="fn-row" style={{ position: "static", height: 20 }} key={w.addr}>
                  <span className="faint" style={{ width: 44 }}>
                    {t("debugger.dr", { index: w.index })}
                  </span>
                  <span className="fn-name mono">{hex(w.addr)}</span>
                  <IconButton
                    tip={t("debugger.clearWp", { addr: hex(w.addr, 1) })}
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
            {t("debugger.consoleScan")}
            <div className="spacer" />
            <button
              type="button"
              className="row-action"
              disabled={busy}
              onClick={() => void scanReset()}
            >
              {t("debugger.reset")}
            </button>
          </div>
          <div className="panel-body">
            <div className="dbg-form">
              <input
                className="addr-input mono"
                style={{ width: 100 }}
                aria-label={t("debugger.scanAddr")}
                value={scAddr}
                placeholder={t("debugger.addrPlaceholder")}
                onChange={(e) => setScAddr(e.target.value)}
              />
              <input
                className="addr-input mono"
                style={{ width: 64 }}
                aria-label={t("debugger.scanLen")}
                value={scLen}
                placeholder={t("debugger.lenPlaceholder")}
                onChange={(e) => setScLen(e.target.value)}
              />
              <select
                className="addr-input"
                aria-label={t("debugger.scanType")}
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
                aria-label={t("debugger.scanCompare")}
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
                aria-label={t("debugger.scanValue")}
                value={scVal}
                placeholder={t("debugger.valuePlaceholder")}
                onChange={(e) => setScVal(e.target.value)}
              />
              <button
                type="button"
                className="row-action"
                disabled={busy || !scAddr || !scVal}
                onClick={() => {
                  const a = addrOf(scAddr, t("debugger.scanStart"));
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
                {t("debugger.scan")}
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
                {t("debugger.rescan")}
              </button>
            </div>
            <div className="dbg-form">
              <input
                className="addr-input mono"
                style={{ flex: 1 }}
                aria-label={t("debugger.aobPattern")}
                value={scAob}
                placeholder={t("debugger.aobPlaceholder")}
                onChange={(e) => setScAob(e.target.value)}
              />
              <button
                type="button"
                className="row-action"
                disabled={busy || !scAddr || !scAob}
                onClick={() => {
                  const a = addrOf(scAddr, t("debugger.scanStart"));
                  const l = parseAddress(scLen);
                  if (a !== null && l !== null) void scanAob(a, l, scAob);
                }}
              >
                {t("debugger.aob")}
              </button>
            </div>
            {scan === null || !scan.used ? (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
                {t("debugger.noNativeScan")}
              </div>
            ) : (
              <>
                <div className="faint mono" style={{ padding: "2px var(--pad-md)", fontSize: 11 }}>
                  {t("debugger.scanBase", {
                    base: scan.base_hex ?? hex(scan.base ?? 0),
                    count: scan.count ?? 0,
                  })}
                  {scan.truncated === true ? t("debugger.capped") : ""}
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
          <div className="dbg-head">{t("debugger.console")}</div>
          <div className="panel-body">
            <div className="faint" style={{ padding: "2px var(--pad-md)", fontSize: 11 }}>
              {app === null
                ? t("debugger.appUnknown")
                : app.running === false || app.pid === 0
                  ? t("debugger.noForeground")
                  : t("debugger.foreground", {
                      name: app.name ?? "?",
                      titleid: app.titleid ?? "",
                      version: app.app_ver ?? "?",
                      pid: app.pid,
                    })}
            </div>
            <div className="dbg-form">
              <input
                className="addr-input"
                style={{ flex: 1 }}
                aria-label={t("debugger.notification")}
                value={notifyMsg}
                placeholder={t("debugger.notificationPlaceholder")}
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
                {t("debugger.notify")}
              </button>
            </div>
            <div className="dbg-form">
              <input
                className="addr-input mono"
                style={{ width: 90 }}
                aria-label={t("debugger.moduleToDump")}
                value={dumpName}
                onChange={(e) => setDumpName(e.target.value)}
              />
              <input
                className="addr-input mono"
                style={{ flex: 1 }}
                aria-label={t("debugger.dumpPath")}
                value={dumpPath}
                placeholder={t("debugger.dumpPathPlaceholder")}
                onChange={(e) => setDumpPath(e.target.value)}
              />
              {isTauri() && (
                <IconButton tip={t("debugger.browse")} onClick={() => void pickDumpPath()}>
                  <FolderOpen size={12} />
                </IconButton>
              )}
              <button
                type="button"
                className="row-action"
                disabled={busy || !dumpName || !dumpPath}
                onClick={() => void dumpModule(dumpName, dumpPath, true)}
                data-tip={t("debugger.dumpLoadTip")}
              >
                {t("debugger.dumpLoad")}
              </button>
            </div>
          </div>
        </div>

        <div className="dbg-col">
          <div className="dbg-head">{t("debugger.events")}</div>
          <div className="panel-body">
            {logs.length > 0 && (
              <ol className="plain-list" aria-label={t("debugger.logLines")}>
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
                {t("debugger.noEvents")}
              </div>
            ) : (
              <ol className="plain-list" aria-label={t("debugger.stopEvents")}>
                {events.slice(0, 40).map((e, i) => (
                  <li
                    className="log-row mono"
                    key={i}
                    style={{ padding: "1px var(--pad-md)", fontSize: 11 }}
                  >
                    <span className="faint">
                      {t("debugger.lwp", { lwpid: e.lwpid })}
                      {e.thread !== undefined && e.thread !== ""
                        ? t("debugger.eventThread", { thread: e.thread })
                        : ""}
                    </span>
                    <span
                      style={{
                        color: e.signal !== 0 && e.signal !== 5 ? "var(--danger)" : undefined,
                      }}
                    >
                      {t("debugger.signal", { signal: e.signal })}
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
