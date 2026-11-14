// app/src/components/panels/EmulatorPanel.tsx
// Unicorn emulation (tool: emulate): one-shot runs with stop conditions, dump
// windows, trace and taint, plus persistent sessions and the backward slice
// over a recorded trace

import { useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Cpu, Play, Plus, Trash2 } from "lucide-react";
import { hex, parseAddress } from "@/lib/format";
import { useEmulator, type EmuParams, type EmuRegs, type EmuTraceRow } from "@/store/emulator";

const kRow = 18;

function RegTable({ regs }: { regs: EmuRegs }) {
  const names = Object.keys(regs).sort((a, b) => a.localeCompare(b));
  return (
    <table className="table">
      <caption className="sr-only">Registers</caption>
      <thead>
        <tr>
          <th scope="col">Register</th>
          <th scope="col">Value</th>
        </tr>
      </thead>
      <tbody>
        {names.map((name) => (
          <tr key={name}>
            <td className="mono">{name}</td>
            <td className="mono">{hex(regs[name], 1)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function TraceList({ rows }: { rows: EmuTraceRow[] }) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => kRow,
    overscan: 12,
  });
  return (
    <div className="tool-table-wrap">
      <div className="tool-table-scroll" ref={scrollRef}>
        <table className="table">
          <caption className="sr-only">Execution trace</caption>
          <thead>
            <tr>
              <th scope="col">IP</th>
              <th scope="col">Instruction</th>
            </tr>
          </thead>
          <tbody style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
            {virtualizer.getVirtualItems().map((v) => {
              const t = rows[v.index];
              return (
                <tr
                  key={`${t.ip}-${v.index}`}
                  style={{
                    position: "absolute",
                    top: v.start,
                    left: 0,
                    width: "100%",
                    height: kRow,
                    display: "table",
                    tableLayout: "fixed",
                  }}
                >
                  <td className="mono faint">{hex(t.ip, 1)}</td>
                  <td className="mono">{t.text}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

type Dump = { addr: string; len: string };

export default function EmulatorPanel() {
  const {
    run,
    session,
    slice,
    busy,
    error,
    emulate,
    backSlice,
    sessionCreate,
    sessionStep,
    sessionDestroy,
    snapshot,
    restore,
  } = useEmulator();
  const [source, setSource] = useState<"hex" | "file_addr" | "target_addr">("hex");
  const [hexText, setHexText] = useState("");
  const [fileAddr, setFileAddr] = useState("");
  const [targetAddr, setTargetAddr] = useState("");
  const [arch, setArch] = useState("x64");
  const [until, setUntil] = useState("");
  const [count, setCount] = useState("1000");
  const [timeoutMs, setTimeoutMs] = useState("5000");
  const [trace, setTrace] = useState(true);
  const [traceMax, setTraceMax] = useState("256");
  const [orbis, setOrbis] = useState(false);
  const [taintOn, setTaintOn] = useState(false);
  const [taintAddr, setTaintAddr] = useState("");
  const [taintLen, setTaintLen] = useState("16");
  const [dumps, setDumps] = useState<Dump[]>([]);
  const [traceId, setTraceId] = useState("");
  const [sliceReg, setSliceReg] = useState("");
  const [sliceAddr, setSliceAddr] = useState("");
  const [sliceLen, setSliceLen] = useState("8");
  const [sliceAt, setSliceAt] = useState("");

  const params = (): EmuParams | null => {
    const p: EmuParams = { arch };
    if (source === "hex") {
      if (hexText.trim() === "") return null;
      p.hex = hexText.trim();
    } else if (source === "file_addr") {
      const va = parseAddress(fileAddr);
      if (va === null) return null;
      p.file_addr = va;
    } else {
      const va = parseAddress(targetAddr);
      if (va === null) return null;
      p.target_addr = va;
    }
    const untilVa = parseAddress(until);
    if (untilVa !== null) p.until = untilVa;
    const countValue = Number.parseInt(count, 10);
    if (Number.isFinite(countValue) && countValue > 0) p.count = countValue;
    const timeoutValue = Number.parseInt(timeoutMs, 10);
    if (Number.isFinite(timeoutValue) && timeoutValue > 0) p.timeout_ms = timeoutValue;
    if (trace) {
      p.trace = true;
      const maxValue = Number.parseInt(traceMax, 10);
      if (Number.isFinite(maxValue) && maxValue > 0) p.trace_max = maxValue;
    }
    if (orbis) p.orbis_syscalls = true;
    const windows = dumps
      .map((d) => ({ addr: parseAddress(d.addr), len: Number.parseInt(d.len, 10) }))
      .filter(
        (d): d is { addr: number; len: number } =>
          d.addr !== null && Number.isFinite(d.len) && d.len > 0,
      );
    if (windows.length > 0) p.dump = windows;
    const taintVa = parseAddress(taintAddr);
    const taintLength = Number.parseInt(taintLen, 10);
    if (taintOn && taintVa !== null && Number.isFinite(taintLength) && taintLength > 0)
      p.taint = [{ addr: taintVa, len: taintLength }];
    return p;
  };

  const doRun = async () => {
    const p = params();
    if (p === null) return;
    await emulate(p);
    const id = useEmulator.getState().run?.trace_id;
    if (id !== undefined) setTraceId(String(id));
  };

  return (
    <div className="panel tool-panel">
      <div className="panel-head">
        <span className="panel-title">Emulator</span>
        <span className="faint" style={{ fontSize: "var(--type-small)" }}>
          Unicorn · isolated
        </span>
        <div className="spacer" />
        <button
          type="button"
          className="row-action"
          disabled={busy !== null}
          onClick={() => void doRun()}
        >
          <Play size={11} aria-hidden /> Run
        </button>
      </div>
      <div className="panel-body tool-body">
        <div className="tool-form">
          <select
            className="select"
            aria-label="Code source"
            value={source}
            onChange={(e) => setSource(e.target.value as typeof source)}
          >
            <option value="hex">hex bytes</option>
            <option value="file_addr">image address</option>
            <option value="target_addr">target address</option>
          </select>
          <select
            className="select"
            aria-label="Architecture"
            value={arch}
            onChange={(e) => setArch(e.target.value)}
          >
            <option value="x64">x86-64</option>
            <option value="arm64">arm64</option>
          </select>
          <label className="faint tool-field">
            until
            <input
              className="addr-input mono"
              style={{ width: 96 }}
              aria-label="Stop at address (hex)"
              placeholder="stop VA"
              value={until}
              onChange={(e) => setUntil(e.target.value)}
            />
          </label>
          <label className="faint tool-field">
            count
            <input
              className="addr-input"
              style={{ width: 64 }}
              aria-label="Instruction count"
              inputMode="numeric"
              value={count}
              onChange={(e) => setCount(e.target.value)}
            />
          </label>
          <label className="faint tool-field">
            timeout ms
            <input
              className="addr-input"
              style={{ width: 64 }}
              aria-label="Timeout in milliseconds"
              inputMode="numeric"
              value={timeoutMs}
              onChange={(e) => setTimeoutMs(e.target.value)}
            />
          </label>
        </div>

        {source === "hex" ? (
          <textarea
            className="tool-hex mono"
            aria-label="Code bytes (hex)"
            placeholder="48 31 C0 C3"
            rows={3}
            value={hexText}
            onChange={(e) => setHexText(e.target.value)}
          />
        ) : (
          <div className="tool-form">
            <input
              className="addr-input mono"
              style={{ width: 130 }}
              aria-label={source === "file_addr" ? "Image address (hex)" : "Target address (hex)"}
              placeholder={source === "file_addr" ? "file_addr" : "target_addr"}
              value={source === "file_addr" ? fileAddr : targetAddr}
              onChange={(e) =>
                source === "file_addr" ? setFileAddr(e.target.value) : setTargetAddr(e.target.value)
              }
            />
          </div>
        )}

        <div className="tool-form">
          <label className="faint tool-field">
            <input
              type="checkbox"
              aria-label="Record trace"
              checked={trace}
              onChange={(e) => setTrace(e.target.checked)}
            />
            trace
          </label>
          <input
            className="addr-input"
            style={{ width: 64 }}
            aria-label="Trace max instructions"
            inputMode="numeric"
            value={traceMax}
            onChange={(e) => setTraceMax(e.target.value)}
          />
          <label className="faint tool-field">
            <input
              type="checkbox"
              aria-label="Orbis syscalls"
              checked={orbis}
              onChange={(e) => setOrbis(e.target.checked)}
            />
            orbis syscalls
          </label>
          <label className="faint tool-field">
            <input
              type="checkbox"
              aria-label="Enable taint"
              checked={taintOn}
              onChange={(e) => setTaintOn(e.target.checked)}
            />
            taint
          </label>
          <input
            className="addr-input mono"
            style={{ width: 96 }}
            aria-label="Taint source address (hex)"
            placeholder="taint VA"
            value={taintAddr}
            onChange={(e) => setTaintAddr(e.target.value)}
          />
          <input
            className="addr-input"
            style={{ width: 56 }}
            aria-label="Taint source length"
            inputMode="numeric"
            value={taintLen}
            onChange={(e) => setTaintLen(e.target.value)}
          />
        </div>

        <div className="tool-form">
          <span className="faint">dump windows</span>
          {dumps.map((d, i) => (
            <span key={i} className="tool-field">
              <input
                className="addr-input mono"
                style={{ width: 96 }}
                aria-label={`Dump ${i + 1} address`}
                placeholder="addr"
                value={d.addr}
                onChange={(e) =>
                  setDumps(dumps.map((x, j) => (j === i ? { ...x, addr: e.target.value } : x)))
                }
              />
              <input
                className="addr-input"
                style={{ width: 56 }}
                aria-label={`Dump ${i + 1} length`}
                placeholder="len"
                inputMode="numeric"
                value={d.len}
                onChange={(e) =>
                  setDumps(dumps.map((x, j) => (j === i ? { ...x, len: e.target.value } : x)))
                }
              />
              <button
                type="button"
                className="row-action"
                aria-label={`Remove dump ${i + 1}`}
                onClick={() => setDumps(dumps.filter((_, j) => j !== i))}
              >
                <Trash2 size={11} aria-hidden />
              </button>
            </span>
          ))}
          <button
            type="button"
            className="row-action"
            onClick={() => setDumps([...dumps, { addr: "", len: "16" }])}
          >
            <Plus size={11} aria-hidden /> Add
          </button>
        </div>

        <div className="tool-form">
          <button
            type="button"
            className="row-action"
            disabled={busy !== null}
            onClick={() => {
              const p = params();
              if (p !== null) void sessionCreate(p);
            }}
          >
            Create session
          </button>
          <button
            type="button"
            className="row-action"
            disabled={busy !== null || session === null}
            onClick={() => void sessionStep(1, false)}
          >
            Step
          </button>
          <button
            type="button"
            className="row-action"
            disabled={busy !== null || session === null}
            onClick={() => void sessionStep(0, true)}
          >
            Run session
          </button>
          <button
            type="button"
            className="row-action"
            disabled={busy !== null || session === null}
            onClick={() => void snapshot()}
          >
            Snapshot
          </button>
          <button
            type="button"
            className="row-action"
            disabled={busy !== null || session === null}
            onClick={() => void restore()}
          >
            Restore
          </button>
          <button
            type="button"
            className="row-action"
            disabled={busy !== null || session === null}
            onClick={() => void sessionDestroy()}
          >
            Destroy
          </button>
          {busy !== null && <span className="faint">{busy}…</span>}
        </div>

        {error !== null && (
          <div className="empty-hint error-text" role="alert">
            {error}
          </div>
        )}

        {run !== null && (
          <div className="tool-summary">
            <div className="faint">
              {run.stopped_reason} · {run.instructions} instructions · {run.arch} / {run.abi}
              {run.exited === true ? ` · exited ${run.exit_code ?? 0}` : ""}
              {run.paged_in !== undefined ? ` · ${run.paged_in} pages in` : ""}
              {run.trace_id !== undefined ? ` · trace ${run.trace_id}` : ""}
            </div>
            {run.fault !== undefined && (
              <div className="sev-bad mono">
                fault at {hex(run.fault.ip, 1)} accessing {hex(run.fault.addr, 1)} (
                {run.fault.access})
              </div>
            )}
            {run.note !== undefined && <div className="faint">{run.note}</div>}
            {run.stdout !== undefined && <pre className="tool-pre">{run.stdout}</pre>}
          </div>
        )}

        {run !== null && <RegTable regs={run.regs} />}

        {run?.trace !== undefined && run.trace.length > 0 && (
          <>
            <div className="tool-section-head">
              <span className="panel-title">Trace</span>
              <span className="faint">{run.trace.length} instructions</span>
            </div>
            <TraceList rows={run.trace} />
          </>
        )}

        {run?.taint_ranges !== undefined && (
          <div className="tool-summary">
            <div className="faint">
              taint: {run.taint_ranges.length} ranges
              {run.output_tainted === true ? " · output tainted" : " · output clean"}
            </div>
            <ul className="tool-steps mono">
              {run.taint_ranges.map((r, i) => (
                <li key={i}>
                  {hex(r.addr, 1)} + {r.len}
                </li>
              ))}
            </ul>
          </div>
        )}

        {run?.memory !== undefined && run.memory.length > 0 && (
          <div className="tool-summary">
            {run.memory.map((m, i) => (
              <div key={i} className="mono">
                dump {hex(m.addr, 1)} · {m.len}/{m.requested} B · {m.hex}
              </div>
            ))}
          </div>
        )}

        <div className="tool-section-head">
          <span className="panel-title">Backward slice</span>
          <span className="faint">needs trace=true</span>
        </div>
        <div className="tool-form">
          <input
            className="addr-input"
            style={{ width: 64 }}
            aria-label="Trace id"
            placeholder="trace id"
            inputMode="numeric"
            value={traceId}
            onChange={(e) => setTraceId(e.target.value)}
          />
          <input
            className="addr-input mono"
            style={{ width: 64 }}
            aria-label="Slice register"
            placeholder="reg"
            value={sliceReg}
            onChange={(e) => setSliceReg(e.target.value)}
          />
          <input
            className="addr-input mono"
            style={{ width: 96 }}
            aria-label="Slice address (hex)"
            placeholder="addr"
            value={sliceAddr}
            onChange={(e) => setSliceAddr(e.target.value)}
          />
          <input
            className="addr-input"
            style={{ width: 56 }}
            aria-label="Slice length"
            placeholder="len"
            inputMode="numeric"
            value={sliceLen}
            onChange={(e) => setSliceLen(e.target.value)}
          />
          <input
            className="addr-input"
            style={{ width: 56 }}
            aria-label="Slice trace index"
            placeholder="at"
            inputMode="numeric"
            value={sliceAt}
            onChange={(e) => setSliceAt(e.target.value)}
          />
          <button
            type="button"
            className="row-action"
            disabled={busy !== null}
            onClick={() => {
              const id = Number.parseInt(traceId, 10);
              if (!Number.isFinite(id)) return;
              const at = Number.parseInt(sliceAt, 10);
              const len = Number.parseInt(sliceLen, 10);
              const addr = parseAddress(sliceAddr);
              void backSlice({
                trace_id: id,
                ...(sliceReg.trim() !== "" ? { reg: sliceReg.trim() } : {}),
                ...(addr !== null ? { addr } : {}),
                ...(Number.isFinite(len) && len > 0 ? { len } : {}),
                ...(Number.isFinite(at) ? { at } : {}),
              });
            }}
          >
            Slice
          </button>
        </div>
        {slice !== null && (
          <div className="tool-summary">
            <div className="faint">
              {slice.count} instructions for trace {slice.trace_id}
            </div>
            <ol className="tool-steps mono">
              {slice.instructions.map((i, n) => (
                <li key={n}>
                  {hex(i.ip, 1)} {i.text}
                </li>
              ))}
            </ol>
          </div>
        )}

        {session !== null && (
          <div className="tool-summary">
            <div className="faint">
              session {session.session} · {session.arch} · {session.instructions} instructions ·{" "}
              {session.snapshots} snapshots
              {session.stopped_reason !== undefined ? ` · ${session.stopped_reason}` : ""}
              {session.restored === true ? " · restored" : ""}
            </div>
            <RegTable regs={session.regs} />
          </div>
        )}

        {run === null && session === null && error === null && (
          <div className="empty">
            <div className="empty-glyph">
              <Cpu size={28} strokeWidth={1.5} />
            </div>
            <div className="empty-title">Emulate code.</div>
            <div className="empty-hint">
              Paste hex bytes, or point at the loaded image or an attached target. The VM is
              isolated from the target process.
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
