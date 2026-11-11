// app/src/components/panels/ScannerPanel.tsx
// scanner config, results and watchlist, a scan started here is the scan an
// agent sees over mcp

import { useEffect, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Eye, Plus, RotateCcw, Search, Snowflake, X } from "lucide-react";
import IconButton from "@/components/IconButton";
import { hex, parseAddress } from "@/lib/format";
import { useEngine } from "@/store/engine";
import { kFirstKinds, kNextKinds, kWidths, useScanner } from "@/store/scanner";
import { useWatch } from "@/store/watch";

const kRow = 19;
/** Widths a watch can hold ("all" is a scan-only mode). */
const kWatchWidths = kWidths.filter((w) => w !== "all");

/** Inline add-watch row: validated address, width and optional label. */
function AddWatchRow({ onDone, defaultWidth }: { onDone: () => void; defaultWidth: string }) {
  const add = useWatch((s) => s.add);
  const [addr, setAddr] = useState("");
  const [width, setWidth] = useState(
    kWatchWidths.includes(defaultWidth as never) ? defaultWidth : "u32",
  );
  const [label, setLabel] = useState("");
  const [invalid, setInvalid] = useState(false);

  const submit = async () => {
    const parsed = parseAddress(addr);
    if (parsed === null) {
      setInvalid(true);
      return;
    }
    if (await add(parsed, width, label.trim() || undefined)) onDone();
  };

  return (
    <form
      className="watch-add"
      aria-label="Add watch"
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
      onKeyDown={(e) => e.key === "Escape" && onDone()}
    >
      <input
        className="addr-input mono"
        style={{ width: 110 }}
        autoFocus
        aria-label="Watch address (hex)"
        aria-invalid={invalid}
        placeholder="address (hex)"
        value={addr}
        onChange={(e) => {
          setAddr(e.target.value);
          setInvalid(false);
        }}
      />
      <select
        className="select"
        aria-label="Watch width"
        value={width}
        onChange={(e) => setWidth(e.target.value)}
      >
        {kWatchWidths.map((w) => (
          <option key={w} value={w}>
            {w}
          </option>
        ))}
      </select>
      <input
        className="addr-input"
        style={{ flex: 1, minWidth: 60 }}
        aria-label="Watch label"
        placeholder="label"
        value={label}
        onChange={(e) => setLabel(e.target.value)}
      />
      <button type="submit" className="row-action" disabled={addr.trim() === ""}>
        Add
      </button>
      <IconButton tip="Cancel" onClick={onDone}>
        <X size={12} />
      </IconButton>
    </form>
  );
}

export default function ScannerPanel() {
  const attached = useEngine((s) => s.target.attached);
  const scanner = useScanner();
  const {
    entries,
    values,
    error: watchError,
    load,
    add,
    remove,
    setFreeze,
    poke,
    clear,
  } = useWatch();
  const [editing, setEditing] = useState<number | null>(null);
  const [adding, setAdding] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const refreshState = useScanner((s) => s.refreshState);

  useEffect(() => {
    // Engine-state seeds; the watch list keeps itself current from
    // `watch.list` events afterwards
    void load();
    void refreshState();
  }, [load, refreshState]);

  const virtualizer = useVirtualizer({
    count: scanner.hits.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => kRow,
    overscan: 15,
  });

  const kinds = scanner.hasState ? kNextKinds : kFirstKinds;
  const needsValue = scanner.kind !== "unknown";

  return (
    <div className="panel">
      <div className="panel-head scanner-head">
        <select
          className="select"
          aria-label="Value width"
          value={scanner.width}
          onChange={(e) => scanner.set({ width: e.target.value })}
        >
          {kWidths.map((w) => (
            <option key={w} value={w}>
              {w}
            </option>
          ))}
        </select>
        <select
          className="select"
          aria-label="Scan kind"
          value={kinds.includes(scanner.kind as never) ? scanner.kind : kinds[0]}
          onChange={(e) => scanner.set({ kind: e.target.value })}
        >
          {kinds.map((k) => (
            <option key={k} value={k}>
              {k}
            </option>
          ))}
        </select>
        {needsValue && (
          <input
            className="addr-input mono"
            style={{ width: 76 }}
            aria-label="Value"
            value={scanner.value}
            placeholder="value"
            onChange={(e) => scanner.set({ value: e.target.value })}
            onKeyDown={(e) => e.key === "Enter" && void scanner.scan(scanner.hasState)}
          />
        )}
        {scanner.kind === "between" && (
          <input
            className="addr-input mono"
            style={{ width: 76 }}
            aria-label="Upper bound"
            value={scanner.value2}
            placeholder="to"
            onChange={(e) => scanner.set({ value2: e.target.value })}
          />
        )}
        <button
          type="button"
          className="row-action"
          disabled={!attached || scanner.busy}
          onClick={() => void scanner.scan(scanner.hasState)}
        >
          <Search size={11} aria-hidden /> {scanner.hasState ? "Next" : "First"}
        </button>
        {scanner.hasState && (
          <IconButton tip="Reset scan" onClick={() => void scanner.reset()}>
            <RotateCcw size={13} />
          </IconButton>
        )}
      </div>

      <div className="scanner-body">
        <div className="dbg-head">
          Results
          <div className="spacer" />
          <span className="faint" style={{ fontSize: 11 }} aria-live="polite">
            {scanner.busy ? "scanning…" : `${scanner.total}`}
          </span>
        </div>

        <div className="panel-body" ref={scrollRef}>
          {scanner.error !== null && (
            <div
              className="empty-hint error-text"
              role="alert"
              style={{ padding: "var(--pad-sm) var(--pad-md)" }}
            >
              {scanner.error}
            </div>
          )}
          {!attached ? (
            <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
              attach a target first.
            </div>
          ) : scanner.hits.length === 0 ? (
            <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
              {scanner.busy ? "" : "no results yet, run a scan."}
            </div>
          ) : (
            <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
              {virtualizer.getVirtualItems().map((v) => {
                const h = scanner.hits[v.index];
                return (
                  <div
                    key={h.addr}
                    className="hex-row mono"
                    style={{ top: v.start, height: kRow, fontSize: 11.5 }}
                  >
                    <span className="insn-va">{hex(h.addr, 12)}</span>
                    <span className="insn-text">{h.formatted}</span>
                    <span className="faint">{h.type}</span>
                    <IconButton tip="Add to watchlist" onClick={() => void add(h.addr, h.type)}>
                      <Eye size={11} />
                    </IconButton>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="dbg-head" style={{ borderTop: "1px solid var(--border-soft)" }}>
          Watchlist
          <div className="spacer" />
          <IconButton
            tip="Add address"
            pressed={adding}
            disabled={!attached}
            onClick={() => setAdding((v) => !v)}
          >
            <Plus size={13} />
          </IconButton>
          {entries.length > 0 && (
            <IconButton tip="Clear all watches" onClick={() => void clear()}>
              <X size={13} />
            </IconButton>
          )}
        </div>

        <div className="panel-body">
          {adding && attached && (
            <AddWatchRow defaultWidth={scanner.width} onDone={() => setAdding(false)} />
          )}
          {watchError !== null && (
            <div
              className="empty-hint error-text"
              role="alert"
              style={{ padding: "var(--pad-sm) var(--pad-md)" }}
            >
              {watchError}
            </div>
          )}
          {entries.length === 0 ? (
            <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
              {attached ? "no watches." : "no target."}
            </div>
          ) : (
            <table className="table watch-table">
              <caption className="sr-only">Watched addresses</caption>
              <thead className="sr-only">
                <tr>
                  <th scope="col">Label</th>
                  <th scope="col">Address</th>
                  <th scope="col">Width</th>
                  <th scope="col">Value</th>
                  <th scope="col">Freeze</th>
                  <th scope="col">Remove</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((e) => {
                  const v = values.get(e.id);
                  return (
                    <tr key={e.id}>
                      <td className="watch-label" data-tip={e.label || undefined}>
                        {e.label !== "" ? e.label : <span className="faint">-</span>}
                      </td>
                      <td className="mono" style={{ width: 96 }}>
                        {hex(e.addr, 12)}
                      </td>
                      <td className="faint" style={{ width: 32 }}>
                        {e.width}
                      </td>
                      <td className="mono" onDoubleClick={() => setEditing(e.id)}>
                        {editing === e.id ? (
                          <input
                            className="addr-input mono"
                            style={{ width: 70 }}
                            aria-label={`New value for ${e.label || hex(e.addr, 12)}`}
                            autoFocus
                            defaultValue={v?.text ?? ""}
                            onBlur={() => setEditing(null)}
                            onKeyDown={(e2) => {
                              if (e2.key === "Enter") {
                                void poke(e.id, e2.currentTarget.value);
                                setEditing(null);
                              }
                              if (e2.key === "Escape") setEditing(null);
                            }}
                          />
                        ) : (
                          <>
                            {v?.ok === true ? v.text : "-"}
                            {e.freeze && <span className="faint"> *</span>}
                          </>
                        )}
                      </td>
                      <td style={{ width: 26 }}>
                        <IconButton
                          tip={e.freeze ? "Unfreeze" : "Freeze"}
                          pressed={e.freeze}
                          style={{ color: e.freeze ? "var(--accent)" : undefined }}
                          onClick={() => void setFreeze(e.id, !e.freeze)}
                        >
                          <Snowflake size={11} />
                        </IconButton>
                      </td>
                      <td style={{ width: 24 }}>
                        <IconButton tip="Remove watch" onClick={() => void remove(e.id)}>
                          <X size={11} />
                        </IconButton>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
