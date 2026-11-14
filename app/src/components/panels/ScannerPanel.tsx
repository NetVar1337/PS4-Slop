// app/src/components/panels/ScannerPanel.tsx
// scanner config, results and watchlist, a scan started here is the scan an
// agent sees over mcp

import { useEffect, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Download, Eye, Plus, RotateCcw, Search, Snowflake, Upload, X } from "lucide-react";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import IconButton from "@/components/IconButton";
import { useT } from "@/i18n";
import { isTauri } from "@/lib/endpoint";
import { hex, parseAddress } from "@/lib/format";
import { useEngine } from "@/store/engine";
import { kFirstKinds, kNextKinds, kWidths, useScanner } from "@/store/scanner";
import { useWatch } from "@/store/watch";

const kRow = 19;
/** Widths a watch can hold ("all" is a scan-only mode). */
const kWatchWidths = kWidths.filter((w) => w !== "all");

/** Native save dialog in the app, a prompt in browser dev mode. */
async function pickSavePath(title: string, defaultPath: string): Promise<string | null> {
  if (isTauri()) return saveDialog({ title, defaultPath });
  return window.prompt(title, defaultPath);
}

/** Native open dialog in the app, a prompt in browser dev mode. */
async function pickOpenPath(title: string): Promise<string | null> {
  if (isTauri()) {
    const picked = await openDialog({ title, multiple: false });
    return typeof picked === "string" ? picked : null;
  }
  return window.prompt(title, "table.CT");
}

/** Inline add-watch row: validated address, width and optional label. */
function AddWatchRow({ onDone, defaultWidth }: { onDone: () => void; defaultWidth: string }) {
  const t = useT();
  const add = useWatch((s) => s.add);
  const [addr, setAddr] = useState("");
  const [width, setWidth] = useState(
    kWatchWidths.includes(defaultWidth as never) ? defaultWidth : "u32",
  );
  const [label, setLabel] = useState("");
  const [intervalMs, setIntervalMs] = useState("100");
  const [invalid, setInvalid] = useState(false);

  const submit = async () => {
    const parsed = parseAddress(addr);
    if (parsed === null) {
      setInvalid(true);
      return;
    }
    const rate = Number.parseInt(intervalMs, 10);
    if (await add(parsed, width, label.trim() || undefined, Number.isFinite(rate) ? rate : 100))
      onDone();
  };

  return (
    <form
      className="watch-add"
      aria-label={t("scanner.addWatch")}
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
        aria-label={t("scanner.watchAddress")}
        aria-invalid={invalid}
        placeholder={t("scanner.addressPlaceholder")}
        value={addr}
        onChange={(e) => {
          setAddr(e.target.value);
          setInvalid(false);
        }}
      />
      <select
        className="select"
        aria-label={t("scanner.watchWidth")}
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
        aria-label={t("scanner.watchLabel")}
        placeholder={t("scanner.labelPlaceholder")}
        value={label}
        onChange={(e) => setLabel(e.target.value)}
      />
      <input
        className="addr-input mono"
        style={{ width: 52 }}
        aria-label={t("scanner.watchInterval")}
        title={t("scanner.watchIntervalTip")}
        inputMode="numeric"
        value={intervalMs}
        onChange={(e) => setIntervalMs(e.target.value)}
      />
      <button type="submit" className="row-action" disabled={addr.trim() === ""}>
        {t("common.add")}
      </button>
      <IconButton tip={t("common.cancel")} onClick={onDone}>
        <X size={12} />
      </IconButton>
    </form>
  );
}

export default function ScannerPanel() {
  const t = useT();
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
    exportCt,
    importCt,
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
          aria-label={t("scanner.valueWidth")}
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
          aria-label={t("scanner.scanKind")}
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
            aria-label={t("scanner.value")}
            value={scanner.value}
            placeholder={t("scanner.valuePlaceholder")}
            onChange={(e) => scanner.set({ value: e.target.value })}
            onKeyDown={(e) => e.key === "Enter" && void scanner.scan(scanner.hasState)}
          />
        )}
        {scanner.kind === "between" && (
          <input
            className="addr-input mono"
            style={{ width: 76 }}
            aria-label={t("scanner.upperBound")}
            value={scanner.value2}
            placeholder={t("scanner.toPlaceholder")}
            onChange={(e) => scanner.set({ value2: e.target.value })}
          />
        )}
        <button
          type="button"
          className="row-action"
          disabled={!attached || scanner.busy}
          onClick={() => void scanner.scan(scanner.hasState)}
        >
          <Search size={11} aria-hidden />{" "}
          {scanner.hasState ? t("scanner.next") : t("scanner.first")}
        </button>
        {scanner.hasState && (
          <IconButton tip={t("scanner.reset")} onClick={() => void scanner.reset()}>
            <RotateCcw size={13} />
          </IconButton>
        )}
      </div>

      <div className="scanner-body">
        <div className="dbg-head">
          {t("scanner.results")}
          <div className="spacer" />
          <span className="faint" style={{ fontSize: 11 }} aria-live="polite">
            {scanner.busy ? t("scanner.scanning") : `${scanner.total}`}
          </span>
          <IconButton
            tip={t("scanner.exportCsvTip")}
            disabled={scanner.total === 0}
            onClick={() => {
              void (async () => {
                const path = await pickSavePath(t("scanner.exportCsvTitle"), "scan-results.csv");
                if (path) await scanner.exportCsv(path);
              })();
            }}
          >
            <Download size={12} />
          </IconButton>
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
              {t("scanner.attachFirst")}
            </div>
          ) : scanner.hits.length === 0 ? (
            <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
              {scanner.busy ? "" : t("scanner.noResults")}
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
                    <IconButton
                      tip={t("scanner.addToWatchlist")}
                      onClick={() => void add(h.addr, h.type)}
                    >
                      <Eye size={11} />
                    </IconButton>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="dbg-head" style={{ borderTop: "1px solid var(--border-soft)" }}>
          {t("scanner.watchlist")}
          <div className="spacer" />
          <IconButton
            tip={t("scanner.importCtTip")}
            onClick={() => {
              void (async () => {
                const path = await pickOpenPath(t("scanner.importCtTitle"));
                if (path) await importCt(path);
              })();
            }}
          >
            <Upload size={12} />
          </IconButton>
          <IconButton
            tip={t("scanner.exportCtTip")}
            disabled={entries.length === 0}
            onClick={() => {
              void (async () => {
                const path = await pickSavePath(t("scanner.exportCtTitle"), "watchlist.CT");
                if (path) await exportCt(path);
              })();
            }}
          >
            <Download size={12} />
          </IconButton>
          <IconButton
            tip={t("scanner.addAddress")}
            pressed={adding}
            disabled={!attached}
            onClick={() => setAdding((v) => !v)}
          >
            <Plus size={13} />
          </IconButton>
          {entries.length > 0 && (
            <IconButton tip={t("scanner.clearWatches")} onClick={() => void clear()}>
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
              {attached ? t("scanner.noWatches") : t("scanner.noTarget")}
            </div>
          ) : (
            <table className="table watch-table">
              <caption className="sr-only">{t("scanner.watchedAddresses")}</caption>
              <thead className="sr-only">
                <tr>
                  <th scope="col">{t("scanner.colLabel")}</th>
                  <th scope="col">{t("scanner.colAddress")}</th>
                  <th scope="col">{t("scanner.colWidth")}</th>
                  <th scope="col">{t("scanner.colValue")}</th>
                  <th scope="col">{t("scanner.colFreeze")}</th>
                  <th scope="col">{t("scanner.colRemove")}</th>
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
                            aria-label={t("scanner.newValue", {
                              label: e.label || hex(e.addr, 12),
                            })}
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
                          tip={e.freeze ? t("scanner.unfreeze") : t("scanner.freeze")}
                          pressed={e.freeze}
                          style={{ color: e.freeze ? "var(--accent)" : undefined }}
                          onClick={() => void setFreeze(e.id, !e.freeze)}
                        >
                          <Snowflake size={11} />
                        </IconButton>
                      </td>
                      <td style={{ width: 24 }}>
                        <IconButton
                          tip={t("scanner.removeWatch")}
                          onClick={() => void remove(e.id)}
                        >
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
