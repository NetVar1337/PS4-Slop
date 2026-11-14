// app/src/components/panels/MemoryView.tsx
// Hex editor over live target memory, port of src/ui/view_memory.cpp
// Region list on the left, 16-bytes-per-row grid on the right, edit in place.
// The grid scrolls continuously through a 1 MiB window of the region, pages
// are read as they scroll in; prev/next move the window along the region

import { useCallback, useEffect, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  ArrowRight,
  Camera,
  ChevronLeft,
  ChevronRight,
  GitCompare,
  Microscope,
  RefreshCw,
  X,
} from "lucide-react";
import IconButton from "@/components/IconButton";
import { escapeControl, hex, parseAddress } from "@/lib/format";
import { call, errorText } from "@/lib/rpc";
import { byteAt, kHexCols, kHexRowPx, kWindowBytes, protectName, useMemory } from "@/store/memory";
import { useTypes } from "@/store/types";

const kRow = kHexRowPx;
const kCols = kHexCols;

function ascii(b: number | undefined): string {
  return b === undefined ? " " : b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".";
}

interface DissectRow {
  offset: number;
  hex: string;
  kind: string;
  value?: unknown;
  target?: { kind: string; text?: string; symbol?: string; vtable_symbol?: string };
}

function describe(r: DissectRow): string {
  if (r.target) {
    const t = r.target;
    const what = t.text !== undefined ? `"${t.text}"` : (t.vtable_symbol ?? t.symbol ?? "");
    return `→ ${t.kind}${what ? ` ${what}` : ""}`;
  }
  return r.value === undefined ? "" : JSON.stringify(r.value);
}

// one row per 8-byte slot from memory.dissect: a first draft of a struct
function DissectPane({ addr, onClose }: { addr: number; onClose: () => void }) {
  const [rows, setRows] = useState<DissectRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setRows(null);
    setError(null);
    call<{ rows: DissectRow[] }>("memory", "dissect", { addr, size: 0x100 })
      .then((r) => setRows(r.rows))
      .catch((e: unknown) => setError(errorText(e)));
  }, [addr]);
  return (
    <div className="stack" style={{ maxHeight: "40%", borderTop: "1px solid var(--border)" }}>
      <div className="view-bar">
        <span className="panel-title">Dissect {hex(addr, 12)}</span>
        <div className="spacer" />
        <IconButton tip="Close dissect" onClick={onClose}>
          <X size={13} />
        </IconButton>
      </div>
      <div className="panel-body mono" style={{ fontSize: 11, padding: "var(--pad-sm)" }}>
        {error !== null && (
          <div className="error-text" role="alert">
            {error}
          </div>
        )}
        {rows === null && error === null && <div className="faint">reading…</div>}
        {rows?.map((r) => (
          <div key={r.offset} style={{ display: "flex", gap: 12 }}>
            <span className="faint">+{r.offset.toString(16).toUpperCase().padStart(3, "0")}</span>
            <span style={{ minWidth: 150 }}>{r.hex}</span>
            <span style={{ minWidth: 70 }}>{r.kind}</span>
            <span>{describe(r)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

type SnapshotRec = { id: number; addr: number; size: number; bytes: number; complete: boolean };
type DiffRange = { offset: number; length: number };

function bytesOf(text: string): Uint8Array {
  const clean = text.replace(/[^0-9a-fA-F]/g, "");
  const out = new Uint8Array(clean.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** The caret's bytes as every width the engine can read, little-endian. */
function interpret(bytes: Uint8Array): { label: string; text: string }[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const has = (n: number) => bytes.byteLength >= n;
  const text = new TextDecoder().decode(bytes).split("\0")[0] ?? "";
  return [
    { label: "u8", text: has(1) ? String(view.getUint8(0)) : "—" },
    { label: "u16", text: has(2) ? String(view.getUint16(0, true)) : "—" },
    { label: "u32", text: has(4) ? String(view.getUint32(0, true)) : "—" },
    { label: "u64", text: has(8) ? String(view.getBigUint64(0, true)) : "—" },
    { label: "f32", text: has(4) ? view.getFloat32(0, true).toPrecision(6) : "—" },
    { label: "f64", text: has(8) ? view.getFloat64(0, true).toPrecision(10) : "—" },
    { label: "utf8", text: escapeControl(text) },
    {
      label: "pointer",
      text: has(8)
        ? `0x${view.getBigUint64(0, true).toString(16).toUpperCase().padStart(16, "0")}`
        : "—",
    },
  ];
}

/** Side pane: interpreted caret value, plus the selected struct rendered there. */
function CaretInspector({ addr }: { addr: number }) {
  const structType = useTypes((s) => s.selected);
  const [bytes, setBytes] = useState<Uint8Array | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [rendered, setRendered] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setError(null);
    call<{ hex?: string }>("memory", "read", { addr, len: 16, format: "hex" })
      .then((r) => {
        if (alive) setBytes(bytesOf(r.hex ?? ""));
      })
      .catch((e: unknown) => {
        if (!alive) return;
        setBytes(null);
        setError(errorText(e));
      });
    return () => {
      alive = false;
    };
  }, [addr]);

  useEffect(() => {
    if (structType === null) {
      setRendered(null);
      return;
    }
    let alive = true;
    call<{ rendered: string }>("types", "format_at", { addr, type: structType })
      .then((r) => {
        if (alive) setRendered(r.rendered);
      })
      .catch((e: unknown) => {
        if (alive) setRendered(`format_at ${structType}: ${errorText(e)}`);
      });
    return () => {
      alive = false;
    };
  }, [addr, structType]);

  return (
    <div className="mem-inspect">
      <div className="view-bar" style={{ padding: "var(--pad-sm)" }}>
        <span className="panel-title">Caret</span>
        <div className="spacer" />
        <span className="faint mono">{hex(addr, 12)}</span>
      </div>
      <div className="panel-body mono mem-values">
        {error !== null && (
          <div className="error-text" role="alert">
            {error}
          </div>
        )}
        {bytes !== null &&
          interpret(bytes).map((r) => (
            <div key={r.label} className="mem-value">
              <span className="faint">{r.label}</span>
              <span>{r.text}</span>
            </div>
          ))}
        {rendered !== null && <pre className="mem-struct">{rendered}</pre>}
      </div>
    </div>
  );
}

/** Snapshot capture/compare pane; the diff it produces highlights the grid. */
function SnapshotPane({
  base,
  size,
  onDiff,
  onClose,
}: {
  base: number;
  size: number;
  onDiff: (diff: { base: number; ranges: DiffRange[] } | null) => void;
  onClose: () => void;
}) {
  const [snaps, setSnaps] = useState<SnapshotRec[]>([]);
  const [a, setA] = useState<number | null>(null);
  const [b, setB] = useState<number | null>(null);
  const [ranges, setRanges] = useState<DiffRange[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await call<{ snapshots: SnapshotRec[] }>("memory", "snapshots");
      const list = res.snapshots ?? [];
      setSnaps(list);
      setA((v) => v ?? list[0]?.id ?? null);
      setB((v) => v ?? list[1]?.id ?? null);
    } catch (e) {
      setError(errorText(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const capture = async () => {
    setError(null);
    try {
      await call("memory", "snapshot", { addr: base, len: size });
      await load();
    } catch (e) {
      setError(errorText(e));
    }
  };

  const compare = async () => {
    if (a === null || b === null) return;
    setError(null);
    try {
      const res = await call<{ changed: DiffRange[] }>("memory", "diff", { a, b, limit: 512 });
      const snap = snaps.find((s) => s.id === a);
      setRanges(res.changed);
      onDiff(snap ? { base: snap.addr, ranges: res.changed } : null);
    } catch (e) {
      setError(errorText(e));
    }
  };

  return (
    <div className="stack mem-snap">
      <div className="view-bar">
        <span className="panel-title">Snapshot diff</span>
        <select
          className="select"
          aria-label="Snapshot A"
          value={a ?? ""}
          onChange={(e) => setA(Number(e.target.value))}
        >
          <option value="">A…</option>
          {snaps.map((s) => (
            <option key={s.id} value={s.id}>
              {`#${s.id} ${hex(s.addr, 12)} (${s.size})`}
            </option>
          ))}
        </select>
        <select
          className="select"
          aria-label="Snapshot B"
          value={b ?? ""}
          onChange={(e) => setB(Number(e.target.value))}
        >
          <option value="">B…</option>
          {snaps.map((s) => (
            <option key={s.id} value={s.id}>
              {`#${s.id} ${hex(s.addr, 12)} (${s.size})`}
            </option>
          ))}
        </select>
        <button
          type="button"
          className="row-action"
          disabled={a === null || b === null || a === b}
          onClick={() => void compare()}
        >
          compare
        </button>
        <IconButton
          tip="Capture snapshot of this window"
          disabled={size === 0}
          onClick={() => void capture()}
        >
          <Camera size={13} />
        </IconButton>
        <div className="spacer" />
        {ranges !== null && <span className="faint">{ranges.length} changed ranges</span>}
        <IconButton tip="Close snapshot diff" onClick={onClose}>
          <X size={13} />
        </IconButton>
      </div>
      <div className="panel-body mono" style={{ fontSize: 11, padding: "var(--pad-sm)" }}>
        {error !== null && (
          <div className="error-text" role="alert">
            {error}
          </div>
        )}
        {snaps.length === 0 && <div className="faint">no snapshots yet, capture one above</div>}
        {ranges?.map((r) => (
          <div key={r.offset}>
            <span className="faint">+{r.offset.toString(16).toUpperCase().padStart(4, "0")}</span>{" "}
            <span>{r.length} bytes</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function RegionList() {
  const regions = useMemory((s) => s.regions);
  const cursor = useMemory((s) => s.cursor);
  const loadRegions = useMemory((s) => s.loadRegions);
  const goto = useMemory((s) => s.goto);
  const scrollRef = useRef<HTMLDivElement>(null);
  // PS4 targets can report thousands of mappings
  const virtualizer = useVirtualizer({
    count: regions.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => kRow,
    overscan: 12,
  });

  return (
    <div className="mem-regions">
      <div className="view-bar" style={{ padding: "var(--pad-sm)" }}>
        <span className="panel-title">Regions</span>
        <div className="spacer" />
        <span className="faint" style={{ fontSize: 11 }}>
          {regions.length}
        </span>
        <IconButton tip="Refresh regions" onClick={() => void loadRegions()}>
          <RefreshCw size={13} />
        </IconButton>
      </div>
      <div className="panel-body" ref={scrollRef}>
        <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
          {virtualizer.getVirtualItems().map((v) => {
            const r = regions[v.index];
            return (
              <button
                type="button"
                key={r.base}
                className="fn-row"
                data-selected={cursor >= r.base && cursor < r.base + r.size}
                style={{ top: v.start, height: kRow }}
                onClick={() => goto(r.base)}
                data-tip={`${r.size} bytes · ${protectName(r.protect)}`}
              >
                <span className="fn-name">{hex(r.base, 12)}</span>
                <span className="faint" style={{ fontSize: 10 }}>
                  {protectName(r.protect)}
                </span>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export default function MemoryView() {
  const regions = useMemory((s) => s.regions);
  const cursor = useMemory((s) => s.cursor);
  const windowBase = useMemory((s) => s.windowBase);
  const windowSize = useMemory((s) => s.windowSize);
  const pages = useMemory((s) => s.pages);
  const loading = useMemory((s) => s.loading);
  const error = useMemory((s) => s.error);
  const gotoText = useMemory((s) => s.gotoText);
  const gotoSeq = useMemory((s) => s.gotoSeq);
  const {
    loadRegions,
    goto,
    ensurePages,
    writeBytes,
    setGotoText,
    setScrollTop,
    reload,
    setCursor,
  } = useMemory.getState();
  const [edit, setEdit] = useState<number | null>(null);
  const [gotoError, setGotoError] = useState(false);
  const [dissectAt, setDissectAt] = useState<number | null>(null);
  const [snapOpen, setSnapOpen] = useState(false);
  const [diff, setDiff] = useState<{ base: number; ranges: DiffRange[] } | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    void loadRegions();
  }, [loadRegions]);

  // Land on the first readable region so the pane is never blank; a position
  // the user already had (tab switch, remount) is kept
  useEffect(() => {
    if (windowSize === 0 && regions.length > 0) goto(regions[0].base);
  }, [regions, windowSize, goto]);

  const rowCount = Math.ceil(windowSize / kCols);
  const virtualizer = useVirtualizer({
    count: rowCount,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => kRow,
    overscan: 12,
    initialOffset: () => useMemory.getState().scrollTop,
    onChange: (v) => setScrollTop(v.scrollOffset ?? 0),
  });

  const items = virtualizer.getVirtualItems();
  const firstRow = items[0]?.index ?? 0;
  const lastRow = items[items.length - 1]?.index ?? 0;
  useEffect(() => {
    if (windowSize === 0) return;
    ensurePages(windowBase + firstRow * kCols, windowBase + (lastRow + 1) * kCols);
  }, [firstRow, lastRow, windowBase, windowSize, ensurePages]);

  // Bring the goto target into view on every new goto. A remount (tab switch)
  // sees the same sequence number and keeps the restored scroll offset instead
  const seenGoto = useRef(gotoSeq);
  useEffect(() => {
    if (gotoSeq === seenGoto.current) return;
    seenGoto.current = gotoSeq;
    if (cursor < windowBase || cursor >= windowBase + windowSize) return;
    virtualizer.scrollToIndex(Math.floor((cursor - windowBase) / kCols), { align: "start" });
    // keyed on the goto only; scrolling itself must not re-pin the cursor
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [gotoSeq]);

  const jump = () => {
    const parsed = parseAddress(gotoText);
    setGotoError(parsed === null);
    if (parsed !== null) goto(parsed);
  };

  const commitByte = async (addr: number, text: string) => {
    setEdit(null);
    const value = Number.parseInt(text, 16);
    if (!/^[0-9a-f]{1,2}$/i.test(text.trim()) || !Number.isFinite(value)) return;
    if (byteAt(pages, addr) === value) return;
    await writeBytes(addr, new Uint8Array([value]));
  };

  return (
    <div className="mem">
      <RegionList />

      <div className="stack">
        <div className="view-bar">
          <label className="view-label">
            goto
            <input
              className="addr-input mono"
              value={gotoText}
              placeholder="0x400000"
              aria-invalid={gotoError}
              onChange={(e) => {
                setGotoText(e.target.value);
                setGotoError(false);
              }}
              onKeyDown={(e) => e.key === "Enter" && jump()}
            />
          </label>
          <IconButton tip="Go to address" variant="row" onClick={jump}>
            <ArrowRight size={11} />
          </IconButton>
          <span className="faint mono" style={{ fontSize: 11 }}>
            {windowSize > 0
              ? `${hex(windowBase, 12)}–${hex(windowBase + windowSize, 12)}`
              : "no region"}
            {loading ? " · reading…" : ""}
          </span>
          <div className="spacer" />
          <IconButton
            tip="Snapshot diff"
            pressed={snapOpen}
            onClick={() => {
              setSnapOpen((v) => !v);
              if (snapOpen) setDiff(null);
            }}
          >
            <GitCompare size={13} />
          </IconButton>
          <IconButton
            tip="Dissect the structure at the cursor"
            disabled={windowSize === 0}
            onClick={() => setDissectAt(cursor)}
          >
            <Microscope size={13} />
          </IconButton>
          <IconButton tip="Re-read" onClick={reload}>
            <RefreshCw size={13} />
          </IconButton>
          <IconButton
            tip="Previous window"
            variant="row"
            disabled={windowBase === 0}
            onClick={() => goto(Math.max(0, windowBase - kWindowBytes / 2))}
          >
            <ChevronLeft size={11} /> prev
          </IconButton>
          <IconButton
            tip="Next window"
            variant="row"
            disabled={windowSize === 0}
            onClick={() => goto(windowBase + windowSize)}
          >
            next <ChevronRight size={11} />
          </IconButton>
        </div>

        <div className="panel-body" ref={scrollRef}>
          {error !== null && (
            <div
              className="empty-hint error-text"
              role="alert"
              style={{ padding: "var(--pad-md)" }}
            >
              {error}
            </div>
          )}
          <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
            {items.map((v) => {
              const rowAddr = windowBase + v.index * kCols;
              const cells = Array.from({ length: kCols }, (_, i) => byteAt(pages, rowAddr + i));
              // changed spans are snapshot-relative; mark the cells this row covers
              const changed = diff === null ? null : new Uint8Array(kCols);
              if (diff !== null && changed !== null)
                for (const r of diff.ranges) {
                  const start = Math.max(0, diff.base + r.offset - rowAddr);
                  const end = Math.min(kCols, diff.base + r.offset + r.length - rowAddr);
                  for (let i = start; i < end; i++) changed[i] = 1;
                }
              return (
                <div key={rowAddr} className="hex-row mono" style={{ top: v.start, height: kRow }}>
                  <span className="insn-va">{hex(rowAddr, 12)}</span>
                  <span className="hex-cells">
                    {cells.map((b, i) => {
                      const addr = rowAddr + i;
                      const text =
                        b === undefined ? "??" : b.toString(16).padStart(2, "0").toUpperCase();
                      return edit === addr ? (
                        <input
                          key={i}
                          className="hex-edit mono"
                          aria-label={`Byte at ${hex(addr, 12)}`}
                          autoFocus
                          maxLength={2}
                          defaultValue={b === undefined ? "" : text}
                          onBlur={(e) => void commitByte(addr, e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") void commitByte(addr, e.currentTarget.value);
                            if (e.key === "Escape") setEdit(null);
                          }}
                        />
                      ) : (
                        <button
                          type="button"
                          key={i}
                          className="hex-cell"
                          data-zero={b === 0}
                          data-unread={b === undefined}
                          data-diff={changed?.[i] === 1}
                          disabled={b === undefined}
                          aria-label={`${hex(addr, 12)} = ${text}${changed?.[i] === 1 ? " (changed)" : ""}`}
                          onClick={() => {
                            setCursor(addr);
                            setEdit(addr);
                          }}
                          data-tip={b === undefined ? undefined : `${hex(addr, 12)} = ${b}`}
                        >
                          {text}
                        </button>
                      );
                    })}
                  </span>
                  <span className="hex-ascii">{cells.map(ascii).join("")}</span>
                </div>
              );
            })}
          </div>
        </div>
        {snapOpen && (
          <SnapshotPane
            base={windowBase}
            size={windowSize}
            onDiff={setDiff}
            onClose={() => {
              setSnapOpen(false);
              setDiff(null);
            }}
          />
        )}
        {dissectAt !== null && <DissectPane addr={dissectAt} onClose={() => setDissectAt(null)} />}
      </div>

      <CaretInspector addr={cursor} />
    </div>
  );
}
