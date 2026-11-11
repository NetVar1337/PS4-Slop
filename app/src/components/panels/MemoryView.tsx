// app/src/components/panels/MemoryView.tsx
// Hex editor over live target memory, port of src/ui/view_memory.cpp
// Region list on the left, 16-bytes-per-row grid on the right, edit in place.
// The grid scrolls continuously through a 1 MiB window of the region, pages
// are read as they scroll in; prev/next move the window along the region

import { useEffect, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ArrowRight, ChevronLeft, ChevronRight, RefreshCw } from "lucide-react";
import IconButton from "@/components/IconButton";
import { hex, parseAddress } from "@/lib/format";
import { byteAt, kHexCols, kHexRowPx, kWindowBytes, protectName, useMemory } from "@/store/memory";

const kRow = kHexRowPx;
const kCols = kHexCols;

function ascii(b: number | undefined): string {
  return b === undefined ? " " : b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".";
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
  const { loadRegions, goto, ensurePages, writeBytes, setGotoText, setScrollTop, reload } =
    useMemory.getState();
  const [edit, setEdit] = useState<number | null>(null);
  const [gotoError, setGotoError] = useState(false);
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
                          disabled={b === undefined}
                          aria-label={`${hex(addr, 12)} = ${text}`}
                          onClick={() => setEdit(addr)}
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
      </div>
    </div>
  );
}
