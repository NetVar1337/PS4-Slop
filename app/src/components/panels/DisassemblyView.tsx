// app/src/components/panels/DisassemblyView.tsx
// port of the disasm view, function list and instruction listing, both
// virtualized since a real binary has tens of thousands of each. The function
// list is paged and filtered server-side (disasm.functions offset/limit/filter)

import { useCallback, useEffect, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Pencil, Search } from "lucide-react";
import { useT } from "@/i18n";
import { functionLabel, hex, rowAt, useDisasm, type FunctionRow } from "@/store/disasm";
import Minimap from "@/components/panels/Minimap";

const kRow = 20;

function flowColor(flow: string): string | undefined {
  switch (flow) {
    case "call":
      return "var(--accent)";
    case "jump":
    case "cond_jump":
      return "var(--warning)";
    case "ret":
      return "var(--danger)";
    default:
      return undefined;
  }
}

function FunctionList() {
  const t = useT();
  const pages = useDisasm((s) => s.pages);
  const total = useDisasm((s) => s.total);
  const matched = useDisasm((s) => s.matched);
  const selected = useDisasm((s) => s.selected);
  const filter = useDisasm((s) => s.filter);
  const setFilter = useDisasm((s) => s.setFilter);
  const select = useDisasm((s) => s.select);
  const rename = useDisasm((s) => s.rename);
  const ensureRows = useDisasm((s) => s.ensureRows);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [editing, setEditing] = useState<number | null>(null);

  const virtualizer = useVirtualizer({
    count: matched,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => kRow,
    overscan: 15,
  });

  const items = virtualizer.getVirtualItems();
  const first = items[0]?.index ?? 0;
  const last = items[items.length - 1]?.index ?? 0;
  // Fetch the pages that scrolled into view
  useEffect(() => {
    ensureRows(first, last);
  }, [first, last, matched, pages, ensureRows]);

  const commit = async (fn: FunctionRow, value: string) => {
    setEditing(null);
    if (value !== functionLabel(fn)) await rename(fn.va, value);
  };

  return (
    <div className="fn-list">
      <div className="search">
        <Search size={13} aria-hidden />
        <input
          value={filter}
          aria-label={t("disasm.filter")}
          placeholder={t("disasm.filterPlaceholder", { total })}
          onChange={(e) => setFilter(e.target.value)}
        />
        {filter !== "" && <span className="faint fn-count">{matched}</span>}
      </div>
      <div className="panel-body" ref={scrollRef} role="listbox" aria-label={t("disasm.functions")}>
        <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
          {items.map((v) => {
            const fn = rowAt({ pages }, v.index);
            if (fn === undefined) {
              return (
                <div
                  key={`pending-${v.index}`}
                  className="fn-row faint"
                  style={{ top: v.start, height: kRow }}
                >
                  …
                </div>
              );
            }
            return (
              <div
                key={fn.va}
                className="fn-row"
                role="option"
                aria-selected={fn.va === selected}
                tabIndex={fn.va === selected ? 0 : -1}
                data-selected={fn.va === selected}
                style={{ top: v.start, height: kRow }}
                onClick={() => void select(fn.va, fn)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") void select(fn.va, fn);
                  if (e.key === "F2") setEditing(fn.va);
                }}
                onDoubleClick={() => setEditing(fn.va)}
                data-tip={t("disasm.rowTip", {
                  addr: hex(fn.va),
                  size: fn.size,
                  callconv: fn.callconv ? t("disasm.callconv", { callconv: fn.callconv }) : "",
                })}
              >
                {editing === fn.va ? (
                  <input
                    className="fn-rename mono"
                    aria-label={t("disasm.rename", { name: functionLabel(fn) })}
                    autoFocus
                    defaultValue={functionLabel(fn)}
                    onBlur={(e) => void commit(fn, e.target.value)}
                    onKeyDown={(e) => {
                      e.stopPropagation();
                      if (e.key === "Enter") void commit(fn, e.currentTarget.value);
                      if (e.key === "Escape") setEditing(null);
                    }}
                  />
                ) : (
                  <>
                    <span className="fn-name">{functionLabel(fn)}</span>
                    {fn.noreturn === true && <span className="pill">{t("disasm.noret")}</span>}
                    {fn.blocks !== undefined && (
                      <span className="faint">{t("disasm.blocks", { count: fn.blocks })}</span>
                    )}
                    <Pencil className="fn-edit" size={11} aria-hidden />
                  </>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function Listing() {
  const t = useT();
  const insns = useDisasm((s) => s.insns);
  const selected = useDisasm((s) => s.selected);
  const fn = useDisasm((s) => s.selectedFn);
  const gotoAddress = useDisasm((s) => s.gotoAddress);
  const linear = useDisasm((s) => s.linear);
  const scrollRef = useRef<HTMLDivElement>(null);

  const virtualizer = useVirtualizer({
    count: insns.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => kRow,
    overscan: 25,
  });

  const items = virtualizer.getVirtualItems();
  const first = items[0]?.index ?? 0;
  const last = items[items.length - 1]?.index ?? 0;
  const jumpTo = useCallback(
    (index: number) => virtualizer.scrollToIndex(index, { align: "start" }),
    [virtualizer],
  );

  return (
    <div className="listing">
      <div className="listing-head mono">
        {fn !== null && fn.va === selected ? (
          <>
            <span style={{ color: "var(--accent)" }}>{functionLabel(fn)}</span>
            <span className="faint">
              {t("disasm.head", {
                addr: hex(fn.va),
                size: fn.size,
                count: insns.length,
                callconv: fn.callconv ? t("disasm.callconv", { callconv: fn.callconv }) : "",
              })}
            </span>
            {linear && (
              <span className="pill" data-tip={t("disasm.linearTip")}>
                {t("disasm.linear")}
              </span>
            )}
          </>
        ) : selected !== null ? (
          <span className="faint">
            {t("disasm.noFunctionAt", { addr: hex(selected), count: insns.length })}
          </span>
        ) : (
          <span className="faint">{t("disasm.noSelection")}</span>
        )}
      </div>
      {/* Keyed on the selection so picking a new function fades its listing in
          rather than swapping rows underneath the cursor. Remounting also puts
          the scroll back at the top. */}
      <div className="listing-body">
        <Minimap insns={insns} first={first} last={last} onJump={jumpTo} />
        <div className="panel-body swap-fade" key={selected ?? "none"} ref={scrollRef}>
          <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
            {items.map((v) => {
              const insn = insns[v.index];
              const target = insn.target;
              return (
                <div key={insn.va} className="insn-row mono" style={{ top: v.start, height: kRow }}>
                  <span className="insn-va">{hex(insn.va)}</span>
                  <span className="insn-text" style={{ color: flowColor(insn.flow) }}>
                    {insn.text}
                  </span>
                  {target !== undefined && (
                    <button
                      type="button"
                      className="insn-target"
                      onClick={() => void gotoAddress(target)}
                      data-tip={t("disasm.follow", { addr: hex(target) })}
                      aria-label={t("disasm.follow", { addr: hex(target) })}
                    >
                      → {hex(target, 8)}
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function DisassemblyView() {
  return (
    <div className="disasm">
      <FunctionList />
      <Listing />
    </div>
  );
}
