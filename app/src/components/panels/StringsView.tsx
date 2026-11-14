// app/src/components/panels/StringsView.tsx
// Port of src/ui/view_strings.cpp. Virtualized because a real image yields
// thousands of hits, and the engine caps at 10k

import { useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Search } from "lucide-react";
import { useT } from "@/i18n";
import { escapeControl } from "@/lib/format";
import { showInDisassembly } from "@/lib/navigate";
import { hex, useDisasm } from "@/store/disasm";

const kRow = 20;

export default function StringsView() {
  const t = useT();
  const { strings, stringsTruncated, loadStrings, busy } = useDisasm();
  const [minChars, setMinChars] = useState(4);
  const [includeExec, setIncludeExec] = useState(false);
  const [filter, setFilter] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    void loadStrings(minChars, includeExec);
  }, [loadStrings, minChars, includeExec]);

  const rows = useMemo(() => {
    if (filter === "") return strings;
    const needle = filter.toLowerCase();
    return strings.filter((s) => s.text.toLowerCase().includes(needle));
  }, [strings, filter]);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => kRow,
    overscan: 20,
  });

  return (
    <div className="stack">
      <div className="view-bar">
        <div className="search" style={{ margin: 0, flex: 1 }}>
          <Search size={13} aria-hidden />
          <input
            value={filter}
            aria-label={t("strings.filter")}
            placeholder={t("strings.filterPlaceholder", { count: strings.length })}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
        <label className="view-label">
          {t("strings.min")}
          <select
            className="select"
            value={minChars}
            onChange={(e) => setMinChars(Number(e.target.value))}
          >
            {[3, 4, 6, 8, 12, 16].map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </label>
        <label className="view-label">
          <input
            type="checkbox"
            checked={includeExec}
            onChange={(e) => setIncludeExec(e.target.checked)}
          />
          {t("strings.exec")}
        </label>
        {stringsTruncated && <span className="pill">{t("common.truncated")}</span>}
      </div>

      <div className="panel-body" ref={scrollRef}>
        {rows.length === 0 ? (
          <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
            {busy ? t("strings.scanning") : t("strings.empty")}
          </div>
        ) : (
          <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
            {virtualizer.getVirtualItems().map((v) => {
              const s = rows[v.index];
              return (
                <div
                  key={`${s.va}-${v.index}`}
                  className="insn-row mono"
                  style={{ top: v.start, height: kRow }}
                >
                  <button
                    type="button"
                    className="insn-va link"
                    onClick={() => showInDisassembly(s.va)}
                    data-tip={t("strings.follow")}
                    aria-label={t("strings.followAria", { addr: hex(s.va) })}
                  >
                    {hex(s.va)}
                  </button>
                  {s.utf16 && <span className="pill">w</span>}
                  <span className="insn-text" style={{ userSelect: "text" }}>
                    {/* one line per row: a raw newline would spill into the next row */}
                    {escapeControl(s.text)}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
