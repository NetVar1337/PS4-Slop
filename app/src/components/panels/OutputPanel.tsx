// app/src/components/panels/OutputPanel.tsx
// output and log tabs, the app ring and the tagged diag ring side by side

import { useEffect, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ChevronDown, Eraser, Trash2 } from "lucide-react";
import IconButton from "@/components/IconButton";
import Tabs, { panelId, tabId } from "@/components/Tabs";
import { useT } from "@/i18n";
import { call } from "@/lib/rpc";
import { useOutput } from "@/store/output";
import { useUi, type OutputTab } from "@/store/ui";

type DiagEntry = { ms: number; level: string; tag: string; message: string };

const timeFormat = new Intl.DateTimeFormat(undefined, {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});
const clock = (ms: number) => timeFormat.format(ms);

export default function OutputPanel() {
  const t = useT();
  const tab = useUi((s) => s.outputTab);
  const setTab = useUi((s) => s.setOutputTab);
  const [diag, setDiag] = useState<DiagEntry[]>([]);
  const [follow, setFollow] = useState(true);
  const lines = useOutput((s) => s.lines);
  const clear = useOutput((s) => s.clear);
  const bodyRef = useRef<HTMLDivElement>(null);
  const count = tab === "output" ? lines.length : diag.length;
  const virtualizer = useVirtualizer({
    count,
    getScrollElement: () => bodyRef.current,
    estimateSize: () => 20,
    overscan: 12,
    initialRect: { width: 800, height: 300 },
    getItemKey: (index) => (tab === "output" ? `output-${lines[index].seq}` : `diag-${index}`),
  });
  const totalSize = virtualizer.getTotalSize();

  // While following, a re-measured row must not nudge the scroll position; the
  // pin below owns it. Configured in an effect: render must stay side-effect free
  useEffect(() => {
    virtualizer.shouldAdjustScrollPositionOnItemSizeChange = follow ? () => false : undefined;
  }, [virtualizer, follow]);

  // diag has no push channel: it is a high-volume ring that would swamp the
  // event stream, so the Log tab polls it while it is the visible tab
  useEffect(() => {
    if (tab !== "log") return;
    let alive = true;
    let revision = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const pull = async () => {
      try {
        const res = await call<{ entries: DiagEntry[]; revision: number }>("app", "diag", {
          limit: 1000,
          since_revision: revision,
        });
        if (alive) {
          const reset = res.revision < revision;
          const replace = revision === 0 || reset;
          if (res.entries.length || reset)
            setDiag((previous) =>
              (replace ? res.entries : [...previous, ...res.entries]).slice(-1000),
            );
          revision = reset ? 0 : res.revision;
        }
      } catch {
        /* engine down: keep the last snapshot */
      } finally {
        if (alive) timer = setTimeout(() => void pull(), 1000);
      }
    };
    void pull();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [tab]);

  // Follow mode: one observer per pane watching the content's height; it fires
  // when lines arrive (total size grows), so nothing re-subscribes per line
  useEffect(() => {
    const el = bodyRef.current;
    const content = el?.firstElementChild;
    if (!follow || !el || !content) return;
    const pin = () => {
      el.scrollTop = el.scrollHeight;
    };
    const observer = new ResizeObserver(pin);
    observer.observe(content);
    pin();
    return () => observer.disconnect();
  }, [follow, tab]);

  return (
    <div className="panel output-panel">
      <div className="tabs">
        <Tabs<OutputTab>
          items={[
            { id: "output", label: t("output.output") },
            { id: "log", label: t("output.log") },
          ]}
          active={tab}
          onChange={setTab}
          label={t("output.panes")}
          idPrefix="output"
        />
        <div className="spacer" />
        <div className="tab-actions">
          <IconButton
            tip={tab === "output" ? t("output.clear") : t("output.clearLog")}
            onClick={() => void (tab === "output" ? clear() : setDiag([]))}
          >
            <Trash2 size={14} />
          </IconButton>
          <IconButton tip={t("output.clearRing")} onClick={() => void clear()}>
            <Eraser size={14} />
          </IconButton>
          <IconButton
            tip={follow ? t("output.following") : t("output.locked")}
            pressed={follow}
            style={{ color: follow ? "var(--accent)" : undefined }}
            onClick={() => setFollow((v) => !v)}
          >
            <ChevronDown size={14} />
          </IconButton>
        </div>
      </div>

      {/* Keyed so switching Output <-> Log replays the enter animation and
          resets the scroll position to the new pane's tail. */}
      <div
        className="panel-body log swap-fade"
        key={tab}
        ref={bodyRef}
        role="tabpanel"
        id={panelId("output", tab)}
        aria-labelledby={tabId("output", tab)}
        aria-live="off"
      >
        <div style={{ height: totalSize, position: "relative", width: "100%" }}>
          {virtualizer.getVirtualItems().map((row) => {
            const l = lines[row.index];
            const e = diag[row.index];
            return (
              <div
                key={row.key}
                data-index={row.index}
                ref={virtualizer.measureElement}
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  transform: `translateY(${row.start}px)`,
                }}
              >
                {tab === "output" ? (
                  <div className="log-row">
                    <span className="log-time">{clock(l.ms)}</span>
                    <span>{l.text}</span>
                  </div>
                ) : (
                  <div className="log-row">
                    <span className="log-time">{clock(e.ms)}</span>
                    <span className="log-level" data-level={e.level}>
                      {e.level}
                    </span>
                    <span className="log-tag">{e.tag}</span>
                    <span>{e.message}</span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
