// app/src/components/panels/WorkspacePanel.tsx
// The tabbed centre area, shared across ELF, PE, Mach-O and live-target views.

import { FolderOpen, ScanSearch, X } from "lucide-react";
import IconButton from "@/components/IconButton";
import Tabs, { panelId, tabId } from "@/components/Tabs";
import DisassemblyView from "@/components/panels/DisassemblyView";
import DecompView from "@/components/panels/DecompView";
import DebuggerView from "@/components/panels/DebuggerView";
import MemoryView from "@/components/panels/MemoryView";
import PeView from "@/components/panels/PeView";
import StringsView from "@/components/panels/StringsView";
import { browserLabel, formatLabel } from "@/lib/format";
import { openBinary } from "@/lib/openBinary";
import { useEngine } from "@/store/engine";
import { useDisasm } from "@/store/disasm";
import { useUi, type WorkspaceTab } from "@/store/ui";

// Which tabs read the static analysis session and which need a live process.
// Getting this wrong is what made Memory and Debugger look broken behind a
// "no binary loaded" wall they never needed. The debugger renders its own
// console / attach states.
const kTabs: readonly { id: WorkspaceTab; label: string; needs: "image" | "target" | "none" }[] = [
  { id: "disassembly", label: "Disassembly", needs: "image" },
  { id: "decomp", label: "Pseudocode", needs: "image" },
  { id: "strings", label: "Strings", needs: "image" },
  { id: "memory", label: "Memory", needs: "target" },
  { id: "debugger", label: "Debugger", needs: "none" },
  { id: "pe", label: "Image Browser", needs: "image" },
];

export default function WorkspacePanel() {
  const active = useUi((s) => s.workspaceTab);
  const setActive = useUi((s) => s.setWorkspaceTab);
  const target = useEngine((s) => s.target);
  const hype = useEngine((s) => s.hype);
  // The session is shared with agents, so the image can change without this
  // window doing anything; the engine store refreshes the mirror on
  // image.changed / hype.progress and on every reconnect
  const { image, busy, error, unload } = useDisasm();

  const tabLabel = (t: (typeof kTabs)[number]) =>
    t.id === "pe" ? browserLabel(image.format) : t.label;

  const body = () => {
    const tab = kTabs.find((t) => t.id === active);

    if (tab?.needs === "target" && !target.attached) {
      return (
        <div className="empty">
          <div className="empty-glyph">
            <ScanSearch size={28} strokeWidth={1.5} />
          </div>
          <div className="empty-title">No target attached.</div>
          <div className="empty-hint">
            Attach to a process from the Targets panel to use {tab.label}.
          </div>
        </div>
      );
    }

    if (tab?.needs === "image") {
      if (busy && !image.ready) {
        return (
          <div className="empty">
            <div className="empty-title">Loading…</div>
          </div>
        );
      }
      if (!image.ready) {
        return (
          <div className="empty">
            <div className="empty-glyph">
              <ScanSearch size={28} strokeWidth={1.5} />
            </div>
            <div className="empty-title">No binary loaded.</div>
            <div className="empty-hint">
              {target.attached
                ? "Open a file, or dump a module from the attached target."
                : "Open an ELF / SELF / PRX, or connect a console and dump a module."}
            </div>
            <button type="button" className="row-action" onClick={() => void openBinary()}>
              <FolderOpen size={12} style={{ marginRight: 6, verticalAlign: -2 }} aria-hidden />
              Open binary…
            </button>
            {error !== null && (
              <div className="empty-hint error-text" role="alert">
                {error}
              </div>
            )}
          </div>
        );
      }
    }

    switch (active) {
      case "disassembly":
        return <DisassemblyView />;
      case "decomp":
        return <DecompView />;
      case "strings":
        return <StringsView />;
      case "pe":
        return <PeView />;
      case "memory":
        return <MemoryView />;
      case "debugger":
        return <DebuggerView />;
    }
  };

  const warning =
    image.warning ||
    (image.encrypted === true
      ? "Encrypted image: on-disk code is protected; disassembly may be invalid."
      : undefined);

  return (
    <div className="panel">
      <div className="tabs">
        <Tabs<WorkspaceTab>
          items={kTabs.map((t) => ({ id: t.id, label: tabLabel(t) }))}
          active={active}
          onChange={setActive}
          label="Workspace views"
          idPrefix="workspace"
        />
        <div className="spacer" />
        {image.ready && (
          <span className="faint workspace-meta">
            {image.name}
            {image.format !== undefined ? ` · ${formatLabel(image.format)}` : ""}
            {image.arch !== undefined ? ` · ${image.arch}` : ""}
            {hype.running ? ` · analyzing ${Math.round(hype.progress * 100)}%` : ""}
          </span>
        )}
        <IconButton
          tip={image.ready ? "Close binary" : "Open binary…"}
          style={{ alignSelf: "center", marginRight: 6 }}
          onClick={() => void (image.ready ? unload() : openBinary())}
        >
          {image.ready ? <X size={14} /> : <FolderOpen size={14} />}
        </IconButton>
      </div>
      <div className="workspace-body">
        {image.ready && warning !== undefined && (
          <div className="workspace-warning" role="alert">
            {warning}
          </div>
        )}
        <div
          className="panel-body"
          style={{ overflow: "hidden" }}
          role="tabpanel"
          id={panelId("workspace", active)}
          aria-labelledby={tabId("workspace", active)}
        >
          {/* Keyed on the active tab so the enter animation replays on every
              switch rather than only on first mount. */}
          <div className="view-swap" key={active}>
            {body()}
          </div>
        </div>
      </div>
    </div>
  );
}
