// app/src/components/StatusBar.tsx
// indicator row, everything here is pushed by the engine so nothing polls

import { useEffect, useState } from "react";
import { Command, MonitorCog, Settings2, SunMoon } from "lucide-react";
import IconButton from "@/components/IconButton";
import { formatLabel } from "@/lib/format";
import { useDisasm } from "@/store/disasm";
import { useEngine } from "@/store/engine";
import { useTargets } from "@/store/targets";
import { kThemes, useTheme } from "@/store/theme";
import { useUi } from "@/store/ui";

type DotState = "ok" | "busy" | "bad" | "idle";

function Pill({ label, state }: { label: string; state: DotState }) {
  return (
    <span className="status-pill">
      <span className="dot" data-state={state} aria-hidden />
      {label}
    </span>
  );
}

export default function StatusBar() {
  const connected = useEngine((s) => s.connected);
  const backend = useEngine((s) => s.backend);
  const target = useEngine((s) => s.target);
  const hype = useEngine((s) => s.hype);
  const crash = useEngine((s) => s.crash);
  // The image pill reads the disasm mirror (refreshed on image.changed and
  // every reconnect), so a binary loaded by an agent over MCP shows up too
  const image = useDisasm((s) => s.image);
  const theme = useTheme((s) => s.theme);
  const setTheme = useTheme((s) => s.setTheme);
  const openSettings = useUi((s) => s.openSettings);
  const setRail = useUi((s) => s.setRail);
  const setPaletteOpen = useUi((s) => s.setPaletteOpen);
  const consoles = useTargets((s) => s.consoles);
  const activeConsole = useTargets((s) => s.activeConsole);
  const loadConsoles = useTargets((s) => s.loadConsoles);
  const switchConsole = useTargets((s) => s.switchConsole);
  const [consoleMenu, setConsoleMenu] = useState(false);

  useEffect(() => {
    void loadConsoles();
  }, [loadConsoles]);

  const cycleTheme = () => {
    const i = kThemes.findIndex((t) => t.id === theme);
    setTheme(kThemes[(i + 1) % kThemes.length].id);
  };

  const analysis: DotState = hype.running
    ? "busy"
    : hype.ready
      ? "ok"
      : hype.error !== ""
        ? "bad"
        : "idle";

  const engineLabel = connected
    ? "Engine: Connected"
    : crash !== null
      ? crash.retry_in_ms === null
        ? "Engine: Crashed"
        : "Engine: Restarting…"
      : "Engine: Offline";

  return (
    <footer className="statusbar" aria-label="Status">
      <span role="status">
        {target.attached
          ? `${target.name ?? "target"} (${target.pid ?? 0})`
          : connected
            ? "Ready"
            : "Disconnected"}
      </span>

      <div className="spacer" />

      {consoles.length > 0 && (
        <div className="menu-root">
          <button
            type="button"
            className="status-pill console-switch"
            aria-haspopup="menu"
            aria-expanded={consoleMenu}
            data-tip="Saved consoles: quick switch"
            onClick={() => setConsoleMenu((v) => !v)}
          >
            <span className="dot" data-state={activeConsole === "" ? "idle" : "ok"} aria-hidden />
            {activeConsole === "" ? "No console" : activeConsole}
          </button>
          {consoleMenu && (
            <div
              className="menu-pop up"
              role="menu"
              aria-label="Consoles"
              onClick={() => setConsoleMenu(false)}
            >
              {consoles.map((c) => (
                <button
                  type="button"
                  key={c.name}
                  role="menuitemradio"
                  aria-checked={c.name === activeConsole}
                  className="menu-item"
                  onClick={() => void switchConsole(c.name)}
                >
                  <span>{c.name}</span>
                  <span className="faint">
                    {c.host}:{c.port}
                    {c.last_fw !== "" ? ` · fw ${c.last_fw}` : ""}
                  </span>
                  {c.name === activeConsole && <span className="faint">●</span>}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      <Pill label={`Backend: ${backend.badge}`} state={backend.ps4 ? "ok" : "idle"} />
      <Pill
        label={engineLabel}
        state={connected ? "ok" : crash !== null && crash.retry_in_ms !== null ? "busy" : "bad"}
      />
      <Pill
        label={target.attached ? "Memory: Ready" : "Memory: Idle"}
        state={target.attached ? "ok" : "idle"}
      />
      <Pill
        label={
          image.ready
            ? `Image: ${image.name ?? "?"}${image.format !== undefined ? ` (${formatLabel(image.format)})` : ""}`
            : "Image: none"
        }
        state={image.ready ? "ok" : "idle"}
      />
      <Pill
        label={
          hype.running
            ? `Analysis: ${Math.round(hype.progress * 100)}%`
            : hype.ready
              ? "Analysis: Ready"
              : "Analysis: Idle"
        }
        state={analysis}
      />

      <div className="status-actions">
        <IconButton tip="Command palette (Ctrl+K)" onClick={() => setPaletteOpen(true)}>
          <Command size={14} />
        </IconButton>
        <IconButton tip={`Theme: ${theme}`} onClick={cycleTheme}>
          <SunMoon size={14} />
        </IconButton>
        <IconButton tip="Scripts" onClick={() => setRail("scripts")}>
          <MonitorCog size={14} />
        </IconButton>
        <IconButton tip="Settings" onClick={openSettings}>
          <Settings2 size={14} />
        </IconButton>
      </div>
    </footer>
  );
}
