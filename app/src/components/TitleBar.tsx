// app/src/components/TitleBar.tsx
// custom titlebar, drag region and buttons through the tauri window api

import { Fragment, useEffect, useRef, useState, type ReactNode } from "react";
import { Minus, Square, X } from "lucide-react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { isInsecureDev, isTauri } from "@/lib/endpoint";
import { call } from "@/lib/rpc";
import { openBinary } from "@/lib/openBinary";
import { kShortcuts } from "@/lib/shortcuts";
import { useEngine } from "@/store/engine";
import { useTheme, kThemes } from "@/store/theme";
import { useUi } from "@/store/ui";
import IconButton from "@/components/IconButton";
import logoUrl from "@/assets/reverse-slop-icon.png";

type MenuName = "File" | "View" | "Window" | "Theme" | "Help";

async function windowAction(action: "minimize" | "toggleMaximize" | "close") {
  // Running in a plain browser (npm run dev): nothing to drive
  if (!isTauri()) return;
  const win = getCurrentWindow();
  if (action === "minimize") await win.minimize();
  else if (action === "toggleMaximize") await win.toggleMaximize();
  else await win.close();
}

export default function TitleBar() {
  const [open, setOpen] = useState<MenuName | null>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const theme = useTheme((s) => s.theme);
  const setTheme = useTheme((s) => s.setTheme);
  const quitting = useEngine((s) => s.quitting);
  const rail = useUi((s) => s.rail);
  const setRail = useUi((s) => s.setRail);
  const openSettings = useUi((s) => s.openSettings);
  const setPaletteOpen = useUi((s) => s.setPaletteOpen);
  const inspectorOpen = useUi((s) => s.inspectorOpen);
  const setInspectorOpen = useUi((s) => s.setInspectorOpen);
  const resetLayout = useUi((s) => s.resetLayout);

  useEffect(() => {
    if (open === null) return;
    const onDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(null);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(null);
    };
    window.addEventListener("mousedown", onDown);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onDown);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const menu = (name: MenuName, body: ReactNode) => (
    <div className="menu-root" key={name}>
      <button
        type="button"
        className="menu-button"
        data-open={open === name}
        aria-haspopup="menu"
        aria-expanded={open === name}
        onClick={() => setOpen(open === name ? null : name)}
        onMouseEnter={() => open !== null && setOpen(name)}
      >
        {name}
      </button>
      {open === name && (
        <div className="menu-pop" role="menu" aria-label={name} onClick={() => setOpen(null)}>
          {body}
        </div>
      )}
    </div>
  );

  const item = (label: ReactNode, onClick: () => void, hint?: string, checked?: boolean) => (
    <button
      type="button"
      role={checked === undefined ? "menuitem" : "menuitemradio"}
      aria-checked={checked}
      className="menu-item"
      onClick={onClick}
    >
      <span>{label}</span>
      {hint !== undefined && <span className="faint">{hint}</span>}
      {checked === true && <span className="faint">●</span>}
    </button>
  );

  return (
    <div className="titlebar" ref={rootRef}>
      <div className="brand">
        <img src={logoUrl} width={16} height={16} alt="" draggable={false} />
      </div>

      {menu(
        "File",
        <>
          {item("Open binary…", () => void openBinary(), "Ctrl+O")}
          {item("Attach to process…", () => setRail("targets"))}
          <div className="menu-sep" role="separator" />
          {item(
            "Exit",
            () => {
              // Ask the engine to run its own teardown before the window goes
              // away, so a closed UI never orphans state
              void call("app", "shutdown", { reason: "File > Exit" }).finally(() =>
                windowAction("close"),
              );
            },
            "Alt+F4",
          )}
        </>,
      )}

      {menu(
        "View",
        <>
          {item("Command palette…", () => setPaletteOpen(true), "Ctrl+K")}
          <div className="menu-sep" role="separator" />
          {(
            [
              ["targets", "Targets"],
              ["modules", "Modules"],
              ["scripts", "Scripts"],
            ] as const
          ).map(([id, label]) => (
            <Fragment key={id}>{item(label, () => setRail(id), undefined, rail === id)}</Fragment>
          ))}
          <div className="menu-sep" role="separator" />
          {item(
            inspectorOpen ? "Hide inspector" : "Show inspector",
            () => setInspectorOpen(!inspectorOpen),
            "Ctrl+Alt+I",
          )}
          {item("Reset layout", resetLayout)}
        </>,
      )}

      {menu(
        "Window",
        <>
          {item("Settings…", openSettings, "Ctrl+,")}
          <div className="menu-sep" role="separator" />
          {item("Reload interface", () => window.location.reload())}
        </>,
      )}

      {menu(
        "Theme",
        <>
          {kThemes.map((t) => (
            <Fragment key={t.id}>
              {item(t.label, () => setTheme(t.id), undefined, theme === t.id)}
            </Fragment>
          ))}
        </>,
      )}

      {menu(
        "Help",
        <>
          {kShortcuts.map((s) => (
            <div className="menu-item menu-static" key={s.keys}>
              <span>{s.label}</span>
              <span className="faint">{s.keys}</span>
            </div>
          ))}
          <div className="menu-sep" role="separator" />
          <div className="menu-item menu-static">SlopStation</div>
        </>,
      )}

      <div className="titlebar-drag" data-tauri-drag-region />

      {isInsecureDev() && (
        <span
          className="insecure-badge"
          role="status"
          data-tip="Browser dev mode: connected to whatever listens on 127.0.0.1:8765 with no token or handshake"
        >
          insecure dev mode
        </span>
      )}
      {quitting !== null && <span className="faint">shutting down…</span>}

      <div className="win-buttons">
        <IconButton
          tip="Minimize"
          variant="bare"
          className="win-button"
          onClick={() => void windowAction("minimize")}
        >
          <Minus size={14} />
        </IconButton>
        <IconButton
          tip="Maximize"
          variant="bare"
          className="win-button"
          onClick={() => void windowAction("toggleMaximize")}
        >
          <Square size={12} />
        </IconButton>
        <IconButton
          tip="Close"
          variant="bare"
          className="win-button close"
          onClick={() => void windowAction("close")}
        >
          <X size={14} />
        </IconButton>
      </div>
    </div>
  );
}
