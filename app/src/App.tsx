// app/src/App.tsx
// the shell, css grid layout driven by splitter custom properties

import { useEffect, useRef } from "react";
import { RotateCcw, X } from "lucide-react";
import ActivityRail from "@/components/ActivityRail";
import CommandPalette from "@/components/CommandPalette";
import IconButton from "@/components/IconButton";
import SettingsModal from "@/components/SettingsModal";
import Splash from "@/components/Splash";
import Splitter from "@/components/Splitter";
import StatusBar from "@/components/StatusBar";
import TitleBar from "@/components/TitleBar";
import TooltipLayer from "@/components/TooltipLayer";
import InspectorPanel from "@/components/panels/InspectorPanel";
import ModulesPanel from "@/components/panels/ModulesPanel";
import OutputPanel from "@/components/panels/OutputPanel";
import ScannerPanel from "@/components/panels/ScannerPanel";
import ScriptsPanel from "@/components/panels/ScriptsPanel";
import TargetsPanel from "@/components/panels/TargetsPanel";
import WorkspacePanel from "@/components/panels/WorkspacePanel";
import { panelId, tabId } from "@/components/Tabs";
import { useShortcuts } from "@/lib/shortcuts";
import { useEngine } from "@/store/engine";
import { useOutput } from "@/store/output";
import { kLayoutVars, useUi, type LayoutVar } from "@/store/ui";
import { useWatch } from "@/store/watch";

/** Post-boot failures (snapshot, engine crash) surface here, not on the splash. */
function EngineBanner() {
  const startupError = useEngine((s) => s.startupError);
  const crash = useEngine((s) => s.crash);
  const retry = useEngine((s) => s.retry);
  const dismiss = useEngine((s) => s.dismissError);
  if (startupError === null && crash === null) return null;
  const text =
    crash !== null
      ? crash.retry_in_ms === null
        ? `Engine crashed and was not restarted: ${crash.reason}`
        : `Engine crashed (${crash.reason}); restarting in ${Math.ceil(crash.retry_in_ms / 1000)}s…`
      : `Engine error: ${startupError}`;
  return (
    <div className="engine-banner" role="alert">
      <span>
        {text}
        {crash !== null && crash.log_path !== "" ? ` · log: ${crash.log_path}` : ""}
      </span>
      <div className="spacer" />
      <button type="button" className="row-action" onClick={() => void retry()}>
        <RotateCcw size={11} aria-hidden /> Retry
      </button>
      {crash === null && (
        <IconButton tip="Dismiss" onClick={dismiss}>
          <X size={13} />
        </IconButton>
      )}
    </div>
  );
}

export default function App() {
  const rail = useUi((s) => s.rail);
  const setRail = useUi((s) => s.setRail);
  const settingsOpen = useUi((s) => s.settingsOpen);
  const openSettings = useUi((s) => s.openSettings);
  const closeSettings = useUi((s) => s.closeSettings);
  const inspectorOpen = useUi((s) => s.inspectorOpen);
  const appRef = useRef<HTMLDivElement>(null);
  const boot = useEngine((s) => s.boot);
  const start = useEngine((s) => s.start);
  const attachOutput = useOutput((s) => s.attach);
  const attachWatch = useWatch((s) => s.attach);
  const sizes = useUi((s) => s.sizes);

  // Persisted splitter sizes drive the grid's CSS variables; an unset entry
  // (fresh install, Reset layout) falls back to the stylesheet default
  useEffect(() => {
    const root = appRef.current;
    if (root === null) return;
    for (const key of Object.keys(kLayoutVars) as LayoutVar[]) {
      const px = sizes[key];
      if (px === undefined) root.style.removeProperty(key);
      else root.style.setProperty(key, `${px}px`);
    }
  }, [sizes]);

  useShortcuts();

  useEffect(() => {
    // Event handlers must be registered before connect() so the first frames
    // after the stream opens are not dropped
    const detachOutput = attachOutput();
    const detachWatch = attachWatch();
    void start();
    return () => {
      detachOutput();
      detachWatch();
    };
  }, [start, attachOutput, attachWatch]);

  const leftPanel = () => {
    // Keyed so switching rails remounts the panel and replays its enter
    // animation (see `.panel` in the motion section of app.css)
    switch (rail) {
      case "targets":
        return <TargetsPanel key="targets" />;
      case "modules":
        return <ModulesPanel key="modules" />;
      case "scripts":
        return <ScriptsPanel key="scripts" />;
    }
  };

  return (
    <div className="app" ref={appRef}>
      <TitleBar />

      {!boot.done ? (
        <Splash />
      ) : (
        <div className="app-shell">
          <EngineBanner />
          <main className="app-body" data-inspector={inspectorOpen ? "open" : "closed"}>
            <ActivityRail active={rail} onSelect={setRail} onSettings={openSettings} />

            <section
              className="left-slot"
              role="tabpanel"
              id={panelId("rail", rail)}
              aria-labelledby={tabId("rail", rail)}
            >
              {leftPanel()}
            </section>
            <Splitter
              axis="x"
              variable="--left-w"
              target={appRef}
              min={200}
              max={620}
              label="Resize side panel"
            />

            <div className="center-col">
              <div className="center-top">
                <ScannerPanel />
                <Splitter
                  axis="x"
                  variable="--scan-w"
                  target={appRef}
                  min={220}
                  max={620}
                  label="Resize scanner"
                />
                <WorkspacePanel />
              </div>
              <Splitter
                axis="y"
                variable="--bottom-h"
                target={appRef}
                min={100}
                max={640}
                invert
                label="Resize output panel"
              />
              <OutputPanel />
            </div>

            {inspectorOpen && (
              <>
                <Splitter
                  axis="x"
                  variable="--right-w"
                  target={appRef}
                  min={220}
                  max={620}
                  invert
                  label="Resize inspector"
                />
                <InspectorPanel />
              </>
            )}
          </main>
        </div>
      )}

      <StatusBar />
      {settingsOpen && <SettingsModal onClose={closeSettings} />}
      <CommandPalette />
      <TooltipLayer />
    </div>
  );
}
