// app/src/App.tsx
// the shell, css grid layout driven by splitter custom properties

import { useEffect, useRef } from "react";
import { FolderOpen, RotateCcw, X } from "lucide-react";
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
import { useT } from "@/i18n";
import { useShortcuts } from "@/lib/shortcuts";
import { openPath } from "@/lib/shell";
import { useEngine } from "@/store/engine";
import { useOutput } from "@/store/output";
import { kLayoutVars, useUi, type LayoutVar } from "@/store/ui";
import { useUpdater } from "@/store/updater";
import { useWatch } from "@/store/watch";

/** Post-boot failures (snapshot, engine crash) surface here, not on the splash. */
function EngineBanner() {
  const t = useT();
  const startupError = useEngine((s) => s.startupError);
  const crash = useEngine((s) => s.crash);
  const retry = useEngine((s) => s.retry);
  const dismiss = useEngine((s) => s.dismissError);
  if (startupError === null && crash === null) return null;
  const text =
    crash !== null
      ? crash.retry_in_ms === null
        ? t("app.crashStopped", { reason: crash.reason })
        : t("app.crashRestarting", {
            reason: crash.reason,
            seconds: Math.ceil(crash.retry_in_ms / 1000),
          })
      : t("app.engineError", { error: startupError ?? "" });
  return (
    <div className="engine-banner" role="alert">
      <span>
        {text}
        {crash !== null && crash.log_path !== "" ? t("app.logPath", { path: crash.log_path }) : ""}
      </span>
      <div className="spacer" />
      {crash !== null && crash.log_path !== "" && (
        <button type="button" className="row-action" onClick={() => void openPath(crash.log_path)}>
          <FolderOpen size={11} aria-hidden /> {t("app.openLogFolder")}
        </button>
      )}
      <button type="button" className="row-action" onClick={() => void retry()}>
        <RotateCcw size={11} aria-hidden /> {t("common.retry")}
      </button>
      {crash === null && (
        <IconButton tip={t("common.dismiss")} onClick={dismiss}>
          <X size={13} />
        </IconButton>
      )}
    </div>
  );
}

/** Update check, download and restart, surfaced above the workspace. */
function UpdateBanner() {
  const t = useT();
  const phase = useUpdater((s) => s.phase);
  const version = useUpdater((s) => s.version);
  const progress = useUpdater((s) => s.progress);
  const error = useUpdater((s) => s.error);
  const dismissed = useUpdater((s) => s.dismissed);
  const install = useUpdater((s) => s.install);
  const dismiss = useUpdater((s) => s.dismiss);
  const check = useUpdater((s) => s.check);
  if (dismissed || phase === "idle" || phase === "checking") return null;
  if (phase === "available") {
    return (
      <div className="engine-banner update-banner" role="status">
        <span>{t("app.updateAvailable", { version: version ?? "" })}</span>
        <div className="spacer" />
        <button type="button" className="row-action" onClick={() => void install()}>
          {t("app.installRestart")}
        </button>
        <IconButton tip={t("common.dismiss")} onClick={dismiss}>
          <X size={13} />
        </IconButton>
      </div>
    );
  }
  if (phase === "downloading") {
    const pct = progress < 0 ? null : Math.round(progress * 100);
    return (
      <div className="engine-banner update-banner" role="status">
        <span>
          {t("app.updateDownloading", {
            version: version ?? "",
            percent: pct === null ? "" : ` ${pct}%`,
          })}
        </span>
        <div className="update-progress" aria-hidden>
          <span style={{ width: pct === null ? "100%" : `${pct}%` }} />
        </div>
      </div>
    );
  }
  if (phase === "ready") {
    return (
      <div className="engine-banner update-banner" role="status">
        <span>{t("app.updateInstalled")}</span>
      </div>
    );
  }
  return (
    <div className="engine-banner update-banner" role="alert">
      <span>{t("app.updateFailed", { error: error ?? "" })}</span>
      <div className="spacer" />
      <button type="button" className="row-action" onClick={() => void check(true)}>
        <RotateCcw size={11} aria-hidden /> {t("common.retry")}
      </button>
      <IconButton tip={t("common.dismiss")} onClick={dismiss}>
        <X size={13} />
      </IconButton>
    </div>
  );
}

export default function App() {
  const t = useT();
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
    // Release builds check for a newer installer once per launch; browser dev
    // and offline runs resolve to a no-op.
    void useUpdater.getState().check();
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
          {/* Always present: with no banner the main would land in the auto
              row and the 1fr row would stay empty (black lower half). */}
          <div className="banner-slot">
            <EngineBanner />
            <UpdateBanner />
          </div>
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
              label={t("app.resizeSidePanel")}
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
                  label={t("app.resizeScanner")}
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
                label={t("app.resizeOutput")}
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
                  label={t("app.resizeInspector")}
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
