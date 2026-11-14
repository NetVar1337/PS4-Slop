// app/src/components/Splash.tsx
// boot checklist fed by boot.stage events so the uac pause doesnt look like a hang

import { RotateCcw } from "lucide-react";
import { useT } from "@/i18n";
import { kStageLabels, useEngine } from "@/store/engine";
import { useOutput } from "@/store/output";
import logoUrl from "@/assets/reverse-slop-icon.png";

export default function Splash() {
  const t = useT();
  const boot = useEngine((s) => s.boot);
  const stageLabels = useEngine((s) => s.stageLabels);
  const connected = useEngine((s) => s.connected);
  const startupError = useEngine((s) => s.startupError);
  const crash = useEngine((s) => s.crash);
  const retry = useEngine((s) => s.retry);
  const lines = useOutput((s) => s.lines);
  const tail = lines.slice(-4);
  // One row per stage the engine counts, labelled as the engine reports them
  const rows = Array.from(
    { length: Math.max(1, boot.total) },
    (_, i) =>
      stageLabels[i] ??
      (kStageLabels[i] !== undefined ? t(kStageLabels[i]) : t("splash.stage", { n: i + 1 })),
  );
  const failed = startupError !== null || (crash !== null && crash.retry_in_ms === null);

  return (
    <div className="splash">
      <div className="splash-card">
        <img className="splash-logo" src={logoUrl} alt="SlopStation" draggable={false} />
        <div className="splash-title">SlopStation</div>
        <div className="faint" style={{ fontSize: "var(--type-small)" }}>
          {t("splash.tagline")}
        </div>

        <ol className="splash-rows" aria-label={t("splash.stages")}>
          {rows.map((label, i) => {
            const status = i < boot.stage ? "ok" : i === boot.stage ? "run" : "wait";
            const marker = status === "ok" ? "[ ok ]" : status === "run" ? "[ .. ]" : "[    ]";
            return (
              <li className="splash-row" data-status={status} key={i}>
                {marker} {label}
              </li>
            );
          })}
        </ol>

        {tail.length > 0 && (
          <div className="log" style={{ padding: 0, marginBottom: "var(--pad-md)" }}>
            {tail.map((l) => (
              <div className="log-row faint" key={l.seq}>
                {l.text}
              </div>
            ))}
          </div>
        )}

        <div
          className="progress"
          role="progressbar"
          aria-label={t("splash.progress")}
          aria-valuemin={0}
          aria-valuemax={boot.total}
          aria-valuenow={boot.stage}
        >
          <div
            className="progress-fill"
            style={{ width: `${Math.round((boot.stage / Math.max(1, boot.total)) * 100)}%` }}
          />
        </div>
        <div className="empty-hint" style={{ marginTop: "var(--pad-sm)" }}>
          {failed ? (
            <div className="splash-error" role="alert">
              <span>
                {t("splash.failed", {
                  reason: startupError ?? crash?.reason ?? t("splash.exited"),
                })}
                {crash !== null && crash.log_path !== ""
                  ? t("splash.log", { path: crash.log_path })
                  : ""}
              </span>
              <button type="button" className="row-action" onClick={() => void retry()}>
                <RotateCcw size={11} aria-hidden /> {t("common.retry")}
              </button>
            </div>
          ) : crash !== null ? (
            t("splash.crashed", { reason: crash.reason })
          ) : connected ? (
            t("splash.tip")
          ) : (
            t("splash.waiting")
          )}
        </div>
      </div>
    </div>
  );
}
