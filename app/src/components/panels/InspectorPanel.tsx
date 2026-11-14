// app/src/components/panels/InspectorPanel.tsx
// right hand pane, whatever the engine knows about the target and image

import { Search, X } from "lucide-react";
import IconButton from "@/components/IconButton";
import { useT } from "@/i18n";
import { formatLabel } from "@/lib/format";
import { hex as hexAddr, useDisasm } from "@/store/disasm";
import { useEngine } from "@/store/engine";
import { useTargets } from "@/store/targets";
import { useUi } from "@/store/ui";

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="inspector-row">
      <span className="faint inspector-key">{k}</span>
      {/* Ellipsis rather than break-all: a wrapped path or process name split
          mid-word ("reverse-slo p-engine.ex e") is harder to read than a
          truncated one with the full value on hover. */}
      <span className="mono inspector-value" data-tip={v}>
        {v}
      </span>
    </div>
  );
}

export default function InspectorPanel() {
  const t = useT();
  const target = useEngine((s) => s.target);
  const backend = useEngine((s) => s.backend);
  const hype = useEngine((s) => s.hype);
  // Kept current by the engine store on target.changed (MCP attach included)
  const modules = useTargets((s) => s.modules);
  const ps4 = useTargets((s) => s.ps4);
  const setInspectorOpen = useUi((s) => s.setInspectorOpen);
  // Image facts come from the disasm store, not from `hype.image`: the
  // workspace reads `disasm.loaded` and the event mirror can lag it, which had
  // the Inspector naming one image while the listing showed another
  const image = useDisasm((s) => s.image);

  return (
    <aside className="panel" aria-label={t("inspector.title")}>
      <div className="panel-head">
        <span className="panel-title">{t("inspector.title")}</span>
        <div className="spacer" />
        <IconButton tip={t("inspector.hide")} onClick={() => setInspectorOpen(false)}>
          <X size={14} />
        </IconButton>
      </div>

      <div className="panel-body">
        {!target.attached && !image.ready ? (
          <div className="empty">
            <div className="empty-glyph">
              <Search size={28} strokeWidth={1.5} />
            </div>
            <div className="empty-title">{t("inspector.empty")}</div>
            <div className="empty-hint">{t("inspector.emptyHint")}</div>
          </div>
        ) : (
          <div className="inspector">
            {target.attached && (
              <>
                <Row k={t("inspector.process")} v={target.name ?? "?"} />
                <Row k={t("inspector.pid")} v={String(target.pid ?? 0)} />
                <Row k={t("inspector.backend")} v={backend.badge} />
                {backend.ps4 && ps4 !== null && ps4.endpoint !== "" && (
                  <Row k={t("inspector.console")} v={ps4.endpoint} />
                )}
                <Row k={t("inspector.modules")} v={String(modules.length)} />
              </>
            )}
            {image.ready && (
              <>
                {target.attached && <div className="menu-sep" role="separator" />}
                <Row k={t("inspector.image")} v={image.name ?? "?"} />
                {image.format !== undefined && (
                  <Row k={t("inspector.format")} v={formatLabel(image.format)} />
                )}
                {image.arch !== undefined && <Row k={t("inspector.arch")} v={image.arch} />}
                {image.encrypted !== undefined && (
                  <Row
                    k={t("inspector.encrypted")}
                    v={image.encrypted ? t("common.yes") : t("common.no")}
                  />
                )}
                <Row
                  k={t("inspector.base")}
                  v={image.base !== undefined ? hexAddr(image.base) : t("common.na")}
                />
                {image.entry_va !== undefined && (
                  <Row k={t("inspector.entry")} v={hexAddr(image.entry_va)} />
                )}
                <Row k={t("inspector.functions")} v={String(image.functions ?? 0)} />
                {image.strings !== undefined && (
                  <Row k={t("inspector.strings")} v={String(image.strings)} />
                )}
                <Row
                  k={t("inspector.analysis")}
                  v={
                    hype.running
                      ? `${Math.round(hype.progress * 100)}%`
                      : hype.ready
                        ? t("common.ready")
                        : hype.error || t("common.idle")
                  }
                />
                {image.bundle !== undefined && (
                  <>
                    <div className="menu-sep" role="separator" />
                    <Row k={t("inspector.appDir")} v={image.bundle.app_dir} />
                    <Row k={t("inspector.executable")} v={image.bundle.executable} />
                    <Row k={t("inspector.archivePath")} v={image.bundle.executable_path} />
                    {image.bundle.bundle_id !== "" && (
                      <Row k={t("inspector.bundleId")} v={image.bundle.bundle_id} />
                    )}
                    {image.bundle.version !== "" && (
                      <Row k={t("inspector.version")} v={image.bundle.version} />
                    )}
                    {image.bundle.build !== "" && (
                      <Row k={t("inspector.build")} v={image.bundle.build} />
                    )}
                    {image.bundle.min_os !== "" && (
                      <Row k={t("inspector.minOs")} v={image.bundle.min_os} />
                    )}
                  </>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </aside>
  );
}
