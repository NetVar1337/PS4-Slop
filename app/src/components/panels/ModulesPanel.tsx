// app/src/components/panels/ModulesPanel.tsx
// Module list for the attached target, with the dump / dump+analyze workflow the
// ImGui Targets view carried (src/ui/view_targets.cpp, module table). On a PS4
// the module is pulled over the ps4debug wire and rebuilt as an ELF

import { useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Download, RefreshCw, Search } from "lucide-react";
import { save } from "@tauri-apps/plugin-dialog";
import IconButton from "@/components/IconButton";
import { useT } from "@/i18n";
import { isTauri } from "@/lib/endpoint";
import { call, errorText } from "@/lib/rpc";
import { hex, useDisasm } from "@/store/disasm";
import { useEngine } from "@/store/engine";
import { useTargets } from "@/store/targets";

const kRow = 22;

/** `target.dump_module` / `target.ps4_dump_module` result. */
type DumpResult = {
  dumped?: boolean;
  complete?: boolean;
  path?: string;
  bytes_written?: number;
  sections?: number;
  loaded?: boolean;
  warnings?: string[];
};

function dumpFileName(name: string, base: number, ps4: boolean): string {
  if (ps4) return name.toLowerCase().endsWith(".elf") ? name : `${name}.elf`;
  return `${name}_${hex(base, 12)}.dump.${name.toLowerCase().endsWith(".dll") ? "dll" : "exe"}`;
}

export default function ModulesPanel() {
  const t = useT();
  const target = useEngine((s) => s.target);
  const ps4 = useEngine((s) => s.backend.ps4);
  // The engine store refreshes this list on every target.changed
  const modules = useTargets((s) => s.modules);
  const refreshModules = useTargets((s) => s.refreshModules);
  const refreshLoaded = useDisasm((s) => s.refreshLoaded);
  const [filter, setFilter] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  const rows = modules.filter((m) => m.name.toLowerCase().includes(filter.toLowerCase()));

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => kRow,
    overscan: 12,
  });

  // dump_module reconstructs a loadable image from the mapped one; load=true
  // hands it straight to the shared analysis session, which is the fast path
  // from "attached to a packed process" to "looking at real code"
  const dump = async (base: number, name: string) => {
    let path: string | null;
    if (isTauri()) {
      path = await save({
        title: t("modules.dumpTitle", { name }),
        defaultPath: dumpFileName(name, base, ps4),
      });
    } else {
      // Browser dev mode has no native dialog
      path = window.prompt(t("modules.dumpPrompt", { name }), dumpFileName(name, base, ps4));
    }
    if (path === null || path.trim() === "") {
      setStatus(null);
      return;
    }
    setStatus(t("modules.dumping", { name }));
    try {
      // strict=false so a packed image with unreadable spans still produces a
      // file; the engine zero-fills those and reports complete=false
      const res = ps4
        ? await call<DumpResult>(
            "target",
            "ps4_dump_module",
            { name, path, load: true },
            { timeoutMs: 600_000 },
          )
        : await call<DumpResult>(
            "target",
            "dump_module",
            { base, path, load: true, strict: false },
            { timeoutMs: 600_000 },
          );
      const size =
        res.bytes_written !== undefined
          ? t("modules.size", { kib: Math.round(res.bytes_written / 1024) })
          : "";
      const partial = res.complete === false ? t("modules.partial") : "";
      const warn =
        res.warnings !== undefined && res.warnings.length > 0
          ? t("modules.warnings", { count: res.warnings.length, first: res.warnings[0] })
          : "";
      const sections =
        res.sections !== undefined ? t("modules.sections", { count: res.sections }) : "";
      setStatus(t("modules.dumped", { name, size, sections, partial, warn }));
      await refreshLoaded();
    } catch (e) {
      setStatus(errorText(e));
    }
  };

  if (!target.attached) {
    return (
      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">{t("modules.title")}</span>
        </div>
        <div className="empty">
          <div className="empty-hint">{t("modules.empty")}</div>
        </div>
      </div>
    );
  }

  return (
    <div className="panel">
      <div className="panel-head">
        <span className="panel-title">{t("modules.title")}</span>
        <div className="spacer" />
        <span className="faint" style={{ fontSize: 11 }}>
          {modules.length}
        </span>
        <IconButton tip={t("modules.refresh")} onClick={() => void refreshModules()}>
          <RefreshCw size={14} />
        </IconButton>
      </div>

      <div className="modules-body">
        <div className="search">
          <Search size={13} aria-hidden />
          <input
            value={filter}
            aria-label={t("modules.filter")}
            placeholder={t("modules.filterPlaceholder")}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>

        <div className="panel-body" ref={scrollRef}>
          <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
            {virtualizer.getVirtualItems().map((v) => {
              const m = rows[v.index];
              return (
                <div
                  key={`${m.base}-${m.name}`}
                  className="fn-row"
                  style={{ top: v.start, height: kRow }}
                  data-tip={m.path ?? m.name}
                >
                  <span className="fn-name">{m.name}</span>
                  <span className="faint" style={{ fontSize: 10 }}>
                    {hex(m.base, 12)}
                  </span>
                  <IconButton
                    tip={t("modules.dump", { name: m.name })}
                    onClick={() => void dump(m.base, m.name)}
                  >
                    <Download size={11} />
                  </IconButton>
                </div>
              );
            })}
          </div>
        </div>

        {status !== null && (
          <div
            className="empty-hint"
            role="status"
            style={{ padding: "var(--pad-sm) var(--pad-md)" }}
          >
            {status}
          </div>
        )}
      </div>
    </div>
  );
}
