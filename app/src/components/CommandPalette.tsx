// app/src/components/CommandPalette.tsx
// Ctrl+K / Ctrl+Shift+P command palette (cmdk): jump to a function by name or
// address, go to an address in the listing or the hex view, switch tabs and
// panels, and run the shell actions the menus carry

import { useEffect, useMemo, useState } from "react";
import { Command } from "cmdk";
import { useT } from "@/i18n";
import type { Key } from "@/i18n/en";
import { openBinary } from "@/lib/openBinary";
import { browserLabel, hex, parseAddress } from "@/lib/format";
import { loadHelpIndex, openHelp, searchHelp, type HelpEntry } from "@/lib/help";
import { functionLabel, useDisasm, type FunctionRow } from "@/store/disasm";
import { useDecomp } from "@/store/decomp";
import { useEngine } from "@/store/engine";
import { useMemory } from "@/store/memory";
import { kThemes, useTheme } from "@/store/theme";
import { useUi, type RailView, type WorkspaceTab } from "@/store/ui";

type Action = {
  id: string;
  group: "navigate" | "actions" | "theme";
  label: string;
  hint?: string;
  run: () => void;
  enabled?: boolean;
};

const kSearchLimit = 50;
const kSearchDebounceMs = 120;
const kHelpLimit = 8;

const kGroupLabels: Record<Action["group"], Key> = {
  navigate: "palette.navigate",
  actions: "palette.actions",
  theme: "palette.theme",
};

export default function CommandPalette() {
  const t = useT();
  const open = useUi((s) => s.paletteOpen);
  const setOpen = useUi((s) => s.setPaletteOpen);
  const setWorkspaceTab = useUi((s) => s.setWorkspaceTab);
  const setRail = useUi((s) => s.setRail);
  const openSettings = useUi((s) => s.openSettings);
  const inspectorOpen = useUi((s) => s.inspectorOpen);
  const setInspectorOpen = useUi((s) => s.setInspectorOpen);
  const resetLayout = useUi((s) => s.resetLayout);
  const image = useDisasm((s) => s.image);
  const searchFunctions = useDisasm((s) => s.searchFunctions);
  const attached = useEngine((s) => s.target.attached);
  const setTheme = useTheme((s) => s.setTheme);
  const [query, setQuery] = useState("");
  const [found, setFound] = useState<FunctionRow[]>([]);
  const [help, setHelp] = useState<HelpEntry[]>([]);

  useEffect(() => {
    if (!open) setQuery("");
  }, [open]);

  // The docs index is a generated chunk: load it the first time the palette
  // opens, never at startup
  useEffect(() => {
    if (!open) return;
    let alive = true;
    void loadHelpIndex().then((entries) => alive && setHelp(entries));
    return () => {
      alive = false;
    };
  }, [open]);

  const helpHits = useMemo(() => searchHelp(help, query.trim(), kHelpLimit), [help, query]);

  // Function search is server-side: the list can hold far more functions
  // than the UI ever loads
  useEffect(() => {
    if (!open || !image.ready || query.trim() === "") {
      setFound([]);
      return;
    }
    let alive = true;
    const timer = setTimeout(() => {
      searchFunctions(query.trim(), kSearchLimit)
        .then((rows) => alive && setFound(rows))
        .catch(() => alive && setFound([]));
    }, kSearchDebounceMs);
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [open, query, image.ready, searchFunctions]);

  const close = () => setOpen(false);
  const tab = (id: WorkspaceTab) => () => setWorkspaceTab(id);
  const rail = (id: RailView) => () => setRail(id);
  // Pseudocode follows the listing selection, so the tab only has to be shown
  const showDecomp = (split: boolean) => () => {
    const sel = useDisasm.getState().selected;
    setWorkspaceTab("decomp");
    useDecomp.getState().setSplit(split);
    if (sel !== null) void useDecomp.getState().load(sel);
  };

  const actions: Action[] = useMemo(
    () => [
      {
        id: "tab-disassembly",
        group: "navigate",
        label: t("workspace.disassembly"),
        run: tab("disassembly"),
      },
      { id: "tab-decomp", group: "navigate", label: t("workspace.decomp"), run: tab("decomp") },
      {
        id: "show-pseudocode",
        group: "navigate",
        label: t("palette.showPseudocode"),
        enabled: image.ready,
        run: showDecomp(false),
      },
      {
        id: "show-cfg",
        group: "navigate",
        label: t("palette.showCfg"),
        enabled: image.ready,
        run: showDecomp(true),
      },
      { id: "tab-strings", group: "navigate", label: t("workspace.strings"), run: tab("strings") },
      { id: "tab-memory", group: "navigate", label: t("workspace.memory"), run: tab("memory") },
      {
        id: "tab-debugger",
        group: "navigate",
        label: t("workspace.debugger"),
        run: tab("debugger"),
      },
      { id: "tab-pe", group: "navigate", label: browserLabel(image.format), run: tab("pe") },
      {
        id: "rail-targets",
        group: "navigate",
        label: t("palette.targetsPanel"),
        run: rail("targets"),
      },
      {
        id: "rail-modules",
        group: "navigate",
        label: t("palette.modulesPanel"),
        run: rail("modules"),
      },
      {
        id: "rail-scripts",
        group: "navigate",
        label: t("palette.scriptsPanel"),
        run: rail("scripts"),
      },
      {
        id: "open",
        group: "actions",
        label: t("common.openBinary"),
        hint: "Ctrl+O",
        run: () => void openBinary(),
      },
      {
        id: "close",
        group: "actions",
        label: t("palette.closeBinary"),
        enabled: image.ready,
        run: () => void useDisasm.getState().unload(),
      },
      {
        id: "settings",
        group: "actions",
        label: t("titlebar.settings"),
        hint: "Ctrl+,",
        run: openSettings,
      },
      {
        id: "inspector",
        group: "actions",
        label: t(inspectorOpen ? "titlebar.hideInspector" : "titlebar.showInspector"),
        run: () => setInspectorOpen(!inspectorOpen),
      },
      { id: "layout", group: "actions", label: t("titlebar.resetLayout"), run: resetLayout },
      {
        id: "reload",
        group: "actions",
        label: t("titlebar.reload"),
        run: () => window.location.reload(),
      },
      ...kThemes.map((th): Action => ({
        id: `theme-${th.id}`,
        group: "theme",
        label: t("palette.themeItem", { theme: t(th.labelKey) }),
        run: () => setTheme(th.id),
      })),
    ],
    // tab/rail are stable closures over stable setters
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [
      image.format,
      image.ready,
      inspectorOpen,
      openSettings,
      setInspectorOpen,
      resetLayout,
      setTheme,
      t,
    ],
  );

  const addr = parseAddress(query);
  const runAndClose = (fn: () => void) => () => {
    close();
    fn();
  };

  return (
    <Command.Dialog
      open={open}
      onOpenChange={setOpen}
      label={t("palette.label")}
      className="palette"
      overlayClassName="palette-scrim"
      contentClassName="palette-content"
    >
      <Command.Input
        className="palette-input"
        value={query}
        onValueChange={setQuery}
        placeholder={t("palette.placeholder")}
      />
      <Command.List className="palette-list">
        <Command.Empty className="palette-empty">{t("palette.noMatches")}</Command.Empty>

        {addr !== null && (
          <Command.Group heading={t("palette.gotoAddress")}>
            {image.ready && (
              <Command.Item
                value={`goto-disasm ${query}`}
                onSelect={runAndClose(() => {
                  setWorkspaceTab("disassembly");
                  void useDisasm.getState().gotoAddress(addr);
                })}
              >
                {t("palette.disasmAt", { addr: hex(addr, 1) })}
              </Command.Item>
            )}
            {image.ready && (
              <Command.Item
                value={`pseudocode ${query}`}
                onSelect={runAndClose(() => {
                  setWorkspaceTab("decomp");
                  void useDecomp.getState().load(addr);
                })}
              >
                {t("palette.pseudocodeAt", { addr: hex(addr, 1) })}
              </Command.Item>
            )}
            {attached && (
              <Command.Item
                value={`goto-memory ${query}`}
                onSelect={runAndClose(() => {
                  setWorkspaceTab("memory");
                  useMemory.getState().goto(addr);
                })}
              >
                {t("palette.memoryAt", { addr: hex(addr, 1) })}
              </Command.Item>
            )}
          </Command.Group>
        )}

        {found.length > 0 && (
          <Command.Group heading={t("palette.functions")}>
            {found.map((fn) => (
              <Command.Item
                key={fn.va}
                value={`fn ${functionLabel(fn)} ${fn.va.toString(16)}`}
                keywords={[functionLabel(fn), fn.va.toString(16), query]}
                onSelect={runAndClose(() => {
                  setWorkspaceTab("disassembly");
                  void useDisasm.getState().select(fn.va, fn);
                })}
              >
                <span className="mono">{functionLabel(fn)}</span>
                <span className="palette-hint mono">{hex(fn.va, 1)}</span>
              </Command.Item>
            ))}
          </Command.Group>
        )}

        {helpHits.length > 0 && (
          <Command.Group heading={t("palette.help")}>
            {helpHits.map((e) => (
              <Command.Item
                key={`${e.path}#${e.anchor}`}
                // cmdk filters on `value`, so the excerpt has to be in it or a
                // body-text match from searchHelp would be dropped again
                value={`help ${e.title} ${e.section} ${e.path} ${e.text}`}
                onSelect={runAndClose(() => void openHelp(e.url))}
              >
                <span>{e.title}</span>
                <span className="palette-hint">{e.path.replace(/\.md$/, "")}</span>
              </Command.Item>
            ))}
          </Command.Group>
        )}

        {(["navigate", "actions", "theme"] as const).map((group) => (
          <Command.Group heading={t(kGroupLabels[group])} key={group}>
            {actions
              .filter((a) => a.group === group && a.enabled !== false)
              .map((a) => (
                <Command.Item key={a.id} value={a.label} onSelect={runAndClose(a.run)}>
                  <span>{a.label}</span>
                  {a.hint !== undefined && <span className="palette-hint">{a.hint}</span>}
                </Command.Item>
              ))}
          </Command.Group>
        ))}
      </Command.List>
    </Command.Dialog>
  );
}
