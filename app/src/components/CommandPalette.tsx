// app/src/components/CommandPalette.tsx
// Ctrl+K / Ctrl+Shift+P command palette (cmdk): jump to a function by name or
// address, go to an address in the listing or the hex view, switch tabs and
// panels, and run the shell actions the menus carry

import { useEffect, useMemo, useState } from "react";
import { Command } from "cmdk";
import { openBinary } from "@/lib/openBinary";
import { browserLabel, hex, parseAddress } from "@/lib/format";
import { functionLabel, useDisasm, type FunctionRow } from "@/store/disasm";
import { useEngine } from "@/store/engine";
import { useMemory } from "@/store/memory";
import { kThemes, useTheme } from "@/store/theme";
import { useUi, type RailView, type WorkspaceTab } from "@/store/ui";

type Action = {
  id: string;
  group: "Navigate" | "Actions" | "Theme";
  label: string;
  hint?: string;
  run: () => void;
  enabled?: boolean;
};

const kSearchLimit = 50;
const kSearchDebounceMs = 120;

export default function CommandPalette() {
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

  useEffect(() => {
    if (!open) setQuery("");
  }, [open]);

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

  const actions: Action[] = useMemo(
    () => [
      { id: "tab-disassembly", group: "Navigate", label: "Disassembly", run: tab("disassembly") },
      { id: "tab-strings", group: "Navigate", label: "Strings", run: tab("strings") },
      { id: "tab-memory", group: "Navigate", label: "Memory", run: tab("memory") },
      { id: "tab-debugger", group: "Navigate", label: "Debugger", run: tab("debugger") },
      { id: "tab-pe", group: "Navigate", label: browserLabel(image.format), run: tab("pe") },
      { id: "rail-targets", group: "Navigate", label: "Targets panel", run: rail("targets") },
      { id: "rail-modules", group: "Navigate", label: "Modules panel", run: rail("modules") },
      { id: "rail-scripts", group: "Navigate", label: "Scripts panel", run: rail("scripts") },
      {
        id: "open",
        group: "Actions",
        label: "Open binary…",
        hint: "Ctrl+O",
        run: () => void openBinary(),
      },
      {
        id: "close",
        group: "Actions",
        label: "Close binary",
        enabled: image.ready,
        run: () => void useDisasm.getState().unload(),
      },
      { id: "settings", group: "Actions", label: "Settings…", hint: "Ctrl+,", run: openSettings },
      {
        id: "inspector",
        group: "Actions",
        label: inspectorOpen ? "Hide inspector" : "Show inspector",
        run: () => setInspectorOpen(!inspectorOpen),
      },
      { id: "layout", group: "Actions", label: "Reset layout", run: resetLayout },
      {
        id: "reload",
        group: "Actions",
        label: "Reload interface",
        run: () => window.location.reload(),
      },
      ...kThemes.map((t): Action => ({
        id: `theme-${t.id}`,
        group: "Theme",
        label: `Theme: ${t.label}`,
        run: () => setTheme(t.id),
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
      label="Command palette"
      className="palette"
      overlayClassName="palette-scrim"
      contentClassName="palette-content"
    >
      <Command.Input
        className="palette-input"
        value={query}
        onValueChange={setQuery}
        placeholder="Type a command, function name or address…"
      />
      <Command.List className="palette-list">
        <Command.Empty className="palette-empty">No matches.</Command.Empty>

        {addr !== null && (
          <Command.Group heading="Go to address">
            {image.ready && (
              <Command.Item
                value={`goto-disasm ${query}`}
                onSelect={runAndClose(() => {
                  setWorkspaceTab("disassembly");
                  void useDisasm.getState().gotoAddress(addr);
                })}
              >
                Disassembly at {hex(addr, 1)}
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
                Memory at {hex(addr, 1)}
              </Command.Item>
            )}
          </Command.Group>
        )}

        {found.length > 0 && (
          <Command.Group heading="Functions">
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

        {(["Navigate", "Actions", "Theme"] as const).map((group) => (
          <Command.Group heading={group} key={group}>
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
