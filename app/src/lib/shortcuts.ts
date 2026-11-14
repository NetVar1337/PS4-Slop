// app/src/lib/shortcuts.ts
// Global keyboard shortcuts. One window-level keydown listener so every
// shortcut advertised in a menu or tooltip actually does something

import { useEffect } from "react";
import type { Key } from "@/i18n/en";
import { openBinary } from "@/lib/openBinary";
import { useUi, type WorkspaceTab } from "@/store/ui";

export type Shortcut = { keys: string; labelKey: Key };

/** What the Help menu lists; keep in sync with `handle` below. */
export const kShortcuts: readonly Shortcut[] = [
  { keys: "Ctrl+K", labelKey: "shortcut.commandPalette" },
  { keys: "Ctrl+Shift+P", labelKey: "shortcut.commandPalette" },
  { keys: "Ctrl+G", labelKey: "shortcut.goto" },
  { keys: "Ctrl+O", labelKey: "shortcut.openBinary" },
  { keys: "Ctrl+,", labelKey: "shortcut.settings" },
  { keys: "Ctrl+1…5", labelKey: "shortcut.tabs" },
  { keys: "Ctrl+Alt+I", labelKey: "shortcut.inspector" },
];

const kTabByDigit: Record<string, WorkspaceTab> = {
  "1": "disassembly",
  "2": "strings",
  "3": "memory",
  "4": "debugger",
  "5": "pe",
};

/** Returns true when the event was a shortcut and has been handled. */
export function handleShortcut(e: KeyboardEvent): boolean {
  if (!(e.ctrlKey || e.metaKey)) return false;
  const ui = useUi.getState();
  const key = e.key.toLowerCase();

  if ((key === "k" && !e.shiftKey) || (key === "p" && e.shiftKey) || (key === "g" && !e.shiftKey)) {
    ui.setPaletteOpen(!ui.paletteOpen);
    return true;
  }
  if (e.altKey && key === "i") {
    ui.setInspectorOpen(!ui.inspectorOpen);
    return true;
  }
  if (e.altKey || e.shiftKey) return false;
  if (key === "o") {
    void openBinary();
    return true;
  }
  if (key === ",") {
    ui.openSettings();
    return true;
  }
  const tab = kTabByDigit[e.key];
  if (tab !== undefined) {
    ui.setWorkspaceTab(tab);
    return true;
  }
  return false;
}

/** Install the global listener for the lifetime of the calling component. */
export function useShortcuts(): void {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.repeat) return;
      if (handleShortcut(e)) e.preventDefault();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
}
