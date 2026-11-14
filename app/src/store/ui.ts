// app/src/store/ui.ts
// Shell-level UI state more than one component needs: dialogs, which left
// panel the rail selected, the active tabs and the splitter sizes. The layout
// half is persisted so a reload (or the next launch) comes back the same

import { create } from "zustand";

export type RailView = "targets" | "modules" | "scripts";
export type WorkspaceTab = "disassembly" | "decomp" | "strings" | "memory" | "debugger" | "pe";
export type OutputTab = "output" | "log";

/** Splitter-driven CSS variables and their defaults (px), see app.css. */
export const kLayoutVars = {
  "--left-w": 300,
  "--scan-w": 316,
  "--bottom-h": 260,
  "--right-w": 320,
} as const;
export type LayoutVar = keyof typeof kLayoutVars;

type Layout = {
  rail: RailView;
  workspaceTab: WorkspaceTab;
  outputTab: OutputTab;
  inspectorOpen: boolean;
  sizes: Partial<Record<LayoutVar, number>>;
};

const kStorageKey = "reverse-slop.layout";

const kDefaultLayout: Layout = {
  rail: "targets",
  workspaceTab: "disassembly",
  outputTab: "output",
  inspectorOpen: true,
  sizes: {},
};

const kRails: readonly RailView[] = ["targets", "modules", "scripts"];
const kWorkspaceTabs: readonly WorkspaceTab[] = [
  "disassembly",
  "decomp",
  "strings",
  "memory",
  "debugger",
  "pe",
];

/** Parse persisted layout defensively: a hand-edited or stale blob must not break boot. */
export function parseLayout(raw: string | null): Layout {
  if (raw === null) return kDefaultLayout;
  try {
    const v = JSON.parse(raw) as Partial<Layout>;
    const sizes: Partial<Record<LayoutVar, number>> = {};
    for (const key of Object.keys(kLayoutVars) as LayoutVar[]) {
      const n = v.sizes?.[key];
      if (typeof n === "number" && Number.isFinite(n) && n > 0 && n < 4000)
        sizes[key] = Math.round(n);
    }
    return {
      rail: kRails.includes(v.rail as RailView) ? (v.rail as RailView) : kDefaultLayout.rail,
      workspaceTab: kWorkspaceTabs.includes(v.workspaceTab as WorkspaceTab)
        ? (v.workspaceTab as WorkspaceTab)
        : kDefaultLayout.workspaceTab,
      outputTab: v.outputTab === "log" ? "log" : "output",
      inspectorOpen: v.inspectorOpen !== false,
      sizes,
    };
  } catch {
    return kDefaultLayout;
  }
}

function load(): Layout {
  try {
    return parseLayout(localStorage.getItem(kStorageKey));
  } catch {
    return kDefaultLayout;
  }
}

function save(layout: Layout): void {
  try {
    localStorage.setItem(kStorageKey, JSON.stringify(layout));
  } catch {
    // storage unavailable: layout just does not persist
  }
}

type UiStore = Layout & {
  settingsOpen: boolean;
  paletteOpen: boolean;
  setRail: (rail: RailView) => void;
  setWorkspaceTab: (tab: WorkspaceTab) => void;
  setOutputTab: (tab: OutputTab) => void;
  setInspectorOpen: (open: boolean) => void;
  setSize: (key: LayoutVar, px: number) => void;
  resetLayout: () => void;
  openSettings: () => void;
  closeSettings: () => void;
  setPaletteOpen: (open: boolean) => void;
};

export const useUi = create<UiStore>((set, get) => {
  const update = (patch: Partial<Layout>) => {
    set(patch);
    const s = get();
    save({
      rail: s.rail,
      workspaceTab: s.workspaceTab,
      outputTab: s.outputTab,
      inspectorOpen: s.inspectorOpen,
      sizes: s.sizes,
    });
  };

  return {
    ...load(),
    settingsOpen: false,
    paletteOpen: false,
    setRail: (rail) => update({ rail }),
    setWorkspaceTab: (workspaceTab) => update({ workspaceTab }),
    setOutputTab: (outputTab) => update({ outputTab }),
    setInspectorOpen: (inspectorOpen) => update({ inspectorOpen }),
    setSize: (key, px) => update({ sizes: { ...get().sizes, [key]: Math.round(px) } }),
    resetLayout: () => update({ ...kDefaultLayout, sizes: {} }),
    openSettings: () => set({ settingsOpen: true, paletteOpen: false }),
    closeSettings: () => set({ settingsOpen: false }),
    setPaletteOpen: (paletteOpen) => set({ paletteOpen }),
  };
});
