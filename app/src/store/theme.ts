// app/src/store/theme.ts
// theme pick, palettes are css, this only picks the live block and remembers

import { create } from "zustand";

export type ThemeName = "obsidian" | "nord-slop" | "blood-orange" | "daylight" | "high-contrast";

export const kThemes: readonly { id: ThemeName; label: string; scheme: "dark" | "light" }[] = [
  { id: "obsidian", label: "Obsidian", scheme: "dark" },
  { id: "nord-slop", label: "Nord-slop", scheme: "dark" },
  { id: "blood-orange", label: "Blood-orange", scheme: "dark" },
  { id: "daylight", label: "Daylight", scheme: "light" },
  { id: "high-contrast", label: "High contrast", scheme: "dark" },
];

const kStorageKey = "reverse-slop.theme";

function initial(): ThemeName {
  const saved = localStorage.getItem(kStorageKey);
  if (kThemes.some((t) => t.id === saved)) return saved as ThemeName;
  // First run: follow an explicit OS contrast / light preference
  if (window.matchMedia?.("(prefers-contrast: more)").matches) return "high-contrast";
  if (window.matchMedia?.("(prefers-color-scheme: light)").matches) return "daylight";
  return "obsidian";
}

function apply(name: ThemeName): void {
  const root = document.documentElement;
  root.setAttribute("data-theme", name);
  // Native form controls and scrollbars follow color-scheme
  root.style.colorScheme = kThemes.find((t) => t.id === name)?.scheme ?? "dark";
}

type ThemeStore = {
  theme: ThemeName;
  setTheme: (name: ThemeName) => void;
};

export const useTheme = create<ThemeStore>((set) => {
  const theme = initial();
  apply(theme);
  return {
    theme,
    setTheme: (name) => {
      apply(name);
      localStorage.setItem(kStorageKey, name);
      set({ theme: name });
    },
  };
});
