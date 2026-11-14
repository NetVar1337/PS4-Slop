// app/src/store/theme.ts
// theme pick, palettes are css, this only picks the live block and remembers.
// The theme editor writes the same custom properties inline on <html>, and
// named custom themes are a base palette plus those overrides

import { create } from "zustand";
import type { Key } from "@/i18n/en";

export type ThemeName = "obsidian" | "nord-slop" | "blood-orange" | "daylight" | "high-contrast";

export const kThemes: readonly { id: ThemeName; labelKey: Key; scheme: "dark" | "light" }[] = [
  { id: "obsidian", labelKey: "theme.obsidian", scheme: "dark" },
  { id: "nord-slop", labelKey: "theme.nordSlop", scheme: "dark" },
  { id: "blood-orange", labelKey: "theme.bloodOrange", scheme: "dark" },
  { id: "daylight", labelKey: "theme.daylight", scheme: "light" },
  { id: "high-contrast", labelKey: "theme.highContrast", scheme: "dark" },
];

/** Palette tokens the theme editor exposes. All are opaque hex in every
 *  palette, so a native color input can round-trip them. */
export const kThemeTokens = [
  { id: "--bg-0", labelKey: "token.bg0" },
  { id: "--bg-1", labelKey: "token.bg1" },
  { id: "--bg-2", labelKey: "token.bg2" },
  { id: "--border", labelKey: "token.border" },
  { id: "--border-soft", labelKey: "token.borderSoft" },
  { id: "--text", labelKey: "token.text" },
  { id: "--text-dim", labelKey: "token.textDim" },
  { id: "--text-faint", labelKey: "token.textFaint" },
  { id: "--accent", labelKey: "token.accent" },
  { id: "--success", labelKey: "token.success" },
  { id: "--warning", labelKey: "token.warning" },
  { id: "--danger", labelKey: "token.danger" },
] as const satisfies readonly { id: string; labelKey: Key }[];

export type ThemeToken = (typeof kThemeTokens)[number]["id"];

/** Overrides for a subset of the palette tokens. */
export type ThemeColors = Partial<Record<ThemeToken, string>>;

export type CustomTheme = { name: string; base: ThemeName; colors: ThemeColors };

const kStorageKey = "reverse-slop.theme";
const kCustomKey = "reverse-slop.custom-themes";
const kHex = /^#[0-9a-f]{6}$/i;

function initialTheme(): ThemeName {
  const saved = localStorage.getItem(kStorageKey);
  if (kThemes.some((t) => t.id === saved)) return saved as ThemeName;
  // First run: follow an explicit OS contrast / light preference
  if (window.matchMedia?.("(prefers-contrast: more)").matches) return "high-contrast";
  if (window.matchMedia?.("(prefers-color-scheme: light)").matches) return "daylight";
  return "obsidian";
}

function validColors(input: unknown): ThemeColors {
  const out: ThemeColors = {};
  if (typeof input !== "object" || input === null) return out;
  for (const { id } of kThemeTokens) {
    const value = (input as Record<string, unknown>)[id];
    if (typeof value === "string" && kHex.test(value)) out[id] = value;
  }
  return out;
}

function readCustom(): { themes: CustomTheme[]; active: string | null } {
  try {
    const raw = JSON.parse(localStorage.getItem(kCustomKey) ?? "{}") as {
      themes?: unknown;
      active?: unknown;
    };
    const themes = Array.isArray(raw.themes)
      ? raw.themes.flatMap((t): CustomTheme[] => {
          const item = t as Partial<CustomTheme> | null;
          if (typeof item?.name !== "string" || item.name === "") return [];
          const base = kThemes.some((b) => b.id === item.base) ? (item.base as ThemeName) : null;
          return base === null ? [] : [{ name: item.name, base, colors: validColors(item.colors) }];
        })
      : [];
    const active =
      typeof raw.active === "string" && themes.some((t) => t.name === raw.active)
        ? raw.active
        : null;
    return { themes, active };
  } catch {
    return { themes: [], active: null };
  }
}

function persist(theme: ThemeName, themes: CustomTheme[], active: string | null): void {
  localStorage.setItem(kStorageKey, theme);
  localStorage.setItem(kCustomKey, JSON.stringify({ themes, active }));
}

function applyBase(name: ThemeName): void {
  const root = document.documentElement;
  root.setAttribute("data-theme", name);
  // Native form controls and scrollbars follow color-scheme
  root.style.colorScheme = kThemes.find((t) => t.id === name)?.scheme ?? "dark";
}

/** Write (or clear) the palette overrides on <html>. */
function applyColors(colors: ThemeColors | null): void {
  const root = document.documentElement;
  for (const { id } of kThemeTokens) {
    const value = colors?.[id];
    if (value === undefined) root.style.removeProperty(id);
    else root.style.setProperty(id, value);
  }
}

type ThemeStore = {
  theme: ThemeName;
  customThemes: CustomTheme[];
  /** Name of the applied custom theme, or null for a plain base palette. */
  activeCustom: string | null;
  setTheme: (name: ThemeName) => void;
  /** Live preview while editing; null restores the active theme. */
  previewColors: (colors: ThemeColors | null) => void;
  /** Create or replace a named theme; returns it, or null for an empty name. */
  saveCustom: (name: string, base: ThemeName, colors: ThemeColors) => CustomTheme | null;
  applyCustom: (name: string) => void;
  deleteCustom: (name: string) => void;
  /** JSON for one custom theme, or null when it does not exist. */
  exportCustom: (name: string) => string | null;
  /** Parse and store a theme JSON; returns it, or null when invalid. */
  importCustom: (json: string) => CustomTheme | null;
};

export const useTheme = create<ThemeStore>((set, get) => {
  const { themes, active } = readCustom();
  const theme = initialTheme();
  const activeTheme = themes.find((t) => t.name === active);
  applyBase(theme);
  applyColors(activeTheme?.colors ?? null);

  return {
    theme,
    customThemes: themes,
    activeCustom: activeTheme?.name ?? null,

    setTheme: (name) => {
      applyBase(name);
      applyColors(null);
      persist(name, get().customThemes, null);
      set({ theme: name, activeCustom: null });
    },

    previewColors: (colors) => {
      const current = get().customThemes.find((t) => t.name === get().activeCustom);
      applyColors(colors ?? current?.colors ?? null);
    },

    saveCustom: (name, base, colors) => {
      const trimmed = name.trim();
      if (trimmed === "") return null;
      const saved: CustomTheme = { name: trimmed, base, colors: validColors(colors) };
      const themes = [...get().customThemes.filter((t) => t.name !== trimmed), saved];
      persist(get().theme, themes, get().activeCustom);
      set({ customThemes: themes });
      return saved;
    },

    applyCustom: (name) => {
      const custom = get().customThemes.find((t) => t.name === name);
      if (custom === undefined) return;
      applyBase(custom.base);
      applyColors(custom.colors);
      persist(custom.base, get().customThemes, name);
      set({ theme: custom.base, activeCustom: name });
    },

    deleteCustom: (name) => {
      const themes = get().customThemes.filter((t) => t.name !== name);
      const active = get().activeCustom === name ? null : get().activeCustom;
      if (active === null) applyColors(null);
      persist(get().theme, themes, active);
      set({ customThemes: themes, activeCustom: active });
    },

    exportCustom: (name) => {
      const custom = get().customThemes.find((t) => t.name === name);
      return custom === undefined ? null : JSON.stringify(custom, null, 2);
    },

    importCustom: (json) => {
      let raw: { name?: unknown; base?: unknown; colors?: unknown };
      try {
        raw = JSON.parse(json) as { name?: unknown; base?: unknown; colors?: unknown };
      } catch {
        return null;
      }
      if (typeof raw.name !== "string" || raw.name.trim() === "") return null;
      if (!kThemes.some((t) => t.id === raw.base)) return null;
      const imported: CustomTheme = {
        name: raw.name.trim(),
        base: raw.base as ThemeName,
        colors: validColors(raw.colors),
      };
      const themes = [...get().customThemes.filter((t) => t.name !== imported.name), imported];
      persist(get().theme, themes, get().activeCustom);
      set({ customThemes: themes });
      return imported;
    },
  };
});
