// app/src/i18n/index.ts
// Typed message catalog. `t()` reads the active language outside React;
// `useT()` subscribes a component so a language switch re-renders it. The
// language is a local preference (localStorage) because it must apply on the
// first paint, before the engine answers app.settings_get.

import { useCallback } from "react";
import { create } from "zustand";
import { de } from "@/i18n/de";
import { en, type Key } from "@/i18n/en";

export type { Key };

export type Language = "en" | "de";

export type Params = Record<string, string | number>;

export const kLanguages: readonly { id: Language; label: string }[] = [
  { id: "en", label: "English" },
  { id: "de", label: "Deutsch" },
];

const kCatalog: Record<Language, Record<Key, string>> = { en, de };

const kStorageKey = "reverse-slop.language";

function initial(): Language {
  const saved = localStorage.getItem(kStorageKey);
  return saved === "en" || saved === "de" ? saved : "en";
}

function apply(language: Language): void {
  // Screen readers and hyphenation follow the document language
  document.documentElement.lang = language;
}

/** Interpolate `{name}` placeholders; an unknown one stays verbatim. */
export function translate(language: Language, key: Key, params?: Params): string {
  const text = kCatalog[language][key];
  if (params === undefined) return text;
  return text.replace(/\{(\w+)\}/g, (match, name: string) =>
    params[name] === undefined ? match : String(params[name]),
  );
}

type I18nStore = {
  language: Language;
  setLanguage: (language: Language) => void;
};

export const useI18n = create<I18nStore>((set) => {
  const language = initial();
  apply(language);
  return {
    language,
    setLanguage: (next) => {
      apply(next);
      localStorage.setItem(kStorageKey, next);
      set({ language: next });
    },
  };
});

/** Message in the active language, for code outside a render. */
export function t(key: Key, params?: Params): string {
  return translate(useI18n.getState().language, key, params);
}

/** `t` bound to the active language; the caller re-renders on a switch. */
export function useT(): (key: Key, params?: Params) => string {
  const language = useI18n((s) => s.language);
  return useCallback((key: Key, params?: Params) => translate(language, key, params), [language]);
}
