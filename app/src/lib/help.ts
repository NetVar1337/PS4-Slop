// app/src/lib/help.ts
// In-app help search: the docs index `tools/gen_help_index.mjs` writes
// (`npm run help:index` -> src/generated/help-index.json), the ranking the
// command palette uses, and the URL a result opens. The index is a build
// artifact, so it is loaded lazily and a missing one just means no results

import { isTauri } from "@/lib/endpoint";
import { openUrl } from "@/lib/shell";

export type HelpEntry = {
  title: string;
  anchor: string;
  section: string;
  text: string;
  url: string;
  path: string;
};

export type HelpIndex = {
  generated: string;
  source: string;
  count: number;
  entries: HelpEntry[];
};

/** mdBook site base (book.toml `site-url`); browser dev opens the page relative. */
const kDocsSite = "https://netvar1337.github.io/SlopStation/";

// glob, not a static import: the file is generated, and an unbuilt tree (fresh
// clone, `npx vitest` before `npm run help:index`) must still boot
const kIndexModules = import.meta.glob<HelpIndex>("../generated/help-index.json", {
  import: "default",
});

let pending: Promise<HelpEntry[]> | null = null;

/** The generated index entries, loaded once per session. Never hits the network. */
export function loadHelpIndex(): Promise<HelpEntry[]> {
  const load = Object.values(kIndexModules)[0];
  if (load === undefined) return Promise.resolve([]);
  pending ??= load().then(
    (index) => index.entries,
    () => [],
  );
  return pending;
}

/**
 * Rank entries against a query: every whitespace-separated term must match, and
 * a title hit outranks a section hit, which outranks body text. Ties keep the
 * book's reading order.
 */
export function searchHelp(entries: HelpEntry[], query: string, limit = 20): HelpEntry[] {
  const terms = query
    .toLowerCase()
    .split(/\s+/)
    .filter((t) => t !== "");
  if (terms.length === 0) return [];
  const hits: { entry: HelpEntry; score: number }[] = [];
  for (const entry of entries) {
    const title = entry.title.toLowerCase();
    const section = entry.section.toLowerCase();
    const body = `${entry.text} ${entry.path}`.toLowerCase();
    let score = 0;
    let all = true;
    for (const term of terms) {
      if (title.includes(term)) score += 4;
      else if (section.includes(term)) score += 3;
      else if (body.includes(term)) score += 1;
      else {
        all = false;
        break;
      }
    }
    if (all) hits.push({ entry, score });
  }
  return hits
    .sort((a, b) => b.score - a.score)
    .slice(0, limit)
    .map((h) => h.entry);
}

/** Where a result opens: the published site inside the shell, the page itself in dev. */
export function helpHref(url: string): string {
  return isTauri() ? kDocsSite + url : url;
}

/** Open a docs result in the default browser (new tab in browser dev). */
export async function openHelp(url: string): Promise<void> {
  await openUrl(helpHref(url));
}
