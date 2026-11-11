// app/src/store/disasm.ts
// the shared analysis session, a binary opened here is the binary an agent sees

import { create } from "zustand";
import type { ImageFormat } from "@/lib/events";
import { defaultFunctionName, hex } from "@/lib/format";
import { call, errorText } from "@/lib/rpc";

export { hex };
export type { ImageFormat };

export type FunctionRow = {
  va: number;
  size: number;
  symbol?: string;
  name?: string;
  blocks?: number;
  callconv?: string;
  loops?: number;
  noreturn?: boolean;
};

export type Insn = {
  va: number;
  len: number;
  text: string;
  flow: string;
  target?: number;
  rip_rel?: number;
};

export type ImageArch = "x86" | "x64" | "arm" | "arm64";

export type LoadedImage = {
  ready: boolean;
  // Optional for engines predating Mach-O / ELF support.
  format?: ImageFormat;
  arch?: ImageArch;
  encrypted?: boolean;
  warning?: string;
  bundle?: {
    app_dir: string;
    executable: string;
    executable_path: string;
    bundle_id: string;
    version: string;
    build: string;
    min_os: string;
  };
  name?: string;
  path?: string;
  base?: number;
  entry_va?: number;
  functions?: number;
  strings?: number;
  hype?: { available: boolean; ready?: boolean; progress?: number; error?: string };
};

export type StringHit = { va: number; text: string; utf16: boolean };

/** Rows per `disasm.functions` page; the list fetches pages as they scroll in. */
export const kFnPageSize = 512;
/** Typing in the filter box waits this long before asking the engine. */
export const kFilterDebounceMs = 150;

type FunctionsReply = {
  functions?: FunctionRow[];
  total?: number;
  matched?: number;
  returned?: number;
};

type DisasmStore = {
  image: LoadedImage;
  /** Every function the index knows. */
  total: number;
  /** Functions matching the current filter (== total when unfiltered). */
  matched: number;
  /** Loaded pages of the filtered list, keyed by page index. */
  pages: Record<number, FunctionRow[]>;
  /** Bumped on every filter/image change; stale page replies are dropped. */
  query: number;
  selected: number | null;
  /** The selected row, kept even when its page scrolls out of the cache. */
  selectedFn: FunctionRow | null;
  insns: Insn[];
  /** True when the listing ran past the function bounds (unreliable size). */
  linear: boolean;
  filter: string;
  busy: boolean;
  error: string | null;
  /** Last hyperion-ready state seen on the event stream, for edge detection. */
  hypeReady: boolean;

  setFilter: (v: string) => void;
  /** Re-read the image summary; `force` treats it as a new binary even if the path matches. */
  refreshLoaded: (force?: boolean) => Promise<void>;
  loadFile: (path: string) => Promise<void>;
  unload: () => Promise<void>;
  refreshFunctions: () => Promise<void>;
  /** Make sure rows [start, end] of the filtered list are loaded. */
  ensureRows: (start: number, end: number) => void;
  /** Server-side name/address search, for the command palette. */
  searchFunctions: (text: string, limit: number) => Promise<FunctionRow[]>;
  /** Fed by the engine's `hype.progress` stream (see store/engine.ts). */
  onHypeProgress: (ready: boolean, hasImage: boolean) => void;
  /** Fed by the engine's `image.changed` stream. */
  onImageChanged: (loaded: boolean) => void;
  select: (va: number, row?: FunctionRow) => Promise<void>;
  gotoAddress: (va: number) => Promise<void>;
  rename: (va: number, name: string) => Promise<void>;

  strings: StringHit[];
  stringsTruncated: boolean;
  loadStrings: (minChars: number, includeExec: boolean) => Promise<void>;
};

/** Display name: user symbol, then engine name, then the canonical sub_ label. */
export function functionLabel(fn: FunctionRow): string {
  return fn.symbol ?? fn.name ?? defaultFunctionName(fn.va);
}

/** Row `index` of the filtered list, or undefined while its page loads. */
export function rowAt(s: Pick<DisasmStore, "pages">, index: number): FunctionRow | undefined {
  return s.pages[Math.floor(index / kFnPageSize)]?.[index % kFnPageSize];
}

function loadedRows(s: Pick<DisasmStore, "pages">): FunctionRow[] {
  return Object.values(s.pages).flat();
}

/** Identity of a loaded image; a change means a different binary is open. */
function imageKey(image: LoadedImage): string {
  return image.ready ? `${image.path ?? image.name ?? ""}|${image.base ?? 0}` : "";
}

function matchesLocally(fn: FunctionRow, filter: string): boolean {
  if (filter === "") return true;
  const needle = filter.toLowerCase();
  const bare = needle.replace(/^0x/, "");
  return (
    functionLabel(fn).toLowerCase().includes(needle) ||
    (bare !== "" && fn.va.toString(16).includes(bare))
  );
}

const kEmptyFunctions = {
  total: 0,
  matched: 0,
  pages: {} as Record<number, FunctionRow[]>,
  selected: null,
  selectedFn: null,
  insns: [] as Insn[],
  linear: false,
};

const inflight = new Set<string>();
let filterTimer: ReturnType<typeof setTimeout> | undefined;

export const useDisasm = create<DisasmStore>((set, get) => {
  const fetchPage = async (page: number, query: number): Promise<void> => {
    const key = `${query}:${page}`;
    if (inflight.has(key)) return;
    inflight.add(key);
    try {
      const filter = get().filter;
      const res = await call<FunctionsReply>("disasm", "functions", {
        limit: kFnPageSize,
        offset: page * kFnPageSize,
        ...(filter !== "" ? { filter } : {}),
      });
      if (get().query !== query) return;
      const rows = res.functions ?? [];
      if (res.matched === undefined) {
        // Engine without server-side paging: the reply is the whole list.
        const filtered = rows.filter((f) => matchesLocally(f, filter));
        const pages: Record<number, FunctionRow[]> = {};
        for (let i = 0; i < filtered.length; i += kFnPageSize)
          pages[i / kFnPageSize] = filtered.slice(i, i + kFnPageSize);
        set({ pages, total: res.total ?? rows.length, matched: filtered.length });
        return;
      }
      set((s) => ({
        pages: { ...s.pages, [page]: rows },
        total: res.total ?? s.total,
        matched: res.matched ?? s.matched,
      }));
    } catch (e) {
      if (get().query === query) set({ error: errorText(e) });
    } finally {
      inflight.delete(key);
    }
  };

  return {
    image: { ready: false },
    ...kEmptyFunctions,
    query: 0,
    filter: "",
    busy: false,
    error: null,
    hypeReady: false,

    setFilter: (filter) => {
      set({ filter });
      clearTimeout(filterTimer);
      filterTimer = setTimeout(() => {
        void get().refreshFunctions();
      }, kFilterDebounceMs);
    },

    refreshLoaded: async (force = false) => {
      try {
        const image = await call<LoadedImage>("disasm", "loaded");
        const changed = force || imageKey(image) !== imageKey(get().image);
        set({ image });
        if (!image.ready) {
          set({ ...kEmptyFunctions, query: get().query + 1, strings: [] });
          return;
        }
        if (changed) {
          // A different binary (possibly opened by an agent over MCP): the old
          // selection and listing belong to the previous image
          set({ ...kEmptyFunctions, strings: [] });
          await get().refreshFunctions();
        }
      } catch (e) {
        set({ error: errorText(e) });
      }
    },

    loadFile: async (path) => {
      // A fresh image restarts analysis; clear the ready edge so its completion
      // re-pulls the function list (see onHypeProgress).
      set({ busy: true, error: null, hypeReady: false });
      try {
        await call("disasm", "load", { path }, { timeoutMs: 120_000 });
        await get().refreshLoaded();
      } catch (e) {
        set({ error: errorText(e) });
      } finally {
        set({ busy: false });
      }
    },

    unload: async () => {
      try {
        await call("disasm", "unload");
      } catch (e) {
        set({ error: errorText(e) });
        return;
      }
      set({
        image: { ready: false },
        ...kEmptyFunctions,
        query: get().query + 1,
        hypeReady: false,
        strings: [],
      });
    },

    onHypeProgress: (ready, hasImage) => {
      // The engine streams background-analysis status. At load time the function
      // list is seeded from the fast native index, which for a .NET/IL image
      // holds only the entry stub — every managed method surfaces only once
      // hyperion analysis finishes. Re-pull the listing (and the loaded summary)
      // on the not-ready -> ready edge so the panel isn't stuck on that stale,
      // native-only view.
      const wasReady = get().hypeReady;
      set({ hypeReady: ready });
      if (ready && !wasReady && hasImage && get().image.ready) {
        void get().refreshLoaded();
        void get().refreshFunctions();
      }
    },

    onImageChanged: (loaded) => {
      if (!loaded) {
        set({
          image: { ready: false },
          ...kEmptyFunctions,
          query: get().query + 1,
          hypeReady: false,
          strings: [],
        });
        return;
      }
      // the engine says the image changed, even when it is the same path again
      void get().refreshLoaded(true);
    },

    refreshFunctions: async () => {
      const query = get().query + 1;
      set({ query, pages: {}, busy: true, error: null });
      try {
        await fetchPage(0, query);
        if (get().query !== query) return;
        // Land on the entry point (or the first function) so the pane is never
        // blank after a load
        const s = get();
        if (s.selected === null && s.filter === "") {
          const first = rowAt(s, 0);
          const entry = s.image.entry_va;
          const atEntry = loadedRows(s).find((f) => f.va === entry);
          if (atEntry !== undefined) await get().select(atEntry.va, atEntry);
          else if (entry !== undefined && entry !== 0) await get().select(entry);
          else if (first !== undefined) await get().select(first.va, first);
        }
      } finally {
        if (get().query === query) set({ busy: false });
      }
    },

    ensureRows: (start, end) => {
      const s = get();
      if (s.matched === 0) return;
      const last = Math.min(end, s.matched - 1);
      for (
        let p = Math.floor(Math.max(0, start) / kFnPageSize);
        p <= Math.floor(last / kFnPageSize);
        p++
      ) {
        if (s.pages[p] === undefined) void fetchPage(p, s.query);
      }
    },

    searchFunctions: async (text, limit) => {
      const res = await call<FunctionsReply>("disasm", "functions", {
        limit,
        offset: 0,
        ...(text !== "" ? { filter: text } : {}),
      });
      const rows = res.functions ?? [];
      return res.matched === undefined
        ? rows.filter((f) => matchesLocally(f, text)).slice(0, limit)
        : rows;
    },

    select: async (va, row) => {
      const s = get();
      const fn =
        row ??
        loadedRows(s).find((f) => f.va === va) ??
        (s.selectedFn?.va === va ? s.selectedFn : null);
      set({ selected: va, selectedFn: fn });
      // Ask for more than the function should need, then trim: the engine
      // disassembles linearly and will happily run past the end into the next
      // function, which made the header's byte count disagree with the listing
      const size = fn?.size ?? 0;
      const count = Math.min(4000, Math.max(64, Math.ceil(size / 2)));
      try {
        const res = await call<{ instructions: Insn[] }>("disasm", "disassemble", {
          addr: va,
          count,
        });
        if (get().selected !== va) return;
        const all = res.instructions ?? [];
        const inRange = size > 0 ? all.filter((i) => i.va < va + size) : all;
        // A function index can under-report size (tail merging, jump tables). If
        // trimming leaves almost nothing, show the linear sweep instead of a
        // misleadingly empty function
        const clamped = inRange.length >= 4;
        set({ insns: clamped ? inRange : all, linear: !clamped });
      } catch (e) {
        if (get().selected === va) set({ insns: [], error: errorText(e) });
      }
    },

    gotoAddress: async (va) => {
      // Prefer the enclosing function so the listing keeps its context
      const fn = loadedRows(get()).find((f) => va >= f.va && va < f.va + f.size);
      await get().select(fn ? fn.va : va, fn);
    },

    rename: async (va, name) => {
      try {
        await call("disasm", "symbol_set", { addr: va, name });
      } catch (e) {
        set({ error: errorText(e) });
        return;
      }
      const patch = (f: FunctionRow): FunctionRow =>
        f.va === va ? { ...f, symbol: name || undefined } : f;
      set((s) => {
        const pages: Record<number, FunctionRow[]> = {};
        for (const [k, rows] of Object.entries(s.pages)) pages[Number(k)] = rows.map(patch);
        return {
          pages,
          selectedFn: s.selectedFn !== null ? patch(s.selectedFn) : null,
          error: null,
        };
      });
    },

    strings: [],
    stringsTruncated: false,

    loadStrings: async (minChars, includeExec) => {
      set({ busy: true });
      try {
        const res = await call<{ strings: StringHit[]; truncated: boolean }>(
          "disasm",
          "strings",
          { min_chars: minChars, include_exec: includeExec, limit: 10000 },
          { timeoutMs: 120_000 },
        );
        set({ strings: res.strings ?? [], stringsTruncated: res.truncated === true });
      } catch (e) {
        set({ strings: [], error: errorText(e) });
      } finally {
        set({ busy: false });
      }
    },
  };
});
