// app/src/store/watch.ts
// watchlist mirror, the list lives in core and the app tick services it, a
// watch added over mcp shows up here and vice versa

import { create } from "zustand";
import * as events from "@/lib/events";
import { call, errorText } from "@/lib/rpc";
import type { WatchEntry, WatchValue } from "@/lib/events";

type WatchStore = {
  entries: WatchEntry[];
  values: Map<number, WatchValue>;
  attached: boolean;
  /** Last failed action, shown above the watchlist until the next success. */
  error: string | null;
  attach: () => () => void;
  load: () => Promise<void>;
  add: (addr: number, width: string, label?: string) => Promise<boolean>;
  remove: (id: number) => Promise<boolean>;
  setFreeze: (id: number, freeze: boolean) => Promise<boolean>;
  poke: (id: number, value: string) => Promise<boolean>;
  clear: () => Promise<boolean>;
};

export const useWatch = create<WatchStore>((set) => {
  /** Every watch action reports through `error` instead of rejecting. */
  const run = async (fn: () => Promise<unknown>): Promise<boolean> => {
    try {
      await fn();
      set({ error: null });
      return true;
    } catch (e) {
      set({ error: errorText(e) });
      return false;
    }
  };

  return {
    entries: [],
    values: new Map(),
    attached: false,
    error: null,

    attach: () => {
      const offList = events.on("watch.list", ({ entries }) => set({ entries }));
      const offValues = events.on("watch.values", ({ attached, values }) =>
        set({ attached, values: new Map(values.map((v) => [v.id, v])) }),
      );
      return () => {
        offList();
        offValues();
      };
    },

    load: async () => {
      await run(async () => {
        const res = await call<{ entries: WatchEntry[]; values: WatchValue[] }>(
          "memory",
          "watch_list",
        );
        set({
          entries: res.entries ?? [],
          values: new Map((res.values ?? []).map((v) => [v.id, v])),
        });
      });
    },

    add: (addr, width, label) =>
      run(() => call("memory", "watch_add", { addr, width, ...(label ? { label } : {}) })),

    remove: (id) => run(() => call("memory", "watch_remove", { id })),

    setFreeze: (id, freeze) => run(() => call("memory", "watch_set", { id, freeze })),

    // Text form so f32/f64 and signed widths round-trip through the same
    // parse_value_text() the scanner's value box used
    poke: (id, value) => run(() => call("memory", "watch_set", { id, value })),

    clear: () => run(() => call("memory", "watch_clear")),
  };
});
