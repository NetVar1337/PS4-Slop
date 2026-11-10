// app/src/store/targets.ts
// process list and attach flow, refresh is explicit and the target mirror
// arrives over events

import { create } from "zustand";
import { call } from "@/lib/rpc";

export type ProcessRow = {
  pid: number;
  name: string;
  arch: string;
  path?: string;
  elevation?: string;
};

export type ModuleRow = {
  name: string;
  base: number;
  size: number;
  path?: string;
};

export type Ps4Info = {
  endpoint: string;
  branding: string;
};

type TargetsStore = {
  processes: ProcessRow[];
  modules: ModuleRow[];
  filter: string;
  loading: boolean;
  error: string | null;
  ps4: Ps4Info | null;
  setFilter: (v: string) => void;
  refresh: () => Promise<void>;
  refreshModules: () => Promise<void>;
  attach: (pid: number) => Promise<boolean>;
  detach: () => Promise<void>;
  connectPs4: (host: string, port: number) => Promise<boolean>;
  disconnectPs4: () => Promise<void>;
};

export const useTargets = create<TargetsStore>((set, get) => ({
  processes: [],
  modules: [],
  filter: "",
  loading: false,
  error: null,
  ps4: null,

  setFilter: (filter) => set({ filter }),

  refresh: async () => {
    set({ loading: true, error: null });
    try {
      const res = await call<{ processes: ProcessRow[] }>("target", "list");
      const processes = [...(res.processes ?? [])].sort((a, b) =>
        a.name.localeCompare(b.name, undefined, { sensitivity: "base" }),
      );
      set({ processes, loading: false });
    } catch (e) {
      set({ loading: false, error: e instanceof Error ? e.message : String(e) });
    }
  },

  refreshModules: async () => {
    try {
      const res = await call<{ modules: ModuleRow[] }>("target", "modules");
      set({ modules: res.modules ?? [] });
    } catch {
      set({ modules: [] });
    }
  },

  attach: async (pid) => {
    try {
      await call("target", "attach", { pid });
      await get().refreshModules();
      return true;
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
      return false;
    }
  },

  detach: async () => {
    await call("target", "detach");
    set({ modules: [] });
  },

  connectPs4: async (host, port) => {
    try {
      const res = await call<{ endpoint?: string; branding?: string }>("target", "ps4_connect", {
        host,
        port,
      });
      set({ ps4: { endpoint: res.endpoint ?? `${host}:${port}`, branding: res.branding ?? "" } });
      await get().refresh();
      return true;
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
      return false;
    }
  },

  disconnectPs4: async () => {
    try {
      await call("target", "ps4_disconnect");
    } finally {
      set({ ps4: null });
      await get().refresh();
    }
  },
}));

/** Name-or-pid substring match, same rule as NameFilterMatch() in the ImGui view. */
export function matchesFilter(row: ProcessRow, filter: string): boolean {
  if (filter === "") return true;
  const needle = filter.toLowerCase();
  return row.name.toLowerCase().includes(needle) || String(row.pid) === needle;
}
