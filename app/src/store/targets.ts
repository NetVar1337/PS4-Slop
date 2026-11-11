// app/src/store/targets.ts
// process list and attach flow, refresh is explicit and the target mirror
// arrives over events

import { create } from "zustand";
import { call, errorText } from "@/lib/rpc";

export type ProcessRow = {
  pid: number;
  name: string;
  arch: string;
  path?: string;
  /** "user" | "admin" | "system" | "unknown" from target.list. */
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

const kShowHostKey = "reverse-slop.show-host-processes";

type TargetsStore = {
  processes: ProcessRow[];
  modules: ModuleRow[];
  filter: string;
  loading: boolean;
  error: string | null;
  ps4: Ps4Info | null;
  /**
   * The engine falls back to the local usermode backend when no console is
   * connected. Its process list is this PC's, which is not what a PS4
   * workbench should show by default; listing it is an explicit opt-in.
   */
  showHost: boolean;
  setFilter: (v: string) => void;
  setShowHost: (v: boolean) => void;
  refresh: () => Promise<void>;
  refreshModules: () => Promise<void>;
  /** Re-read the console endpoint after a backend change (MCP or UI). */
  syncPs4: (ps4Active: boolean) => Promise<void>;
  attach: (pid: number) => Promise<boolean>;
  detach: () => Promise<void>;
  connectPs4: (host: string, port: number) => Promise<boolean>;
  disconnectPs4: () => Promise<void>;
};

function initialShowHost(): boolean {
  try {
    return localStorage.getItem(kShowHostKey) === "1";
  } catch {
    return false;
  }
}

export const useTargets = create<TargetsStore>((set, get) => ({
  processes: [],
  modules: [],
  filter: "",
  loading: false,
  error: null,
  ps4: null,
  showHost: initialShowHost(),

  setFilter: (filter) => set({ filter }),

  setShowHost: (showHost) => {
    try {
      localStorage.setItem(kShowHostKey, showHost ? "1" : "0");
    } catch {
      // storage unavailable: the choice just does not persist
    }
    set({ showHost });
    if (showHost) void get().refresh();
    else if (get().ps4 === null) set({ processes: [] });
  },

  refresh: async () => {
    set({ loading: true, error: null });
    try {
      const res = await call<{ processes: ProcessRow[] }>("target", "list");
      const processes = [...(res.processes ?? [])].sort((a, b) =>
        a.name.localeCompare(b.name, undefined, { sensitivity: "base" }),
      );
      set({ processes, loading: false });
    } catch (e) {
      set({ loading: false, error: errorText(e) });
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

  syncPs4: async (ps4Active) => {
    if (!ps4Active) {
      set({ ps4: null });
      return;
    }
    try {
      const res = await call<{ ps4?: { endpoint?: string; branding?: string } }>(
        "target",
        "status",
      );
      if (res.ps4 !== undefined)
        set({ ps4: { endpoint: res.ps4.endpoint ?? "", branding: res.ps4.branding ?? "" } });
    } catch {
      // the badge alone still says PS4; the banner just lacks the endpoint
    }
  },

  attach: async (pid) => {
    try {
      await call("target", "attach", { pid });
      await get().refreshModules();
      return true;
    } catch (e) {
      set({ error: errorText(e) });
      return false;
    }
  },

  detach: async () => {
    try {
      await call("target", "detach");
    } catch (e) {
      set({ error: errorText(e) });
    } finally {
      set({ modules: [] });
    }
  },

  connectPs4: async (host, port) => {
    set({ error: null });
    try {
      const res = await call<{ endpoint?: string; branding?: string }>("target", "ps4_connect", {
        host,
        port,
      });
      set({ ps4: { endpoint: res.endpoint ?? `${host}:${port}`, branding: res.branding ?? "" } });
      await get().refresh();
      return true;
    } catch (e) {
      set({ error: errorText(e) });
      return false;
    }
  },

  disconnectPs4: async () => {
    try {
      await call("target", "ps4_disconnect");
    } catch (e) {
      set({ error: errorText(e) });
    } finally {
      // The engine is back on the local backend: its list is this PC's
      // processes, shown only when the user opted in
      set({ ps4: null, modules: [] });
      if (get().showHost) await get().refresh();
      else set({ processes: [] });
    }
  },
}));

/** Name-or-pid substring match, same rule as NameFilterMatch() in the ImGui view. */
export function matchesFilter(row: ProcessRow, filter: string): boolean {
  if (filter === "") return true;
  const needle = filter.toLowerCase();
  return row.name.toLowerCase().includes(needle) || String(row.pid) === needle;
}
