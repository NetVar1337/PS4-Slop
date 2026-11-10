// app/src/store/debugger.ts
// PS4 live-debug control surface over the ps4debug-NG wire: attach/detach,
// run control, breakpoints/watchpoints, registers, callstack, event feed.
// Every call maps to a debugger ps4_* MCP action

import { create } from "zustand";
import { call } from "@/lib/rpc";

export type Ps4Status = {
  backend: string;
  ps4_connected: boolean;
  debug_attached: boolean;
  debug_pid: number;
  pending_events: number;
};

export type Regs = Record<string, number>;

export type Frame = {
  ret_addr?: number;
  frame_ptr?: number;
  snippet?: string;
  scanned?: boolean;
};

export type Ps4Event = {
  lwpid: number;
  signal: number;
  status?: number;
  thread?: string;
  rip?: number;
  dr?: number[];
};

export type SlotEntry = { addr: number; index: number };

export type ScanHit = { addr: number; addr_hex?: string; value_hex?: string };

export type ScanState = {
  used: boolean;
  count?: number;
  base?: number;
  base_hex?: string;
  hits?: ScanHit[];
  truncated?: boolean;
  note?: string;
};

export type AppInfo = {
  pid: number;
  titleid?: string;
  contentid?: string;
  name?: string;
  app_ver?: string;
  running?: boolean;
};

const kIdle: Ps4Status = {
  backend: "user",
  ps4_connected: false,
  debug_attached: false,
  debug_pid: 0,
  pending_events: 0,
};

type DebuggerStore = {
  status: Ps4Status;
  regs: Regs | null;
  regsLwpid: number;
  frames: Frame[];
  events: Ps4Event[];
  breakpoints: SlotEntry[];
  watchpoints: SlotEntry[];
  scan: ScanState | null;
  app: AppInfo | null;
  error: string | null;
  busy: boolean;

  refresh: () => Promise<void>;
  attach: (pid: number) => Promise<void>;
  detach: () => Promise<void>;
  cont: () => Promise<void>;
  step: (lwpid: number) => Promise<void>;
  waitHalt: (timeoutMs: number) => Promise<void>;
  bpSet: (addr: number) => Promise<void>;
  bpClear: (addr: number) => Promise<void>;
  wpSet: (addr: number, type: number, len: number) => Promise<void>;
  wpClear: (addr: number) => Promise<void>;
  readRegs: (lwpid: number) => Promise<void>;
  readStack: (lwpid: number) => Promise<void>;
  scanFirst: (a: { addr: number; len: number; value_type: string; compare: string; value?: number | string; hex?: string }) => Promise<void>;
  scanRescan: (compare: string, value?: number | string) => Promise<void>;
  scanAob: (addr: number, len: number, pattern: string) => Promise<{ found?: boolean; addr?: number; addr_hex?: string } | null>;
  scanReset: () => Promise<void>;
  scanRefreshInternal: () => Promise<void>;
  notify: (msg: string) => Promise<void>;
  readApp: () => Promise<void>;
  dumpModule: (name: string, path: string, load: boolean) => Promise<void>;
  reset: () => void;
};

export const useDebugger = create<DebuggerStore>((set, get) => ({
  status: kIdle,
  regs: null,
  regsLwpid: 0,
  frames: [],
  events: [],
  breakpoints: [],
  watchpoints: [],
  scan: null,
  app: null,
  error: null,
  busy: false,

  refresh: async () => {
    try {
      const status = await call<Ps4Status>("debugger", "status");
      set({ status, error: null });
      if (status.ps4_connected) {
        void get().scanRefreshInternal();
        void get().readApp();
      }
      if (!status.ps4_connected || !status.debug_attached) {
        set({ regs: null, frames: [], breakpoints: [], watchpoints: [] });
        return;
      }
      const [bps, wps, evs] = await Promise.allSettled([
        call<{ breakpoints?: SlotEntry[] }>("debugger", "ps4_bp_list"),
        call<{ watchpoints?: SlotEntry[] }>("debugger", "ps4_watch_list"),
        call<{ events?: Ps4Event[] }>("debugger", "ps4_events", { max: 64, clear: true }),
      ]);
      const events =
        evs.status === "fulfilled" ? (evs.value.events ?? []) : [];
      set({
        breakpoints: bps.status === "fulfilled" ? (bps.value.breakpoints ?? []) : [],
        watchpoints: wps.status === "fulfilled" ? (wps.value.watchpoints ?? []) : [],
        events: [...events.reverse(), ...get().events].slice(0, 200),
      });
      // after a stop event, pull registers + callstack of the stopped thread
      const last = events[0];
      if (last !== undefined) {
        await get().readRegs(last.lwpid);
        await get().readStack(last.lwpid);
      }
    } catch (e) {
      set({ status: kIdle, error: e instanceof Error ? e.message : String(e) });
    }
  },

  attach: async (pid) => {
    set({ busy: true, error: null });
    try {
      await call("debugger", "ps4_attach", { pid });
      await get().refresh();
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    } finally {
      set({ busy: false });
    }
  },

  detach: async () => {
    await call("debugger", "ps4_detach").catch(() => undefined);
    set({ regs: null, frames: [], breakpoints: [], watchpoints: [] });
    await get().refresh();
  },

  cont: async () => {
    set({ busy: true });
    try {
      await call("debugger", "ps4_continue", { stop: 0 });
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    } finally {
      set({ busy: false });
    }
  },

  step: async (lwpid) => {
    set({ busy: true });
    try {
      await call("debugger", "ps4_step", { lwpid });
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    } finally {
      set({ busy: false });
    }
  },

  waitHalt: async (timeoutMs) => {
    set({ busy: true });
    try {
      await call("debugger", "ps4_wait", { timeout_ms: timeoutMs });
      await get().refresh();
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    } finally {
      set({ busy: false });
    }
  },

  bpSet: async (addr) => {
    try {
      await call("debugger", "ps4_bp_set", { addr });
      set({ error: null });
      await get().refresh();
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    }
  },

  bpClear: async (addr) => {
    await call("debugger", "ps4_bp_clear", { addr }).catch(() => undefined);
    set((s) => ({ breakpoints: s.breakpoints.filter((b) => b.addr !== addr) }));
  },

  wpSet: async (addr, type, len) => {
    try {
      await call("debugger", "ps4_watch_set", { addr, type, len });
      set({ error: null });
      await get().refresh();
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    }
  },

  wpClear: async (addr) => {
    await call("debugger", "ps4_watch_clear", { addr }).catch(() => undefined);
    set((s) => ({ watchpoints: s.watchpoints.filter((w) => w.addr !== addr) }));
  },

  readRegs: async (lwpid) => {
    try {
      const regs = await call<Regs>("debugger", "ps4_regs", { lwpid });
      set({ regs, regsLwpid: lwpid, error: null });
    } catch {
      set({ regs: null });
    }
  },

  readStack: async (lwpid) => {
    try {
      const stack = await call<{ frames?: Frame[] }>("debugger", "ps4_callstack", {
        lwpid,
        depth: 32,
      });
      set({ frames: stack.frames ?? [] });
    } catch {
      set({ frames: [] });
    }
  },

  scanFirst: async (a) => {
    set({ busy: true });
    try {
      await call("debugger", "ps4_scan", a);
      await get().scanRefreshInternal();
      set({ error: null });
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    } finally {
      set({ busy: false });
    }
  },

  scanRescan: async (compare, value) => {
    set({ busy: true });
    try {
      const args: Record<string, unknown> = { compare };
      if (value !== undefined) args.value = value;
      await call("debugger", "ps4_rescan", args);
      await get().scanRefreshInternal();
      set({ error: null });
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    } finally {
      set({ busy: false });
    }
  },

  scanAob: async (addr, len, pattern) => {
    set({ busy: true });
    try {
      const r = await call<{ found?: boolean; addr?: number; addr_hex?: string }>(
        "debugger", "ps4_scan_aob", { addr, len, pattern });
      set({ error: null });
      return r;
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
      return null;
    } finally {
      set({ busy: false });
    }
  },

  scanReset: async () => {
    await call("debugger", "ps4_scan_reset").catch(() => undefined);
    set({ scan: null });
  },

  scanRefreshInternal: async () => {
    try {
      const scan = await call<ScanState>("debugger", "ps4_scan_state");
      set({ scan });
    } catch {
      set({ scan: null });
    }
  },

  notify: async (msg) => {
    try {
      await call("debugger", "ps4_notify", { msg });
      set({ error: null });
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    }
  },

  readApp: async () => {
    try {
      const app = await call<AppInfo>("debugger", "ps4_app");
      set({ app, error: null });
    } catch {
      set({ app: null });
    }
  },

  dumpModule: async (name, path, load) => {
    set({ busy: true });
    try {
      await call("target", "ps4_dump_module", { name, path, load });
      set({ error: null });
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    } finally {
      set({ busy: false });
    }
  },

  reset: () =>
    set({
      status: kIdle,
      regs: null,
      regsLwpid: 0,
      frames: [],
      events: [],
      breakpoints: [],
      watchpoints: [],
      scan: null,
      app: null,
    }),
}));
