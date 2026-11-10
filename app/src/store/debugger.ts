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
  error: null,
  busy: false,

  refresh: async () => {
    try {
      const status = await call<Ps4Status>("debugger", "status");
      set({ status, error: null });
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

  reset: () =>
    set({
      status: kIdle,
      regs: null,
      regsLwpid: 0,
      frames: [],
      events: [],
      breakpoints: [],
      watchpoints: [],
    }),
}));
