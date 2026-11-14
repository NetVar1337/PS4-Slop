// app/src/store/debugger.ts
// PS4 live-debug control surface over the ps4debug-NG wire: attach/detach,
// run control, breakpoints/watchpoints, registers, callstack, event feed.
// Every call maps to a debugger ps4_* MCP action

import { create } from "zustand";
import * as events from "@/lib/events";
import { batch, batchData, call, errorText } from "@/lib/rpc";

export type Ps4Status = {
  backend: string;
  ps4_connected: boolean;
  debug_attached: boolean;
  debug_pid: number;
  pending_events: number;
  /** Console firmware, e.g. "11.00" (debugger.ps4_status). */
  fw?: string;
  /** Stop events the engine discarded because its queue was full. */
  events_dropped?: number;
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

/** `debugger.ps4_wait`: the stop event with its register context inline. */
export type WaitResult = Partial<Ps4Event> &
  Partial<Regs> & { halted: boolean; pending?: number; timeout_ms?: number };

/** A breakpoint/watchpoint slot; the engine adds the rule it keeps for it. */
export type SlotEntry = {
  addr: number;
  index: number;
  armed?: boolean;
  /** MCP session (or "ui") that armed the slot. */
  owner?: string;
  /** Stop only on the Nth hit (0 = every hit). */
  hits?: number;
  hit_mode?: string;
  /** Hits the engine has seen since the rule was armed. */
  count?: number;
  log?: string;
  condition?: string;
};

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

export const kRegOrder = [
  "rip",
  "rsp",
  "rbp",
  "rax",
  "rbx",
  "rcx",
  "rdx",
  "rsi",
  "rdi",
  "r8",
  "r9",
  "r10",
  "r11",
  "r12",
  "r13",
  "r14",
  "r15",
  "flags",
] as const;

const kIdle: Ps4Status = {
  backend: "user",
  ps4_connected: false,
  debug_attached: false,
  debug_pid: 0,
  pending_events: 0,
};

const kMaxEvents = 200;

/** Register file out of an event / wait reply that carries the context inline. */
export function regsFrom(source: Record<string, unknown>): Regs | null {
  const regs: Regs = {};
  for (const name of kRegOrder) {
    const v = source[name];
    if (typeof v !== "number") return null;
    regs[name] = v;
  }
  return regs;
}

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
  /** Result line of the last wait ("halted lwp 101 sig 5" / "no stop in 5s"). */
  waitNote: string | null;
  /** Log-breakpoint lines pushed over /events, newest first. */
  logs: string[];
  busy: boolean;

  /** Subscribe to the pushed debugger events; returns the unsubscribe. */
  connectStream: () => () => void;
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
  scanFirst: (a: {
    addr: number;
    len: number;
    value_type: string;
    compare: string;
    value?: number | string;
    hex?: string;
  }) => Promise<void>;
  scanRescan: (compare: string, value?: number | string) => Promise<void>;
  scanAob: (
    addr: number,
    len: number,
    pattern: string,
  ) => Promise<{ found?: boolean; addr?: number; addr_hex?: string } | null>;
  scanReset: () => Promise<void>;
  scanRefreshInternal: () => Promise<void>;
  notify: (msg: string) => Promise<void>;
  readApp: () => Promise<void>;
  dumpModule: (name: string, path: string, load: boolean) => Promise<void>;
  reset: () => void;
};

export const useDebugger = create<DebuggerStore>((set, get) => {
  /** Run a mutating action with busy/error bookkeeping. */
  const guarded = async (fn: () => Promise<void>, busy = true): Promise<void> => {
    if (busy) set({ busy: true });
    try {
      await fn();
      set({ error: null });
    } catch (e) {
      set({ error: errorText(e) });
    } finally {
      if (busy) set({ busy: false });
    }
  };

  return {
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
    waitNote: null,
    logs: [],
    busy: false,

    connectStream: () => {
      // the engine pushes every console stop over /events; the slow poll in
      // the view is only a fallback for a dropped stream
      const offStop = events.on("debugger.stop", (e) => {
        const ev: Ps4Event = {
          lwpid: e.lwpid,
          signal: e.signal,
          ...(e.status !== undefined ? { status: e.status } : {}),
          ...(e.thread !== undefined ? { thread: e.thread } : {}),
          ...(e.rip !== undefined ? { rip: e.rip } : {}),
        };
        const regs = regsFrom(e as unknown as Record<string, unknown>);
        set((s) => ({
          events: [ev, ...s.events].slice(0, kMaxEvents),
          ...(regs !== null ? { regs, regsLwpid: ev.lwpid } : {}),
          waitNote: `stopped lwp ${ev.lwpid}${ev.thread ? ` (${ev.thread})` : ""} · signal ${ev.signal}`,
        }));
        if (regs === null) void get().readRegs(ev.lwpid);
        void get().readStack(ev.lwpid);
      });
      const offState = events.on("debugger.state", (e) => {
        set((s) => ({
          status: { ...s.status, debug_attached: e.attached, debug_pid: e.pid },
          ...(e.attached
            ? {}
            : { regs: null, frames: [], breakpoints: [], watchpoints: [], waitNote: null }),
        }));
      });
      const offLog = events.on("debugger.log", (e) => {
        set((s) => ({ logs: [e.text, ...s.logs].slice(0, 50) }));
      });
      return () => {
        offStop();
        offState();
        offLog();
      };
    },

    refresh: async () => {
      // One round trip for the whole view instead of six stacked ones;
      // per-request failures (not connected, not attached) come back inline
      try {
        const [st, ps4, bps, wps, evs, scan, app] = await batch([
          { tool: "debugger", action: "status" },
          { tool: "debugger", action: "ps4_status" },
          { tool: "debugger", action: "ps4_bp_list" },
          { tool: "debugger", action: "ps4_watch_list" },
          { tool: "debugger", action: "ps4_events", params: { max: 64, clear: true } },
          { tool: "debugger", action: "ps4_scan_state" },
          { tool: "debugger", action: "ps4_app" },
        ]);
        const base = batchData<Ps4Status>(st);
        if (base === undefined) throw new Error("debugger.status failed");
        const extra = batchData<{ fw?: string; events_dropped?: number }>(ps4);
        const status: Ps4Status = {
          ...base,
          ...(extra?.fw !== undefined ? { fw: extra.fw } : {}),
          ...(extra?.events_dropped !== undefined ? { events_dropped: extra.events_dropped } : {}),
        };
        set({
          status,
          error: null,
          scan: status.ps4_connected ? (batchData<ScanState>(scan) ?? null) : null,
          app: status.ps4_connected ? (batchData<AppInfo>(app) ?? null) : null,
        });
        if (!status.ps4_connected || !status.debug_attached) {
          set({ regs: null, frames: [], breakpoints: [], watchpoints: [] });
          return;
        }
        // ps4_events returns oldest first; the feed shows newest first
        const fresh = [...(batchData<{ events?: Ps4Event[] }>(evs)?.events ?? [])].reverse();
        set((s) => ({
          breakpoints: batchData<{ breakpoints?: SlotEntry[] }>(bps)?.breakpoints ?? [],
          watchpoints: batchData<{ watchpoints?: SlotEntry[] }>(wps)?.watchpoints ?? [],
          events: [...fresh, ...s.events].slice(0, kMaxEvents),
        }));
        // after a stop event, pull registers + callstack of the stopped thread
        const last = fresh[0];
        if (last !== undefined) {
          const inline = regsFrom(last as unknown as Record<string, unknown>);
          if (inline !== null) set({ regs: inline, regsLwpid: last.lwpid });
          else await get().readRegs(last.lwpid);
          await get().readStack(last.lwpid);
        }
      } catch (e) {
        set({ status: kIdle, error: errorText(e) });
      }
    },

    attach: (pid) =>
      guarded(async () => {
        await call("debugger", "ps4_attach", { pid });
        await get().refresh();
      }),

    detach: async () => {
      try {
        await call("debugger", "ps4_detach");
      } catch (e) {
        set({ error: errorText(e) });
      } finally {
        set({ regs: null, frames: [], breakpoints: [], watchpoints: [], waitNote: null });
        await get().refresh();
      }
    },

    cont: () =>
      guarded(async () => {
        await call("debugger", "ps4_continue", { stop: 0 });
        set({ regs: null, frames: [], waitNote: null });
      }),

    step: (lwpid) =>
      guarded(async () => {
        await call("debugger", "ps4_step", { lwpid });
      }),

    waitHalt: (timeoutMs) =>
      guarded(async () => {
        // ps4_wait pops the stop event off the engine queue, so the result IS
        // the halt: render it directly. A refresh afterwards would drain an
        // already-empty queue and never show the registers
        const res = await call<WaitResult>(
          "debugger",
          "ps4_wait",
          { timeout_ms: timeoutMs },
          { timeoutMs: timeoutMs + 15_000 },
        );
        set((s) => ({
          status: { ...s.status, pending_events: res.pending ?? s.status.pending_events },
        }));
        if (!res.halted || res.lwpid === undefined) {
          set({ waitNote: `no stop event within ${Math.round(timeoutMs / 1000)}s` });
          return;
        }
        const ev: Ps4Event = {
          lwpid: res.lwpid,
          signal: res.signal ?? 0,
          ...(res.status !== undefined ? { status: res.status } : {}),
          ...(res.thread !== undefined ? { thread: res.thread } : {}),
          ...(res.rip !== undefined ? { rip: res.rip } : {}),
          ...(res.dr !== undefined ? { dr: res.dr } : {}),
        };
        const regs = regsFrom(res as Record<string, unknown>);
        set((s) => ({
          events: [ev, ...s.events].slice(0, kMaxEvents),
          regs,
          regsLwpid: ev.lwpid,
          waitNote: `halted lwp ${ev.lwpid}${ev.thread ? ` (${ev.thread})` : ""} · signal ${ev.signal}`,
        }));
        if (regs === null) await get().readRegs(ev.lwpid);
        await get().readStack(ev.lwpid);
      }),

    bpSet: (addr) =>
      guarded(async () => {
        await call("debugger", "ps4_bp_set", { addr });
        await get().refresh();
      }, false),

    bpClear: (addr) =>
      guarded(async () => {
        await call("debugger", "ps4_bp_clear", { addr });
        set((s) => ({ breakpoints: s.breakpoints.filter((b) => b.addr !== addr) }));
      }, false),

    wpSet: (addr, type, len) =>
      guarded(async () => {
        await call("debugger", "ps4_watch_set", { addr, type, len });
        await get().refresh();
      }, false),

    wpClear: (addr) =>
      guarded(async () => {
        await call("debugger", "ps4_watch_clear", { addr });
        set((s) => ({ watchpoints: s.watchpoints.filter((w) => w.addr !== addr) }));
      }, false),

    readRegs: async (lwpid) => {
      try {
        const regs = await call<Regs>("debugger", "ps4_regs", { lwpid });
        set({ regs, regsLwpid: lwpid, error: null });
      } catch (e) {
        set({ regs: null, error: errorText(e) });
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

    scanFirst: (a) =>
      guarded(async () => {
        await call("debugger", "ps4_scan", a, { timeoutMs: 300_000 });
        await get().scanRefreshInternal();
      }),

    scanRescan: (compare, value) =>
      guarded(async () => {
        const args: Record<string, unknown> = { compare };
        if (value !== undefined) args.value = value;
        await call("debugger", "ps4_rescan", args, { timeoutMs: 300_000 });
        await get().scanRefreshInternal();
      }),

    scanAob: async (addr, len, pattern) => {
      set({ busy: true });
      try {
        const r = await call<{ found?: boolean; addr?: number; addr_hex?: string }>(
          "debugger",
          "ps4_scan_aob",
          { addr, len, pattern },
          { timeoutMs: 300_000 },
        );
        set({ error: null });
        return r;
      } catch (e) {
        set({ error: errorText(e) });
        return null;
      } finally {
        set({ busy: false });
      }
    },

    scanReset: () =>
      guarded(async () => {
        await call("debugger", "ps4_scan_reset");
        set({ scan: null });
      }, false),

    scanRefreshInternal: async () => {
      try {
        const scan = await call<ScanState>("debugger", "ps4_scan_state");
        set({ scan });
      } catch {
        set({ scan: null });
      }
    },

    notify: (msg) =>
      guarded(async () => {
        await call("debugger", "ps4_notify", { msg });
      }, false),

    readApp: async () => {
      try {
        const app = await call<AppInfo>("debugger", "ps4_app");
        set({ app });
      } catch {
        set({ app: null });
      }
    },

    dumpModule: (name, path, load) =>
      guarded(async () => {
        await call("target", "ps4_dump_module", { name, path, load }, { timeoutMs: 600_000 });
      }),

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
        waitNote: null,
        logs: [],
        error: null,
      }),
  };
});
