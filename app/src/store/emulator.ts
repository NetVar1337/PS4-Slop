// app/src/store/emulator.ts
// Unicorn emulation: one-shot runs, persistent sessions and the backward
// slice over a recorded trace. The engine owns the VM; this holds the last
// result the panel renders

import { create } from "zustand";
import { call, errorText } from "@/lib/rpc";

export type EmuRegs = Record<string, number>;

export type EmuTraceRow = { ip: number; text: string };
export type EmuFault = { ip: number; addr: number; access: string };
export type EmuMemory = { addr: number; len: number; requested: number; hex: string };
export type EmuTaintRange = { addr: number; len: number };
export type EmuTaintEvent = { ip: number; insn: string; kind: string; target: number };
export type EmuSyscall = {
  ip: number;
  num: number;
  ret: number;
  args: number[];
  name?: string;
  enosys?: boolean;
};
export type EmuApiCall = { ip: number; ret: number; name: string; args: number[] };

export type EmuRun = {
  ok: boolean;
  stopped_reason: string;
  instructions: number;
  arch: string;
  abi: string;
  regs: EmuRegs;
  trace?: EmuTraceRow[];
  trace_id?: number;
  fault?: EmuFault;
  note?: string;
  error?: string;
  memory?: EmuMemory[];
  taint_ranges?: EmuTaintRange[];
  taint_events?: EmuTaintEvent[];
  output_tainted?: boolean;
  syscalls?: EmuSyscall[];
  total_syscalls?: number;
  api_calls?: EmuApiCall[];
  total_api_calls?: number;
  stdout?: string;
  exited?: boolean;
  exit_code?: number;
  paged_in?: number;
};

export type EmuSession = {
  session: number;
  arch: string;
  instructions: number;
  regs: EmuRegs;
  snapshots: number;
  stopped_reason?: string;
  stdout?: string;
  exited?: boolean;
  exit_code?: number;
  pages?: number;
  restored?: boolean;
};

export type EmuSlice = {
  trace_id: number;
  count: number;
  instructions: EmuTraceRow[];
};

/** Everything emulate.run / session_create accept, minus the action. */
export type EmuParams = {
  hex?: string;
  arch?: string;
  file_addr?: number;
  target_addr?: number;
  code_len?: number;
  until?: number;
  count?: number;
  timeout_ms?: number;
  trace?: boolean;
  trace_max?: number;
  orbis_syscalls?: boolean;
  dump?: { addr: number; len: number }[];
  taint?: { addr: number; len: number }[];
};

export type SliceParams = {
  trace_id: number;
  reg?: string;
  addr?: number;
  len?: number;
  at?: number;
};

type EmulatorStore = {
  run: EmuRun | null;
  session: EmuSession | null;
  slice: EmuSlice | null;
  busy: string | null;
  error: string | null;
  emulate: (params: EmuParams) => Promise<void>;
  backSlice: (params: SliceParams) => Promise<void>;
  sessionCreate: (params: EmuParams) => Promise<void>;
  sessionStep: (count: number, runAll: boolean) => Promise<void>;
  sessionDestroy: () => Promise<void>;
  snapshot: () => Promise<void>;
  restore: () => Promise<void>;
  reset: () => void;
};

export const useEmulator = create<EmulatorStore>((set, get) => ({
  run: null,
  session: null,
  slice: null,
  busy: null,
  error: null,

  emulate: async (params) => {
    set({ busy: "run", error: null, slice: null });
    try {
      set({ run: await call<EmuRun>("emulate", "run", params) });
    } catch (e) {
      set({ run: null, error: errorText(e) });
    } finally {
      set({ busy: null });
    }
  },

  backSlice: async (params) => {
    set({ busy: "slice", error: null });
    try {
      set({ slice: await call<EmuSlice>("emulate", "slice", params) });
    } catch (e) {
      set({ slice: null, error: errorText(e) });
    } finally {
      set({ busy: null });
    }
  },

  sessionCreate: async (params) => {
    set({ busy: "session", error: null });
    try {
      set({ session: await call<EmuSession>("emulate", "session_create", params) });
    } catch (e) {
      set({ session: null, error: errorText(e) });
    } finally {
      set({ busy: null });
    }
  },

  sessionStep: async (count, runAll) => {
    const id = get().session?.session;
    if (id === undefined) return;
    set({ busy: "session", error: null });
    try {
      set({
        session: await call<EmuSession>("emulate", runAll ? "session_run" : "session_step", {
          session: id,
          count,
        }),
      });
    } catch (e) {
      set({ error: errorText(e) });
    } finally {
      set({ busy: null });
    }
  },

  sessionDestroy: async () => {
    const id = get().session?.session;
    if (id === undefined) return;
    set({ busy: "session", error: null });
    try {
      await call("emulate", "session_destroy", { session: id });
      set({ session: null });
    } catch (e) {
      set({ error: errorText(e) });
    } finally {
      set({ busy: null });
    }
  },

  snapshot: async () => {
    const id = get().session?.session;
    if (id === undefined) return;
    set({ busy: "session", error: null });
    try {
      set({ session: await call<EmuSession>("emulate", "snapshot", { session: id }) });
    } catch (e) {
      set({ error: errorText(e) });
    } finally {
      set({ busy: null });
    }
  },

  restore: async () => {
    const id = get().session?.session;
    if (id === undefined) return;
    set({ busy: "session", error: null });
    try {
      set({ session: await call<EmuSession>("emulate", "restore", { session: id }) });
    } catch (e) {
      set({ error: errorText(e) });
    } finally {
      set({ busy: null });
    }
  },

  reset: () => set({ run: null, session: null, slice: null, error: null, busy: null }),
}));
