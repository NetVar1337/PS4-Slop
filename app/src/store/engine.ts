// app/src/store/engine.ts
// connection, boot progress and the state the status bar mirrors, all fed by
// events, nothing polls. Engine events also fan out to the stores that mirror
// engine-side state (image, targets, modules), so a change made by an agent
// over MCP shows up here without the user doing anything

import { create } from "zustand";
import * as events from "@/lib/events";
import { call, errorText } from "@/lib/rpc";
import {
  engineStatus,
  isTauri,
  onEngineLifecycle,
  resolveEndpoint,
  restartEngine,
  startupDeadlineMs,
  waitForEngine,
  type EngineCrash,
} from "@/lib/endpoint";
import { useDebugger } from "@/store/debugger";
import { useDisasm } from "@/store/disasm";
import { useMemory } from "@/store/memory";
import { usePe } from "@/store/pe";
import { useTargets } from "@/store/targets";

export type BootStage = {
  stage: number;
  total: number;
  label: string;
  done: boolean;
};

export type TargetState = { attached: boolean; pid?: number; name?: string };

export type HypeState = {
  has_image: boolean;
  image: string;
  present: boolean;
  ready: boolean;
  running: boolean;
  progress: number;
  error: string;
};

export type BackendState = { badge: string; ps4: boolean };

type EngineStore = {
  connected: boolean;
  boot: BootStage;
  /** Stage labels as the engine reported them, by stage index. */
  stageLabels: string[];
  backend: BackendState;
  target: TargetState;
  hype: HypeState;
  quitting: string | null;
  startupError: string | null;
  /** Last supervisor crash report; cleared once the engine is back. */
  crash: EngineCrash | null;
  start: () => Promise<void>;
  /** Start over after a failure, re-arming the supervisor if it gave up. */
  retry: () => Promise<void>;
  dismissError: () => void;
};

/**
 * Engine boot stages (src/core/infra/lifecycle.hpp, kStageCount = 5). Labels
 * are only the fallback: the engine sends its own with every boot.stage.
 */
export const kStageLabels = [
  "runtime pool & job queue",
  "process / target services",
  "settings & session store",
  "mcp server",
  "interface",
];

const kInitialBoot: BootStage = {
  stage: 0,
  total: kStageLabels.length,
  label: "connecting",
  done: false,
};
const kInitialHype: HypeState = {
  has_image: false,
  image: "",
  present: false,
  ready: false,
  running: false,
  progress: 0,
  error: "",
};

/** The engine badge is "PS4"/"user"; never trust its case. */
export function backendFrom(badge: string, ps4?: boolean): BackendState {
  return { badge, ps4: typeof ps4 === "boolean" ? ps4 : badge.toLowerCase() === "ps4" };
}

let starting: Promise<void> | undefined;
let subscribed = false;

/** Mirror a backend switch into the target-side stores. */
function syncBackend(backend: BackendState): void {
  const targets = useTargets.getState();
  void targets.syncPs4(backend.ps4);
  if (backend.ps4 || targets.showHost) void targets.refresh();
  else useTargets.setState({ processes: [] });
  if (!backend.ps4) useDebugger.getState().reset();
}

/** Mirror an attach/detach (from the UI or an agent) into modules/memory. */
function syncTarget(prev: TargetState, next: TargetState): void {
  const targets = useTargets.getState();
  if (next.attached) void targets.refreshModules();
  else useTargets.setState({ modules: [] });
  if (prev.pid !== next.pid || prev.attached !== next.attached) useMemory.getState().reset();
}

export const useEngine = create<EngineStore>((set, get) => {
  const refreshStatus = async () => {
    try {
      const status = await call<{ backend: string; ps4?: boolean; target: TargetState }>(
        "app",
        "status",
      );
      const backend = backendFrom(status.backend, status.ps4);
      const prevTarget = get().target;
      const total = get().boot.total;
      set({
        backend,
        target: status.target,
        boot: { stage: total, total, label: "ready", done: true },
        startupError: null,
        crash: null,
      });
      // State changed while the stream was down is only visible in the
      // snapshot: re-seed every mirror from it
      syncBackend(backend);
      syncTarget(prevTarget, status.target);
      void useDisasm.getState().refreshLoaded();
    } catch (error) {
      set({ startupError: errorText(error) });
    }
  };

  const subscribe = () => {
    // Boot/backend events can precede subscription. Snapshot after each stream
    // open, not before the engine accepts connections, and again on reconnect.
    events.onConnectionChange((connected) => {
      set({ connected });
      if (connected) void refreshStatus();
    });
    events.on("boot.stage", (boot) =>
      set((s) => {
        const stageLabels = [...s.stageLabels];
        if (!boot.done && boot.stage >= 0 && boot.stage < 64) stageLabels[boot.stage] = boot.label;
        return { boot, stageLabels };
      }),
    );
    events.on("backend.changed", (data) => {
      const backend = backendFrom(data.badge, data.ps4);
      set({ backend });
      syncBackend(backend);
    });
    events.on("target.changed", (target) => {
      const prev = get().target;
      set({ target });
      syncTarget(prev, target);
      // An attach can start/stop a process (spawn, crash): refresh the list
      // the Targets panel shows, when it shows one
      const targets = useTargets.getState();
      if (get().backend.ps4 || targets.showHost) void targets.refresh();
    });
    events.on("hype.progress", (hype) => {
      const prev = get().hype;
      set({ hype });
      // Let the disassembly store refresh its function list when background
      // analysis completes (the fast native index queried at load time misses
      // hyperion-only functions, e.g. every method of a .NET/IL image).
      useDisasm.getState().onHypeProgress(hype.ready, hype.has_image);
      // An engine without image.changed still moves hype.image on a load
      if (prev.has_image !== hype.has_image || prev.image !== hype.image)
        void useDisasm.getState().refreshLoaded();
    });
    events.on("image.changed", ({ loaded }) => {
      usePe.getState().reset();
      useDisasm.getState().onImageChanged(loaded);
    });
    events.on("app.quitting", ({ reason }) => set({ quitting: reason }));

    if (isTauri()) {
      // A restarted engine may listen on a new port: ask the supervisor where
      // it is before every reconnect (this blocks while a restart is underway)
      events.setReconnectHook(async () => {
        await resolveEndpoint();
      });
      void onEngineLifecycle({
        onCrashed: (crash) => set({ crash, connected: false }),
        onRestarted: () => {
          set({ crash: null });
          void resolveEndpoint()
            .then(() => events.connect())
            .catch((e: unknown) => set({ startupError: errorText(e) }));
        },
      }).catch(() => undefined);
    }
  };

  return {
    connected: false,
    boot: kInitialBoot,
    stageLabels: [],
    backend: { badge: "user", ps4: false },
    target: { attached: false },
    hype: kInitialHype,
    quitting: null,
    startupError: null,
    crash: null,

    start: () =>
      (starting ??= (async () => {
        set({ startupError: null });
        await resolveEndpoint();
        // the endpoint can resolve before the engine accepts connections; gate the
        // event stream on /health so the first connect does not race the listener
        const deadline = await startupDeadlineMs();
        if (!(await waitForEngine(deadline)))
          throw new Error(`engine did not answer /health within ${Math.round(deadline / 1000)}s`);
        if (!subscribed) {
          subscribed = true;
          subscribe();
        }
        events.connect();
      })().catch((error: unknown) => {
        starting = undefined;
        set({ startupError: errorText(error) });
      })),

    retry: async () => {
      starting = undefined;
      set({ startupError: null });
      try {
        const st = await engineStatus();
        if (st !== null && (st.phase === "failed" || st.phase === "stopped")) await restartEngine();
      } catch (e) {
        set({ startupError: errorText(e) });
        return;
      }
      set({ crash: null });
      if (subscribed) {
        // Booted before: the stream just needs a fresh endpoint + connection
        try {
          await resolveEndpoint();
          events.connect();
        } catch (e) {
          set({ startupError: errorText(e) });
        }
        return;
      }
      await get().start();
    },

    dismissError: () => set({ startupError: null }),
  };
});
