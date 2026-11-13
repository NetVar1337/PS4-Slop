// app/src/store/updater.ts
// Tauri updater bridge: check on boot, download + install, relaunch. Browser
// dev has no updater plugin, so every entry point is a no-op there.

import { create } from "zustand";
import type { DownloadEvent } from "@tauri-apps/plugin-updater";
import { isTauri } from "@/lib/endpoint";

export type UpdatePhase = "idle" | "checking" | "available" | "downloading" | "ready" | "error";

type PendingUpdate = {
  version: string;
  body: string;
  downloadAndInstall: (onEvent: (event: DownloadEvent) => void) => Promise<void>;
};

type UpdaterStore = {
  phase: UpdatePhase;
  version: string;
  notes: string;
  /** 0..1 while downloading, -1 when the server sent no length. */
  progress: number;
  error: string | null;
  dismissed: boolean;
  check: (manual?: boolean) => Promise<void>;
  install: () => Promise<void>;
  dismiss: () => void;
};

let pending: PendingUpdate | null = null;

async function plugins() {
  const [updater, process] = await Promise.all([
    import("@tauri-apps/plugin-updater"),
    import("@tauri-apps/plugin-process"),
  ]);
  return { check: updater.check, relaunch: process.relaunch };
}

export const useUpdater = create<UpdaterStore>((set, get) => ({
  phase: "idle",
  version: "",
  notes: "",
  progress: 0,
  error: null,
  dismissed: false,

  check: async (manual = false) => {
    if (!isTauri()) return;
    const phase = get().phase;
    if (phase === "checking" || phase === "downloading" || phase === "ready") return;
    set({ phase: "checking", error: null, dismissed: false });
    try {
      const { check } = await plugins();
      const update = await check();
      if (update === null) {
        set({ phase: "idle", version: "", notes: "", progress: 0 });
        return;
      }
      pending = {
        version: update.version,
        body: update.body ?? "",
        downloadAndInstall: (onEvent) => update.downloadAndInstall(onEvent),
      };
      set({ phase: "available", version: update.version, notes: update.body ?? "" });
      void manual;
    } catch (e) {
      // An offline launch must not nag; only a manual check surfaces the error.
      if (manual) {
        set({ phase: "error", error: e instanceof Error ? e.message : String(e) });
      } else {
        set({ phase: "idle", error: null });
      }
    }
  },

  install: async () => {
    if (!isTauri() || pending === null) return;
    set({ phase: "downloading", progress: 0, error: null });
    let total = 0;
    let done = 0;
    try {
      await pending.downloadAndInstall((event) => {
        if (event.event === "Started") {
          total = event.data.contentLength ?? 0;
        } else if (event.event === "Progress") {
          done += event.data.chunkLength;
          set({ progress: total > 0 ? Math.min(done / total, 1) : -1 });
        } else if (event.event === "Finished") {
          set({ phase: "ready", progress: 1 });
        }
      });
      // NSIS installs and exits on its own; relaunch is the explicit path for
      // installers that return control to us.
      const { relaunch } = await plugins();
      await relaunch();
    } catch (e) {
      set({ phase: "error", error: e instanceof Error ? e.message : String(e) });
    }
  },

  dismiss: () => set({ dismissed: true }),
}));
