// app/src/store/settings.ts
// Engine-side settings (settings.json in the engine's app-data dir), read and
// written over /api app.settings_get / app.settings_set. The MCP token is
// never returned by the engine, only whether one is set; rotating it goes
// through app.rotate_token

import { create } from "zustand";
import { call, errorText, getEndpoint, setEndpoint } from "@/lib/rpc";

export type EngineSettings = Record<string, unknown> & {
  mcp_token?: "set" | "unset" | string;
  script_unsafe?: boolean;
  web_allow_private?: boolean;
  web_allowlist?: string[];
  proxy_token?: string;
};

type RotateReply = { rotated: boolean; clients_updated?: string[]; token?: string };

type SettingsStore = {
  settings: EngineSettings | null;
  loading: boolean;
  error: string | null;
  /** Keys whose change only applies after an engine restart. */
  restartRequired: string[];
  /** A freshly rotated token, shown once so the user can copy it. */
  revealedToken: string | null;
  clientsUpdated: string[];
  load: () => Promise<void>;
  setValue: (key: string, value: unknown) => Promise<boolean>;
  rotateToken: () => Promise<boolean>;
  hideToken: () => void;
};

export const useSettings = create<SettingsStore>((set, get) => ({
  settings: null,
  loading: false,
  error: null,
  restartRequired: [],
  revealedToken: null,
  clientsUpdated: [],

  load: async () => {
    set({ loading: true });
    try {
      const settings = await call<EngineSettings>("app", "settings_get");
      set({ settings, error: null });
    } catch (e) {
      set({ error: errorText(e) });
    } finally {
      set({ loading: false });
    }
  },

  setValue: async (key, value) => {
    try {
      const res = await call<{ ok?: boolean; value?: unknown; restart_required?: boolean }>(
        "app",
        "settings_set",
        { key, value },
      );
      set((s) => ({
        settings: { ...(s.settings ?? {}), [key]: res.value !== undefined ? res.value : value },
        error: null,
        restartRequired:
          res.restart_required === true && !s.restartRequired.includes(key)
            ? [...s.restartRequired, key]
            : s.restartRequired,
      }));
      return true;
    } catch (e) {
      set({ error: errorText(e) });
      return false;
    }
  },

  rotateToken: async () => {
    try {
      const res = await call<RotateReply>("app", "rotate_token");
      // The engine includes the new value only when this request authenticated
      // with the old mcp_token, i.e. this UI was using it as its own bearer:
      // switch to it, or the next request is refused
      if (typeof res.token === "string" && res.token !== "") {
        if (getEndpoint().token !== "") setEndpoint({ ...getEndpoint(), token: res.token });
      }
      set({
        revealedToken: typeof res.token === "string" && res.token !== "" ? res.token : null,
        clientsUpdated: res.clients_updated ?? [],
        error: null,
        settings: { ...(get().settings ?? {}), mcp_token: "set" },
      });
      return res.rotated !== false;
    } catch (e) {
      set({ error: errorText(e) });
      return false;
    }
  },

  hideToken: () => set({ revealedToken: null }),
}));
