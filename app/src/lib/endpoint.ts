// app/src/lib/endpoint.ts
// where the engine is, the tauri command first, then the well known port for
// plain browser dev. Also the supervisor contract: deadline, status, restart
// and the crash / restart events (app/src-tauri/src/lib.rs)

import { setEndpoint, type Endpoint, health } from "./rpc";
import { invoke, isTauri as inTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

const kDefaultPort = 8765;

/** Matches the supervisor's UAC handshake wait; asked from it when available. */
export const kDefaultStartupDeadlineMs = 180_000;

export const isTauri = (): boolean => typeof window !== "undefined" && inTauri();

/**
 * Browser dev mode connects to whatever answers on 127.0.0.1:8765 with no
 * token and no handshake. Useful, but nothing proves that listener is ours, so
 * the shell shows a visible badge while it is in effect.
 */
export const isInsecureDev = (): boolean => !isTauri();

export async function resolveEndpoint(): Promise<Endpoint> {
  if (isTauri()) {
    // SDK IPC is available even when withGlobalTauri is disabled. Native
    // failures must not silently connect to an unrelated default-port engine.
    // While the supervisor is restarting a crashed engine this blocks until the
    // new one has handshaken (or rejects once the supervisor gives up).
    const ep = await invoke<Partial<Endpoint>>("engine_endpoint");
    const port = ep?.port;
    const token = ep?.token;
    if (
      typeof port !== "number" ||
      !Number.isInteger(port) ||
      port < 1 ||
      port > 65535 ||
      typeof token !== "string"
    ) {
      throw new Error("invalid engine endpoint from native bridge");
    }
    const resolved: Endpoint = { port, token };
    setEndpoint(resolved);
    return resolved;
  }

  // Browser dev mode: the well-known port, or VITE_SLOP_PORT / VITE_SLOP_TOKEN
  // from app/.env.local for an engine with a non-default port or a token
  const envPort = Number(import.meta.env.VITE_SLOP_PORT);
  const envToken = import.meta.env.VITE_SLOP_TOKEN;
  const fallback: Endpoint = {
    port: Number.isInteger(envPort) && envPort > 0 && envPort < 65536 ? envPort : kDefaultPort,
    token: typeof envToken === "string" ? envToken : "",
  };
  setEndpoint(fallback);
  return fallback;
}

/** How long the UI waits for /health; the supervisor owns the number. */
export async function startupDeadlineMs(): Promise<number> {
  if (!isTauri()) return kDefaultStartupDeadlineMs;
  try {
    const ms = await invoke<number>("startup_deadline_ms");
    return typeof ms === "number" && Number.isFinite(ms) && ms > 0 ? ms : kDefaultStartupDeadlineMs;
  } catch {
    return kDefaultStartupDeadlineMs;
  }
}

export type EnginePhase = "starting" | "running" | "restarting" | "failed" | "stopped";

export type EngineStatus = {
  phase: EnginePhase;
  generation: number;
  restarts: number;
  port: number | null;
  last_error: string | null;
  log_path: string;
};

/** Supervisor view of the engine process, null outside the Tauri shell. */
export async function engineStatus(): Promise<EngineStatus | null> {
  if (!isTauri()) return null;
  try {
    return await invoke<EngineStatus>("engine_status");
  } catch {
    return null;
  }
}

/** Re-arm the supervisor (after it gave up) or restart a running engine. */
export async function restartEngine(): Promise<void> {
  if (!isTauri()) return;
  await invoke("restart_engine");
}

export type EngineCrash = {
  reason: string;
  exit_code: number | null;
  restarts: number;
  /** null: the supervisor gave up after too many fast crashes. */
  retry_in_ms: number | null;
  log_path: string;
};

export type EngineLifecycle = {
  onCrashed: (crash: EngineCrash) => void;
  onRestarted: (info: { port: number; generation: number }) => void;
};

/** Subscribe to supervisor events. Resolves to an unsubscribe function. */
export async function onEngineLifecycle(handlers: EngineLifecycle): Promise<() => void> {
  if (!isTauri()) return () => undefined;
  const offCrash = await listen<EngineCrash>("engine-crashed", (e) =>
    handlers.onCrashed(e.payload),
  );
  const offRestart = await listen<{ port: number; generation: number }>("engine-restarted", (e) =>
    handlers.onRestarted(e.payload),
  );
  return () => {
    offCrash();
    offRestart();
  };
}

/** Poll /health until the engine answers or the deadline passes. */
export async function waitForEngine(timeoutMs = kDefaultStartupDeadlineMs): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await health()) return true;
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
}
