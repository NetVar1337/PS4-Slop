// app/src/lib/events.ts
// eventsource wrapper over the engine stream, the engine pushes state
// changes and this hands them to subscribers

import { baseUrl, call, getEndpoint } from "./rpc";

export type ImageFormat = "pe" | "macho" | "elf" | "self";

export type EngineEvent =
  | { type: "hello"; data: { output_revision: number } }
  | { type: "output"; data: { seq: number; ms: number; text: string } }
  | { type: "output.cleared"; data: Record<string, never> }
  | {
      type: "boot.stage";
      data: { stage: number; total: number; label: string; done: boolean };
    }
  | {
      type: "target.changed";
      data: { attached: boolean; pid?: number; name?: string };
    }
  | { type: "backend.changed"; data: { badge: string; ps4: boolean } }
  | {
      type: "hype.progress";
      data: {
        has_image: boolean;
        image: string;
        present: boolean;
        ready: boolean;
        running: boolean;
        progress: number;
        error: string;
      };
    }
  | { type: "image.changed"; data: { loaded: boolean; name?: string; format?: ImageFormat } }
  | { type: "watch.list"; data: { entries: WatchEntry[] } }
  | { type: "watch.values"; data: { attached: boolean; values: WatchValue[] } }
  | { type: "app.quitting"; data: { reason: string } }
  | { type: "server.stopping"; data: Record<string, never> };

export type WatchEntry = {
  id: number;
  addr: number;
  width: string;
  label: string;
  freeze: boolean;
  frozen_bits: number;
  frozen_text: string;
  /** Per-entry service rate in ms (default 100). */
  interval_ms?: number;
};

export type WatchValue = {
  id: number;
  addr: number;
  ok: boolean;
  held: boolean;
  bits: number;
  text: string;
};

export type EventName = EngineEvent["type"];
type Handler = (data: unknown) => void;

const kEventNames: EventName[] = [
  "hello",
  "output",
  "output.cleared",
  "boot.stage",
  "target.changed",
  "backend.changed",
  "hype.progress",
  "image.changed",
  "watch.list",
  "watch.values",
  "app.quitting",
  "server.stopping",
];

/** Reconnect delay grows on repeated failures so a dead engine is not hammered. */
const kRetryMinMs = 1_000;
const kRetryMaxMs = 8_000;

const handlers = new Map<EventName, Set<Handler>>();
let source: EventSource | null = null;
let retry: ReturnType<typeof setTimeout> | null = null;
let retryDelay = kRetryMinMs;
let isOpen = false;
/** Bumped by every connect/disconnect so stale async work can tell it lost. */
let generation = 0;
let reconnectHook: (() => Promise<void>) | null = null;
const statusHandlers = new Set<(open: boolean) => void>();

function emit(name: EventName, raw: string): void {
  const set = handlers.get(name);
  if (!set || set.size === 0) return;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return;
  }
  for (const fn of set) fn(parsed);
}

/** Subscribe to one event name. Returns an unsubscribe function. */
export function on<K extends EventName>(
  name: K,
  fn: (data: Extract<EngineEvent, { type: K }>["data"]) => void,
): () => void {
  const set = handlers.get(name) ?? new Set<Handler>();
  set.add(fn as Handler);
  handlers.set(name, set);
  return () => {
    set.delete(fn as Handler);
  };
}

/** Notified when the stream opens or drops, for the status-bar indicator. */
export function onConnectionChange(fn: (open: boolean) => void): () => void {
  statusHandlers.add(fn);
  return () => {
    statusHandlers.delete(fn);
  };
}

/**
 * Runs before every automatic reconnect. The Tauri shell uses it to re-resolve
 * the endpoint, a restarted engine can come back on a different port.
 */
export function setReconnectHook(fn: (() => Promise<void>) | null): void {
  reconnectHook = fn;
}

function setOpen(open: boolean): void {
  // A drop is reported once; every open is reported, each one is a fresh
  // stream and subscribers re-seed their snapshot on it
  if (!open && !isOpen) return;
  isOpen = open;
  for (const fn of statusHandlers) fn(open);
}

export function isConnected(): boolean {
  return isOpen;
}

function scheduleRetry(gen: number): void {
  if (retry !== null || gen !== generation) return;
  const delay = retryDelay;
  retryDelay = Math.min(kRetryMaxMs, retryDelay * 2);
  retry = setTimeout(() => {
    retry = null;
    if (gen !== generation) return;
    const hook = reconnectHook;
    if (hook === null) {
      connect();
      return;
    }
    hook()
      .catch(() => undefined)
      .finally(() => {
        if (gen === generation) connect();
      });
  }, delay);
}

function open(gen: number, url: string): void {
  const es = new EventSource(url);
  source = es;
  es.onopen = () => {
    retryDelay = kRetryMinMs;
    setOpen(true);
  };
  es.onerror = () => {
    setOpen(false);
    // The engine may still be booting, or was restarted. A ticket is single
    // use, so the browser's own auto-reconnect cannot work: close and come
    // back through connect() with a fresh one
    if (source !== es) return;
    es.close();
    source = null;
    scheduleRetry(gen);
  };
  for (const name of kEventNames) {
    es.addEventListener(name, (ev) => emit(name, (ev as MessageEvent<string>).data));
  }
}

/**
 * EventSource cannot send an Authorization header. A token-protected engine
 * hands out a single-use, short-lived ticket over the authenticated /api, and
 * the stream URL carries only that, never the bearer token itself.
 */
export function connect(): void {
  disconnect();
  const gen = ++generation;
  const { token } = getEndpoint();
  if (token === "") {
    open(gen, `${baseUrl()}/events`);
    return;
  }
  call<{ ticket?: string }>("app", "events_ticket", {}, { timeoutMs: 10_000 })
    .then((res) => {
      if (gen !== generation) return;
      if (typeof res.ticket !== "string" || res.ticket === "") throw new Error("no ticket");
      open(gen, `${baseUrl()}/events?ticket=${encodeURIComponent(res.ticket)}`);
    })
    .catch(() => scheduleRetry(gen));
}

export function disconnect(): void {
  generation++;
  if (retry !== null) {
    clearTimeout(retry);
    retry = null;
  }
  if (source) {
    source.close();
    source = null;
  }
  setOpen(false);
}
