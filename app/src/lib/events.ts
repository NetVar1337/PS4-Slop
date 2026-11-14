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
  | { type: "types.changed"; data: { generation: number } }
  | { type: "watch.list"; data: { entries: WatchEntry[] } }
  | { type: "watch.values"; data: { attached: boolean; values: WatchValue[] } }
  | { type: "debugger.stop"; data: DebuggerStop }
  | { type: "debugger.state"; data: DebuggerState }
  | { type: "debugger.log"; data: DebuggerLog }
  | { type: "app.quitting"; data: { reason: string } }
  | { type: "server.stopping"; data: Record<string, never> };

/** Pushed when the console debugger stops (breakpoint, watchpoint, step, signal). */
export type DebuggerStop = {
  lwpid: number;
  signal: number;
  status?: number;
  thread?: string;
  rip?: number;
  rsp?: number;
  rbp?: number;
  [reg: string]: number | string | undefined;
};

export type DebuggerState = {
  attached: boolean;
  pid: number;
  held?: boolean;
  reason?: string;
};

/** One log-breakpoint line (also appended to the output panel). */
export type DebuggerLog = { lwpid: number; rip: number; rip_hex: string; text: string };

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
  "types.changed",
  "watch.list",
  "watch.values",
  "debugger.stop",
  "debugger.state",
  "debugger.log",
  "app.quitting",
  "server.stopping",
];

/** Reconnect delay grows on repeated failures so a dead engine is not hammered. */
const kRetryMinMs = 1_000;
const kRetryMaxMs = 8_000;

const handlers = new Map<EventName, Set<Handler>>();
let source: EventSource | null = null;
let socket: WebSocket | null = null;
let retry: ReturnType<typeof setTimeout> | null = null;
let retryDelay = kRetryMinMs;
let isOpen = false;
/** Bumped by every connect/disconnect so stale async work can tell it lost. */
let generation = 0;
let reconnectHook: (() => Promise<void>) | null = null;
const statusHandlers = new Set<(open: boolean) => void>();

function emitValue(name: EventName, value: unknown): void {
  const set = handlers.get(name);
  if (!set || set.size === 0) return;
  for (const fn of set) fn(value);
}

function emit(name: EventName, raw: string): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return;
  }
  emitValue(name, parsed);
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

function streamUrl(ticket: string | null, ws: boolean): string {
  const base = ws ? baseUrl().replace(/^http/, "ws") : baseUrl();
  const path = ws ? "/api/v1/events/ws" : "/api/v1/events";
  return ticket === null ? `${base}${path}` : `${base}${path}?ticket=${encodeURIComponent(ticket)}`;
}

function openSse(gen: number, ticket: string | null): void {
  const es = new EventSource(streamUrl(ticket, false));
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
 * The engine serves the same stream over a websocket, which skips chunked SSE
 * parsing and gives the server a real close handshake. An engine that predates
 * the route answers 404 without spending the ticket, so the first failure
 * silently falls back to SSE.
 */
function openWs(gen: number, ticket: string | null): void {
  const ws = new WebSocket(streamUrl(ticket, true));
  socket = ws;
  let opened = false;
  ws.onopen = () => {
    opened = true;
    retryDelay = kRetryMinMs;
    setOpen(true);
  };
  ws.onmessage = (ev) => {
    let msg: { event?: unknown; data?: unknown };
    try {
      msg = JSON.parse(String(ev.data)) as { event?: unknown; data?: unknown };
    } catch {
      return;
    }
    if (typeof msg.event !== "string") return;
    if (!kEventNames.includes(msg.event as EventName)) return;
    emitValue(msg.event as EventName, msg.data);
  };
  ws.onclose = () => {
    if (socket !== ws) return;
    socket = null;
    setOpen(false);
    if (opened) {
      scheduleRetry(gen);
      return;
    }
    // never opened: no websocket on this engine, take the same stream over SSE
    fetchTicket()
      .then((t) => {
        if (gen === generation) openSse(gen, t);
      })
      .catch(() => scheduleRetry(gen));
  };
}

/**
 * EventSource cannot send an Authorization header. A token-protected engine
 * hands out a single-use, short-lived ticket over the authenticated /api, and
 * the stream URL carries only that, never the bearer token itself.
 */
function fetchTicket(): Promise<string | null> {
  if (getEndpoint().token === "") return Promise.resolve(null);
  return call<{ ticket?: string }>("app", "events_ticket", {}, { timeoutMs: 10_000 }).then(
    (res) => {
      if (typeof res.ticket !== "string" || res.ticket === "") throw new Error("no ticket");
      return res.ticket;
    },
  );
}

export function connect(): void {
  disconnect();
  const gen = ++generation;
  fetchTicket()
    .then((t) => {
      if (gen === generation) openWs(gen, t);
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
  if (socket) {
    socket.close();
    socket = null;
  }
  setOpen(false);
}
