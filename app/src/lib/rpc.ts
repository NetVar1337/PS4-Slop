// app/src/lib/rpc.ts
// thin transport over the engines /api surface, the ui and an ai agent drive
// exactly the same tool actions

export type Endpoint = { port: number; token: string };

export type ApiEnvelope<T> = { ok: boolean; data: T; id?: number | string };

/** Default per-request deadline. A wedged engine must never strand `busy`. */
export const kDefaultTimeoutMs = 30_000;

let endpoint: Endpoint = { port: 8765, token: "" };

export function setEndpoint(next: Endpoint): void {
  endpoint = next;
}

export function getEndpoint(): Endpoint {
  return endpoint;
}

export function baseUrl(): string {
  return `http://127.0.0.1:${endpoint.port}`;
}

function headers(): HeadersInit {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (endpoint.token) h["Authorization"] = `Bearer ${endpoint.token}`;
  return h;
}

/** Thrown when a tool reports failure; `tool`/`action` aid the error surface. */
export class ToolError extends Error {
  constructor(
    readonly tool: string,
    readonly action: string,
    message: string,
  ) {
    super(`${tool}.${action}: ${message}`);
    this.name = "ToolError";
  }
}

/** Thrown when the engine does not answer within the request deadline. */
export class TimeoutError extends Error {
  constructor(
    readonly what: string,
    readonly timeoutMs: number,
  ) {
    super(`${what}: engine did not answer within ${Math.round(timeoutMs / 1000)}s`);
    this.name = "TimeoutError";
  }
}

export type CallOptions = {
  /** Abort the request after this many milliseconds (default 30 s). */
  timeoutMs?: number;
};

type ToolFailure = { error?: string };

/** Message of any thrown value, for store error fields. */
export function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

async function post(body: unknown, what: string, timeoutMs: number): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${baseUrl()}/api`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`${what}: engine returned HTTP ${res.status}`);
    return await res.json();
  } catch (e) {
    if (controller.signal.aborted) throw new TimeoutError(what, timeoutMs);
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

/** Invoke one action. Rejects with ToolError when the tool reports failure. */
export async function call<T>(
  tool: string,
  action: string,
  params?: Record<string, unknown>,
  options?: CallOptions,
): Promise<T> {
  const env = (await post(
    { tool, action, params: params ?? {} },
    `${tool}.${action}`,
    options?.timeoutMs ?? kDefaultTimeoutMs,
  )) as ApiEnvelope<T>;
  if (!env.ok) {
    const failure = env.data as ToolFailure | undefined;
    throw new ToolError(tool, action, failure?.error ?? "unknown failure");
  }
  return env.data;
}

export type BatchRequest = {
  tool: string;
  action: string;
  params?: Record<string, unknown>;
};

/**
 * One round trip for several unrelated reads, opening a view usually needs
 * status plus a list plus module info, and stacking those latencies is the
 * difference between a snappy first paint and a visibly staged one.
 * Per-request failures are returned rather than thrown; the caller decides.
 */
export async function batch(
  requests: readonly BatchRequest[],
  options?: CallOptions,
): Promise<ApiEnvelope<unknown>[]> {
  if (requests.length === 0) return [];
  const body = requests.map((r, i) => ({
    tool: r.tool,
    action: r.action,
    params: r.params ?? {},
    id: i,
  }));
  const res = await post(body, "batch", options?.timeoutMs ?? kDefaultTimeoutMs);
  if (!Array.isArray(res)) throw new Error("batch: engine returned a non-array reply");
  // Replies carry the request index as id; order by it so a reordering engine
  // cannot hand one request's data to another
  const out: ApiEnvelope<unknown>[] = requests.map(() => ({
    ok: false,
    data: { error: "missing from batch reply" },
  }));
  (res as ApiEnvelope<unknown>[]).forEach((env, i) => {
    const slot = typeof env.id === "number" ? env.id : i;
    if (slot >= 0 && slot < out.length) out[slot] = env;
  });
  return out;
}

/** Data of a batch slot, or undefined when that request failed. */
export function batchData<T>(env: ApiEnvelope<unknown> | undefined): T | undefined {
  return env !== undefined && env.ok ? (env.data as T) : undefined;
}

/** Liveness probe used while waiting for a spawned engine to come up. */
export async function health(timeoutMs = 2_000): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${baseUrl()}/health`, { signal: controller.signal });
    return res.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}
