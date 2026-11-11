// app/src/test/api.ts
// Fake engine /api for tests: routes single and batched tool calls to a
// handler and records every call. A handler may return data, throw (tool
// failure), or return a promise that never settles (wedged engine)

import { vi } from "vitest";

export type ApiCall = { tool: string; action: string; params: Record<string, unknown> };
export type ApiHandler = (call: ApiCall) => unknown;

type Body = { tool: string; action: string; params?: Record<string, unknown>; id?: number };

async function envelope(handler: ApiHandler, b: Body, calls: ApiCall[]) {
  const call = { tool: b.tool, action: b.action, params: b.params ?? {} };
  calls.push(call);
  try {
    const data = await handler(call);
    return { ok: true, data: data ?? {}, ...(b.id !== undefined ? { id: b.id } : {}) };
  } catch (e) {
    return {
      ok: false,
      data: { error: e instanceof Error ? e.message : String(e) },
      ...(b.id !== undefined ? { id: b.id } : {}),
    };
  }
}

/** Install a fetch stub for the engine. Returns the recorded calls. */
export function mockApi(handler: ApiHandler): {
  calls: ApiCall[];
  fetch: ReturnType<typeof vi.fn>;
} {
  const calls: ApiCall[] = [];
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    if (String(url).endsWith("/health")) return { ok: true, json: async () => ({ ok: true }) };
    const body = JSON.parse(String(init?.body)) as Body | Body[];
    const signal = init?.signal;
    const work = Array.isArray(body)
      ? Promise.all(body.map((b) => envelope(handler, b, calls)))
      : envelope(handler, body, calls);
    const result = await new Promise<unknown>((resolve, reject) => {
      signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
      work.then(resolve, reject);
    });
    return { ok: true, json: async () => result };
  });
  vi.stubGlobal("fetch", fetch);
  return { calls, fetch };
}

/** Let pending promise continuations run. */
export async function flushPromises(rounds = 5): Promise<void> {
  for (let i = 0; i < rounds; i++) await Promise.resolve();
}
