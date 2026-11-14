import { describe, expect, it, vi } from "vitest";
import * as events from "@/lib/events";
import {
  browserLabel,
  defaultFunctionName,
  escapeControl,
  formatLabel,
  parseAddress,
} from "@/lib/format";
import { batch, call, TimeoutError, ToolError } from "@/lib/rpc";
import { searchHelp } from "@/lib/help";
import { handleShortcut } from "@/lib/shortcuts";
import { useUi } from "@/store/ui";
import { mockApi } from "@/test/api";
import { EventSourceStub, WebSocketStub } from "@/test/setup";

describe("rpc", () => {
  it("times out a wedged engine instead of hanging (item 93)", async () => {
    vi.useFakeTimers();
    mockApi(() => new Promise(() => undefined));
    const pending = call("memory", "read", {}, { timeoutMs: 1_000 });
    const assertion = expect(pending).rejects.toBeInstanceOf(TimeoutError);
    await vi.advanceTimersByTimeAsync(1_001);
    await assertion;
  });

  it("surfaces tool failures as ToolError", async () => {
    mockApi(() => {
      throw new Error("not attached");
    });
    await expect(call("memory", "read")).rejects.toEqual(
      new ToolError("memory", "read", "not attached"),
    );
  });

  it("batches in one request and keeps per-request failures inline", async () => {
    const { fetch } = mockApi(({ action }) => {
      if (action === "b") throw new Error("nope");
      return { action };
    });
    const res = await batch([
      { tool: "t", action: "a" },
      { tool: "t", action: "b" },
    ]);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(res[0]).toMatchObject({ ok: true, data: { action: "a" } });
    expect(res[1]).toMatchObject({ ok: false });
  });
});

describe("format", () => {
  it("labels ELF and SELF images as such, never PE (item 82)", () => {
    expect(formatLabel("elf")).toBe("ELF");
    expect(formatLabel("self")).toBe("SELF");
    expect(formatLabel("pe", true)).toBe("PE32+");
    expect(browserLabel("elf")).toBe("ELF Browser");
    expect(browserLabel("macho")).toBe("Mach-O Browser");
  });

  it("escapes control characters so a string stays on one row (item 87)", () => {
    expect(escapeControl("a\nb\r\tc")).toBe("a\\nb\\r\\tc");
    expect(escapeControl("bell\u0007")).toBe("bell\\x07");
    expect(escapeControl("plain")).toBe("plain");
  });

  it("parses hex addresses and rejects junk", () => {
    expect(parseAddress("0x400000")).toBe(0x400000);
    expect(parseAddress("7ff6`0000_1000")).toBe(0x7ff600001000);
    expect(parseAddress("zz")).toBeNull();
    expect(parseAddress("")).toBeNull();
  });

  it("uses the canonical unpadded sub_ name (item 179)", () => {
    expect(defaultFunctionName(0x4dda48)).toBe("sub_4DDA48");
  });
});

describe("events", () => {
  it("disconnect() reports the stream closed (item 98)", async () => {
    const seen: boolean[] = [];
    const off = events.onConnectionChange((open) => seen.push(open));
    events.connect();
    await Promise.resolve();
    const ws = WebSocketStub.instances.at(-1);
    expect(ws?.url).toBe("ws://127.0.0.1:8765/api/v1/events/ws");
    ws?.onopen?.();
    events.disconnect();
    off();
    expect(seen).toEqual([true, false]);
    expect(events.isConnected()).toBe(false);
  });

  it("delivers websocket frames to subscribers", async () => {
    const got: unknown[] = [];
    const off = events.on("output", (data) => got.push(data));
    events.connect();
    await Promise.resolve();
    WebSocketStub.instances.at(-1)?.emit("output", { seq: 7, ms: 1, text: "ws" });
    events.disconnect();
    off();
    expect(got).toEqual([{ seq: 7, ms: 1, text: "ws" }]);
  });

  it("falls back to sse when the engine has no websocket route", async () => {
    events.connect();
    await Promise.resolve();
    const ws = WebSocketStub.instances.at(-1);
    ws?.onclose?.(); // closed before it ever opened
    await Promise.resolve();
    await Promise.resolve();
    expect(EventSourceStub.instances.at(-1)?.url).toBe("http://127.0.0.1:8765/api/v1/events");
    events.disconnect();
  });
});

describe("shortcuts (item 91)", () => {
  const key = (k: string, mods: Partial<KeyboardEventInit> = {}) =>
    new KeyboardEvent("keydown", { key: k, ctrlKey: true, ...mods });

  it("opens the palette, settings and switches tabs", () => {
    expect(handleShortcut(key("k"))).toBe(true);
    expect(useUi.getState().paletteOpen).toBe(true);
    handleShortcut(key("k"));
    expect(useUi.getState().paletteOpen).toBe(false);
    expect(handleShortcut(key(","))).toBe(true);
    expect(useUi.getState().settingsOpen).toBe(true);
    useUi.getState().closeSettings();
    expect(handleShortcut(key("3"))).toBe(true);
    expect(useUi.getState().workspaceTab).toBe("memory");
    expect(handleShortcut(key("i", { altKey: true }))).toBe(true);
    expect(useUi.getState().inspectorOpen).toBe(false);
    useUi.getState().setInspectorOpen(true);
  });

  it("ignores plain keys", () => {
    expect(handleShortcut(new KeyboardEvent("keydown", { key: "k" }))).toBe(false);
  });
});

describe("help search (item 85)", () => {
  const entries = [
    {
      title: "Live memory",
      anchor: "live-memory",
      section: "Live memory",
      text: "Read and write console memory; hex, UTF-8, integer and float.",
      url: "features/live-memory.html#live-memory",
      path: "features/live-memory.md",
    },
    {
      title: "Breakpoints",
      anchor: "breakpoints",
      section: "Breakpoints",
      text: "Hardware and software breakpoints on the live memory of the console.",
      url: "features/live-debugging.html#breakpoints",
      path: "features/live-debugging.md",
    },
  ];

  it("ranks a title hit above a body hit and needs every term", () => {
    expect(searchHelp(entries, "memory").map((e) => e.title)).toEqual([
      "Live memory",
      "Breakpoints",
    ]);
    expect(searchHelp(entries, "memory breakpoints").map((e) => e.title)).toEqual(["Breakpoints"]);
    expect(searchHelp(entries, "  ")).toEqual([]);
    expect(searchHelp(entries, "nonexistent")).toEqual([]);
    expect(searchHelp(entries, "memory", 1)).toHaveLength(1);
  });
});
