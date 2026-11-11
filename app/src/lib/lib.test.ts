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
import { handleShortcut } from "@/lib/shortcuts";
import { useUi } from "@/store/ui";
import { mockApi } from "@/test/api";
import { EventSourceStub } from "@/test/setup";

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
  it("disconnect() reports the stream closed (item 98)", () => {
    const seen: boolean[] = [];
    const off = events.onConnectionChange((open) => seen.push(open));
    events.connect();
    const source = EventSourceStub.instances.at(-1);
    source?.onopen?.();
    events.disconnect();
    off();
    expect(seen).toEqual([true, false]);
    expect(events.isConnected()).toBe(false);
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
