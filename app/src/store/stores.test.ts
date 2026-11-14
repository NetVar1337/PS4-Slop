import { beforeEach, describe, expect, it, vi } from "vitest";
import { backendFrom, useEngine } from "@/store/engine";
import { useDebugger } from "@/store/debugger";
import { functionLabel, kFilterDebounceMs, rowAt, useDisasm } from "@/store/disasm";
import { useMemory } from "@/store/memory";
import { kFlushMs, useOutput } from "@/store/output";
import { readShowHost, useTargets } from "@/store/targets";
import { kThemes, useTheme } from "@/store/theme";
import { useMotion } from "@/store/motion";
import { layoutChanges, layoutFile, parseLayout, parseLayoutFile, useUi } from "@/store/ui";
import { useWatch } from "@/store/watch";
import * as events from "@/lib/events";
import { flushPromises, mockApi } from "@/test/api";
import { EventSourceStub } from "@/test/setup";

const initial = {
  debugger: useDebugger.getState(),
  disasm: useDisasm.getState(),
  memory: useMemory.getState(),
  targets: useTargets.getState(),
  watch: useWatch.getState(),
  output: useOutput.getState(),
};

beforeEach(() => {
  useDebugger.setState(initial.debugger, true);
  useDisasm.setState(initial.disasm, true);
  useMemory.setState(initial.memory, true);
  useTargets.setState(initial.targets, true);
  useWatch.setState(initial.watch, true);
  useOutput.setState(initial.output, true);
});

describe("engine backend (item 80)", () => {
  it("treats the engine's upper-case PS4 badge as a console", () => {
    expect(backendFrom("PS4")).toEqual({ badge: "PS4", ps4: true });
    expect(backendFrom("ps4")).toEqual({ badge: "ps4", ps4: true });
    expect(backendFrom("user")).toEqual({ badge: "user", ps4: false });
    expect(backendFrom("user", true).ps4).toBe(true);
  });
});

describe("engine event mirroring (items 83, 84)", () => {
  it("follows attach, backend and image changes made over MCP", async () => {
    const { calls } = mockApi(({ tool, action }) => {
      if (tool === "app" && action === "status")
        return { backend: "user", target: { attached: false } };
      if (action === "modules")
        return { modules: [{ name: "eboot.bin", base: 0x400000, size: 0x1000 }] };
      if (action === "list") return { processes: [{ pid: 77, name: "eboot.bin", arch: "x64" }] };
      if (action === "loaded")
        return { ready: true, name: "eboot.bin", format: "elf", path: "C:/x/eboot.bin" };
      if (action === "functions") return { functions: [], total: 0, matched: 0 };
      return {};
    });
    await useEngine.getState().start();
    const stream = EventSourceStub.instances.at(-1);
    stream?.onopen?.();
    await vi.waitFor(() => expect(useEngine.getState().boot.done).toBe(true));

    // an agent connects a console: the process list follows (item 84)
    stream?.emit("backend.changed", { badge: "PS4", ps4: true });
    await vi.waitFor(() => expect(useTargets.getState().processes).toHaveLength(1));

    // an agent attaches: modules follow without the Modules panel open (item 83)
    stream?.emit("target.changed", { attached: true, pid: 77, name: "eboot.bin" });
    await vi.waitFor(() => expect(useTargets.getState().modules).toHaveLength(1));

    // an agent loads a binary: the image mirror follows (item 83)
    stream?.emit("image.changed", { loaded: true, name: "eboot.bin", format: "elf" });
    await vi.waitFor(() => expect(useDisasm.getState().image.format).toBe("elf"));

    stream?.emit("image.changed", { loaded: false });
    expect(useDisasm.getState().image.ready).toBe(false);
    expect(calls.some((c) => c.action === "list")).toBe(true);
    events.disconnect();
  });
});

describe("debugger", () => {
  it("renders the ps4_wait result directly, then loads the callstack (item 81)", async () => {
    const regs = Object.fromEntries(
      [
        "rip",
        "rsp",
        "rbp",
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        "flags",
      ].map((r, i) => [r, 0x1000 + i]),
    );
    const { calls } = mockApi(({ action }) => {
      if (action === "ps4_wait")
        return { halted: true, lwpid: 101, signal: 5, thread: "main", pending: 0, ...regs };
      if (action === "ps4_callstack") return { frames: [{ ret_addr: 0x401000 }] };
      if (action === "ps4_events") return { events: [] };
      return {};
    });
    await useDebugger.getState().waitHalt(5000);
    const s = useDebugger.getState();
    expect(s.regs?.rip).toBe(0x1000);
    expect(s.regsLwpid).toBe(101);
    expect(s.events[0]).toMatchObject({ lwpid: 101, signal: 5, thread: "main" });
    expect(s.frames).toEqual([{ ret_addr: 0x401000 }]);
    expect(s.waitNote).toContain("halted lwp 101");
    // the event came from the wait itself: no drain of the (now empty) queue
    expect(calls.map((c) => c.action)).toEqual(["ps4_wait", "ps4_callstack"]);
  });

  it("reports a wait timeout instead of silently doing nothing", async () => {
    mockApi(() => ({ halted: false, timeout_ms: 5000, pending: 0 }));
    await useDebugger.getState().waitHalt(5000);
    expect(useDebugger.getState().waitNote).toBe("no stop event within 5s");
    expect(useDebugger.getState().regs).toBeNull();
  });

  it("takes debugger stops and state from the push stream (item 28)", async () => {
    const regs = Object.fromEntries(
      [
        "rip",
        "rsp",
        "rbp",
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        "flags",
      ].map((r, i) => [r, 0x1000 + i]),
    );
    mockApi(({ action }) => {
      if (action === "ps4_callstack") return { frames: [{ ret_addr: 0x401000 }] };
      return {};
    });
    const off = useDebugger.getState().connectStream();
    events.connect();
    const stream = EventSourceStub.instances.at(-1);
    stream?.onopen?.();
    stream?.emit("debugger.stop", {
      ...regs,
      lwpid: 101,
      signal: 5,
      thread: "main",
      rip: 0x400500,
    });
    await vi.waitFor(() =>
      expect(useDebugger.getState().events[0]).toMatchObject({
        lwpid: 101,
        signal: 5,
        rip: 0x400500,
      }),
    );
    expect(useDebugger.getState().regs?.rip).toBe(0x400500);
    expect(useDebugger.getState().regsLwpid).toBe(101);
    expect(useDebugger.getState().waitNote).toContain("stopped lwp 101");
    await vi.waitFor(() => expect(useDebugger.getState().frames).toEqual([{ ret_addr: 0x401000 }]));

    stream?.emit("debugger.log", {
      lwpid: 101,
      rip: 0x400500,
      rip_hex: "0x400500",
      text: "rax=0x2a rip=0x400500",
    });
    expect(useDebugger.getState().logs[0]).toBe("rax=0x2a rip=0x400500");

    stream?.emit("debugger.state", { attached: false, pid: 0 });
    expect(useDebugger.getState().status.debug_attached).toBe(false);
    expect(useDebugger.getState().regs).toBeNull();
    off();
    events.disconnect();
  });

  it("refreshes the whole view in one batched round trip (item 106)", async () => {
    const { fetch } = mockApi(({ action }) => {
      if (action === "status")
        return {
          backend: "PS4",
          ps4_connected: true,
          debug_attached: true,
          debug_pid: 77,
          pending_events: 0,
        };
      if (action === "ps4_status") return { fw: "11.00", events_dropped: 3 };
      if (action === "ps4_bp_list") return { breakpoints: [{ addr: 0x10, index: 0 }] };
      return {};
    });
    await useDebugger.getState().refresh();
    expect(fetch).toHaveBeenCalledTimes(1);
    const s = useDebugger.getState();
    expect(s.status.fw).toBe("11.00");
    expect(s.status.events_dropped).toBe(3);
    expect(s.breakpoints).toEqual([{ addr: 0x10, index: 0 }]);
  });
});

describe("disasm functions (item 105)", () => {
  it("filters server-side and pages by offset", async () => {
    vi.useFakeTimers();
    const { calls } = mockApi(({ action, params }) => {
      if (action !== "functions") return {};
      const offset = Number(params.offset ?? 0);
      const filtered = params.filter === "main";
      const matched = filtered ? 2 : 20_000;
      const rows = Array.from(
        { length: Math.min(Number(params.limit), matched - offset) },
        (_, i) => ({
          va: 0x1000 + (offset + i) * 16,
          size: 16,
        }),
      );
      return { functions: rows, total: 20_000, matched, returned: rows.length };
    });
    useDisasm.setState({ image: { ready: true, name: "eboot.bin", format: "elf" }, selected: 1 });
    await useDisasm.getState().refreshFunctions();
    expect(useDisasm.getState().matched).toBe(20_000);
    useDisasm.getState().ensureRows(15_000, 15_010);
    await vi.waitFor(() => expect(rowAt(useDisasm.getState(), 15_000)).toBeDefined());
    expect(calls.some((c) => c.params.offset === Math.floor(15_000 / 512) * 512)).toBe(true);

    useDisasm.getState().setFilter("main");
    await vi.advanceTimersByTimeAsync(kFilterDebounceMs + 1);
    await vi.waitFor(() => expect(useDisasm.getState().matched).toBe(2));
    expect(calls.at(-1)?.params.filter).toBe("main");
    expect(useDisasm.getState().total).toBe(20_000);
  });

  it("names unnamed functions canonically", () => {
    expect(functionLabel({ va: 0x4dda48, size: 1 })).toBe("sub_4DDA48");
  });
});

describe("memory", () => {
  it("surfaces write failures instead of dropping them (item 94)", async () => {
    mockApi(({ action }) => {
      if (action === "write") throw new Error("page is read-only");
      return { hex: "00".repeat(0x1000) };
    });
    useMemory.setState({ windowBase: 0x400000, windowSize: 0x1000 });
    const ok = await useMemory.getState().writeBytes(0x400010, new Uint8Array([0x90]));
    expect(ok).toBe(false);
    expect(useMemory.getState().error).toContain("page is read-only");
  });

  it("keeps the position across a view remount (item 89)", () => {
    mockApi(() => ({ hex: "" }));
    useMemory.setState({
      regions: [{ base: 0x400000, size: 0x200000, protect: 4, state: 0x1000, type: 0 }],
    });
    useMemory.getState().goto(0x480000);
    useMemory.getState().setGotoText("0x480000");
    const { cursor, windowBase, gotoText } = useMemory.getState();
    expect(cursor).toBe(0x480000);
    expect(windowBase).toBeLessThanOrEqual(0x480000);
    expect(gotoText).toBe("0x480000");
  });
});

describe("watch (item 95)", () => {
  it("turns engine failures into an error, not an unhandled rejection", async () => {
    mockApi(() => {
      throw new Error("engine down");
    });
    await expect(useWatch.getState().remove(1)).resolves.toBe(false);
    expect(useWatch.getState().error).toContain("engine down");
    await expect(useWatch.getState().clear()).resolves.toBe(false);
  });
});

describe("targets (item 96)", () => {
  it("clears modules even when detach fails", async () => {
    mockApi(() => {
      throw new Error("detach failed");
    });
    useTargets.setState({ modules: [{ name: "eboot.bin", base: 0x400000, size: 0x1000 }] });
    await useTargets.getState().detach();
    expect(useTargets.getState().modules).toEqual([]);
    expect(useTargets.getState().error).toContain("detach failed");
  });

  it("remembers the console vs local-process choice across launches (item 82)", () => {
    expect(readShowHost()).toBe(false);
    useTargets.getState().setShowHost(true);
    expect(localStorage.getItem("reverse-slop.show-host-processes")).toBe("1");
    // a fresh launch reads the same key
    expect(readShowHost()).toBe(true);
    useTargets.getState().setShowHost(false);
    expect(readShowHost()).toBe(false);
  });

  it("loads saved consoles and switches between them", async () => {
    const consoles = [
      {
        name: "devkit-a",
        host: "10.0.0.5",
        port: 744,
        notes: "",
        default_pid: 0,
        title_filter: "",
        auto_connect: false,
        profile: { watchlist: "a", scan_width: "u32", scan_kind: "exact" },
        last_seen_ms: 0,
        last_fw: "11.00",
        last_branding: "ps4debug-NG",
        last_caps: "1.1",
        active: true,
      },
      {
        name: "devkit-b",
        host: "10.0.0.6",
        port: 744,
        notes: "",
        default_pid: 0,
        title_filter: "",
        auto_connect: false,
        profile: { watchlist: "b", scan_width: "f32", scan_kind: "changed" },
        last_seen_ms: 0,
        last_fw: "",
        last_branding: "",
        last_caps: "",
        active: false,
      },
    ];
    const { calls } = mockApi(({ action }) => {
      if (action === "consoles_list") return { consoles, active: "devkit-a" };
      if (action === "consoles_switch")
        return { endpoint: "10.0.0.6:744", branding: "ps4debug-NG" };
      return { processes: [] };
    });
    await useTargets.getState().loadConsoles();
    expect(useTargets.getState().consoles).toHaveLength(2);
    expect(useTargets.getState().activeConsole).toBe("devkit-a");

    expect(await useTargets.getState().switchConsole("devkit-b")).toBe(true);
    expect(calls.some((c) => c.action === "consoles_switch" && c.params.name === "devkit-b")).toBe(
      true,
    );
    expect(useTargets.getState().ps4?.endpoint).toBe("10.0.0.6:744");
  });
});

describe("output batching (item 104)", () => {
  it("commits a burst of streamed lines in one update", async () => {
    vi.useFakeTimers();
    events.connect();
    const stream = EventSourceStub.instances.at(-1);
    let commits = 0;
    const stop = useOutput.subscribe(() => commits++);
    const detach = useOutput.getState().attach();
    for (let seq = 1; seq <= 1000; seq++) stream?.emit("output", { seq, ms: 0, text: `l${seq}` });
    expect(useOutput.getState().lines).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(kFlushMs + 1);
    expect(useOutput.getState().lines).toHaveLength(1000);
    expect(commits).toBe(1);
    // duplicates (reconnect overlap) are dropped by sequence
    stream?.emit("output", { seq: 1000, ms: 0, text: "dup" });
    useOutput.getState().flush();
    expect(useOutput.getState().lines.at(-1)?.text).toBe("l1000");
    detach();
    stop();
    events.disconnect();
    await flushPromises();
  });

  it("keeps the replayed backlog when live output races the reconnect replay", async () => {
    vi.useFakeTimers();
    // Engine ring holds the gap 5..7; replayFrom(since) returns what is newer.
    mockApi((c) => {
      if (c.tool === "app" && c.action === "output") {
        const since = Number(c.params.since ?? 0);
        return {
          revision: 7,
          lines: [5, 6, 7].filter((s) => s > since).map((seq) => ({ seq, ms: 0, text: `g${seq}` })),
        };
      }
      return {};
    });
    events.connect();
    const stream = EventSourceStub.instances.at(-1);
    const detach = useOutput.getState().attach();
    stream?.emit("output.cleared", {}); // reset module-level seq cursor from prior tests
    for (let seq = 1; seq <= 4; seq++) stream?.emit("output", { seq, ms: 0, text: `l${seq}` });
    await vi.advanceTimersByTimeAsync(kFlushMs + 1);
    expect(useOutput.getState().revision).toBe(4);

    // Reconnect: hello kicks off the async replayFrom(4); before it resolves,
    // live lines 8,9 flush and advance revision past the replay window.
    stream?.emit("hello", { output_revision: 7 });
    for (const seq of [8, 9]) stream?.emit("output", { seq, ms: 0, text: `live${seq}` });
    await vi.advanceTimersByTimeAsync(kFlushMs + 1);
    expect(useOutput.getState().revision).toBe(9);

    // The replay reply (5,6,7) must not be dropped just because revision is now 9.
    await flushPromises();
    await vi.advanceTimersByTimeAsync(kFlushMs + 1);
    expect(useOutput.getState().lines.map((l) => l.seq)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);

    detach();
    events.disconnect();
    await flushPromises();
  });
});

describe("layout + themes (items 107, 116, 117)", () => {
  it("persists layout and survives a corrupt blob", () => {
    useUi.getState().setSize("--left-w", 333);
    useUi.getState().setWorkspaceTab("strings");
    const saved = parseLayout(localStorage.getItem("reverse-slop.layout"));
    expect(saved.sizes["--left-w"]).toBe(333);
    expect(saved.workspaceTab).toBe("strings");
    expect(parseLayout("{not json").rail).toBe("targets");
    expect(parseLayout(JSON.stringify({ rail: "bogus", sizes: { "--left-w": -5 } })).sizes).toEqual(
      {},
    );
    useUi.getState().resetLayout();
  });

  it("round-trips a layout file and refuses a bad one (item 90)", () => {
    useUi.getState().setSize("--left-w", 420);
    useUi.getState().setRail("modules");
    useUi.getState().setWorkspaceTab("memory");
    useTheme.getState().setTheme("daylight");
    useMotion.getState().setMotion("off");
    const file = layoutFile();

    useUi.getState().resetLayout();
    useTheme.getState().setTheme("obsidian");
    useMotion.getState().setMotion("auto");
    const parsed = parseLayoutFile(JSON.stringify(file));
    expect(layoutChanges(layoutFile(), parsed)).toEqual(
      expect.arrayContaining(["theme obsidian → daylight", "rail targets → modules"]),
    );

    useUi.getState().importLayout(parsed);
    expect(useUi.getState().rail).toBe("modules");
    expect(useUi.getState().workspaceTab).toBe("memory");
    expect(useUi.getState().sizes["--left-w"]).toBe(420);
    expect(useTheme.getState().theme).toBe("daylight");
    expect(useMotion.getState().motion).toBe("off");
    // the import persists like any other layout change
    expect(parseLayout(localStorage.getItem("reverse-slop.layout")).rail).toBe("modules");

    expect(() => parseLayoutFile(JSON.stringify({ ...file, version: 99 }))).toThrow(/version/);
    expect(() => parseLayoutFile(JSON.stringify({ ...file, theme: "neon" }))).toThrow(/theme/);
    expect(() => parseLayoutFile(JSON.stringify({ ...file, rail: "bogus" }))).toThrow(/rail/);
    expect(() => parseLayoutFile("{oops")).toThrow(/JSON/);
    expect(useUi.getState().rail).toBe("modules");

    useTheme.getState().setTheme("obsidian");
    useMotion.getState().setMotion("auto");
    useUi.getState().resetLayout();
  });

  it("ships a light and a high-contrast theme", () => {
    const ids = kThemes.map((t) => t.id);
    expect(ids).toContain("daylight");
    expect(ids).toContain("high-contrast");
    expect(kThemes.find((t) => t.id === "daylight")?.scheme).toBe("light");
  });

  it("defaults motion to auto so the OS reduced-motion setting applies", async () => {
    localStorage.removeItem("reverse-slop.motion");
    // fresh module instance: the store reads storage once, at creation
    vi.resetModules();
    const { useMotion } = await import("@/store/motion");
    expect(useMotion.getState().motion).toBe("auto");
    expect(document.documentElement.getAttribute("data-motion")).toBe("auto");
  });
});
