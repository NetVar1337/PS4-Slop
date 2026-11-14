import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import CommandPalette from "@/components/CommandPalette";
import CfgGraph from "@/components/CfgGraph";
import SettingsModal from "@/components/SettingsModal";
import Splash from "@/components/Splash";
import Splitter from "@/components/Splitter";
import StatusBar from "@/components/StatusBar";
import Tabs from "@/components/Tabs";
import DebuggerView from "@/components/panels/DebuggerView";
import DecompView from "@/components/panels/DecompView";
import DisassemblyView from "@/components/panels/DisassemblyView";
import EmulatorPanel from "@/components/panels/EmulatorPanel";
import InspectorPanel from "@/components/panels/InspectorPanel";
import MemoryView from "@/components/panels/MemoryView";
import { bucketize, kBuckets } from "@/components/panels/Minimap";
import NetworkPanel from "@/components/panels/NetworkPanel";
import PatchPanel from "@/components/panels/PatchPanel";
import ScannerPanel from "@/components/panels/ScannerPanel";
import ScriptsPanel from "@/components/panels/ScriptsPanel";
import StringsView from "@/components/panels/StringsView";
import StructEditor from "@/components/panels/StructEditor";
import TargetsPanel from "@/components/panels/TargetsPanel";
import UnpackerView from "@/components/panels/UnpackerView";
import WorkspacePanel from "@/components/panels/WorkspacePanel";
import XrayPanel from "@/components/panels/XrayPanel";
import { hex } from "@/lib/format";
import { setEndpoint } from "@/lib/rpc";
import { readLayoutFile, saveLayoutFile } from "@/lib/layoutFile";
import { useDebugger } from "@/store/debugger";
import { useDecomp } from "@/store/decomp";
import { useDisasm } from "@/store/disasm";
import { useEmulator } from "@/store/emulator";
import { useEngine } from "@/store/engine";
import { useMemory } from "@/store/memory";
import { useNetwork } from "@/store/network";
import { useSettings } from "@/store/settings";
import { useTargets } from "@/store/targets";
import { useTheme } from "@/store/theme";
import { useTypes } from "@/store/types";
import { useUi } from "@/store/ui";
import { useWatch } from "@/store/watch";
import { useXray } from "@/store/xray";
import { mockApi } from "@/test/api";

// the diagnostics bundle and the payload save both go through the native save
// dialog; jsdom has no dialog, so the plugin is stubbed at module level
vi.mock("@tauri-apps/plugin-dialog", () => ({
  save: vi.fn(async () => "C:\\tmp\\slopstation-diagnostics.zip"),
  open: vi.fn(async () => null),
  message: vi.fn(async () => undefined),
}));

// the shell-only affordances (save dialog, payload card) render only inside
// Tauri; the tests drive them, so the detection is pinned
vi.mock("@/lib/endpoint", async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, isTauri: () => true };
});

// the help index is a generated build artifact and the layout file goes
// through the native dialogs; both are pinned so the tests stay deterministic
const helpMock = vi.hoisted(() => ({
  entries: [
    {
      title: "Live memory",
      anchor: "live-memory",
      section: "Live memory",
      text: "Read and write console memory.",
      url: "features/live-memory.html#live-memory",
      path: "features/live-memory.md",
    },
  ],
  openHelp: vi.fn(async () => undefined),
}));

vi.mock("@/lib/help", async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, loadHelpIndex: async () => helpMock.entries, openHelp: helpMock.openHelp };
});

vi.mock("@/lib/layoutFile", () => ({
  saveLayoutFile: vi.fn(async () => "C:\\tmp\\slopstation-layout.json"),
  readLayoutFile: vi.fn(async () => null),
}));

const initial = {
  engine: useEngine.getState(),
  disasm: useDisasm.getState(),
  targets: useTargets.getState(),
  memory: useMemory.getState(),
  watch: useWatch.getState(),
  ui: useUi.getState(),
  debugger: useDebugger.getState(),
  decomp: useDecomp.getState(),
  settings: useSettings.getState(),
  types: useTypes.getState(),
  xray: useXray.getState(),
  network: useNetwork.getState(),
  emulator: useEmulator.getState(),
};

beforeEach(() => {
  useEngine.setState(initial.engine, true);
  useDisasm.setState(initial.disasm, true);
  useTargets.setState(initial.targets, true);
  useMemory.setState(initial.memory, true);
  useWatch.setState(initial.watch, true);
  useUi.setState(initial.ui, true);
  useDebugger.setState(initial.debugger, true);
  useDecomp.setState(initial.decomp, true);
  useSettings.setState(initial.settings, true);
  useTypes.setState(initial.types, true);
  useXray.setState(initial.xray, true);
  useNetwork.setState(initial.network, true);
  useEmulator.setState(initial.emulator, true);
  setEndpoint({ port: 8765, token: "" });
});

const ps4 = { badge: "PS4", ps4: true };
const attached = { attached: true, pid: 77, name: "eboot.bin" };

describe("image format labels (item 82)", () => {
  it("names the browser tab and header after an ELF image", () => {
    mockApi(() => ({ functions: [], total: 0, matched: 0 }));
    useDisasm.setState({ image: { ready: true, name: "eboot.bin", format: "elf", arch: "x64" } });
    render(<WorkspacePanel />);
    expect(screen.getByRole("tab", { name: "ELF Browser" })).toBeInTheDocument();
    expect(screen.queryByText(/PE Browser/)).not.toBeInTheDocument();
    expect(screen.getByText(/eboot\.bin · ELF · x64/)).toBeInTheDocument();
  });

  it("exposes the workspace tabs as an ARIA tablist (item 109)", async () => {
    mockApi(() => ({}));
    render(<WorkspacePanel />);
    const list = screen.getByRole("tablist", { name: "Workspace views" });
    const tabs = within(list).getAllByRole("tab");
    expect(tabs[0]).toHaveAttribute("aria-selected", "true");
    tabs[0].focus();
    await userEvent.keyboard("{ArrowRight}");
    expect(useUi.getState().workspaceTab).toBe("decomp");
    expect(within(list).getByRole("tab", { name: "Pseudocode" })).toHaveFocus();
    await userEvent.keyboard("{ArrowRight}");
    expect(useUi.getState().workspaceTab).toBe("strings");
    expect(within(list).getByRole("tab", { name: "Strings" })).toHaveFocus();
  });
});

describe("status bar (items 83, 108)", () => {
  it("shows an image loaded over MCP and names every icon button", () => {
    useDisasm.setState({ image: { ready: true, name: "eboot.bin", format: "elf" } });
    render(<StatusBar />);
    expect(screen.getByText("Image: eboot.bin (ELF)")).toBeInTheDocument();
    for (const button of screen.getAllByRole("button")) expect(button).toHaveAccessibleName();
  });
});

describe("targets panel", () => {
  it("asks for a console instead of listing host processes (item 85)", () => {
    const { calls } = mockApi(() => ({ processes: [{ pid: 4, name: "System", arch: "x64" }] }));
    useEngine.setState({ backend: { badge: "user", ps4: false } });
    render(<TargetsPanel />);
    expect(screen.getByText("Connect a console")).toBeInTheDocument();
    expect(screen.getByRole("form", { name: "Connect to a PS4" })).toBeInTheDocument();
    expect(screen.queryByText("System")).not.toBeInTheDocument();
    expect(calls.some((c) => c.action === "list")).toBe(false);
  });

  it("lists console processes with a fixed banner row and elevation (items 86, 115)", async () => {
    mockApi(({ action }) =>
      action === "list"
        ? { processes: [{ pid: 77, name: "eboot.bin", arch: "x64", elevation: "system" }] }
        : {},
    );
    useEngine.setState({ backend: ps4 });
    useTargets.setState({ ps4: { endpoint: "10.0.0.5:744", branding: "ps4debug-NG" } });
    const { container } = render(<TargetsPanel />);
    await screen.findByText("eboot.bin");
    const panel = container.querySelector(".targets-panel");
    // head / banner slot / list: the banner can never take the stretch row
    expect(panel?.children).toHaveLength(3);
    expect(panel?.children[1]).toHaveClass("banner-slot");
    expect(screen.getByText(/10\.0\.0\.5:744/)).toBeInTheDocument();
    expect(screen.getByText("system")).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "PID" })).toHaveAttribute("scope", "col");
  });
});

describe("console manager (multi-console, audit 22/81/82)", () => {
  const consoles = [
    {
      name: "devkit-a",
      host: "10.0.0.5",
      port: 744,
      notes: "living room",
      default_pid: 0,
      title_filter: "",
      auto_connect: false,
      profile: { watchlist: "a-set", scan_width: "u32", scan_kind: "exact" },
      last_seen_ms: 1_700_000_000_000,
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
      profile: { watchlist: "b-set", scan_width: "f32", scan_kind: "changed" },
      last_seen_ms: 0,
      last_fw: "",
      last_branding: "",
      last_caps: "",
      active: false,
    },
  ];

  it("lists saved consoles with firmware/caps and switches to another one", async () => {
    const { calls } = mockApi(({ action }) => {
      if (action === "consoles_list") return { consoles, active: "devkit-a" };
      if (action === "consoles_switch") return { endpoint: "10.0.0.6:744" };
      return { processes: [] };
    });
    useEngine.setState({ backend: { badge: "user", ps4: false } });
    render(<TargetsPanel />);
    await screen.findByText("devkit-a");
    expect(screen.getByText(/fw 11\.00/)).toBeInTheDocument();
    expect(screen.getByText("1.1")).toBeInTheDocument();
    expect(screen.getByText("living room")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Switch" }));
    await waitFor(() =>
      expect(
        calls.some((c) => c.action === "consoles_switch" && c.params.name === "devkit-b"),
      ).toBe(true),
    );
  });

  it("status bar shows the active console and quick-switches", async () => {
    const { calls } = mockApi(({ action }) =>
      action === "consoles_list" ? { consoles, active: "devkit-a" } : {},
    );
    render(<StatusBar />);
    await userEvent.click(await screen.findByRole("button", { name: "devkit-a" }));
    await userEvent.click(screen.getByRole("menuitemradio", { name: /devkit-b/ }));
    expect(calls.some((c) => c.action === "consoles_switch" && c.params.name === "devkit-b")).toBe(
      true,
    );
  });

  it("writes a diagnostics bundle from Settings (item 81)", async () => {
    const { calls } = mockApi(() => ({}));
    render(<SettingsModal onClose={() => undefined} />);
    await userEvent.click(await screen.findByRole("button", { name: "Copy diagnostics" }));
    await waitFor(() =>
      expect(calls.some((c) => c.tool === "app" && c.action === "diag_bundle")).toBe(true),
    );
    expect(calls.find((c) => c.action === "diag_bundle")?.params.path).toBe(
      "C:\\tmp\\slopstation-diagnostics.zip",
    );
  });
});

describe("strings view (item 87)", () => {
  it("renders control characters escaped on one row", async () => {
    mockApi(() => ({
      strings: [{ va: 0x401000, text: "line1\nline2", utf16: false }],
      truncated: false,
    }));
    useDisasm.setState({ image: { ready: true, format: "elf" } });
    render(<StringsView />);
    expect(await screen.findByText("line1\\nline2")).toBeInTheDocument();
  });
});

describe("disassembly minimap (audit 88)", () => {
  const insns = Array.from({ length: 320 }, (_, i) => ({
    va: 0x1000 + i * 4,
    len: 4,
    text: `insn ${i}`,
    flow: i === 10 ? "cond_jump" : "next",
    target: i === 10 ? 0x1000 + 300 * 4 : undefined,
  }));

  it("folds the whole function into fixed buckets and marks branch targets", () => {
    const buckets = bucketize(insns);
    expect(buckets).toHaveLength(kBuckets);
    expect(buckets.reduce((n, b) => n + b.density, 0)).toBe(insns.length);
    expect(buckets.filter((b) => b.branch)).toHaveLength(1);
    expect(buckets[Math.floor((300 * kBuckets) / insns.length)].branch).toBe(true);
    expect(bucketize([])).toEqual([]);
  });

  it("renders one strip with a viewport marker over the listing", () => {
    useDisasm.setState({
      insns,
      selected: 0x1000,
      selectedFn: { va: 0x1000, size: 1280 },
    });
    render(<DisassemblyView />);
    const strip = screen.getByRole("scrollbar", { name: "Function overview" });
    expect(strip.querySelectorAll(".minimap-bar").length).toBeGreaterThan(0);
    expect(strip.querySelectorAll(".minimap-view")).toHaveLength(1);
    // a press on the strip jumps without needing layout from jsdom
    fireEvent.pointerDown(strip, { clientY: 300 });
    fireEvent.pointerUp(strip, { clientY: 300 });
  });
});

describe("scanner watchlist (items 88, 113)", () => {
  it("shows labels and adds watches through an inline, validated row", async () => {
    const { calls } = mockApi(({ action }) =>
      action === "watch_list"
        ? {
            entries: [
              {
                id: 1,
                addr: 0x10,
                width: "u32",
                label: "player hp",
                freeze: false,
                frozen_bits: 0,
                frozen_text: "",
              },
            ],
            values: [],
          }
        : {},
    );
    const prompt = vi.spyOn(window, "prompt");
    useEngine.setState({ target: attached });
    render(<ScannerPanel />);
    expect(await screen.findByText("player hp")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Add address" }));
    const addr = screen.getByRole("textbox", { name: "Watch address (hex)" });
    await userEvent.type(addr, "nothex");
    await userEvent.click(screen.getByRole("button", { name: "Add" }));
    expect(addr).toHaveAttribute("aria-invalid", "true");
    await userEvent.clear(addr);
    await userEvent.type(addr, "0x7f001000");
    await userEvent.type(screen.getByRole("textbox", { name: "Watch label" }), "ammo");
    await userEvent.click(screen.getByRole("button", { name: "Add" }));
    await waitFor(() => expect(calls.some((c) => c.action === "watch_add")).toBe(true));
    expect(calls.find((c) => c.action === "watch_add")?.params).toEqual({
      addr: 0x7f001000,
      width: "u32",
      label: "ammo",
    });
    expect(prompt).not.toHaveBeenCalled();
  });
});

describe("scanner and watchlist exports (item 84)", () => {
  it("writes scan results as CSV and the watchlist as a .CT table", async () => {
    const { calls } = mockApi(({ action }) => {
      if (action === "scan_state") return { active: true, total: 3 };
      if (action === "watch_list")
        return {
          entries: [
            {
              id: 1,
              addr: 0x10,
              width: "u32",
              label: "hp",
              freeze: false,
              frozen_bits: 0,
              frozen_text: "",
            },
          ],
          values: [],
        };
      if (action === "scan_export") return { rows: 3 };
      return { entries: 1 };
    });
    useEngine.setState({ target: attached });
    // the panel saves through the native dialog inside Tauri (pinned above), so
    // the dialog mock supplies the two paths this test exports to
    const dialog = await import("@tauri-apps/plugin-dialog");
    const saveMock = vi.mocked(dialog.save);
    saveMock.mockResolvedValueOnce("C:/tmp/out.csv");
    saveMock.mockResolvedValueOnce("C:/tmp/watch.CT");
    const prompt = vi.spyOn(window, "prompt");
    render(<ScannerPanel />);

    await userEvent.click(screen.getByRole("button", { name: "Export results as CSV" }));
    await waitFor(() => expect(calls.some((c) => c.action === "scan_export")).toBe(true));
    expect(calls.find((c) => c.action === "scan_export")?.params).toEqual({
      path: "C:/tmp/out.csv",
    });

    await userEvent.click(
      screen.getByRole("button", { name: "Export the watchlist as a .CT table" }),
    );
    await waitFor(() => expect(calls.some((c) => c.action === "watch_export_ct")).toBe(true));
    expect(calls.find((c) => c.action === "watch_export_ct")?.params).toEqual({
      path: "C:/tmp/watch.CT",
    });
    prompt.mockRestore();
  });
});

describe("memory view (items 89, 90)", () => {
  it("keeps the goto address across tab switches and uses a PS4 placeholder", async () => {
    mockApi(({ action }) =>
      action === "regions"
        ? { regions: [{ base: 0x400000, size: 0x10000, protect: 4, state: 0x1000, type: 0 }] }
        : { hex: "90".repeat(0x1000) },
    );
    useEngine.setState({ target: attached });
    const first = render(<MemoryView />);
    const input = screen.getByPlaceholderText("0x400000");
    await userEvent.type(input, "0x404000{Enter}");
    expect(useMemory.getState().cursor).toBe(0x404000);
    first.unmount();
    render(<MemoryView />);
    expect(screen.getByPlaceholderText("0x400000")).toHaveValue("0x404000");
    expect(useMemory.getState().cursor).toBe(0x404000);
  });
});

describe("no Windows leftovers (item 90)", () => {
  it("sample script targets PS4 processes", () => {
    render(<ScriptsPanel />);
    const area = screen.getByRole("textbox", { name: "Lua script" });
    expect((area as HTMLTextAreaElement).value).not.toContain("chrome");
    expect((area as HTMLTextAreaElement).value).toContain("eboot");
  });

  it("debugger dump path has no C:/dumps default", () => {
    mockApi(({ action }) =>
      action === "status"
        ? {
            backend: "PS4",
            ps4_connected: true,
            debug_attached: false,
            debug_pid: 0,
            pending_events: 0,
          }
        : {},
    );
    useEngine.setState({ backend: ps4, target: attached });
    render(<DebuggerView />);
    expect(screen.getByRole("textbox", { name: "Dump output path" })).toHaveValue("");
  });

  it("debugger asks for a console when the backend is not PS4 (item 80)", () => {
    mockApi(() => ({}));
    useEngine.setState({ backend: { badge: "user", ps4: false } });
    render(<DebuggerView />);
    expect(screen.getByText("No PS4 console connected.")).toBeInTheDocument();
  });
});

describe("settings modal (items 92, settings API)", () => {
  it("is a labelled dialog, focuses its close button and closes on Escape", async () => {
    mockApi(({ action }) =>
      action === "settings_get"
        ? { mcp_token: "set", script_unsafe: false, web_allowlist: ["example.com"] }
        : {},
    );
    const onClose = vi.fn();
    render(<SettingsModal onClose={onClose} />);
    const dialog = screen.getByRole("dialog", { name: "Settings" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(within(dialog).getByRole("button", { name: "Close" })).toHaveFocus();
    expect(await screen.findByText("set")).toBeInTheDocument();
    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("warns when a client config still holds a plaintext token (item 72)", async () => {
    mockApi(({ action }) =>
      action === "settings_get"
        ? { mcp_token: "set", mcp_plaintext_configs: ["Cursor"], mcp_token_in_configs: false }
        : {},
    );
    render(<SettingsModal onClose={() => undefined} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Cursor");
  });

  it("writes engine settings and reveals a rotated token once", async () => {
    const newToken = "ab".repeat(32);
    const { calls } = mockApi(({ action }) => {
      if (action === "settings_get") return { mcp_token: "set", script_unsafe: false };
      if (action === "settings_set") return { ok: true };
      if (action === "rotate_token")
        return { rotated: true, clients_updated: ["vscode"], token: newToken };
      return {};
    });
    render(<SettingsModal onClose={() => undefined} />);
    await screen.findByText("set");
    await userEvent.click(screen.getByRole("checkbox", { name: /Unsafe Lua scripts/ }));
    await waitFor(() =>
      expect(calls.find((c) => c.action === "settings_set")?.params).toEqual({
        key: "script_unsafe",
        value: true,
      }),
    );
    await userEvent.click(screen.getByRole("button", { name: /Regenerate token/ }));
    await userEvent.click(screen.getByRole("button", { name: "Confirm regenerate" }));
    expect(await screen.findByTestId("revealed-token")).toHaveTextContent(newToken);
  });

  it("exports the shell layout and applies an imported one (item 90)", async () => {
    mockApi(() => ({}));
    useTheme.getState().setTheme("obsidian");
    useUi.getState().setSize("--left-w", 340);
    render(<SettingsModal onClose={() => undefined} />);
    await userEvent.click(await screen.findByRole("button", { name: "Export layout…" }));
    expect(await screen.findByRole("status")).toHaveTextContent("slopstation-layout.json");
    const text = vi.mocked(saveLayoutFile).mock.calls[0]?.[0] ?? "";
    const exported = JSON.parse(text) as Record<string, unknown>;
    expect(exported).toMatchObject({ version: 1, rail: "targets", theme: "obsidian" });
    expect(exported.sizes).toEqual({ "--left-w": 340 });

    vi.mocked(readLayoutFile).mockResolvedValueOnce(
      JSON.stringify({ ...exported, rail: "modules", theme: "daylight" }),
    );
    await userEvent.click(screen.getByRole("button", { name: "Import layout…" }));
    await waitFor(() => expect(useUi.getState().rail).toBe("modules"));
    expect(useTheme.getState().theme).toBe("daylight");
    expect(screen.getByRole("status")).toHaveTextContent("theme obsidian → daylight");

    // a file from another build is refused and nothing is applied
    vi.mocked(readLayoutFile).mockResolvedValueOnce('{"version":1,"rail":"bogus"}');
    await userEvent.click(screen.getByRole("button", { name: "Import layout…" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Import failed"));
    expect(useUi.getState().rail).toBe("modules");
    useTheme.getState().setTheme("obsidian");
  });
});

describe("splash (items 97, 101)", () => {
  it("draws one row per engine stage and offers Retry on failure", async () => {
    const retry = vi.fn(async () => undefined);
    useEngine.setState({
      boot: { stage: 2, total: 5, label: "settings", done: false },
      startupError: "engine did not answer /health within 180s",
      retry,
    });
    render(<Splash />);
    expect(screen.getAllByRole("listitem")).toHaveLength(5);
    expect(screen.getByRole("alert")).toHaveTextContent("180s");
    await userEvent.click(screen.getByRole("button", { name: /Retry/ }));
    expect(retry).toHaveBeenCalledTimes(1);
  });
});

describe("splitter (items 110, 116)", () => {
  it("resizes from the keyboard and persists the size", () => {
    render(<Splitter axis="x" variable="--left-w" min={200} max={620} label="Resize side panel" />);
    const sep = screen.getByRole("separator", { name: "Resize side panel" });
    expect(sep).toHaveAttribute("tabindex", "0");
    sep.focus();
    fireEvent.keyDown(sep, { key: "End" });
    expect(sep).toHaveAttribute("aria-valuenow", "620");
    expect(useUi.getState().sizes["--left-w"]).toBe(620);
    fireEvent.keyDown(sep, { key: "Home" });
    expect(useUi.getState().sizes["--left-w"]).toBe(200);
  });
});

describe("inspector (items 83, 112)", () => {
  it("has a working close and no dead Options control", async () => {
    useEngine.setState({ target: attached, backend: ps4 });
    useTargets.setState({ modules: [{ name: "eboot.bin", base: 0x400000, size: 0x1000 }] });
    render(<InspectorPanel />);
    expect(screen.getByText("1")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Options" })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Hide inspector/ }));
    expect(useUi.getState().inspectorOpen).toBe(false);
  });
});

describe("tabs", () => {
  it("supports Home/End and roving tabindex", () => {
    const onChange = vi.fn();
    render(
      <Tabs
        items={[
          { id: "a", label: "A" },
          { id: "b", label: "B" },
          { id: "c", label: "C" },
        ]}
        active="a"
        onChange={onChange}
        label="Test"
        idPrefix="t"
      />,
    );
    const [a, b] = screen.getAllByRole("tab");
    expect(a).toHaveAttribute("tabindex", "0");
    expect(b).toHaveAttribute("tabindex", "-1");
    fireEvent.keyDown(a, { key: "End" });
    expect(onChange).toHaveBeenLastCalledWith("c");
  });
});

describe("command palette (item 123)", () => {
  it("opens from the store and runs an action", async () => {
    mockApi(() => ({}));
    render(<CommandPalette />);
    act(() => useUi.getState().setPaletteOpen(true));
    const input = await screen.findByPlaceholderText(/Type a command/);
    await userEvent.type(input, "Strings");
    await userEvent.keyboard("{Enter}");
    expect(useUi.getState().workspaceTab).toBe("strings");
    expect(useUi.getState().paletteOpen).toBe(false);
  });

  it("finds functions server-side and jumps to them", async () => {
    const { calls } = mockApi(({ action, params }) =>
      action === "functions"
        ? {
            functions: [{ va: 0x4dda48, size: 32, name: "Player::Update" }],
            total: 900,
            matched: 1,
            filter: params.filter,
          }
        : { instructions: [] },
    );
    useDisasm.setState({ image: { ready: true, format: "elf" } });
    render(<CommandPalette />);
    act(() => useUi.getState().setPaletteOpen(true));
    await userEvent.type(await screen.findByPlaceholderText(/Type a command/), "Player");
    const item = await screen.findByText("Player::Update");
    await userEvent.click(item);
    expect(calls.find((c) => c.action === "functions")?.params.filter).toBe("Player");
    await waitFor(() => expect(useDisasm.getState().selected).toBe(0x4dda48));
  });

  it("searches the generated docs index and opens the page (item 85)", async () => {
    mockApi(() => ({}));
    render(<CommandPalette />);
    act(() => useUi.getState().setPaletteOpen(true));
    await userEvent.type(await screen.findByPlaceholderText(/Type a command/), "live memory");
    const item = await screen.findByText("Live memory");
    expect(screen.getByText("features/live-memory")).toBeInTheDocument();
    await userEvent.click(item);
    expect(helpMock.openHelp).toHaveBeenCalledWith("features/live-memory.html#live-memory");
  });
});

describe("scripts panel: snippets, completion, unsafe consent (68, 69, 70)", () => {
  const apiList = {
    functions: [
      { name: "slop.mem.read_hex", signature: "(addr, len) -> hex string", doc: "read" },
      { name: "slop.mem.read_bytes", signature: "(addr, len) -> string", doc: "raw" },
      { name: "slop.target.status", signature: "() -> status", doc: "target" },
    ],
  };

  it("offers the built-in examples and loads one into the editor", async () => {
    mockApi(({ action }) => (action === "list" ? { snippets: [] } : apiList));
    render(<ScriptsPanel />);
    const area = screen.getByRole("textbox", { name: "Lua script" }) as HTMLTextAreaElement;
    await userEvent.click(screen.getByRole("button", { name: "bp + wait" }));
    expect(area.value).toContain("slop.debugger.bp_set");
    await userEvent.click(screen.getByRole("button", { name: "find value" }));
    expect(area.value).toContain("slop.mem.scan");
  });

  it("completes slop.* names from script.api", async () => {
    mockApi(({ action }) => (action === "list" ? { snippets: [] } : apiList));
    render(<ScriptsPanel />);
    const area = screen.getByRole("textbox", { name: "Lua script" }) as HTMLTextAreaElement;
    await waitFor(() => expect(screen.queryByRole("listbox")).toBeNull());
    await userEvent.clear(area);
    await userEvent.type(area, "slop.me");
    const list = await screen.findByRole("listbox", { name: "slop completions" });
    expect(within(list).getByText("slop.mem.read_hex")).toBeInTheDocument();
    await userEvent.keyboard("{Enter}");
    expect(area.value).toBe("slop.mem.read_hex");
  });

  it("sends unsafe consent for one run only", async () => {
    const { calls } = mockApi(({ action, params }) =>
      action === "list"
        ? { snippets: [] }
        : action === "api"
          ? apiList
          : { ok: true, output: "", params },
    );
    render(<ScriptsPanel />);
    const consent = screen.getByRole("checkbox", { name: "Allow unsafe for this run" });
    await userEvent.click(consent);
    expect(consent).toBeChecked();
    await userEvent.click(screen.getByRole("button", { name: "Run (Ctrl+Enter)" }));
    await waitFor(() => expect(calls.some((c) => c.action === "run")).toBe(true));
    const run = calls.find((c) => c.action === "run");
    expect(run?.params.unsafe).toBe(true);
    expect(run?.params.confirm).toBe(true);
    // consent does not stick: the next run is sandboxed again
    await waitFor(() => expect(consent).not.toBeChecked());
  });

  it("lists saved snippets and loads one into the editor", async () => {
    const { calls } = mockApi(({ action, params }) => {
      if (action === "api") return apiList;
      if (action === "list") return { snippets: [{ name: "mine" }] };
      if (action === "load") return { name: params.name, code: "return 7" };
      return { ok: true };
    });
    render(<ScriptsPanel />);
    const item = await screen.findByRole("button", { name: "mine" });
    await userEvent.click(item);
    const area = screen.getByRole("textbox", { name: "Lua script" }) as HTMLTextAreaElement;
    await waitFor(() => expect(area.value).toBe("return 7"));

    await userEvent.type(screen.getByRole("textbox", { name: "Snippet name" }), "saved-one");
    await userEvent.click(screen.getByRole("button", { name: "Save snippet" }));
    await waitFor(() => expect(calls.some((c) => c.action === "save")).toBe(true));
    expect(calls.find((c) => c.action === "save")?.params.name).toBe("saved-one");
  });
});

// disasm.blocks / xray.cfg graph shape: nodes carry the range and an
// instruction count, edges the successor kind
const cfgFixture = {
  nodes: [
    { id: 0x1000, start: 0x1000, end: 0x1010, size: 16, insn_count: 3, summary: "test eax, eax" },
    { id: 0x1010, start: 0x1010, end: 0x1020, size: 16, insn_count: 2, summary: "mov ecx, 4" },
    { id: 0x1020, start: 0x1020, end: 0x1030, size: 16, insn_count: 5, summary: "call memcpy" },
    { id: 0x1030, start: 0x1030, end: 0x1038, size: 8, insn_count: 1, summary: "ret" },
  ],
  edges: [
    { from: 0x1000, to: 0x1010, kind: "fallthrough" },
    { from: 0x1000, to: 0x1020, kind: "branch" },
    { from: 0x1010, to: 0x1030, kind: "fallthrough" },
    { from: 0x1020, to: 0x1030, kind: "branch" },
    { from: 0x1030, to: 0x1000, kind: "branch" },
  ],
};

describe("pseudocode view (audit 52)", () => {
  const decompFixture = {
    signature: "int Player::Update(int arg_10)",
    callconv: "win64",
    function_va: 0x4dda48,
    insn_count: 12,
    call_sites: [{ va: 0x4ddb00, arg_types: ["int", "char *"] }],
    types_generation: 7,
    lines: [
      { va: 0x4dda48, text: "if (arg_10 == 0x10) {" },
      { va: 0, text: "  return memcpy(dst, src, 4);" },
      { va: 0x4dda60, text: "} // done" },
    ],
  };

  it("highlights tokens and follows a function name into the listing", async () => {
    const { calls } = mockApi(({ tool, action }) => {
      if (tool === "decomp") return decompFixture;
      if (action === "blocks") return { entry: 0x4dda48, graph: cfgFixture };
      if (action === "functions")
        return {
          functions: [{ va: 0x4d0000, size: 32, name: "memcpy" }],
          total: 1,
          matched: 1,
        };
      return { instructions: [] };
    });
    useDisasm.setState({ selected: 0x4dda48, image: { ready: true, format: "elf" } });
    const { container } = render(<DecompView />);

    await waitFor(() => expect(container.querySelector(".decomp-kw")?.textContent).toBe("if"));
    expect(container.querySelector(".decomp-num")?.textContent).toBe("0x10");
    expect(container.querySelector(".decomp-com")?.textContent).toBe("// done");
    expect(container.querySelector(".decomp-meta")?.textContent).toContain("types gen 7");
    expect(container.querySelector(".decomp-meta")?.textContent).toContain("12 insns");
    expect(screen.getByRole("button", { name: "call site 004DDB00" })).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "go to memcpy" }));
    await waitFor(() => expect(useDisasm.getState().selected).toBe(0x4d0000));
    expect(useUi.getState().workspaceTab).toBe("disassembly");
    expect(calls.find((c) => c.action === "functions")?.params.filter).toBe("memcpy");
  });

  it("shows the CFG beside the code and jumps to a block", async () => {
    mockApi(({ tool, action }) => {
      if (tool === "decomp") return decompFixture;
      if (action === "blocks") return { entry: 0x4dda48, graph: cfgFixture };
      return { instructions: [] };
    });
    useDisasm.setState({ selected: 0x4dda48, image: { ready: true, format: "elf" } });
    const { container } = render(<DecompView />);
    await userEvent.click(screen.getByRole("button", { name: "Control-flow graph" }));
    await waitFor(() => expect(container.querySelectorAll(".cfg-node")).toHaveLength(4));
    expect(container.querySelectorAll(".cfg-edge")).toHaveLength(5);

    await userEvent.click(screen.getByRole("button", { name: /^block 00001020/ }));
    await waitFor(() => expect(useDisasm.getState().selected).toBe(0x1020));
    expect(useUi.getState().workspaceTab).toBe("disassembly");
  });
});

describe("CFG graph layout", () => {
  it("draws one box per block, one edge per successor, one column per depth", () => {
    const onPick = vi.fn();
    const { container } = render(<CfgGraph graph={cfgFixture} entry={0x1000} onPick={onPick} />);
    const boxes = [...container.querySelectorAll<HTMLElement>(".cfg-node")];
    expect(boxes).toHaveLength(4);
    expect(container.querySelectorAll(".cfg-edge")).toHaveLength(5);
    expect(container.querySelectorAll('.cfg-edge[data-edge="fallthrough"]')).toHaveLength(2);

    // 0x1010 and 0x1020 are both one hop from the entry: same column
    const left = (va: number) =>
      boxes.find((b) => b.getAttribute("aria-label")?.includes(hex(va, 8)))?.style.left;
    expect(left(0x1010)).toBe(left(0x1020));
    expect(left(0x1000)).not.toBe(left(0x1010));

    fireEvent.click(screen.getByRole("button", { name: /^block 00001020/ }));
    expect(onPick).toHaveBeenCalledWith(0x1020);
  });

  it("has an empty state and refuses more than 500 blocks", () => {
    const { container, rerender } = render(<CfgGraph graph={null} onPick={vi.fn()} />);
    expect(screen.getByText("No control-flow graph.")).toBeInTheDocument();

    const nodes = Array.from({ length: 501 }, (_, i) => ({
      id: 0x1000 + i * 0x10,
      start: 0x1000 + i * 0x10,
      end: 0x1010 + i * 0x10,
      size: 16,
      insn_count: 2,
    }));
    rerender(<CfgGraph graph={{ nodes, edges: [] }} onPick={vi.fn()} />);
    expect(screen.getByText("Too many blocks (501).")).toBeInTheDocument();
    expect(container.querySelectorAll(".cfg-node")).toHaveLength(0);
  });

  it("opens the CFG from the palette", async () => {
    mockApi(() => ({}));
    useDisasm.setState({ image: { ready: true, format: "elf" } });
    render(<CommandPalette />);
    act(() => useUi.getState().setPaletteOpen(true));
    await userEvent.type(await screen.findByPlaceholderText(/Type a command/), "CFG");
    await userEvent.keyboard("{Enter}");
    expect(useUi.getState().workspaceTab).toBe("decomp");
    expect(useDecomp.getState().split).toBe(true);
  });
});

describe("struct editor (item 114)", () => {
  it("adds and removes members through the engine catalog", async () => {
    const fields = [{ name: "hp", type: "u32", offset: 0, size: 4, array_count: 0 }];
    const def = () => ({
      name: "Player",
      size: fields.length * 4,
      packed: false,
      fields: [...fields],
    });
    const { calls } = mockApi(({ tool, action, params }) => {
      if (tool !== "types") return {};
      if (action === "list_structs") return { structs: [def()], count: 1 };
      if (action === "list_enums") return { enums: [], count: 0 };
      if (action === "get_struct") return def();
      if (action === "add_member") {
        fields.push({
          name: String(params.field),
          type: String(params.type),
          offset: fields.length * 4,
          size: 4,
          array_count: 0,
        });
        return def();
      }
      if (action === "declare") {
        // the test only removes members, so the rebuilt struct is empty
        fields.splice(0, fields.length);
        return { declared: 1 };
      }
      return {};
    });
    render(<StructEditor />);
    await screen.findByRole("button", { name: /^Player/ });
    await userEvent.type(screen.getByLabelText("Member name"), "mp");
    await userEvent.click(screen.getByRole("button", { name: "add member" }));
    await waitFor(() =>
      expect(calls.some((c) => c.action === "add_member" && c.params.field === "mp")).toBe(true),
    );
    await screen.findByText("mp");
    expect(screen.getByText(/decompiler cache invalidated/)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Remove member mp" }));
    await waitFor(() =>
      expect(
        calls.some((c) => c.action === "declare" && !String(c.params.decl).includes("mp")),
      ).toBe(true),
    );
    await waitFor(() => expect(screen.queryByText("mp")).not.toBeInTheDocument());
  });
});

describe("unpacker view (item 112)", () => {
  it("shows the journal and reverts it behind an explicit button", async () => {
    let reverted = false;
    const { calls } = mockApi(({ tool, action }) => {
      if (tool === "analyze" && action === "packer")
        return {
          image: "eboot.bin",
          packed: true,
          family: "upx",
          confidence: 0.9,
          file_entropy: 7.4,
          detections: [{ type: "section", protector: "UPX", detail: "UPX0", location: "UPX0" }],
          sections: [
            { name: "UPX0", rva: 0x1000, raw_size: 0x200, entropy: 7.9, writable_exec: true },
          ],
        };
      if (tool === "patch" && action === "journal")
        return reverted
          ? { patches: [], total: 0 }
          : { patches: [{ va: 0x401000, before: 0x90, after: 0xcc }], total: 1 };
      if (tool === "patch" && action === "revert_all") {
        reverted = true;
        return { ok: true, bytes_changed: 1, journal_total: 0 };
      }
      return {};
    });
    render(<UnpackerView />);
    expect(await screen.findByText("000000401000")).toBeInTheDocument();
    expect(screen.getByText("packed")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /revert all/ }));
    await waitFor(() => expect(calls.some((c) => c.action === "revert_all")).toBe(true));
    expect(await screen.findByText("no edits recorded")).toBeInTheDocument();
  });
});

describe("memory snapshot diff (item 83)", () => {
  it("highlights changed bytes from a fixture diff", async () => {
    mockApi(({ tool, action }) => {
      if (tool === "target" && action === "regions")
        return { regions: [{ base: 0x400000, size: 0x10000, protect: 4, state: 0x1000, type: 0 }] };
      if (tool === "memory" && action === "snapshots")
        return {
          snapshots: [
            { id: 1, addr: 0x400000, size: 0x1000, bytes: 0x1000, complete: true },
            { id: 2, addr: 0x400000, size: 0x1000, bytes: 0x1000, complete: true },
          ],
        };
      if (tool === "memory" && action === "diff")
        return { changed: [{ offset: 1, length: 2 }], count: 1, truncated: false };
      if (tool === "memory" && action === "read") return { hex: "90".repeat(0x1000) };
      return {};
    });
    useEngine.setState({ target: attached });
    const { container } = render(<MemoryView />);
    await userEvent.click(screen.getByRole("button", { name: "Snapshot diff" }));
    const compare = await screen.findByRole("button", { name: "compare" });
    await waitFor(() => expect(compare).toBeEnabled());
    await userEvent.click(compare);
    await waitFor(() =>
      expect(container.querySelectorAll('.hex-cell[data-diff="true"]').length).toBe(2),
    );
  });
});

describe("memory caret inspector (item 83)", () => {
  it("formats the caret bytes and the selected struct at that address", async () => {
    mockApi(({ tool, action }) => {
      if (tool === "target" && action === "regions")
        return { regions: [{ base: 0x400000, size: 0x10000, protect: 4, state: 0x1000, type: 0 }] };
      if (tool === "memory" && action === "read")
        return { hex: "4142434400000000" + "00".repeat(8) };
      if (tool === "types" && action === "format_at")
        return {
          ok: true,
          addr: 0x400000,
          type: "Player",
          source: "file",
          rendered: "Player { hp: 65 }",
        };
      return {};
    });
    useEngine.setState({ target: attached });
    useTypes.setState({ selected: "Player" });
    render(<MemoryView />);
    // 41 42 43 44 little-endian u32 (u64 shares the same digits here)
    await screen.findByText("ABCD");
    expect(screen.getByText("u32").closest(".mem-value")?.textContent).toContain("1145258561");
    expect(await screen.findByText("Player { hp: 65 }")).toBeInTheDocument();
  });
});

describe("xray panel", () => {
  it("renders pass rows with severity and jumps to the address", async () => {
    const { calls } = mockApi(({ action }) =>
      action === "hooks"
        ? {
            hooks: [
              { address: 0x401000, hook_type: "jmp", target: 0x500000, prologue_bytes: "E9" },
            ],
            functions_checked: 12,
            hooks_found: 1,
            source: "index",
          }
        : {},
    );
    useDisasm.setState({ image: { ready: true, name: "eboot.bin", format: "elf" } });
    render(<XrayPanel />);
    await userEvent.click(screen.getByRole("button", { name: "Hooks" }));
    expect(await screen.findByText("jmp")).toBeInTheDocument();
    expect(screen.getByText(/1 hooks in 12 functions/)).toBeInTheDocument();
    const row = screen.getByText("jmp").closest("tr");
    expect(row).toHaveAttribute("data-severity", "bad");
    await userEvent.click(screen.getByRole("button", { name: "0x401000" }));
    expect(useUi.getState().workspaceTab).toBe("disassembly");
    expect(calls.some((c) => c.tool === "xray" && c.action === "hooks")).toBe(true);
  });
});

describe("patch panel", () => {
  it("lists the journal and reverts after a confirm", async () => {
    const { calls } = mockApi(({ action }) =>
      action === "journal"
        ? {
            patches: [{ va: 0x401000, before: 0x90, after: 0xcc }],
            total: 1,
            indexes_dirty: false,
          }
        : { ok: true, bytes_changed: 1, journal_total: 0, patches: [] },
    );
    render(<PatchPanel />);
    expect(await screen.findByText("401000")).toBeInTheDocument();
    expect(screen.getByText("90")).toBeInTheDocument();
    expect(screen.getByText("CC")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Revert all…" }));
    expect(screen.getByRole("alertdialog", { name: "Confirm patch" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Confirm Revert all" }));
    await waitFor(() => expect(calls.some((c) => c.action === "revert_all")).toBe(true));
  });
});

describe("network panel", () => {
  const status = {
    capture_running: true,
    capture_filter: { host: "", port: 0, protocol: 0 },
    store_packets: 1,
    proxy_running: false,
    proxy_port: 0,
    proxy_mitm: false,
  };

  it("shows captured packets and exports a pcap", async () => {
    const { calls } = mockApi(({ action }) => {
      if (action === "status") return status;
      if (action === "packets")
        return {
          packets: [
            {
              id: 1,
              at_ms: 1000,
              protocol: 6,
              protocol_str: "tcp",
              direction: 0,
              direction_str: "outbound",
              ip_version: 4,
              local: "10.0.0.5:1234",
              remote: "1.2.3.4:80",
              payload_bytes: 10,
              wire_bytes: 54,
            },
          ],
          last_id: 1,
        };
      if (action === "export_pcap") return { exported: true, packets: 1 };
      return {};
    });
    render(<NetworkPanel />);
    expect(await screen.findByText("10.0.0.5:1234")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Export PCAP…" }));
    await waitFor(() => expect(calls.some((c) => c.action === "export_pcap")).toBe(true));
    expect(await screen.findByText(/1 packets written/)).toBeInTheDocument();
  });

  it("shows an Administrator error verbatim", async () => {
    mockApi(({ action }) => {
      if (action === "status") return { ...status, capture_running: false };
      if (action === "capture_start")
        throw new Error("capture needs Administrator: run reverse-slop elevated");
      return {};
    });
    render(<NetworkPanel />);
    await userEvent.click(screen.getByRole("button", { name: "Start capture" }));
    expect(await screen.findByText(/capture needs Administrator/)).toBeInTheDocument();
  });
});

describe("emulator panel", () => {
  it("renders a run result and the backward slice", async () => {
    const { calls } = mockApi(({ action }) => {
      if (action === "run")
        return {
          ok: true,
          stopped_reason: "count",
          instructions: 1,
          arch: "x64",
          abi: "win64",
          regs: { rip: 0x1000, rax: 0 },
          trace: [{ ip: 0x1000, text: "nop" }],
          trace_id: 3,
        };
      if (action === "slice")
        return { trace_id: 3, count: 1, instructions: [{ ip: 0x1000, text: "nop" }] };
      return {};
    });
    render(<EmulatorPanel />);
    await userEvent.type(screen.getByLabelText("Code bytes (hex)"), "90");
    await userEvent.click(screen.getByRole("button", { name: "Run" }));
    expect(await screen.findByText(/count · 1 instructions/)).toBeInTheDocument();
    expect(screen.getByText("rip")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Slice" }));
    await waitFor(() => expect(calls.some((c) => c.action === "slice")).toBe(true));
    expect(await screen.findByText(/1 instructions for trace 3/)).toBeInTheDocument();
  });
});

describe("PS5 connect", () => {
  it("auto-connects and shows the console firmware", async () => {
    const { calls } = mockApi(({ action }) => {
      if (action === "status")
        return {
          ps5: {
            endpoint: "10.0.0.9:744",
            branding: "ps5debug-NG",
            server_version: "1.0",
            caps: "0x3",
            fw: "3.00",
            platform: "ps5",
            connected: true,
            lost: false,
            lost_reason: "",
            drops: 0,
            debug_attached: false,
            debug_pid: 0,
          },
        };
      if (action === "ps5_auto")
        return { connected: true, pid: 5, name: "game.elf", debug_attached: true };
      return {};
    });
    useEngine.setState({ backend: { badge: "user", ps4: false } });
    render(<TargetsPanel />);
    expect(await screen.findByText(/fw 3\.00/)).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("PS5 IP address"), "10.0.0.9");
    await userEvent.click(screen.getByRole("button", { name: "Auto connect" }));
    await waitFor(() =>
      expect(calls.some((c) => c.action === "ps5_auto" && c.params.host === "10.0.0.9")).toBe(true),
    );
    expect(await screen.findByText(/pid 5 game\.elf/)).toBeInTheDocument();
  });
});
