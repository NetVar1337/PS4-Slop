import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import CommandPalette from "@/components/CommandPalette";
import SettingsModal from "@/components/SettingsModal";
import Splash from "@/components/Splash";
import Splitter from "@/components/Splitter";
import StatusBar from "@/components/StatusBar";
import Tabs from "@/components/Tabs";
import DebuggerView from "@/components/panels/DebuggerView";
import InspectorPanel from "@/components/panels/InspectorPanel";
import MemoryView from "@/components/panels/MemoryView";
import ScannerPanel from "@/components/panels/ScannerPanel";
import ScriptsPanel from "@/components/panels/ScriptsPanel";
import StringsView from "@/components/panels/StringsView";
import TargetsPanel from "@/components/panels/TargetsPanel";
import WorkspacePanel from "@/components/panels/WorkspacePanel";
import { setEndpoint } from "@/lib/rpc";
import { useDebugger } from "@/store/debugger";
import { useDisasm } from "@/store/disasm";
import { useEngine } from "@/store/engine";
import { useMemory } from "@/store/memory";
import { useSettings } from "@/store/settings";
import { useTargets } from "@/store/targets";
import { useUi } from "@/store/ui";
import { useWatch } from "@/store/watch";
import { mockApi } from "@/test/api";

const initial = {
  engine: useEngine.getState(),
  disasm: useDisasm.getState(),
  targets: useTargets.getState(),
  memory: useMemory.getState(),
  watch: useWatch.getState(),
  ui: useUi.getState(),
  debugger: useDebugger.getState(),
  settings: useSettings.getState(),
};

beforeEach(() => {
  useEngine.setState(initial.engine, true);
  useDisasm.setState(initial.disasm, true);
  useTargets.setState(initial.targets, true);
  useMemory.setState(initial.memory, true);
  useWatch.setState(initial.watch, true);
  useUi.setState(initial.ui, true);
  useDebugger.setState(initial.debugger, true);
  useSettings.setState(initial.settings, true);
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
});
