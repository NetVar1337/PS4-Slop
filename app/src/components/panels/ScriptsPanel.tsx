// app/src/components/panels/ScriptsPanel.tsx
// Lua scratchpad over the `script.run` tool, the engine's embedded interpreter
// with the core bindings. Snippets live in the engine (<app_data>\scripts), so
// the same names show up for the MCP script tool; completion comes from
// script.api, which the engine generates from its registration tables.

import { useCallback, useEffect, useRef, useState, type KeyboardEvent } from "react";
import { Play, Save, Trash2 } from "lucide-react";
import IconButton from "@/components/IconButton";
import { call, errorText } from "@/lib/rpc";

const kScriptTimeoutMs = 10_000;

export const kSampleScript = `-- engine Lua: the bindings the script tool exposes
local st = slop.target.status()
print("backend:", st.backend)
print("attached:", st.attached, st.name or "", st.pid or 0)
-- on a PS4 the running game is eboot.bin; SceShellUI / SceShellCore are system
for _, p in ipairs(slop.target.list()) do
  if p.name:find("eboot") or p.name:find("SceShell") then print(p.pid, p.name, p.arch) end
end
`;

/** Built-in examples (audit 68): the four workflows the docs promise. */
export const kExamples: readonly { name: string; code: string }[] = [
  {
    name: "find value",
    code: `-- first scan for a 4-byte value, then narrow it
local hits = slop.mem.scan({ kind = "exact", width = "i32", value = 100, alignment = 4 })
print("hits:", #hits)
for i = 1, math.min(#hits, 20) do print(string.format("0x%X", hits[i])) end
`,
  },
  {
    name: "dump module",
    code: `-- load the attached process's main module into the shared session
slop.image.load_from_target()
local st = slop.image.status()
print("module:", st.name, string.format("base=0x%X entry=0x%X", st.base, st.entry))
slop.image.wait_ready(30000)
print("functions:", slop.image.status().functions)
`,
  },
  {
    name: "decompile top functions",
    code: `-- largest functions of the loaded image, decompiled
slop.image.wait_ready(30000)
local fns = slop.disasm.functions(4000)
table.sort(fns, function(a, b) return a.size > b.size end)
for i = 1, 3 do
  local d = slop.decomp.decompile(fns[i].va)
  print(("-- %s (%d bytes) %s"):format(d.name, fns[i].size, d.signature))
  for _, l in ipairs(d.lines) do
    print(string.rep("  ", l.indent) .. l.text)
  end
end
`,
  },
  {
    name: "bp + wait",
    code: `-- console breakpoint + wait (slop.debugger, not slop.ps4)
local st = slop.target.status()
slop.debugger.attach(st.pid)
slop.debugger.bp_set(0x484490)
local ev = slop.debugger.wait(5000)
print(("stop: rip=0x%X thread=%s"):format(ev.rip, ev.thread))
`,
  },
];

type Run = { ok: boolean; output: string; error?: string; ms: number };
type ApiEntry = { name: string; signature: string; doc: string };
type Snippet = { name: string };

type Suggest = { items: ApiEntry[]; start: number; end: number };

/** The `slop.*` token the caret sits in, or null outside one. */
function tokenAt(text: string, caret: number): { token: string; start: number } | null {
  const m = /[A-Za-z0-9_.]+$/.exec(text.slice(0, caret));
  if (!m) return null;
  const token = m[0];
  if (!token.startsWith("slop")) return null;
  return { token, start: caret - token.length };
}

export default function ScriptsPanel() {
  const [code, setCode] = useState(kSampleScript);
  const [runs, setRuns] = useState<Run[]>([]);
  const [busy, setBusy] = useState(false);
  const [unsafe, setUnsafe] = useState(false);
  const [api, setApi] = useState<ApiEntry[]>([]);
  const [snippets, setSnippets] = useState<Snippet[]>([]);
  const [snippetName, setSnippetName] = useState("");
  const [suggest, setSuggest] = useState<Suggest | null>(null);
  const [sel, setSel] = useState(0);
  const areaRef = useRef<HTMLTextAreaElement>(null);

  const refreshSnippets = useCallback(
    () =>
      void call<{ snippets: Snippet[] }>("script", "list")
        .then((r) => setSnippets(r.snippets ?? []))
        .catch(() => setSnippets([])),
    [],
  );

  useEffect(() => {
    void call<{ functions: ApiEntry[] }>("script", "api")
      .then((r) => setApi(r.functions ?? []))
      .catch(() => setApi([]));
    refreshSnippets();
  }, [refreshSnippets]);

  const run = async () => {
    if (busy) return;
    setBusy(true);
    const started = Date.now();
    try {
      const res = await call<{ ok: boolean; output: string; error?: string }>(
        "script",
        "run",
        // unsafe is per-run consent: the flag resets after every run
        { code, timeout_ms: kScriptTimeoutMs, ...(unsafe ? { unsafe: true, confirm: true } : {}) },
        // the engine enforces the script timeout; leave it room to report
        { timeoutMs: kScriptTimeoutMs + 15_000 },
      );
      setRuns((r) => [...r.slice(-19), { ...res, ms: Date.now() - started }]);
    } catch (e) {
      setRuns((r) => [
        ...r.slice(-19),
        { ok: false, output: "", error: errorText(e), ms: Date.now() - started },
      ]);
    } finally {
      setBusy(false);
      setUnsafe(false);
    }
  };

  const updateSuggest = (text: string, caret: number) => {
    const tok = tokenAt(text, caret);
    if (!tok) {
      setSuggest(null);
      return;
    }
    const items = api
      .filter((e) => e.name.startsWith(tok.token) && e.name !== tok.token)
      .slice(0, 20);
    setSel(0);
    setSuggest(items.length > 0 ? { items, start: tok.start, end: caret } : null);
  };

  const accept = (entry: ApiEntry) => {
    if (!suggest) return;
    const at = suggest.start + entry.name.length;
    setCode(code.slice(0, suggest.start) + entry.name + code.slice(suggest.end));
    setSuggest(null);
    requestAnimationFrame(() => {
      const el = areaRef.current;
      if (!el) return;
      el.focus();
      el.setSelectionRange(at, at);
    });
  };

  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (suggest) {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setSel((s) => (s + 1) % suggest.items.length);
        return;
      }
      if (e.key === "ArrowUp") {
        e.preventDefault();
        setSel((s) => (s - 1 + suggest.items.length) % suggest.items.length);
        return;
      }
      if (e.key === "Enter" || e.key === "Tab") {
        e.preventDefault();
        accept(suggest.items[sel]);
        return;
      }
      if (e.key === "Escape") {
        e.preventDefault();
        setSuggest(null);
        return;
      }
    }
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      void run();
    }
  };

  const loadSnippet = (name: string) => {
    void call<{ code: string }>("script", "load", { name })
      .then((r) => setCode(r.code ?? ""))
      .catch((e) =>
        setRuns((r) => [...r.slice(-19), { ok: false, output: "", error: errorText(e), ms: 0 }]),
      );
  };

  const saveSnippet = () => {
    const name = snippetName.trim();
    if (!name) return;
    void call<{ ok: boolean }>("script", "save", { name, code })
      .then(() => {
        setSnippetName("");
        refreshSnippets();
      })
      .catch((e) =>
        setRuns((r) => [...r.slice(-19), { ok: false, output: "", error: errorText(e), ms: 0 }]),
      );
  };

  const deleteSnippet = (name: string) => {
    void call<{ ok: boolean }>("script", "delete", { name })
      .then(refreshSnippets)
      .catch((e) =>
        setRuns((r) => [...r.slice(-19), { ok: false, output: "", error: errorText(e), ms: 0 }]),
      );
  };

  return (
    <div className="panel">
      <div className="panel-head">
        <span className="panel-title">Scripts</span>
        <div className="spacer" />
        <label
          className="faint"
          style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 11 }}
          title="Runs this script with the full standard library and host-file actions. Consent lasts one run."
        >
          <input
            type="checkbox"
            aria-label="Allow unsafe for this run"
            checked={unsafe}
            onChange={(e) => setUnsafe(e.target.checked)}
          />
          unsafe
        </label>
        <IconButton tip="Clear output" onClick={() => setRuns([])}>
          <Trash2 size={14} />
        </IconButton>
        <IconButton tip="Run (Ctrl+Enter)" disabled={busy} onClick={() => void run()}>
          <Play size={14} />
        </IconButton>
      </div>

      <div style={{ display: "flex", minHeight: 0 }}>
        <aside
          aria-label="Snippets"
          style={{
            width: 170,
            flex: "0 0 auto",
            overflowY: "auto",
            padding: "var(--pad-sm)",
            borderRight: "1px solid var(--border-soft)",
            fontSize: 12,
          }}
        >
          <div className="faint" style={{ marginBottom: 4 }}>
            Examples
          </div>
          {kExamples.map((ex) => (
            <button
              key={ex.name}
              type="button"
              className="row-action"
              style={{ display: "block", width: "100%", textAlign: "left" }}
              onClick={() => setCode(ex.code)}
            >
              {ex.name}
            </button>
          ))}
          <div className="faint" style={{ margin: "var(--pad-sm) 0 4px" }}>
            Saved
          </div>
          {snippets.length === 0 ? (
            <div className="faint">none yet</div>
          ) : (
            snippets.map((s) => (
              <div key={s.name} style={{ display: "flex", alignItems: "center", gap: 2 }}>
                <button
                  type="button"
                  className="row-action"
                  style={{
                    flex: 1,
                    textAlign: "left",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                  }}
                  onClick={() => loadSnippet(s.name)}
                >
                  {s.name}
                </button>
                <IconButton tip={`Delete ${s.name}`} onClick={() => deleteSnippet(s.name)}>
                  <Trash2 size={12} />
                </IconButton>
              </div>
            ))
          )}
          <div style={{ display: "flex", gap: 2, marginTop: "var(--pad-sm)" }}>
            <input
              aria-label="Snippet name"
              placeholder="name"
              value={snippetName}
              onChange={(e) => setSnippetName(e.target.value)}
              style={{ minWidth: 0, flex: 1 }}
            />
            <IconButton tip="Save snippet" onClick={saveSnippet}>
              <Save size={12} />
            </IconButton>
          </div>
        </aside>

        <div className="scripts-body" style={{ flex: 1, minWidth: 0 }}>
          <div style={{ position: "relative", display: "flex", minHeight: 0 }}>
            <textarea
              ref={areaRef}
              className="code-area mono"
              aria-label="Lua script"
              value={code}
              spellCheck={false}
              onChange={(e) => {
                setCode(e.target.value);
                updateSuggest(e.target.value, e.target.selectionStart);
              }}
              onKeyDown={onKeyDown}
              onBlur={() => setSuggest(null)}
            />
            {suggest && (
              <div
                role="listbox"
                aria-label="slop completions"
                style={{
                  position: "absolute",
                  left: 8,
                  bottom: 8,
                  maxHeight: 140,
                  overflowY: "auto",
                  background: "var(--bg-1)",
                  border: "1px solid var(--border)",
                  borderRadius: 4,
                  fontSize: 11,
                  zIndex: 5,
                }}
              >
                {suggest.items.map((entry, i) => (
                  <div
                    key={entry.name}
                    role="option"
                    aria-selected={i === sel}
                    title={entry.doc}
                    style={{
                      padding: "2px 6px",
                      cursor: "pointer",
                      background: i === sel ? "var(--bg-2)" : "transparent",
                    }}
                    onMouseDown={(e) => {
                      e.preventDefault();
                      accept(entry);
                    }}
                  >
                    <span className="mono">{entry.name}</span>{" "}
                    <span className="faint">{entry.signature}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
          <div className="dbg-head" style={{ borderTop: "1px solid var(--border-soft)" }}>
            Output
            <div className="spacer" />
            <span className="faint" style={{ fontSize: 11 }}>
              {busy ? "running…" : `${runs.length} runs`}
            </span>
          </div>
          <div className="panel-body log" aria-live="polite">
            {runs.length === 0 ? (
              <div className="empty-hint">Ctrl+Enter to run.</div>
            ) : (
              runs.map((r, i) => (
                <div key={i} style={{ marginBottom: "var(--pad-sm)" }}>
                  <div className="log-row faint">
                    <span>{r.ok ? "ok" : "error"}</span>
                    <span>{r.ms}ms</span>
                  </div>
                  {r.output !== "" && <div className="log-row">{r.output}</div>}
                  {r.error !== undefined && r.error !== "" && (
                    <div className="log-row error-text">{r.error}</div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
