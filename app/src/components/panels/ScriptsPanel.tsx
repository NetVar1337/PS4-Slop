// app/src/components/panels/ScriptsPanel.tsx
// Lua scratchpad over the `script.run` tool, the engine's embedded interpreter
// with the core bindings

import { useState } from "react";
import { Play, Trash2 } from "lucide-react";
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

type Run = { ok: boolean; output: string; error?: string; ms: number };

export default function ScriptsPanel() {
  const [code, setCode] = useState(kSampleScript);
  const [runs, setRuns] = useState<Run[]>([]);
  const [busy, setBusy] = useState(false);

  const run = async () => {
    if (busy) return;
    setBusy(true);
    const started = Date.now();
    try {
      const res = await call<{ ok: boolean; output: string; error?: string }>(
        "script",
        "run",
        { code, timeout_ms: kScriptTimeoutMs },
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
    }
  };

  return (
    <div className="panel">
      <div className="panel-head">
        <span className="panel-title">Scripts</span>
        <div className="spacer" />
        <IconButton tip="Clear output" onClick={() => setRuns([])}>
          <Trash2 size={14} />
        </IconButton>
        <IconButton tip="Run (Ctrl+Enter)" disabled={busy} onClick={() => void run()}>
          <Play size={14} />
        </IconButton>
      </div>

      <div className="scripts-body">
        <textarea
          className="code-area mono"
          aria-label="Lua script"
          value={code}
          spellCheck={false}
          onChange={(e) => setCode(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
              e.preventDefault();
              void run();
            }
          }}
        />
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
  );
}
