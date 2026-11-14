// app/src/components/panels/PatchPanel.tsx
// Image patch journal and the heuristic passes (tool: patch). Every mutating
// action is a button with a confirm step, and the journal delta is shown
// after each run

import { useCallback, useEffect, useState } from "react";
import { call, errorText } from "@/lib/rpc";
import { hex, parseAddress } from "@/lib/format";
import { useDisasm } from "@/store/disasm";

type JournalEntry = { va: number; before: number; after: number };
type JournalReply = { patches?: JournalEntry[]; total?: number; indexes_dirty?: boolean };
type PatchHit = { va: number; action: string; detail?: string };
type Step = { step: string; success: boolean; note: string };
type OpReply = {
  ok?: boolean;
  dry_run?: boolean;
  patches?: PatchHit[];
  bytes_changed?: number;
  journal_total?: number;
  detected_key?: number;
  key_confidence?: number;
  strings_found?: number;
  note?: string;
  steps?: Step[];
  pre_obfuscation_score?: number;
  post_obfuscation_score?: number;
  score_reduction?: number;
};

type Pending = { label: string; action: string; params: Record<string, unknown> };

const kPasses: readonly { action: string; label: string }[] = [
  { action: "nop_junk", label: "Nop junk" },
  { action: "resolve_opaque", label: "Resolve opaque" },
  { action: "patch_antidebug", label: "Patch anti-debug" },
  { action: "unpack_xor", label: "Unpack XOR" },
  { action: "decode_strings", label: "Decode strings" },
  { action: "full_pass", label: "Full pass" },
];

const kXorMethods = ["auto", "xor_single", "xor_multi", "xor_rolling"] as const;

export default function PatchPanel() {
  const selected = useDisasm((s) => s.selected);
  const [journal, setJournal] = useState<JournalEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [dirty, setDirty] = useState(false);
  const [addrText, setAddrText] = useState("");
  const [hexText, setHexText] = useState("");
  const [size, setSize] = useState("4096");
  const [keyHex, setKeyHex] = useState("");
  const [method, setMethod] = useState<string>(kXorMethods[0]);
  const [dryRun, setDryRun] = useState(false);
  const [aggressive, setAggressive] = useState(false);
  const [pending, setPending] = useState<Pending | null>(null);
  const [last, setLast] = useState<OpReply | null>(null);
  const [delta, setDelta] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refreshJournal = useCallback(async () => {
    try {
      const res = await call<JournalReply>("patch", "journal", { limit: 100 });
      setJournal(res.patches ?? []);
      setTotal(res.total ?? 0);
      setDirty(res.indexes_dirty === true);
    } catch (e) {
      setError(errorText(e));
    }
  }, []);

  useEffect(() => {
    void refreshJournal();
  }, [refreshJournal]);

  const addr = parseAddress(addrText) ?? selected ?? undefined;

  const runOp = async (action: string, params: Record<string, unknown>) => {
    setBusy(true);
    setError(null);
    const before = total;
    try {
      const res = await call<OpReply>("patch", action, params);
      setLast(res);
      setDelta((res.journal_total ?? before) - before);
      await refreshJournal();
    } catch (e) {
      setLast(null);
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const ask = (label: string, action: string, params: Record<string, unknown>) =>
    setPending({ label, action, params });

  const passParams = (action: string): Record<string, unknown> => {
    const params: Record<string, unknown> = {};
    if (addr !== undefined) params.addr = addr;
    if (action === "nop_junk") {
      params.aggressive = aggressive;
    }
    if (action === "resolve_opaque" || action === "patch_antidebug" || action === "full_pass") {
      params.dry_run = dryRun;
    }
    if (action === "unpack_xor") {
      const sizeValue = Number.parseInt(size, 10);
      if (Number.isFinite(sizeValue) && sizeValue > 0) params.size = sizeValue;
      params.method = method;
      if (keyHex.trim() !== "") params.key_hex = keyHex.trim();
    }
    return params;
  };

  return (
    <div className="panel tool-panel">
      <div className="panel-head">
        <span className="panel-title">Patch journal</span>
        <span className="faint" style={{ fontSize: "var(--type-small)" }}>
          {total} {total === 1 ? "entry" : "entries"}
        </span>
        {dirty && (
          <span className="pill sev-warn" data-tip="Indexes are stale until rebuilt">
            indexes dirty
          </span>
        )}
        <div className="spacer" />
        <button type="button" className="row-action" onClick={() => void refreshJournal()}>
          Refresh
        </button>
      </div>
      <div className="panel-body tool-body">
        <div className="tool-form">
          <input
            className="addr-input mono"
            style={{ width: 110 }}
            aria-label="Function address (hex)"
            placeholder={selected === null ? "function VA" : hex(selected, 1)}
            value={addrText}
            onChange={(e) => setAddrText(e.target.value)}
          />
          <label className="faint tool-field">
            size
            <input
              className="addr-input"
              style={{ width: 72 }}
              aria-label="XOR size"
              inputMode="numeric"
              value={size}
              onChange={(e) => setSize(e.target.value)}
            />
          </label>
          <label className="faint tool-field">
            <input
              type="checkbox"
              aria-label="Dry run"
              checked={dryRun}
              onChange={(e) => setDryRun(e.target.checked)}
            />
            dry run
          </label>
          <label className="faint tool-field">
            <input
              type="checkbox"
              aria-label="Aggressive nop"
              checked={aggressive}
              onChange={(e) => setAggressive(e.target.checked)}
            />
            aggressive
          </label>
          <select
            className="select"
            aria-label="XOR method"
            value={method}
            onChange={(e) => setMethod(e.target.value)}
          >
            {kXorMethods.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
          <input
            className="addr-input mono"
            style={{ width: 120 }}
            aria-label="XOR key (hex)"
            placeholder="key hex"
            value={keyHex}
            onChange={(e) => setKeyHex(e.target.value)}
          />
        </div>

        <div className="tool-grid" role="group" aria-label="Patch passes">
          {kPasses.map((p) => (
            <button
              type="button"
              key={p.action}
              className="row-action"
              disabled={busy || (addr === undefined && p.action !== "patch_antidebug")}
              onClick={() => ask(p.label, p.action, passParams(p.action))}
            >
              {p.label}
            </button>
          ))}
        </div>

        <form
          className="tool-form"
          aria-label="Write bytes"
          onSubmit={(e) => {
            e.preventDefault();
            if (addr === undefined || hexText.trim() === "") return;
            ask("Write bytes", "write_bytes", { addr, hex: hexText.trim() });
          }}
        >
          <input
            className="addr-input mono"
            style={{ width: 110 }}
            aria-label="Write address (hex)"
            placeholder="address"
            value={addrText}
            onChange={(e) => setAddrText(e.target.value)}
          />
          <input
            className="addr-input mono"
            style={{ flex: 1, minWidth: 140 }}
            aria-label="Bytes to write (hex)"
            placeholder="hex bytes, e.g. 90 90 C3"
            value={hexText}
            onChange={(e) => setHexText(e.target.value)}
          />
          <button
            type="submit"
            className="row-action"
            disabled={busy || addr === undefined || hexText.trim() === ""}
          >
            Write bytes…
          </button>
        </form>

        {pending !== null && (
          <div className="confirm-bar" role="alertdialog" aria-label="Confirm patch">
            <span>
              Apply {pending.label}? This edits the loaded image session
              {pending.action === "write_bytes" ? ` at ${hex(addr ?? 0, 1)}` : ""}.
            </span>
            <button
              type="button"
              className="row-action"
              onClick={() => {
                const p = pending;
                setPending(null);
                void runOp(p.action, p.params);
              }}
            >
              Confirm {pending.label}
            </button>
            <button type="button" className="row-action" onClick={() => setPending(null)}>
              Cancel
            </button>
          </div>
        )}

        <div className="tool-form">
          <button
            type="button"
            className="row-action"
            disabled={busy || total === 0}
            onClick={() => ask("Revert all", "revert_all", {})}
          >
            Revert all…
          </button>
          {busy && <span className="faint">Working…</span>}
        </div>

        {error !== null && (
          <div className="empty-hint error-text" role="alert">
            {error}
          </div>
        )}

        {last !== null && (
          <div className="tool-summary">
            <span className="faint">
              {last.dry_run === true ? "preview" : "applied"} · {last.bytes_changed ?? 0} bytes ·{" "}
              {delta >= 0 ? `+${delta}` : delta} journal
              {last.detected_key !== undefined
                ? ` · key ${hex(last.detected_key, 2)} (${last.key_confidence ?? 0}%)`
                : ""}
              {last.strings_found !== undefined ? ` · ${last.strings_found} strings` : ""}
              {last.score_reduction !== undefined
                ? ` · score ${last.pre_obfuscation_score ?? "?"} → ${
                    last.post_obfuscation_score ?? "?"
                  }`
                : ""}
            </span>
            {last.note !== undefined && <div className="faint">{last.note}</div>}
            {last.steps !== undefined && (
              <ul className="tool-steps">
                {last.steps.map((s) => (
                  <li key={s.step} data-ok={s.success}>
                    {s.step}: {s.success ? "ok" : "skipped"} {s.note}
                  </li>
                ))}
              </ul>
            )}
            {last.patches !== undefined && last.patches.length > 0 && (
              <ul className="tool-steps">
                {last.patches.map((p, i) => (
                  <li key={`${p.va}-${i}`} className="mono">
                    {hex(p.va, 1)} {p.action} {p.detail ?? ""}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        <table className="table">
          <caption className="sr-only">Patch journal</caption>
          <thead>
            <tr>
              <th scope="col">Address</th>
              <th scope="col">Before</th>
              <th scope="col">After</th>
            </tr>
          </thead>
          <tbody>
            {journal.map((p, i) => (
              <tr key={`${p.va}-${i}`}>
                <td className="mono">{hex(p.va, 1)}</td>
                <td className="mono">{hex(p.before, 2)}</td>
                <td className="mono">{hex(p.after, 2)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {journal.length === 0 && (
          <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
            No patches recorded.
          </div>
        )}
      </div>
    </div>
  );
}
