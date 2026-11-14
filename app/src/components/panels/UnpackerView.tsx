// app/src/components/panels/UnpackerView.tsx
// Unpacker parity with the ImGui shell for the static patch passes: the
// packer verdict from analyze, the mutating patch actions (unpack_xor,
// decode_strings, full_pass) behind explicit buttons, and the edit journal
// with revert_all. Read-mostly: every run reports the journal delta so the
// user can see exactly what it wrote

import { useCallback, useEffect, useState } from "react";
import { Play, RefreshCw, Undo2 } from "lucide-react";
import IconButton from "@/components/IconButton";
import { hex, parseAddress } from "@/lib/format";
import { call, errorText } from "@/lib/rpc";
import { useDisasm } from "@/store/disasm";

type PackerVerdict = {
  image: string;
  packed: boolean;
  family: string;
  confidence: number;
  file_entropy: number;
  detections: { type: string; protector: string; detail: string; location: string }[];
  sections: {
    name: string;
    rva: number;
    raw_size: number;
    entropy: number;
    writable_exec: boolean;
  }[];
  hype_packer?: { name: string; confidence: number; details: string }[];
};

type JournalRec = { va: number; before: number; after: number };

type RunResult = {
  ok: boolean;
  dry_run: boolean;
  bytes_changed: number;
  journal_total: number;
  detected_key?: number;
  key_confidence?: number;
  strings_found?: number;
  score_reduction?: number;
  steps?: { step: string; success: boolean; note: string }[];
};

const kMethods = ["auto", "xor_single", "xor_multi", "xor_rolling"];

export default function UnpackerView() {
  const image = useDisasm((s) => s.image);
  const [packer, setPacker] = useState<PackerVerdict | null>(null);
  const [journal, setJournal] = useState<JournalRec[]>([]);
  const [total, setTotal] = useState(0);
  const [addr, setAddr] = useState("");
  const [size, setSize] = useState("4096");
  const [method, setMethod] = useState("auto");
  const [keyHex, setKeyHex] = useState("");
  const [dryRun, setDryRun] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [last, setLast] = useState<RunResult | null>(null);

  const loadJournal = useCallback(async () => {
    try {
      const res = await call<{ patches: JournalRec[]; total: number }>("patch", "journal", {
        limit: 200,
      });
      setJournal(res.patches ?? []);
      setTotal(res.total ?? 0);
    } catch (e) {
      setError(errorText(e));
    }
  }, []);

  const loadPacker = useCallback(async () => {
    try {
      setPacker(await call<PackerVerdict>("analyze", "packer"));
    } catch (e) {
      setError(errorText(e));
    }
  }, []);

  useEffect(() => {
    void loadJournal();
    void loadPacker();
  }, [loadJournal, loadPacker]);

  // a newly loaded image moves the default address to its entry point
  useEffect(() => {
    const va = image.entry_va ?? image.base;
    if (va !== undefined) setAddr(`0x${hex(va, 8)}`);
  }, [image.entry_va, image.base]);

  const run = async (action: "unpack_xor" | "decode_strings" | "full_pass") => {
    const va = parseAddress(addr);
    if (va === null) {
      setError("bad address");
      return;
    }
    const before = total;
    setBusy(true);
    setError(null);
    setNote(null);
    setLast(null);
    try {
      const params: Record<string, unknown> =
        action === "unpack_xor"
          ? {
              addr: va,
              size: Math.max(1, Number.parseInt(size, 10) || 4096),
              method,
              ...(keyHex.trim() === "" ? {} : { key_hex: keyHex.trim() }),
            }
          : action === "full_pass"
            ? { addr: va, dry_run: dryRun }
            : { addr: va };
      const res = await call<RunResult>("patch", action, params);
      setLast(res);
      setNote(
        `${action}: ${res.bytes_changed} bytes changed · journal ${before} → ${res.journal_total}`,
      );
      await loadJournal();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const revert = async () => {
    const before = total;
    setBusy(true);
    setError(null);
    setNote(null);
    setLast(null);
    try {
      const res = await call<RunResult>("patch", "revert_all");
      setNote(`revert_all: restored ${res.bytes_changed} bytes · journal ${before} → 0`);
      await loadJournal();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="unpacker">
      <div className="stack">
        <div className="view-bar">
          <span className="panel-title">Packer</span>
          <div className="spacer" />
          <IconButton tip="Re-run packer analysis" onClick={() => void loadPacker()}>
            <RefreshCw size={13} />
          </IconButton>
        </div>
        <div className="panel-body unpacker-verdict">
          {packer === null ? (
            <div className="faint">analyzing…</div>
          ) : (
            <>
              <div>
                <span className={packer.packed ? "unpacker-packed" : "unpacker-clean"}>
                  {packer.packed ? "packed" : "not packed"}
                </span>
                <span className="faint">
                  {" "}
                  · {packer.family || "unknown family"} · confidence{" "}
                  {(packer.confidence * 100).toFixed(0)}% · file entropy{" "}
                  {packer.file_entropy.toFixed(2)}
                </span>
              </div>
              {packer.detections.map((d) => (
                <div key={`${d.type}:${d.location}`} className="unpacker-row">
                  <span className="mono">{d.type}</span>
                  <span>{d.protector}</span>
                  <span className="faint">{d.detail}</span>
                  <span className="faint mono">{d.location}</span>
                </div>
              ))}
              {packer.hype_packer?.map((h) => (
                <div key={h.name} className="unpacker-row">
                  <span className="mono">hyperion</span>
                  <span>{h.name}</span>
                  <span className="faint">
                    {(h.confidence * 100).toFixed(0)}% {h.details}
                  </span>
                </div>
              ))}
              <div className="unpacker-row faint">
                {packer.sections
                  .filter((s) => s.entropy > 7)
                  .map((s) => `${s.name} entropy ${s.entropy.toFixed(2)}`)
                  .join(" · ") || "no high-entropy sections"}
              </div>
            </>
          )}
        </div>
      </div>

      <div className="stack">
        <div className="view-bar">
          <span className="panel-title">Passes</span>
          <div className="spacer" />
          <button
            type="button"
            className="row-action"
            disabled={busy || total === 0}
            onClick={() => void revert()}
          >
            <Undo2 size={11} /> revert all
          </button>
        </div>
        <div className="panel-body unpacker-options">
          <label className="view-label">
            addr
            <input
              className="addr-input mono"
              aria-label="Pass address"
              placeholder="0x400000"
              value={addr}
              onChange={(e) => setAddr(e.target.value)}
            />
          </label>
          <label className="view-label">
            size
            <input
              className="addr-input mono"
              style={{ width: 76 }}
              aria-label="XOR region size"
              value={size}
              onChange={(e) => setSize(e.target.value)}
            />
          </label>
          <label className="view-label">
            method
            <select
              className="select"
              aria-label="XOR method"
              value={method}
              onChange={(e) => setMethod(e.target.value)}
            >
              {kMethods.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          </label>
          <label className="view-label">
            key
            <input
              className="addr-input mono"
              aria-label="XOR key hex"
              placeholder="auto"
              value={keyHex}
              onChange={(e) => setKeyHex(e.target.value)}
            />
          </label>
          <label className="view-label">
            <input
              type="checkbox"
              aria-label="Dry run"
              checked={dryRun}
              onChange={(e) => setDryRun(e.target.checked)}
            />
            dry run
          </label>
          <div className="unpacker-buttons">
            <button
              type="button"
              className="row-action"
              disabled={busy}
              onClick={() => void run("unpack_xor")}
            >
              <Play size={11} /> unpack xor
            </button>
            <button
              type="button"
              className="row-action"
              disabled={busy}
              onClick={() => void run("decode_strings")}
            >
              <Play size={11} /> decode strings
            </button>
            <button
              type="button"
              className="row-action"
              disabled={busy}
              onClick={() => void run("full_pass")}
            >
              <Play size={11} /> full pass
            </button>
          </div>
          {error !== null && (
            <div className="error-text" role="alert">
              {error}
            </div>
          )}
          {note !== null && (
            <div className="unpacker-note" role="status">
              {note}
            </div>
          )}
          {last?.steps !== undefined && (
            <div className="unpacker-steps">
              {last.steps.map((s) => (
                <div key={s.step} className="unpacker-row">
                  <span className="mono">{s.step}</span>
                  <span className={s.success ? "unpacker-clean" : "error-text"}>
                    {s.success ? "ok" : "failed"}
                  </span>
                  <span className="faint">{s.note}</span>
                </div>
              ))}
              {last.score_reduction !== undefined && (
                <div className="faint">obfuscation score reduced by {last.score_reduction}</div>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="stack">
        <div className="view-bar">
          <span className="panel-title">Journal</span>
          <div className="spacer" />
          <span className="faint">{total}</span>
          <IconButton tip="Reload journal" onClick={() => void loadJournal()}>
            <RefreshCw size={13} />
          </IconButton>
        </div>
        <div className="panel-body mono unpacker-journal">
          {journal.length === 0 && <div className="faint">no edits recorded</div>}
          {journal.map((p) => (
            <div key={p.va} className="unpacker-row">
              <span className="insn-va">{hex(p.va, 12)}</span>
              <span className="faint">{p.before.toString(16).padStart(2, "0").toUpperCase()}</span>
              <span>→</span>
              <span>{p.after.toString(16).padStart(2, "0").toUpperCase()}</span>
            </div>
          ))}
          {total > journal.length && (
            <div className="faint">… {total - journal.length} older edits</div>
          )}
        </div>
      </div>
    </div>
  );
}
