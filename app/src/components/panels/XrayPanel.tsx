// app/src/components/panels/XrayPanel.tsx
// Read-only static-analysis passes (tool: xray) over the selected function or
// the whole image, one compact table per pass. A row with an address jumps to
// that address in the listing

import { useState } from "react";
import { ScanSearch } from "lucide-react";
import CfgGraph from "@/components/CfgGraph";
import { hex, parseAddress } from "@/lib/format";
import { useDisasm } from "@/store/disasm";
import { useUi } from "@/store/ui";
import {
  kFunctionPasses,
  kHashAlgorithms,
  kXrayPasses,
  useXray,
  type XrayPass,
} from "@/store/xray";

const kRangePasses: readonly XrayPass[] = ["entropy", "pages", "crypto_range"];
const kLimitedPasses: readonly XrayPass[] = ["entropy", "pages", "crypto_range", "gadgets"];

const kLabels: Record<XrayPass, string> = {
  cfg: "CFG",
  complexity: "Complexity",
  cff: "Flattening",
  obfuscation: "Obfuscation",
  strings_recon: "String recon",
  indirect_calls: "Indirect calls",
  anti_analysis: "Anti-analysis",
  hooks: "Hooks",
  syscalls: "Syscalls",
  apihash: "API hashes",
  entropy: "Entropy",
  pages: "Pages",
  crypto_range: "Crypto constants",
  gadgets: "Gadgets",
};

export default function XrayPanel() {
  const selected = useDisasm((s) => s.selected);
  const { action, table, summary, graph, note, busy, error, run } = useXray();
  const [addrText, setAddrText] = useState("");
  const [size, setSize] = useState("4096");
  const [limit, setLimit] = useState("64");
  const [algorithm, setAlgorithm] = useState<string>(kHashAlgorithms[0]);
  const [hash, setHash] = useState("");

  const typed = parseAddress(addrText);
  const addr = typed ?? selected ?? undefined;

  const go = (va: number) => {
    useUi.getState().setWorkspaceTab("disassembly");
    void useDisasm.getState().gotoAddress(va);
  };

  const runPass = (pass: XrayPass) => {
    const params: Record<string, number | string> = {};
    if (kFunctionPasses.includes(pass)) {
      if (addr === undefined) return;
      params.addr = addr;
    }
    // size is a scan length only for the range passes; syscalls would read it
    // as a VA+size window from 0, and the rest ignore it
    const sizeValue = Number.parseInt(size, 10);
    if (kRangePasses.includes(pass) && Number.isFinite(sizeValue) && sizeValue > 0)
      params.size = sizeValue;
    const limitValue = Number.parseInt(limit, 10);
    if (kLimitedPasses.includes(pass) && Number.isFinite(limitValue) && limitValue > 0)
      params.limit = limitValue;
    if (pass === "apihash") {
      params.algorithm = algorithm;
      if (hash.trim() !== "") params.hash = hash.trim();
    }
    void run(pass, params);
  };

  const needsAddr = action !== null && kFunctionPasses.includes(action);

  return (
    <div className="panel tool-panel">
      <div className="panel-head">
        <span className="panel-title">X-ray</span>
        <div className="spacer" />
        <span className="faint" style={{ fontSize: "var(--type-small)" }}>
          read-only
        </span>
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
              aria-label="Scan size"
              inputMode="numeric"
              value={size}
              onChange={(e) => setSize(e.target.value)}
            />
          </label>
          <label className="faint tool-field">
            limit
            <input
              className="addr-input"
              style={{ width: 60 }}
              aria-label="Result limit"
              inputMode="numeric"
              value={limit}
              onChange={(e) => setLimit(e.target.value)}
            />
          </label>
          <select
            className="select"
            aria-label="Hash algorithm"
            value={algorithm}
            onChange={(e) => setAlgorithm(e.target.value)}
          >
            {kHashAlgorithms.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
          <input
            className="addr-input mono"
            style={{ width: 140 }}
            aria-label="API hash or name"
            placeholder="hash / API name"
            value={hash}
            onChange={(e) => setHash(e.target.value)}
          />
        </div>

        <div className="tool-grid" role="group" aria-label="X-ray passes">
          {kXrayPasses.map((pass) => (
            <button
              type="button"
              key={pass}
              className="row-action"
              data-active={action === pass}
              disabled={busy || (kFunctionPasses.includes(pass) && addr === undefined)}
              onClick={() => runPass(pass)}
            >
              {kLabels[pass]}
            </button>
          ))}
        </div>

        {busy && <div className="tool-summary faint">Running…</div>}
        {error !== null && (
          <div className="empty-hint error-text" role="alert">
            {error}
          </div>
        )}
        {note !== "" && <div className="tool-summary faint">{note}</div>}

        {table !== null && (
          <>
            <div className="tool-summary faint">
              {kLabels[action as XrayPass]}: {summary}
            </div>
            {graph !== null && (
              <div className="xray-graph">
                <CfgGraph graph={graph} entry={needsAddr ? addr : undefined} onPick={go} />
              </div>
            )}
            <table className="table">
              <thead>
                <tr>
                  {table.columns.map((c) => (
                    <th key={c} scope="col">
                      {c}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {table.rows.map((row, i) => (
                  <tr key={`${row.addr ?? "row"}-${i}`} data-severity={row.severity ?? "ok"}>
                    {row.cells.map((cell, j) => (
                      <td key={j} className={j === 0 ? "mono" : undefined}>
                        {j === 0 && row.addr !== undefined ? (
                          <button
                            type="button"
                            className="link-button mono"
                            onClick={() => go(row.addr as number)}
                          >
                            {cell}
                          </button>
                        ) : (
                          cell
                        )}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
            {table.rows.length === 0 && (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
                No rows for this pass.
              </div>
            )}
          </>
        )}

        {table === null && !busy && error === null && (
          <div className="empty">
            <div className="empty-glyph">
              <ScanSearch size={28} strokeWidth={1.5} />
            </div>
            <div className="empty-title">Pick a pass.</div>
            <div className="empty-hint">
              Function passes use the address above, or the listing selection. Image passes scan the
              loaded binary.
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
