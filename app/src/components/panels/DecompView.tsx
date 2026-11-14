// app/src/components/panels/DecompView.tsx
// Pseudocode tab: decomp.function for the selected function, highlighted in
// React (no editor library) with clickable identifiers, plus the CFG in a
// split pane. Function names jump the listing; there is no struct editor yet,
// so clicking a type only selects it

import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Network } from "lucide-react";
import CfgGraph from "@/components/CfgGraph";
import IconButton from "@/components/IconButton";
import { useT } from "@/i18n";
import { on } from "@/lib/events";
import { hex, parseAddress } from "@/lib/format";
import { showInDisassembly } from "@/lib/navigate";
import { functionLabel, useDisasm } from "@/store/disasm";
import { useDecomp, type DecompLine } from "@/store/decomp";

type Kind = "kw" | "type" | "num" | "str" | "com" | "fn" | "id" | "punct" | "ws";
type Token = { kind: Kind; text: string };

const kKeywords: Record<string, true> = {
  if: true,
  else: true,
  while: true,
  for: true,
  do: true,
  return: true,
  switch: true,
  case: true,
  break: true,
  continue: true,
  goto: true,
  default: true,
  sizeof: true,
  typedef: true,
  struct: true,
  union: true,
  enum: true,
  static: true,
  const: true,
  volatile: true,
  extern: true,
  inline: true,
  register: true,
};

const kTypes: Record<string, true> = {
  void: true,
  char: true,
  short: true,
  int: true,
  long: true,
  float: true,
  double: true,
  bool: true,
  unsigned: true,
  signed: true,
  size_t: true,
  ssize_t: true,
  uint: true,
  ulong: true,
  ushort: true,
  uchar: true,
  byte: true,
  word: true,
  dword: true,
  qword: true,
  code: true,
  true: true,
  false: true,
  nullptr: true,
  NULL: true,
  BYTE: true,
  WORD: true,
  DWORD: true,
  QWORD: true,
  BOOL: true,
  HANDLE: true,
  LPVOID: true,
  __int8: true,
  __int16: true,
  __int32: true,
  __int64: true,
};

const kNumber = /^(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?)[uUlLfF]*/;
const kIdent = /[A-Za-z0-9_$]/;
const kIdentStart = /[A-Za-z_$]/;
/** Hyperion spells unknown-width values `undefined4`; C widths end in `_t`. */
const kTypeName = /^(?:undefined\d*|u?int(?:8|16|32|64)|.*_t)$/;

function classify(text: string, call: boolean): Kind {
  if (kKeywords[text] === true) return "kw";
  if (kTypes[text] === true || kTypeName.test(text)) return "type";
  if (call) return "fn";
  return "id";
}

/** Split one pseudocode line into highlighted tokens; no library, no state. */
function tokenize(line: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  while (i < line.length) {
    const c = line[i];
    if (c === "/" && line[i + 1] === "/") {
      out.push({ kind: "com", text: line.slice(i) });
      break;
    }
    if (c === "/" && line[i + 1] === "*") {
      const close = line.indexOf("*/", i + 2);
      const end = close < 0 ? line.length : close + 2;
      out.push({ kind: "com", text: line.slice(i, end) });
      i = end;
      continue;
    }
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < line.length && line[j] !== c) j += line[j] === "\\" ? 2 : 1;
      j = Math.min(j + 1, line.length);
      out.push({ kind: "str", text: line.slice(i, j) });
      i = j;
      continue;
    }
    if (c >= "0" && c <= "9") {
      const m = kNumber.exec(line.slice(i));
      const text = m === null ? c : m[0];
      out.push({ kind: "num", text });
      i += text.length;
      continue;
    }
    if (kIdentStart.test(c)) {
      // `Player::Update` is one name, and a following `(` makes it a call
      let j = i;
      for (;;) {
        while (j < line.length && kIdent.test(line[j])) j++;
        if (line[j] === ":" && line[j + 1] === ":") {
          j += 2;
          continue;
        }
        break;
      }
      const text = line.slice(i, j);
      out.push({ kind: classify(text, line[j] === "("), text });
      i = j;
      continue;
    }
    if (/\s/.test(c)) {
      let j = i;
      while (j < line.length && /\s/.test(line[j])) j++;
      out.push({ kind: "ws", text: line.slice(i, j) });
      i = j;
      continue;
    }
    out.push({ kind: "punct", text: c });
    i++;
  }
  return out;
}

/** `sub_4DDA48` carries its own address; anything else needs a name lookup. */
async function goToFunction(name: string): Promise<void> {
  const sub = /^sub_([0-9A-Fa-f]+)$/.exec(name);
  if (sub !== null) {
    showInDisassembly(Number.parseInt(sub[1], 16));
    return;
  }
  const rows = await useDisasm.getState().searchFunctions(name, 8);
  const hit = rows.find((f) => functionLabel(f) === name);
  if (hit !== undefined) showInDisassembly(hit.va);
}

function Tokens({ text }: { text: string }) {
  const t = useT();
  const selectedType = useDecomp((s) => s.selectedType);
  const selectType = useDecomp((s) => s.selectType);
  return (
    <>
      {tokenize(text).map((token, i) => {
        if (token.kind === "ws") return token.text;
        if (token.kind === "fn")
          return (
            <button
              key={i}
              type="button"
              className="decomp-fn"
              aria-label={t("decomp.goTo", { name: token.text })}
              onClick={() => void goToFunction(token.text)}
            >
              {token.text}
            </button>
          );
        if (token.kind === "type")
          return (
            <button
              key={i}
              type="button"
              className="decomp-type"
              aria-pressed={selectedType === token.text}
              aria-label={t("decomp.selectType", { name: token.text })}
              onClick={() => selectType(selectedType === token.text ? null : token.text)}
            >
              {token.text}
            </button>
          );
        return (
          <span key={i} className={`decomp-${token.kind}`}>
            {token.text}
          </span>
        );
      })}
    </>
  );
}

function Line({ line }: { line: DecompLine }) {
  return (
    <div className="decomp-line">
      <span className="decomp-gutter">{line.va !== 0 ? hex(line.va, 8) : ""}</span>
      <span className="decomp-src">
        <Tokens text={line.text} />
      </span>
    </div>
  );
}

export default function DecompView(): ReactNode {
  const t = useT();
  const selected = useDisasm((s) => s.selected);
  const selectedFn = useDisasm((s) => s.selectedFn);
  const va = useDecomp((s) => s.va);
  const load = useDecomp((s) => s.load);
  const split = useDecomp((s) => s.split);
  const setSplit = useDecomp((s) => s.setSplit);
  const signature = useDecomp((s) => s.signature);
  const callconv = useDecomp((s) => s.callconv);
  const insnCount = useDecomp((s) => s.insnCount);
  const callSites = useDecomp((s) => s.callSites);
  const typesGeneration = useDecomp((s) => s.typesGeneration);
  const lines = useDecomp((s) => s.lines);
  const graph = useDecomp((s) => s.graph);
  const entry = useDecomp((s) => s.entry);
  const busy = useDecomp((s) => s.busy);
  const error = useDecomp((s) => s.error);
  const [text, setText] = useState("");

  // The view follows the listing: opening the tab decompiles what is selected
  useEffect(() => {
    if (selected !== null && selected !== va) void load(selected);
  }, [selected, va, load]);

  // A struct edit changes inferred types, so the listing is stale
  useEffect(() => on("types.changed", () => void useDecomp.getState().reload()), []);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const addr = parseAddress(text);
    if (addr !== null) void load(addr);
  };

  const name = va === null ? null : selectedFn !== null && selectedFn.va === va ? selectedFn : null;

  return (
    <div className="decomp">
      <div className="decomp-head">
        <form className="decomp-goto" onSubmit={submit}>
          <input
            className="decomp-input mono"
            aria-label={t("decomp.address")}
            placeholder={t("decomp.addressPlaceholder")}
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
          <button type="submit" className="row-action">
            {t("decomp.decompile")}
          </button>
        </form>
        <span className="decomp-title mono">
          {va === null ? t("decomp.noFunction") : name !== null ? functionLabel(name) : hex(va, 8)}
        </span>
        <IconButton tip={t("decomp.cfgTip")} pressed={split} onClick={() => setSplit(!split)}>
          <Network size={14} />
        </IconButton>
      </div>

      {error !== null && (
        <div className="decomp-note error-text" role="alert">
          {error}
        </div>
      )}

      <div className="decomp-body" data-split={split}>
        <div className="decomp-pane" role="region" aria-label={t("decomp.pseudocode")}>
          {va === null ? (
            <div className="empty">
              <div className="empty-title">{t("decomp.noFunctionSelected")}</div>
              <div className="empty-hint">{t("decomp.noFunctionHint")}</div>
            </div>
          ) : (
            <>
              <div className="decomp-sig mono">
                <Tokens text={signature} />
              </div>
              <div className="decomp-meta mono">
                {callconv !== "" && <span>{callconv}</span>}
                <span>{t("decomp.insns", { count: insnCount })}</span>
                <span>{t("decomp.callSites", { count: callSites.length })}</span>
                {typesGeneration !== null && (
                  <span>{t("decomp.typesGen", { gen: typesGeneration })}</span>
                )}
                {busy && <span className="faint">{t("decomp.decompiling")}</span>}
              </div>
              <div className="decomp-code">
                {lines.map((line, i) => (
                  <Line key={i} line={line} />
                ))}
              </div>
              {callSites.length > 0 && (
                <div className="decomp-calls">
                  {callSites.map((c) => (
                    <button
                      key={c.va}
                      type="button"
                      className="decomp-call mono"
                      aria-label={t("decomp.callSite", { addr: hex(c.va, 8) })}
                      onClick={() => showInDisassembly(c.va)}
                    >
                      {hex(c.va, 8)} {c.arg_types.join(", ")}
                    </button>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
        {split && (
          <div className="decomp-cfg">
            <CfgGraph graph={graph} entry={entry} onPick={(addr) => showInDisassembly(addr)} />
          </div>
        )}
      </div>
    </div>
  );
}
