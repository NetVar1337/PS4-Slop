// app/src/store/xray.ts
// Read-only xray passes over the loaded image or one function. One pass runs
// at a time; the engine reply is flattened into a table the panel can render
// and, for cfg, the shared CfgGraph component

import { create } from "zustand";
import { call, errorText } from "@/lib/rpc";
import type { CfgGraphData } from "@/store/decomp";

export const kXrayPasses = [
  "cfg",
  "complexity",
  "cff",
  "obfuscation",
  "strings_recon",
  "indirect_calls",
  "anti_analysis",
  "hooks",
  "syscalls",
  "apihash",
  "entropy",
  "pages",
  "crypto_range",
  "gadgets",
] as const;
export type XrayPass = (typeof kXrayPasses)[number];

/** Passes that take a function-start VA; the rest scan the whole image. */
export const kFunctionPasses: readonly XrayPass[] = [
  "cfg",
  "complexity",
  "cff",
  "obfuscation",
  "strings_recon",
  "indirect_calls",
  "anti_analysis",
];

export const kHashAlgorithms = ["ror13", "djb2", "crc32", "fnv1a", "sdbm"] as const;

export type Severity = "ok" | "warn" | "bad";
export type XrayRow = { addr?: number; cells: string[]; severity?: Severity };
export type XrayTable = { columns: string[]; rows: XrayRow[] };

export type XrayParams = {
  addr?: number;
  size?: number;
  limit?: number;
  algorithm?: string;
  hash?: string;
};

type XrayReply = {
  image?: string;
  graph?: CfgGraphData;
  blocks?: { start: number; end: number; instructions: number; successors: number[] }[];
  block_count?: number;
  edge_count?: number;
  back_edges?: number;
  cyclomatic_complexity?: number;
  instruction_count?: number;
  basic_block_count?: number;
  call_count?: number;
  branch_count?: number;
  return_count?: number;
  arithmetic_ops?: number;
  memory_accesses?: number;
  string_operations?: number;
  unique_operators?: number;
  unique_operands?: number;
  complexity_rating?: string;
  flattened?: boolean;
  dispatcher?: number;
  dispatcher_backedges?: number;
  state_variable?: string;
  state_blocks?: { start: number; end: number; next_state?: number | null; assign_addr: number }[];
  state_block_count?: number;
  patterns?: { type: string; address: number; detail: string }[];
  opaque_predicates?: number;
  dead_heads?: number;
  junk_sequences?: number;
  indirect_jumps?: number;
  push_ret?: number;
  privileged?: number;
  obfuscation_score_pct?: number;
  warning?: string;
  candidates?: {
    type: string;
    address: number;
    reconstructed?: string;
    xor_key?: number;
    length: number;
  }[];
  count?: number;
  indirect_calls?: {
    address: number;
    text: string;
    classification: string;
    base_register?: string;
    offset?: number;
    target?: number;
  }[];
  total?: number;
  detections?: { type: string; address: number; detail: string }[];
  anti_debug?: number;
  anti_vm?: number;
  timing_checks?: number;
  traps?: number;
  anti_analysis_score_pct?: number;
  functions_checked?: number;
  hooks_found?: number;
  hooks?: { address: number; hook_type: string; target: number; prologue_bytes: string }[];
  source?: string;
  abi?: string;
  syscalls_found?: number;
  syscalls?: { address: number; syscall_number: number; pattern: string; name?: string | null }[];
  algorithm?: string;
  total_queried?: number;
  resolved_count?: number;
  resolved?: { hash: number; api: string; dll: string }[];
  name_inputs?: { name: string; hash: number }[];
  hint?: string;
  overall_entropy?: number;
  min_window_entropy?: number;
  max_window_entropy?: number;
  window_size?: number;
  verdict?: string;
  truncated?: boolean;
  total_windows?: number;
  windows?: { offset: number; entropy: number; verdict: string }[];
  scan_base?: number;
  scan_size?: number;
  total_pages?: number;
  summary?: Record<string, number>;
  pages?: {
    address: number;
    size: number;
    class: string;
    entropy: number;
    insn_ratio: number;
    zero_ratio: number;
    string_ratio: number;
  }[];
  matches?: { va: number; algorithm: string; constant: string; value: number; source: string }[];
  gadgets?: { address: number; text: string }[];
  note?: string;
};

type XrayView = { table: XrayTable; summary: string; graph: CfgGraphData | null };

const kHex = (v: number | undefined) =>
  v === undefined ? "-" : `0x${v.toString(16).toUpperCase()}`;
const kNum = (v: number | undefined) => (v === undefined ? "-" : String(v));
const kPct = (v: number | undefined) => (v === undefined ? "-" : `${v}%`);

function entropySeverity(verdict: string | undefined): Severity {
  if (verdict === "encrypted_or_compressed") return "bad";
  if (verdict === "high_entropy") return "warn";
  return "ok";
}

function pageSeverity(klass: string): Severity {
  if (klass === "encrypted_or_compressed" || klass === "single_byte_encrypted") return "bad";
  if (klass === "mixed") return "warn";
  return "ok";
}

/** Flatten one engine reply into the panel's table + summary. */
function viewFor(action: XrayPass, r: XrayReply): XrayView {
  switch (action) {
    case "cfg":
      return {
        graph: r.graph ?? null,
        summary: `${kNum(r.block_count)} blocks · ${kNum(r.edge_count)} edges · ${kNum(
          r.back_edges,
        )} back edges · cyclomatic ${kNum(r.cyclomatic_complexity)}`,
        table: {
          columns: ["Block", "End", "Insns", "Successors"],
          rows: (r.blocks ?? []).map((b) => ({
            addr: b.start,
            cells: [
              kHex(b.start),
              kHex(b.end),
              kNum(b.instructions),
              b.successors.map((s) => kHex(s)).join(", ") || "-",
            ],
          })),
        },
      };
    case "complexity":
      return {
        graph: null,
        summary: `rating ${r.complexity_rating ?? "-"}`,
        table: {
          columns: ["Metric", "Value"],
          rows: [
            ["Instructions", r.instruction_count],
            ["Basic blocks", r.basic_block_count],
            ["Edges", r.edge_count],
            ["Cyclomatic", r.cyclomatic_complexity],
            ["Calls", r.call_count],
            ["Branches", r.branch_count],
            ["Returns", r.return_count],
            ["Arithmetic ops", r.arithmetic_ops],
            ["Memory accesses", r.memory_accesses],
            ["String ops", r.string_operations],
            ["Unique operators", r.unique_operators],
            ["Unique operands", r.unique_operands],
          ].map(([label, value]) => ({
            cells: [String(label), kNum(value as number | undefined)],
          })),
        },
      };
    case "cff":
      return {
        graph: null,
        summary: r.flattened
          ? `flattened · dispatcher ${kHex(r.dispatcher)} · ${
              r.dispatcher_backedges ?? 0
            } backedges · state ${r.state_variable ?? "-"}`
          : "not flattened (no dispatcher)",
        table: {
          columns: ["State block", "End", "Next state", "Assign at"],
          rows: (r.state_blocks ?? []).map((b) => ({
            addr: b.start,
            cells: [
              kHex(b.start),
              kHex(b.end),
              kHex(b.next_state ?? undefined),
              kHex(b.assign_addr),
            ],
            severity: "warn",
          })),
        },
      };
    case "obfuscation":
      return {
        graph: null,
        summary: `score ${kPct(r.obfuscation_score_pct)} · opaque ${kNum(
          r.opaque_predicates,
        )} · junk ${kNum(r.junk_sequences)} · indirect jumps ${kNum(r.indirect_jumps)}${
          r.warning !== undefined ? ` · ${r.warning}` : ""
        }`,
        table: {
          columns: ["Pattern", "Address", "Detail"],
          rows: (r.patterns ?? []).map((p) => ({
            addr: p.address,
            cells: [p.type, kHex(p.address), p.detail],
            severity: "bad",
          })),
        },
      };
    case "strings_recon":
      return {
        graph: null,
        summary: `${kNum(r.count)} candidates`,
        table: {
          columns: ["Address", "Type", "Length", "XOR key", "Reconstructed"],
          rows: (r.candidates ?? []).map((c) => ({
            addr: c.address,
            cells: [
              kHex(c.address),
              c.type,
              kNum(c.length),
              c.xor_key === undefined ? "-" : kHex(c.xor_key),
              c.reconstructed ?? "-",
            ],
            severity: c.reconstructed !== undefined ? "warn" : "ok",
          })),
        },
      };
    case "indirect_calls":
      return {
        graph: null,
        summary: `${kNum(r.total)} indirect calls`,
        table: {
          columns: ["Address", "Classification", "Base", "Target", "Instruction"],
          rows: (r.indirect_calls ?? []).map((c) => ({
            addr: c.address,
            cells: [
              kHex(c.address),
              c.classification,
              c.base_register === undefined
                ? "-"
                : `${c.base_register}${c.offset === undefined ? "" : `+${kHex(c.offset)}`}`,
              kHex(c.target),
              c.text,
            ],
            severity: "warn",
          })),
        },
      };
    case "anti_analysis":
      return {
        graph: null,
        summary: `score ${kPct(r.anti_analysis_score_pct)} · anti-debug ${kNum(
          r.anti_debug,
        )} · anti-VM ${kNum(r.anti_vm)} · timing ${kNum(r.timing_checks)} · traps ${kNum(r.traps)}`,
        table: {
          columns: ["Type", "Address", "Detail"],
          rows: (r.detections ?? []).map((d) => ({
            addr: d.address,
            cells: [d.type, kHex(d.address), d.detail],
            severity: "bad",
          })),
        },
      };
    case "hooks":
      return {
        graph: null,
        summary: `${kNum(r.hooks_found)} hooks in ${kNum(r.functions_checked)} functions (${
          r.source ?? "index"
        })`,
        table: {
          columns: ["Address", "Hook", "Target", "Prologue"],
          rows: (r.hooks ?? []).map((h) => ({
            addr: h.address,
            cells: [kHex(h.address), h.hook_type, kHex(h.target), h.prologue_bytes],
            severity: "bad",
          })),
        },
      };
    case "syscalls":
      return {
        graph: null,
        summary: `${kNum(r.syscalls_found)} syscalls · abi ${r.abi ?? "-"}`,
        table: {
          columns: ["Address", "Number", "Name", "Pattern"],
          rows: (r.syscalls ?? []).map((s) => ({
            addr: s.address,
            cells: [kHex(s.address), kNum(s.syscall_number), s.name ?? "-", s.pattern],
          })),
        },
      };
    case "apihash":
      return {
        graph: null,
        summary: `${kNum(r.resolved_count)} / ${kNum(r.total_queried)} resolved · ${
          r.algorithm ?? "-"
        }${r.hint !== undefined ? ` · ${r.hint}` : ""}`,
        table: {
          columns: ["Hash", "API", "DLL"],
          rows: (r.resolved ?? []).map((h) => ({
            cells: [kHex(h.hash), h.api, h.dll],
          })),
        },
      };
    case "entropy":
      return {
        graph: null,
        summary: `overall ${r.overall_entropy?.toFixed(3) ?? "-"} · min ${
          r.min_window_entropy?.toFixed(3) ?? "-"
        } · max ${r.max_window_entropy?.toFixed(3) ?? "-"} · ${
          r.verdict ?? "-"
        } · ${kNum(r.total_windows)} windows of ${kNum(r.window_size)} B`,
        table: {
          columns: ["Offset", "Entropy", "Verdict"],
          rows: (r.windows ?? []).map((w) => ({
            cells: [kHex(w.offset), w.entropy.toFixed(3), w.verdict],
            severity: entropySeverity(w.verdict),
          })),
        },
      };
    case "pages":
      return {
        graph: null,
        summary: `${kNum(r.total_pages)} pages · ${Object.entries(r.summary ?? {})
          .map(([k, v]) => `${k} ${v}`)
          .join(" · ")}`,
        table: {
          columns: ["Address", "Size", "Class", "Entropy", "Code", "Zero", "Strings"],
          rows: (r.pages ?? []).map((p) => ({
            addr: p.address,
            cells: [
              kHex(p.address),
              kNum(p.size),
              p.class,
              p.entropy.toFixed(2),
              `${Math.round(p.insn_ratio * 100)}%`,
              `${Math.round(p.zero_ratio * 100)}%`,
              `${Math.round(p.string_ratio * 100)}%`,
            ],
            severity: pageSeverity(p.class),
          })),
        },
      };
    case "crypto_range":
      return {
        graph: null,
        summary: `${kNum(r.count)} constant matches`,
        table: {
          columns: ["Address", "Algorithm", "Constant", "Value", "Source"],
          rows: (r.matches ?? []).map((m) => ({
            addr: m.va,
            cells: [kHex(m.va), m.algorithm, m.constant, kHex(m.value), m.source],
          })),
        },
      };
    case "gadgets":
      return {
        graph: null,
        summary: `${kNum(r.count)} gadgets`,
        table: {
          columns: ["Address", "Gadget"],
          rows: (r.gadgets ?? []).map((g) => ({
            addr: g.address,
            cells: [kHex(g.address), g.text],
          })),
        },
      };
  }
}

type XrayStore = {
  action: XrayPass | null;
  table: XrayTable | null;
  summary: string;
  graph: CfgGraphData | null;
  note: string;
  busy: boolean;
  error: string | null;
  run: (action: XrayPass, params?: XrayParams) => Promise<void>;
  reset: () => void;
};

export const useXray = create<XrayStore>((set) => ({
  action: null,
  table: null,
  summary: "",
  graph: null,
  note: "",
  busy: false,
  error: null,

  run: async (action, params = {}) => {
    set({ busy: true, error: null, note: "" });
    try {
      const reply = await call<XrayReply>("xray", action, params);
      const view = viewFor(action, reply);
      set({
        action,
        table: view.table,
        summary: view.summary,
        graph: view.graph,
        note: reply.note ?? "",
        busy: false,
      });
    } catch (e) {
      set({ action, table: null, summary: "", graph: null, error: errorText(e), busy: false });
    }
  },

  reset: () =>
    set({
      action: null,
      table: null,
      summary: "",
      graph: null,
      note: "",
      error: null,
      busy: false,
    }),
}));
