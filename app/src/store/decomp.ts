// app/src/store/decomp.ts
// Pseudocode view state: the decompiled function, its control-flow graph and
// the split toggle. The CFG comes from disasm.blocks (same shape as
// xray.cfg's graph) because decomp.function returns lines, not blocks

import { create } from "zustand";
import { call, errorText } from "@/lib/rpc";

/** One emitted pseudocode line; `va` is 0 for lines with no instruction. */
export type DecompLine = { va: number; text: string };
/** Callee parameter types recovered at one direct call. */
export type CallSite = { va: number; arg_types: string[] };

export type CfgNode = {
  id: number;
  start: number;
  end: number;
  size: number;
  insn_count: number;
  /** First instruction of the block, when the engine sent one. */
  summary?: string;
};
export type CfgEdge = { from: number; to: number; kind: string };
export type CfgGraphData = { nodes: CfgNode[]; edges: CfgEdge[] };

/** Above this the layered layout is unreadable, so the view refuses it. */
export const kMaxCfgBlocks = 500;

type DecompReply = {
  signature?: string;
  callconv?: string;
  function_va?: number;
  insn_count?: number;
  call_sites?: CallSite[];
  types_generation?: number;
  lines?: DecompLine[];
};

type BlocksReply = { entry?: number; graph?: CfgGraphData };

type DecompStore = {
  /** Function being shown; null until one is picked. */
  va: number | null;
  signature: string;
  callconv: string;
  insnCount: number;
  callSites: CallSite[];
  /** re::type_catalog generation the listing was built against. */
  typesGeneration: number | null;
  lines: DecompLine[];
  graph: CfgGraphData | null;
  entry: number | null;
  /** Code + CFG side by side. */
  split: boolean;
  /** Type name the user clicked; there is no struct editor yet. */
  selectedType: string | null;
  busy: boolean;
  error: string | null;

  load: (va: number) => Promise<void>;
  /** Re-run the current function (types.changed invalidates the listing). */
  reload: () => Promise<void>;
  setSplit: (split: boolean) => void;
  selectType: (name: string | null) => void;
};

const kEmpty = {
  signature: "",
  callconv: "",
  insnCount: 0,
  callSites: [] as CallSite[],
  typesGeneration: null,
  lines: [] as DecompLine[],
  graph: null,
  entry: null,
};

export const useDecomp = create<DecompStore>((set, get) => ({
  va: null,
  ...kEmpty,
  split: false,
  selectedType: null,
  busy: false,
  error: null,

  load: async (va) => {
    set({ va, busy: true, error: null, selectedType: null });
    // The CFG is a separate tool and may be unavailable (no hyperion); a
    // missing graph must not hide the pseudocode that did come back
    const [code, blocks] = await Promise.all([
      call<DecompReply>("decomp", "function", { addr: va }).then(
        (r) => ({ ok: true as const, r }),
        (e: unknown) => ({ ok: false as const, e }),
      ),
      call<BlocksReply>("disasm", "blocks", { addr: va }).catch(() => null),
    ]);
    if (get().va !== va) return; // a newer request won
    if (!code.ok) {
      set({ ...kEmpty, busy: false, error: errorText(code.e) });
      return;
    }
    const r = code.r;
    set({
      signature: r.signature ?? "",
      callconv: r.callconv ?? "",
      insnCount: r.insn_count ?? 0,
      callSites: r.call_sites ?? [],
      typesGeneration: r.types_generation ?? null,
      lines: r.lines ?? [],
      graph: blocks?.graph ?? null,
      entry: blocks?.entry ?? r.function_va ?? null,
      busy: false,
      error: null,
    });
  },

  reload: async () => {
    const va = get().va;
    if (va !== null) await get().load(va);
  },

  setSplit: (split) => set({ split }),
  selectType: (selectedType) => set({ selectedType }),
}));
