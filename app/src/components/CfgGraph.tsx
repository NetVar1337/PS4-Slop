// app/src/components/CfgGraph.tsx
// Control-flow graph for one function: disasm.blocks / xray.cfg return
// {nodes:[{id,start,end,size,insn_count,summary?}], edges:[{from,to,kind}]}
// and this draws it. Layered layout: one column per BFS depth from the entry,
// rows ordered by address, so the same function always draws the same way.
// Nodes are HTML buttons (keyboard reachable, data-tip works on them); edges
// are SVG, dashed for fallthrough, solid with an arrowhead for a branch

import { hex } from "@/lib/format";
import { kMaxCfgBlocks, type CfgGraphData, type CfgNode } from "@/store/decomp";

const kNodeW = 168;
const kGapX = 56;
const kGapY = 12;
const kPad = 12;

/** Box height grows with the block, clamped so one huge block cannot dominate. */
function nodeHeight(insnCount: number): number {
  return Math.max(30, Math.min(96, 24 + insnCount * 5));
}

type Placed = { node: CfgNode; x: number; y: number; h: number; depth: number };

/**
 * BFS depth from the entry gives the column; blocks the walk never reaches
 * (should not happen inside one function) land in the first column too.
 */
function layoutGraph(
  graph: CfgGraphData,
  entry?: number | null,
): { placed: Placed[]; width: number; height: number } {
  const ids = new Set(graph.nodes.map((n) => n.id));
  const root =
    entry !== undefined && entry !== null && ids.has(entry)
      ? entry
      : graph.nodes.reduce((a, b) => (b.start < a.start ? b : a)).id;

  const depth = new Map<number, number>([[root, 0]]);
  const queue = [root];
  while (queue.length > 0) {
    const cur = queue.shift() as number;
    const d = depth.get(cur) as number;
    for (const e of graph.edges) {
      if (e.from !== cur || !ids.has(e.to) || depth.has(e.to)) continue;
      depth.set(e.to, d + 1);
      queue.push(e.to);
    }
  }

  const columns = new Map<number, CfgNode[]>();
  for (const n of graph.nodes) {
    const d = depth.get(n.id) ?? 0;
    const col = columns.get(d);
    if (col === undefined) columns.set(d, [n]);
    else col.push(n);
  }

  const placed: Placed[] = [];
  let width = 0;
  let height = 0;
  for (const d of [...columns.keys()].sort((a, b) => a - b)) {
    const col = (columns.get(d) as CfgNode[]).sort((a, b) => a.start - b.start);
    let y = kPad;
    for (const node of col) {
      const h = nodeHeight(node.insn_count);
      const x = kPad + d * (kNodeW + kGapX);
      placed.push({ node, x, y, h, depth: d });
      y += h + kGapY;
      width = Math.max(width, x + kNodeW + kPad);
      height = Math.max(height, y);
    }
  }
  return { placed, width, height: height + kPad };
}

/** Forward edges curve down; back edges leave right and re-enter on the left. */
function edgePath(a: Placed, b: Placed): string {
  if (b.depth > a.depth) {
    const ax = a.x + kNodeW / 2;
    const ay = a.y + a.h;
    const bx = b.x + kNodeW / 2;
    const by = b.y;
    const mid = (ay + by) / 2;
    return `M ${ax} ${ay} C ${ax} ${mid}, ${bx} ${mid}, ${bx} ${by}`;
  }
  const sx = a.x + kNodeW;
  const sy = a.y + a.h / 2;
  const tx = b.x;
  const ty = b.y + b.h / 2;
  const out = Math.max(sx, tx) + kGapX / 2;
  return `M ${sx} ${sy} C ${out} ${sy}, ${out} ${ty}, ${tx} ${ty}`;
}

type Props = {
  graph: CfgGraphData | null;
  entry?: number | null;
  /** Jump the listing to a block. */
  onPick: (va: number) => void;
};

export default function CfgGraph({ graph, entry, onPick }: Props) {
  if (graph === null || graph.nodes.length === 0) {
    return (
      <div className="empty">
        <div className="empty-title">No control-flow graph.</div>
        <div className="empty-hint">Decompile a function to see its blocks.</div>
      </div>
    );
  }
  if (graph.nodes.length > kMaxCfgBlocks) {
    return (
      <div className="empty" role="status">
        <div className="empty-title">Too many blocks ({graph.nodes.length}).</div>
        <div className="empty-hint">
          The graph stops at {kMaxCfgBlocks} blocks; follow this function in the listing.
        </div>
      </div>
    );
  }

  const { placed, width, height } = layoutGraph(graph, entry);
  const at = new Map(placed.map((p) => [p.node.id, p]));
  const edges = graph.edges.filter((e) => at.has(e.from) && at.has(e.to));

  return (
    <div className="cfg" role="group" aria-label="Control-flow graph">
      <div className="cfg-viewport">
        <div className="cfg-canvas" style={{ width, height }}>
          <svg className="cfg-edges" width={width} height={height} aria-hidden="true">
            <defs>
              <marker
                id="cfg-arrow"
                viewBox="0 0 8 8"
                refX="7"
                refY="4"
                markerWidth="7"
                markerHeight="7"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 8 4 L 0 8 z" className="cfg-arrow" />
              </marker>
            </defs>
            {edges.map((e) => {
              const a = at.get(e.from) as Placed;
              const b = at.get(e.to) as Placed;
              return (
                <path
                  key={`${e.from}-${e.to}`}
                  className="cfg-edge"
                  data-edge={e.kind}
                  data-from={e.from}
                  data-to={e.to}
                  d={edgePath(a, b)}
                  markerEnd="url(#cfg-arrow)"
                />
              );
            })}
          </svg>
          {placed.map(({ node, x, y, h }) => {
            const tip = `${hex(node.start, 8)}–${hex(node.end, 8)} · ${node.insn_count} insns${
              node.summary !== undefined && node.summary !== "" ? ` · ${node.summary}` : ""
            }`;
            return (
              <button
                key={node.id}
                type="button"
                className="cfg-node"
                style={{ left: x, top: y, width: kNodeW, height: h }}
                data-tip={tip}
                aria-label={`block ${hex(node.start, 8)} · ${node.insn_count} instructions`}
                onClick={() => onPick(node.start)}
              >
                <span className="cfg-node-va mono">{hex(node.start, 8)}</span>
                <span className="cfg-node-sum mono">
                  {node.summary ?? `${node.insn_count} insns`}
                </span>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
