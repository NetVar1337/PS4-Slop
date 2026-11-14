// app/src/bench/VirtualListBench.tsx
// bench-only fixture: a virtualized list of 1,000,000 synthetic rows shaped
// like the disassembly listing, with no engine behind it. Loaded by
// app/scripts/bench-ui.mjs, never by the app.

import { useMemo, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";

export const kBenchRows = 1_000_000;
const kRow = 20;

/** Synthetic row text; the filter matches on it. */
export function benchRow(i: number): string {
  return `sub_${(0x140000000 + i * 16).toString(16)} mov rax, [rbx+${i & 0xff}]`;
}

export default function VirtualListBench({ filter = "" }: { filter?: string }) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const matches = useMemo(() => {
    if (filter === "") return null;
    const out: number[] = [];
    for (let i = 0; i < kBenchRows; i++) if (benchRow(i).includes(filter)) out.push(i);
    return out;
  }, [filter]);
  const count = matches === null ? kBenchRows : matches.length;
  const virtualizer = useVirtualizer({
    count,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => kRow,
    overscan: 25,
  });
  return (
    <div ref={scrollRef} style={{ height: 600, overflow: "auto" }}>
      <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
        {virtualizer.getVirtualItems().map((v) => (
          <div key={v.index} style={{ position: "absolute", top: v.start, height: kRow }}>
            {benchRow(matches === null ? v.index : matches[v.index])}
          </div>
        ))}
      </div>
    </div>
  );
}
