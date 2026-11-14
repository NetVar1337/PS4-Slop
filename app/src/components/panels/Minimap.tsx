// app/src/components/panels/Minimap.tsx
// whole-function overview strip beside the listing: instruction density,
// branch targets and the current viewport. The bars are folded once per
// function and the viewport is one separate rect, so scrolling re-renders a
// single element instead of the strip.

import { memo, useMemo, useRef } from "react";
import type { Insn } from "@/store/disasm";

/** Bars in the strip; a function of any size folds down to this many. */
export const kBuckets = 160;

export type MinimapBucket = { density: number; branch: boolean };

/**
 * Fold the listing into `kBuckets` equal slices. `density` is the number of
 * instructions in the slice, `branch` marks a slice holding a jump target.
 */
export function bucketize(insns: Insn[]): MinimapBucket[] {
  const out: MinimapBucket[] = [];
  const n = insns.length;
  if (n === 0) return out;
  const indexOf = new Map<number, number>();
  for (let i = 0; i < n; i++) indexOf.set(insns[i].va, i);
  for (let b = 0; b < kBuckets; b++) out.push({ density: 0, branch: false });
  for (let i = 0; i < n; i++) {
    const b = Math.min(kBuckets - 1, Math.floor((i * kBuckets) / n));
    out[b].density += 1;
    const target = insns[i].target;
    if (target !== undefined) {
      const at = indexOf.get(target);
      if (at !== undefined)
        out[Math.min(kBuckets - 1, Math.floor((at * kBuckets) / n))].branch = true;
    }
  }
  return out;
}

type Props = {
  insns: Insn[];
  /** First and last listing row currently on screen. */
  first: number;
  last: number;
  /** Scroll the listing so `index` is at the top. */
  onJump: (index: number) => void;
};

function Minimap({ insns, first, last, onJump }: Props) {
  const buckets = useMemo(() => bucketize(insns), [insns]);
  const dragging = useRef(false);
  const n = insns.length;
  if (n === 0) return null;
  const peak = buckets.reduce((m, b) => Math.max(m, b.density), 0) || 1;
  const unit = 1000 / kBuckets;

  const jump = (clientY: number, el: Element) => {
    const rect = el.getBoundingClientRect();
    if (rect.height <= 0) return;
    const frac = Math.min(1, Math.max(0, (clientY - rect.top) / rect.height));
    onJump(Math.min(n - 1, Math.floor(frac * n)));
  };

  return (
    <div
      className="minimap"
      role="scrollbar"
      aria-label="Function overview"
      aria-orientation="vertical"
      aria-valuemin={1}
      aria-valuemax={n}
      aria-valuenow={first + 1}
      onPointerDown={(e) => {
        dragging.current = true;
        e.currentTarget.setPointerCapture?.(e.pointerId);
        jump(e.clientY, e.currentTarget);
      }}
      onPointerMove={(e) => {
        if (dragging.current) jump(e.clientY, e.currentTarget);
      }}
      onPointerUp={(e) => {
        dragging.current = false;
        e.currentTarget.releasePointerCapture?.(e.pointerId);
      }}
      onPointerCancel={() => {
        dragging.current = false;
      }}
    >
      <svg viewBox="0 0 100 1000" preserveAspectRatio="none" aria-hidden>
        {buckets.map((b, i) =>
          b.density === 0 ? null : (
            <rect
              key={i}
              className="minimap-bar"
              x={0}
              y={i * unit}
              width={100}
              height={unit}
              opacity={0.15 + (0.85 * b.density) / peak}
            />
          ),
        )}
        {buckets.map((b, i) =>
          b.branch ? (
            <rect
              key={`b${i}`}
              className="minimap-branch"
              x={0}
              y={i * unit}
              width={100}
              height={unit}
            />
          ) : null,
        )}
        <rect
          className="minimap-view"
          x={0}
          y={(first / n) * 1000}
          width={100}
          height={Math.max(unit, ((last - first + 1) / n) * 1000)}
        />
      </svg>
    </div>
  );
}

export default memo(Minimap);
