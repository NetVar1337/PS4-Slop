// app/src/components/Splitter.tsx
// drag handle that writes a css custom property, keeps the layout in css grid.
// Keyboard reachable (role=separator, arrows / Home / End) and persisted via
// the ui store, so a resized layout survives a reload

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type KeyboardEvent,
  type PointerEvent as ReactPointerEvent,
} from "react";
import { kLayoutVars, useUi, type LayoutVar } from "@/store/ui";

/**
 * Read-only view of a ref. Splitter only reads `current`, never writes it, so
 * taking the readonly shape keeps `RefObject<HTMLDivElement | null>` assignable
 * (a mutable `RefObject<HTMLElement>` would be invariant under React 19 types).
 */
type RefTarget = { readonly current: HTMLElement | null };

type Props = {
  axis: "x" | "y";
  /** CSS variable to drive, e.g. "--left-w". */
  variable: LayoutVar;
  /** Element the variable is set on. Defaults to the app root. */
  target?: RefTarget;
  min: number;
  max: number;
  /** Drag right/down shrinks instead of grows (handles on a panel's left edge). */
  invert?: boolean;
  /** Accessible name, e.g. "Resize left panel". */
  label: string;
};

const kStep = 16;

export default function Splitter({ axis, variable, target, min, max, invert, label }: Props) {
  const dragging = useRef(false);
  const ref = useRef<HTMLDivElement>(null);
  const stored = useUi((s) => s.sizes[variable]);
  const setSize = useUi((s) => s.setSize);
  const [value, setValue] = useState<number>(stored ?? kLayoutVars[variable]);

  const host = useCallback(() => target?.current ?? document.documentElement, [target]);

  const apply = useCallback(
    (px: number, persist: boolean) => {
      const next = Math.round(Math.min(max, Math.max(min, px)));
      host().style.setProperty(variable, `${next}px`);
      setValue(next);
      if (persist) setSize(variable, next);
    },
    [host, variable, min, max, setSize],
  );

  // The persisted size itself is applied by the shell (App.tsx); mirror it for
  // aria-valuenow, including after Reset layout
  useEffect(() => {
    setValue(stored ?? kLayoutVars[variable]);
  }, [stored, variable]);

  const current = () => parseFloat(getComputedStyle(host()).getPropertyValue(variable)) || value;

  const onPointerDown = (down: ReactPointerEvent<HTMLDivElement>) => {
    const start = current();
    const origin = axis === "x" ? down.clientX : down.clientY;
    let last = start;

    dragging.current = true;
    ref.current?.setAttribute("data-dragging", "true");
    down.currentTarget.setPointerCapture(down.pointerId);

    const onMove = (move: PointerEvent) => {
      if (!dragging.current) return;
      const now = axis === "x" ? move.clientX : move.clientY;
      last = start + (now - origin) * (invert === true ? -1 : 1);
      apply(last, false);
    };

    const onUp = () => {
      dragging.current = false;
      ref.current?.removeAttribute("data-dragging");
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      apply(last, true);
    };

    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  };

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    // Arrow direction follows the visual edge: for an inverted (right/bottom)
    // panel, moving the handle left/up grows it
    const grow =
      axis === "x" ? (invert ? "ArrowLeft" : "ArrowRight") : invert ? "ArrowUp" : "ArrowDown";
    const shrink =
      axis === "x" ? (invert ? "ArrowRight" : "ArrowLeft") : invert ? "ArrowDown" : "ArrowUp";
    const step = e.shiftKey ? kStep * 4 : kStep;
    let next: number | null = null;
    if (e.key === grow) next = current() + step;
    else if (e.key === shrink) next = current() - step;
    else if (e.key === "Home") next = min;
    else if (e.key === "End") next = max;
    if (next === null) return;
    e.preventDefault();
    apply(next, true);
  };

  return (
    <div
      ref={ref}
      className="splitter"
      data-axis={axis}
      role="separator"
      tabIndex={0}
      aria-label={label}
      // a vertical bar separates columns (axis x), a horizontal one rows
      aria-orientation={axis === "x" ? "vertical" : "horizontal"}
      aria-valuenow={value}
      aria-valuemin={min}
      aria-valuemax={max}
      onPointerDown={onPointerDown}
      onKeyDown={onKeyDown}
      onDoubleClick={() => apply(kLayoutVars[variable], true)}
    />
  );
}
