// app/src/components/Tabs.tsx
// WAI-ARIA tablist: role=tab buttons with aria-selected, roving tabindex and
// arrow / Home / End navigation. Used by the workspace, output and image
// browser tab strips and (vertically) by the activity rail

import { useRef, type KeyboardEvent, type ReactNode } from "react";

export type TabItem<T extends string> = {
  id: T;
  label: ReactNode;
  /** Accessible name when `label` is not text (icons). */
  ariaLabel?: string;
  tip?: string;
};

type Props<T extends string> = {
  items: readonly TabItem<T>[];
  active: T;
  onChange: (id: T) => void;
  /** Accessible name of the tab strip. */
  label: string;
  /** Prefix for tab / panel ids, so panels can reference their tab. */
  idPrefix: string;
  orientation?: "horizontal" | "vertical";
  tabClassName?: string;
};

export function tabId(prefix: string, id: string): string {
  return `${prefix}-tab-${id}`;
}

export function panelId(prefix: string, id: string): string {
  return `${prefix}-panel-${id}`;
}

export default function Tabs<T extends string>({
  items,
  active,
  onChange,
  label,
  idPrefix,
  orientation = "horizontal",
  tabClassName = "tab",
}: Props<T>) {
  const refs = useRef(new Map<T, HTMLButtonElement>());

  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>, index: number) => {
    const prev = orientation === "horizontal" ? "ArrowLeft" : "ArrowUp";
    const next = orientation === "horizontal" ? "ArrowRight" : "ArrowDown";
    let target = -1;
    if (e.key === prev) target = (index - 1 + items.length) % items.length;
    else if (e.key === next) target = (index + 1) % items.length;
    else if (e.key === "Home") target = 0;
    else if (e.key === "End") target = items.length - 1;
    if (target < 0) return;
    e.preventDefault();
    const id = items[target].id;
    onChange(id);
    refs.current.get(id)?.focus();
  };

  return (
    <div role="tablist" aria-label={label} aria-orientation={orientation} className="tablist">
      {items.map((t, i) => {
        const selected = t.id === active;
        return (
          <button
            key={t.id}
            ref={(el) => {
              if (el) refs.current.set(t.id, el);
              else refs.current.delete(t.id);
            }}
            type="button"
            role="tab"
            id={tabId(idPrefix, t.id)}
            aria-selected={selected}
            aria-controls={panelId(idPrefix, t.id)}
            aria-label={t.ariaLabel}
            tabIndex={selected ? 0 : -1}
            className={tabClassName}
            data-active={selected}
            data-tip={t.tip}
            onClick={() => onChange(t.id)}
            onKeyDown={(e) => onKeyDown(e, i)}
          >
            {t.label}
          </button>
        );
      })}
    </div>
  );
}
