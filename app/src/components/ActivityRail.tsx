// app/src/components/ActivityRail.tsx
// The icon strip on the left of the mockup. Chooses what the left panel shows;
// exposed as a vertical tablist controlling the left panel

import { Boxes, ScrollText, Settings, Target } from "lucide-react";
import IconButton from "@/components/IconButton";
import Tabs from "@/components/Tabs";
import type { RailView } from "@/store/ui";

export type { RailView };

const kItems = [
  { id: "targets", label: "Targets", Icon: Target },
  { id: "modules", label: "Modules", Icon: Boxes },
  { id: "scripts", label: "Scripts", Icon: ScrollText },
] as const;

type Props = {
  active: RailView;
  onSelect: (view: RailView) => void;
  onSettings: () => void;
};

export default function ActivityRail({ active, onSelect, onSettings }: Props) {
  return (
    <nav className="rail" aria-label="Activity">
      <Tabs<RailView>
        items={kItems.map(({ id, label, Icon }) => ({
          id,
          label: <Icon size={18} strokeWidth={1.75} aria-hidden />,
          ariaLabel: label,
          tip: label,
        }))}
        active={active}
        onChange={onSelect}
        label="Side panel"
        idPrefix="rail"
        orientation="vertical"
        tabClassName="rail-button"
      />

      <div className="rail-spacer" />

      <IconButton tip="Settings" variant="bare" className="rail-button" onClick={onSettings}>
        <Settings size={18} strokeWidth={1.75} aria-hidden />
      </IconButton>
    </nav>
  );
}
