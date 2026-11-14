// app/src/components/ActivityRail.tsx
// The icon strip on the left of the mockup. Chooses what the left panel shows;
// exposed as a vertical tablist controlling the left panel

import { Boxes, ScrollText, Settings, Target } from "lucide-react";
import IconButton from "@/components/IconButton";
import Tabs from "@/components/Tabs";
import { useT } from "@/i18n";
import type { RailView } from "@/store/ui";

export type { RailView };

const kItems = [
  { id: "targets", labelKey: "rail.targets", Icon: Target },
  { id: "modules", labelKey: "rail.modules", Icon: Boxes },
  { id: "scripts", labelKey: "rail.scripts", Icon: ScrollText },
] as const;

type Props = {
  active: RailView;
  onSelect: (view: RailView) => void;
  onSettings: () => void;
};

export default function ActivityRail({ active, onSelect, onSettings }: Props) {
  const t = useT();
  return (
    <nav className="rail" aria-label={t("rail.activity")}>
      <Tabs<RailView>
        items={kItems.map(({ id, labelKey, Icon }) => ({
          id,
          label: <Icon size={18} strokeWidth={1.75} aria-hidden />,
          ariaLabel: t(labelKey),
          tip: t(labelKey),
        }))}
        active={active}
        onChange={onSelect}
        label={t("rail.sidePanel")}
        idPrefix="rail"
        orientation="vertical"
        tabClassName="rail-button"
      />

      <div className="rail-spacer" />

      <IconButton
        tip={t("common.settings")}
        variant="bare"
        className="rail-button"
        onClick={onSettings}
      >
        <Settings size={18} strokeWidth={1.75} aria-hidden />
      </IconButton>
    </nav>
  );
}
