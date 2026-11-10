// app/src/components/SettingsModal.tsx
// App settings. Everything except the theme is engine-side state, read and
// written through the same tools an agent would use

import { useEffect, useRef, useState } from "react";
import { Check, Copy, X } from "lucide-react";
import logoUrl from "@/assets/reverse-slop-icon.png";
import { call, getEndpoint } from "@/lib/rpc";
import { copyText } from "@/lib/clipboard";
import { useEngine } from "@/store/engine";
import { kMotionOptions, osPrefersReduced, useMotion } from "@/store/motion";
import { kThemes, useTheme, type ThemeName } from "@/store/theme";

type Props = { onClose: () => void };

export default function SettingsModal({ onClose }: Props) {
  const theme = useTheme((s) => s.theme);
  const setTheme = useTheme((s) => s.setTheme);
  const motion = useMotion((s) => s.motion);
  const setMotion = useMotion((s) => s.setMotion);
  const { backend, target } = useEngine();
  const [status, setStatus] = useState<string | null>(null);
  const [copiedMcp, setCopiedMcp] = useState(false);
  const copiedReset = useRef<ReturnType<typeof setTimeout> | null>(null);
  const endpoint = getEndpoint();

  useEffect(
    () => () => {
      if (copiedReset.current !== null) clearTimeout(copiedReset.current);
    },
    [],
  );

  // The MCP endpoint is the one value here a user needs outside the app  
  // wiring an MCP client by hand, so it gets a copy affordance
  const mcpUrl = `http://127.0.0.1:${endpoint.port}/mcp`;

  const copyMcpUrl = async () => {
    try {
      await copyText(mcpUrl);
      setCopiedMcp(true);
      if (copiedReset.current !== null) clearTimeout(copiedReset.current);
      copiedReset.current = setTimeout(() => setCopiedMcp(false), 1600);
    } catch (e) {
      setStatus(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="modal-scrim" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="panel-head">
          <span className="panel-title">Settings</span>
          <div className="spacer" />
          <button className="icon-button" onClick={onClose}>
            <X size={14} />
          </button>
        </div>

        <div className="modal-body">
          <div className="settings-brand">
            <img src={logoUrl} alt="reverse-slop" draggable={false} />
            <div className="settings-brand-name">reverse-slop</div>
            <div className="settings-brand-sub">
              v0.1.1 · {backend.badge} engine
            </div>
          </div>

          <div className="settings-group">
            <div className="settings-label">Theme</div>
            <div style={{ display: "flex", gap: "var(--pad-sm)" }}>
              {kThemes.map((t) => (
                <button
                  key={t.id}
                  className="row-action"
                  data-active={theme === t.id}
                  onClick={() => setTheme(t.id as ThemeName)}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          <div className="settings-group">
            <div className="settings-label">Motion</div>
            <div style={{ display: "flex", gap: "var(--pad-sm)", alignItems: "center" }}>
              {kMotionOptions.map((o) => (
                <button
                  key={o.id}
                  className="row-action"
                  data-active={motion === o.id}
                  data-tip={o.hint}
                  onClick={() => setMotion(o.id)}
                >
                  {o.label}
                </button>
              ))}
            </div>
            {osPrefersReduced() && (
              <div className="settings-rows">
                Windows currently has animation effects switched off. “Auto” follows that
                and disables transitions; “On” overrides it.
              </div>
            )}
          </div>

          <div className="settings-group">
            <div className="settings-label">Target</div>
            <div className="settings-rows mono">
              <div>backend: {backend.badge}{backend.ps4 ? " (ps4 console)" : ""}</div>
              <div>
                ps4:{" "}
                {backend.ps4
                  ? "connected - connect another from the Targets panel or MCP target.ps4_auto"
                  : "not connected - use the Targets panel (ps4 connect) or MCP target.ps4_auto with a host"}
              </div>
              <div>
                target: {target.attached ? `attached pid ${target.pid ?? 0} (${target.name ?? "?"})` : "none"}
              </div>
            </div>
          </div>

          <div className="settings-group">
            <div className="settings-label">Engine</div>
            <div className="settings-rows mono">
              <div>api: http://127.0.0.1:{endpoint.port}/api</div>
              <div className="settings-copy-row">
                <span className="settings-copy-text">mcp: {mcpUrl}</span>
                <button
                  className="icon-button"
                  data-tip={copiedMcp ? "Copied" : "Copy MCP URL"}
                  aria-label="Copy MCP URL"
                  onClick={() => void copyMcpUrl()}
                >
                  {copiedMcp ? <Check size={14} /> : <Copy size={14} />}
                </button>
              </div>
              <div>auth: {endpoint.token === "" ? "none" : "bearer token"}</div>
            </div>
          </div>

          {status !== null && <div className="settings-status">{status}</div>}
        </div>
      </div>
    </div>
  );
}
