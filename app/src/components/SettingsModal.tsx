// app/src/components/SettingsModal.tsx
// App settings. Theme and motion are local; everything under "Engine" is
// engine-side state, read and written over /api (app.settings_get/_set) the
// same way an agent would

import { useEffect, useRef, useState } from "react";
import { Check, Copy, KeyRound } from "lucide-react";
import logoUrl from "@/assets/reverse-slop-icon.png";
import IconButton from "@/components/IconButton";
import Modal from "@/components/Modal";
import { getEndpoint } from "@/lib/rpc";
import { copyText } from "@/lib/clipboard";
import { useEngine } from "@/store/engine";
import { kMotionOptions, osPrefersReduced, useMotion } from "@/store/motion";
import { useSettings } from "@/store/settings";
import { kThemes, useTheme } from "@/store/theme";

type Props = { onClose: () => void };

function CopyButton({ text, tip }: { text: string; tip: string }) {
  const [copied, setCopied] = useState(false);
  const reset = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(reset.current), []);
  return (
    <IconButton
      tip={copied ? "Copied" : tip}
      onClick={() => {
        void copyText(text).then(() => {
          setCopied(true);
          clearTimeout(reset.current);
          reset.current = setTimeout(() => setCopied(false), 1600);
        });
      }}
    >
      {copied ? <Check size={14} /> : <Copy size={14} />}
    </IconButton>
  );
}

function Toggle({
  label,
  hint,
  checked,
  disabled,
  onChange,
}: {
  label: string;
  hint: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="settings-toggle">
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>
        <span>{label}</span>
        <span className="settings-hint">{hint}</span>
      </span>
    </label>
  );
}

export default function SettingsModal({ onClose }: Props) {
  const theme = useTheme((s) => s.theme);
  const setTheme = useTheme((s) => s.setTheme);
  const motion = useMotion((s) => s.motion);
  const setMotion = useMotion((s) => s.setMotion);
  const backend = useEngine((s) => s.backend);
  const target = useEngine((s) => s.target);
  const {
    settings,
    error,
    revealedToken,
    clientsUpdated,
    restartRequired,
    load,
    setValue,
    rotateToken,
    hideToken,
  } = useSettings();
  const [allowlist, setAllowlist] = useState("");
  const [proxyToken, setProxyToken] = useState("");
  const [confirmRotate, setConfirmRotate] = useState(false);
  const endpoint = getEndpoint();

  useEffect(() => {
    void load();
    return () => hideToken();
  }, [load, hideToken]);

  useEffect(() => {
    setAllowlist((settings?.web_allowlist ?? []).join("\n"));
    setProxyToken(typeof settings?.proxy_token === "string" ? settings.proxy_token : "");
  }, [settings?.web_allowlist, settings?.proxy_token]);

  // The MCP endpoint is the one value here a user needs outside the app,
  // wiring an MCP client by hand, so it gets a copy affordance
  const mcpUrl = `http://127.0.0.1:${endpoint.port}/mcp`;
  const tokenState =
    settings?.mcp_token === "set" ? "set" : settings?.mcp_token === "unset" ? "unset" : "unknown";

  const saveAllowlist = () => {
    const hosts = allowlist
      .split(/[\s,]+/)
      .map((h) => h.trim())
      .filter((h) => h !== "");
    void setValue("web_allowlist", hosts);
  };

  return (
    <Modal title="Settings" onClose={onClose}>
      <div className="modal-body">
        <div className="settings-brand">
          <img src={logoUrl} alt="" draggable={false} />
          <div className="settings-brand-name">reverse-slop</div>
          <div className="settings-brand-sub">v0.1.1 · {backend.badge} engine</div>
        </div>

        <fieldset className="settings-group">
          <legend className="settings-label">Theme</legend>
          <div className="settings-choices">
            {kThemes.map((t) => (
              <button
                type="button"
                key={t.id}
                className="row-action"
                data-active={theme === t.id}
                aria-pressed={theme === t.id}
                onClick={() => setTheme(t.id)}
              >
                {t.label}
              </button>
            ))}
          </div>
        </fieldset>

        <fieldset className="settings-group">
          <legend className="settings-label">Motion</legend>
          <div className="settings-choices">
            {kMotionOptions.map((o) => (
              <button
                type="button"
                key={o.id}
                className="row-action"
                data-active={motion === o.id}
                aria-pressed={motion === o.id}
                data-tip={o.hint}
                onClick={() => setMotion(o.id)}
              >
                {o.label}
              </button>
            ))}
          </div>
          {osPrefersReduced() && (
            <div className="settings-rows">
              Windows currently has animation effects switched off. “Auto” follows that and disables
              transitions; “On” overrides it.
            </div>
          )}
        </fieldset>

        <fieldset className="settings-group">
          <legend className="settings-label">Target</legend>
          <div className="settings-rows mono">
            <div>
              backend: {backend.badge}
              {backend.ps4 ? " (ps4 console)" : ""}
            </div>
            <div>
              ps4:{" "}
              {backend.ps4
                ? "connected - connect another from the Targets panel or MCP target.ps4_auto"
                : "not connected - use the Targets panel (ps4 connect) or MCP target.ps4_auto with a host"}
            </div>
            <div>
              target:{" "}
              {target.attached ? `attached pid ${target.pid ?? 0} (${target.name ?? "?"})` : "none"}
            </div>
          </div>
        </fieldset>

        <fieldset className="settings-group">
          <legend className="settings-label">Engine</legend>
          <div className="settings-rows mono">
            <div>api: http://127.0.0.1:{endpoint.port}/api</div>
            <div className="settings-copy-row">
              <span className="settings-copy-text">mcp: {mcpUrl}</span>
              <CopyButton text={mcpUrl} tip="Copy MCP URL" />
            </div>
            <div>ui auth: {endpoint.token === "" ? "none (browser dev mode)" : "bearer token"}</div>
          </div>
        </fieldset>

        <fieldset className="settings-group">
          <legend className="settings-label">MCP token</legend>
          <div className="settings-rows">
            <div>
              External MCP clients authenticate with this token. It is{" "}
              <strong>
                {tokenState === "unknown" ? "unknown (engine not reachable)" : tokenState}
              </strong>
              ; the engine never returns its value.
            </div>
            {revealedToken !== null && (
              <div className="settings-copy-row mono">
                <span className="settings-copy-text" data-testid="revealed-token">
                  {revealedToken}
                </span>
                <CopyButton text={revealedToken} tip="Copy new token" />
              </div>
            )}
            {revealedToken === null && clientsUpdated.length > 0 && (
              <div>Rotated. Updated client configs: {clientsUpdated.join(", ")}.</div>
            )}
            {revealedToken !== null && (
              <div className="faint">
                Shown once. Onboarded clients: {clientsUpdated.join(", ") || "none"}.
              </div>
            )}
            <div className="settings-choices">
              {confirmRotate ? (
                <>
                  <span>Existing MCP clients will need the new token.</span>
                  <button
                    type="button"
                    className="row-action"
                    onClick={() => {
                      setConfirmRotate(false);
                      void rotateToken();
                    }}
                  >
                    Confirm regenerate
                  </button>
                  <button
                    type="button"
                    className="row-action"
                    onClick={() => setConfirmRotate(false)}
                  >
                    Cancel
                  </button>
                </>
              ) : (
                <button type="button" className="row-action" onClick={() => setConfirmRotate(true)}>
                  <KeyRound size={11} aria-hidden /> Regenerate token…
                </button>
              )}
            </div>
          </div>
        </fieldset>

        <fieldset className="settings-group" disabled={settings === null}>
          <legend className="settings-label">Engine policy</legend>
          <Toggle
            label="Unsafe Lua scripts"
            hint="Give script.run the full Lua stdlib (os.execute, io.popen). Off = sandboxed."
            checked={settings?.script_unsafe === true}
            onChange={(v) => void setValue("script_unsafe", v)}
          />
          <Toggle
            label="Allow private network fetches"
            hint="Let web.fetch / web.post reach loopback, link-local and private addresses."
            checked={settings?.web_allow_private === true}
            onChange={(v) => void setValue("web_allow_private", v)}
          />
          <label className="settings-field">
            <span>Web allowlist (one host per line; private hosts listed here are allowed)</span>
            <textarea
              className="code-area mono settings-textarea"
              value={allowlist}
              rows={3}
              spellCheck={false}
              onChange={(e) => setAllowlist(e.target.value)}
              onBlur={saveAllowlist}
            />
          </label>
          <label className="settings-field">
            <span>Proxy token (clients of the HTTP proxy must send it)</span>
            <input
              className="addr-input mono"
              style={{ width: "100%" }}
              type="password"
              value={proxyToken}
              spellCheck={false}
              autoComplete="new-password"
              onChange={(e) => setProxyToken(e.target.value)}
              onBlur={() => {
                if (proxyToken !== (settings?.proxy_token ?? ""))
                  void setValue("proxy_token", proxyToken);
              }}
            />
          </label>
          {restartRequired.length > 0 && (
            <div className="settings-status">
              Restart the engine to apply: {restartRequired.join(", ")}
            </div>
          )}
        </fieldset>

        {error !== null && (
          <div className="settings-status" role="alert">
            {error}
          </div>
        )}
      </div>
    </Modal>
  );
}
