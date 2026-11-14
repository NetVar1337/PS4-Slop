// app/src/components/SettingsModal.tsx
// App settings. Language, theme, theme editor and motion are local; everything
// under "Engine" is engine-side state, read and written over /api
// (app.settings_get/_set) the same way an agent would

import { useEffect, useRef, useState } from "react";
import { Check, Copy, KeyRound } from "lucide-react";
import { save as saveDialog } from "@tauri-apps/plugin-dialog";
import logoUrl from "@/assets/reverse-slop-icon.png";
import IconButton from "@/components/IconButton";
import Modal from "@/components/Modal";
import { kLanguages, useI18n, useT } from "@/i18n";
import { call, getEndpoint } from "@/lib/rpc";
import { copyText } from "@/lib/clipboard";
import { isTauri } from "@/lib/endpoint";
import { readLayoutFile, saveLayoutFile } from "@/lib/layoutFile";
import { useEngine } from "@/store/engine";
import { kMotionOptions, osPrefersReduced, useMotion } from "@/store/motion";
import { useSettings } from "@/store/settings";
import { kThemeTokens, kThemes, useTheme, type ThemeColors, type ThemeName } from "@/store/theme";
import { layoutChanges, layoutFile, parseLayoutFile, useUi } from "@/store/ui";
import { useUpdater } from "@/store/updater";

type Props = { onClose: () => void };

function CopyButton({ text, tip }: { text: string; tip: string }) {
  const t = useT();
  const [copied, setCopied] = useState(false);
  const reset = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(reset.current), []);
  return (
    <IconButton
      tip={copied ? t("settings.copied") : tip}
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

/** Current palette values as hex, so the color inputs start on the live theme. */
function readColors(): ThemeColors {
  const style = getComputedStyle(document.documentElement);
  const out: ThemeColors = {};
  for (const { id } of kThemeTokens) {
    const value = style.getPropertyValue(id).trim();
    if (/^#[0-9a-f]{6}$/i.test(value)) out[id] = value;
  }
  return out;
}

/** Base palette, per-token color inputs with live preview, named saves and a
 *  JSON round-trip. Overrides are inline custom properties on <html>. */
function ThemeEditor() {
  const t = useT();
  const theme = useTheme((s) => s.theme);
  const customThemes = useTheme((s) => s.customThemes);
  const activeCustom = useTheme((s) => s.activeCustom);
  const setTheme = useTheme((s) => s.setTheme);
  const previewColors = useTheme((s) => s.previewColors);
  const saveCustom = useTheme((s) => s.saveCustom);
  const applyCustom = useTheme((s) => s.applyCustom);
  const deleteCustom = useTheme((s) => s.deleteCustom);
  const exportCustom = useTheme((s) => s.exportCustom);
  const importCustom = useTheme((s) => s.importCustom);
  const [base, setBase] = useState<ThemeName>(theme);
  const [colors, setColors] = useState<ThemeColors>(readColors);
  const [name, setName] = useState("");
  const [json, setJson] = useState("");
  const [note, setNote] = useState<string | null>(null);

  const pickBase = (next: ThemeName) => {
    setBase(next);
    setTheme(next);
    setColors(readColors());
  };

  const editColor = (token: keyof ThemeColors, value: string) => {
    const next = { ...colors, [token]: value };
    setColors(next);
    previewColors(next);
  };

  const save = () => {
    const saved = saveCustom(name, base, colors);
    if (saved === null) return;
    setName("");
    setNote(t("settings.themeSaved", { name: saved.name }));
  };

  const importJson = () => {
    const imported = importCustom(json);
    setNote(
      imported === null
        ? t("settings.importFailed")
        : t("settings.themeSaved", { name: imported.name }),
    );
  };

  return (
    <>
      <fieldset className="settings-group">
        <legend className="settings-label">{t("settings.themeEditor")}</legend>
        <div className="settings-choices">
          {kThemes.map((th) => (
            <button
              type="button"
              key={th.id}
              className="row-action"
              data-active={base === th.id}
              aria-pressed={base === th.id}
              onClick={() => pickBase(th.id)}
            >
              {t(th.labelKey)}
            </button>
          ))}
        </div>
        <div className="theme-grid">
          {kThemeTokens.map((token) => (
            <label className="theme-token" key={token.id}>
              <input
                type="color"
                aria-label={t(token.labelKey)}
                value={colors[token.id] ?? "#000000"}
                onChange={(e) => editColor(token.id, e.target.value)}
              />
              <span>{t(token.labelKey)}</span>
            </label>
          ))}
        </div>
        <div className="settings-choices">
          <input
            className="addr-input"
            aria-label={t("settings.themeName")}
            placeholder={t("settings.themeNamePlaceholder")}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <button type="button" className="row-action" disabled={name.trim() === ""} onClick={save}>
            {t("settings.saveTheme")}
          </button>
          <button type="button" className="row-action" onClick={() => previewColors(null)}>
            {t("settings.previewReset")}
          </button>
        </div>
        <div className="settings-rows">
          <div className="faint">{t("settings.customThemes")}</div>
          {customThemes.length === 0 ? (
            <div className="faint">{t("settings.noCustomThemes")}</div>
          ) : (
            customThemes.map((custom) => (
              <div className="settings-copy-row" key={custom.name}>
                <span className="settings-copy-text" data-active={custom.name === activeCustom}>
                  {custom.name}
                </span>
                <button
                  type="button"
                  className="row-action"
                  onClick={() => applyCustom(custom.name)}
                >
                  {t("settings.applyTheme")}
                </button>
                <button
                  type="button"
                  className="row-action"
                  onClick={() => setJson(exportCustom(custom.name) ?? "")}
                >
                  {t("settings.exportTheme")}
                </button>
                <IconButton
                  tip={t("settings.deleteTheme", { name: custom.name })}
                  onClick={() => deleteCustom(custom.name)}
                >
                  <KeyRound size={11} />
                </IconButton>
              </div>
            ))
          )}
        </div>
        <label className="settings-field">
          <span>{t("settings.themeJson")}</span>
          <textarea
            className="code-area mono settings-textarea"
            aria-label={t("settings.themeJson")}
            value={json}
            rows={4}
            spellCheck={false}
            onChange={(e) => setJson(e.target.value)}
          />
        </label>
        <div className="settings-choices">
          <button
            type="button"
            className="row-action"
            disabled={json.trim() === ""}
            onClick={importJson}
          >
            {t("settings.importTheme")}
          </button>
        </div>
        {note !== null && <div className="settings-status mono">{note}</div>}
      </fieldset>
    </>
  );
}

export default function SettingsModal({ onClose }: Props) {
  const t = useT();
  const language = useI18n((s) => s.language);
  const setLanguage = useI18n((s) => s.setLanguage);
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
  const [onboardClients, setOnboardClients] = useState("");
  const [confirmRotate, setConfirmRotate] = useState(false);
  const [appVersion, setAppVersion] = useState("");
  const [diag, setDiag] = useState<string | null>(null);
  const [diagBusy, setDiagBusy] = useState(false);
  const [layoutStatus, setLayoutStatus] = useState<string | null>(null);
  const endpoint = getEndpoint();
  const updatePhase = useUpdater((s) => s.phase);
  const updateVersion = useUpdater((s) => s.version);
  const updateProgress = useUpdater((s) => s.progress);
  const updateError = useUpdater((s) => s.error);
  const checkUpdates = useUpdater((s) => s.check);
  const installUpdate = useUpdater((s) => s.install);

  useEffect(() => {
    if (!isTauri()) return;
    let alive = true;
    void import("@tauri-apps/api/app")
      .then(({ getVersion }) => getVersion())
      .then((v) => {
        if (alive) setAppVersion(v);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, []);

  useEffect(() => {
    void load();
    return () => hideToken();
  }, [load, hideToken]);

  useEffect(() => {
    setAllowlist((settings?.web_allowlist ?? []).join("\n"));
    setProxyToken(typeof settings?.proxy_token === "string" ? settings.proxy_token : "");
    setOnboardClients((settings?.mcp_onboard_clients ?? []).join("\n"));
  }, [settings?.web_allowlist, settings?.proxy_token, settings?.mcp_onboard_clients]);

  // The MCP endpoint is the one value here a user needs outside the app,
  // wiring an MCP client by hand, so it gets a copy affordance
  const mcpUrl = `http://127.0.0.1:${endpoint.port}/mcp`;
  const tokenState =
    settings?.mcp_token === "set" ? "set" : settings?.mcp_token === "unset" ? "unset" : "unknown";
  const updateStatus =
    updatePhase === "checking"
      ? t("settings.updateChecking")
      : updatePhase === "available"
        ? t("settings.updateAvailable", { version: updateVersion ?? "" })
        : updatePhase === "downloading"
          ? t("settings.updateDownloading", {
              percent: updateProgress >= 0 ? ` ${Math.round(updateProgress * 100)}%` : "",
            })
          : updatePhase === "ready"
            ? t("settings.updateInstalling")
            : updatePhase === "error"
              ? t("settings.updateFailed", { error: updateError ?? "" })
              : t("settings.updateUpToDate");

  const saveAllowlist = () => {
    const hosts = allowlist
      .split(/[\s,]+/)
      .map((h) => h.trim())
      .filter((h) => h !== "");
    void setValue("web_allowlist", hosts);
  };

  // keep both
  const saveOnboardClients = () => {
    const clients = onboardClients
      .split(/[\n,]+/)
      .map((c) => c.trim())
      .filter((c) => c !== "");
    void setValue("mcp_onboard_clients", clients);
  };

  const plaintextConfigs = settings?.mcp_plaintext_configs ?? [];
  const setxCommand = 'setx SLOP_MCP_TOKEN "<engine token>"';

  // Support hand-off: one JSON file carries the shell layout, theme and motion
  const exportLayout = async () => {
    try {
      const path = await saveLayoutFile(`${JSON.stringify(layoutFile(), null, 2)}\n`);
      if (path !== null) setLayoutStatus(t("settings.exportedTo", { path }));
    } catch (e) {
      setLayoutStatus(
        t("settings.layoutExportFailed", { error: e instanceof Error ? e.message : String(e) }),
      );
    }
  };

  const importLayout = async () => {
    try {
      const raw = await readLayoutFile();
      if (raw === null) return;
      const file = parseLayoutFile(raw);
      const changes = layoutChanges(layoutFile(), file);
      useUi.getState().importLayout(file);
      setLayoutStatus(
        changes.length === 0
          ? t("settings.importedNothing")
          : t("settings.imported", { changes: changes.join(", ") }),
      );
    } catch (e) {
      setLayoutStatus(
        t("settings.layoutImportFailed", { error: e instanceof Error ? e.message : String(e) }),
      );
    }
  };

  // one zip a user can attach to a bug report: engine log tail, redacted
  // settings, versions and the console status (engine side: app.diag_bundle)
  const copyDiagnostics = async () => {
    setDiagBusy(true);
    setDiag(null);
    try {
      const path = await saveDialog({
        defaultPath: "slopstation-diagnostics.zip",
        filters: [{ name: "Zip archive", extensions: ["zip"] }],
      });
      if (path === null) return;
      await call("app", "diag_bundle", { path });
      setDiag(t("settings.saved", { path }));
    } catch (e) {
      setDiag(e instanceof Error ? e.message : String(e));
    } finally {
      setDiagBusy(false);
    }
  };
  return (
    <Modal title={t("settings.title")} onClose={onClose}>
      <div className="modal-body">
        <div className="settings-brand">
          <img src={logoUrl} alt="" draggable={false} />
          <div className="settings-brand-name">SlopStation</div>
          <div className="settings-brand-sub">
            {t("settings.brand", { version: appVersion || "dev", badge: backend.badge })}
          </div>
        </div>

        <fieldset className="settings-group">
          <legend className="settings-label">{t("settings.language")}</legend>
          <div className="settings-choices">
            {kLanguages.map((l) => (
              <button
                type="button"
                key={l.id}
                className="row-action"
                data-active={language === l.id}
                aria-pressed={language === l.id}
                onClick={() => setLanguage(l.id)}
              >
                {l.label}
              </button>
            ))}
          </div>
        </fieldset>

        <fieldset className="settings-group">
          <legend className="settings-label">{t("settings.theme")}</legend>
          <div className="settings-choices">
            {kThemes.map((th) => (
              <button
                type="button"
                key={th.id}
                className="row-action"
                data-active={theme === th.id}
                aria-pressed={theme === th.id}
                onClick={() => setTheme(th.id)}
              >
                {t(th.labelKey)}
              </button>
            ))}
          </div>
        </fieldset>

        <ThemeEditor />

        <fieldset className="settings-group">
          <legend className="settings-label">{t("settings.motion")}</legend>
          <div className="settings-choices">
            {kMotionOptions.map((o) => (
              <button
                type="button"
                key={o.id}
                className="row-action"
                data-active={motion === o.id}
                aria-pressed={motion === o.id}
                data-tip={t(o.hintKey)}
                onClick={() => setMotion(o.id)}
              >
                {t(o.labelKey)}
              </button>
            ))}
          </div>
          {osPrefersReduced() && <div className="settings-rows">{t("settings.motionOs")}</div>}
        </fieldset>

        <fieldset className="settings-group">
          <legend className="settings-label">{t("settings.layout")}</legend>
          <div className="settings-rows">
            <div className="faint">{t("settings.layoutHint")}</div>
            <div className="settings-choices">
              <button type="button" className="row-action" onClick={() => void exportLayout()}>
                {t("settings.exportLayout")}
              </button>
              <button type="button" className="row-action" onClick={() => void importLayout()}>
                {t("settings.importLayout")}
              </button>
            </div>
            {layoutStatus !== null && (
              <div className="settings-status mono" role="status">
                {layoutStatus}
              </div>
            )}
          </div>
        </fieldset>

        <fieldset className="settings-group">
          <legend className="settings-label">{t("settings.target")}</legend>
          <div className="settings-rows mono">
            <div>
              {t("settings.backend", { badge: backend.badge })}
              {backend.ps4 ? t("settings.backendPs4") : ""}
            </div>
            <div>
              ps4: {backend.ps4 ? t("settings.ps4Connected") : t("settings.ps4Disconnected")}
            </div>
            <div>
              {t("settings.targetValue", {
                value: target.attached
                  ? t("settings.attached", {
                      pid: target.pid ?? 0,
                      name: target.name ?? "?",
                    })
                  : t("common.none"),
              })}
            </div>
          </div>
        </fieldset>

        <fieldset className="settings-group">
          <legend className="settings-label">{t("settings.engine")}</legend>
          <div className="settings-rows mono">
            <div>{t("settings.api", { port: endpoint.port })}</div>
            <div className="settings-copy-row">
              <span className="settings-copy-text">{t("settings.mcp", { url: mcpUrl })}</span>
              <CopyButton text={mcpUrl} tip={t("settings.copyMcp")} />
            </div>
            <div>
              {t("settings.uiAuth", {
                value: endpoint.token === "" ? t("settings.authNone") : t("settings.authBearer"),
              })}
            </div>
          </div>
          <div className="settings-choices">
            <button
              type="button"
              className="row-action"
              disabled={!isTauri() || diagBusy}
              data-tip={t("settings.diagnosticsTip")}
              onClick={() => void copyDiagnostics()}
            >
              {diagBusy ? t("settings.bundling") : t("settings.copyDiagnostics")}
            </button>
          </div>
          {diag !== null && <div className="settings-status mono">{diag}</div>}
        </fieldset>

        <fieldset className="settings-group">
          <legend className="settings-label">{t("settings.updates")}</legend>
          <div className="settings-rows">
            <div>{t("settings.version", { version: appVersion || "dev" })}</div>
            <div>{updateStatus}</div>
            <div className="settings-choices">
              <button
                type="button"
                className="row-action"
                disabled={updatePhase === "checking" || updatePhase === "downloading"}
                onClick={() => void checkUpdates(true)}
              >
                {updatePhase === "checking"
                  ? t("settings.updateChecking")
                  : t("settings.checkUpdates")}
              </button>
              {updatePhase === "available" && (
                <button type="button" className="row-action" onClick={() => void installUpdate()}>
                  {t("settings.installRestart", { version: updateVersion ?? "" })}
                </button>
              )}
            </div>
          </div>
        </fieldset>

        <fieldset className="settings-group">
          <legend className="settings-label">{t("settings.mcpToken")}</legend>
          <div className="settings-rows">
            <div>
              {t("settings.mcpTokenIntro")}{" "}
              <strong>{tokenState === "unknown" ? t("settings.tokenUnknown") : tokenState}</strong>
              {t("settings.mcpTokenOutro")}
            </div>
            <div className="settings-copy-row">
              <span className="settings-copy-text mono">{setxCommand}</span>
              <CopyButton text={setxCommand} tip={t("settings.copySetx")} />
            </div>
            <div className="faint">
              {t("settings.tokenEnvIntro")} <code>${"${SLOP_MCP_TOKEN}"}</code>
              {t("settings.tokenEnvOutro")}
            </div>
            {plaintextConfigs.length > 0 && (
              <div className="settings-status" role="alert">
                {t("settings.plaintext", { list: plaintextConfigs.join(", ") })}{" "}
                {t("settings.plaintextHint")}
              </div>
            )}
            {revealedToken !== null && (
              <div className="settings-copy-row mono">
                <span className="settings-copy-text" data-testid="revealed-token">
                  {revealedToken}
                </span>
                <CopyButton text={revealedToken} tip={t("settings.copyNewToken")} />
              </div>
            )}
            {revealedToken === null && clientsUpdated.length > 0 && (
              <div>{t("settings.rotated", { list: clientsUpdated.join(", ") })}</div>
            )}
            {revealedToken !== null && (
              <div className="faint">
                {t("settings.shownOnce", { list: clientsUpdated.join(", ") || t("common.none") })}
              </div>
            )}
            <div className="settings-choices">
              {confirmRotate ? (
                <>
                  <span>{t("settings.rotateWarning")}</span>
                  <button
                    type="button"
                    className="row-action"
                    onClick={() => {
                      setConfirmRotate(false);
                      void rotateToken();
                    }}
                  >
                    {t("settings.confirmRegenerate")}
                  </button>
                  <button
                    type="button"
                    className="row-action"
                    onClick={() => setConfirmRotate(false)}
                  >
                    {t("common.cancel")}
                  </button>
                </>
              ) : (
                <button type="button" className="row-action" onClick={() => setConfirmRotate(true)}>
                  <KeyRound size={11} aria-hidden /> {t("settings.regenerate")}
                </button>
              )}
            </div>
          </div>
        </fieldset>

        <fieldset className="settings-group" disabled={settings === null}>
          <legend className="settings-label">{t("settings.enginePolicy")}</legend>
          <Toggle
            label={t("settings.unsafeLabel")}
            hint={t("settings.unsafeHint")}
            checked={settings?.script_unsafe === true}
            onChange={(v) => void setValue("script_unsafe", v)}
          />
          <Toggle
            label={t("settings.privateLabel")}
            hint={t("settings.privateHint")}
            checked={settings?.web_allow_private === true}
            onChange={(v) => void setValue("web_allow_private", v)}
          />
          <label className="settings-field">
            <span>{t("settings.allowlistLabel")}</span>
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
            <span>{t("settings.proxyLabel")}</span>
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
          <Toggle
            label={t("settings.writeTokenLabel")}
            hint={t("settings.writeTokenHint")}
            checked={settings?.mcp_token_in_configs === true}
            onChange={(v) => void setValue("mcp_token_in_configs", v)}
          />
          <label className="settings-field">
            <span>{t("settings.onboardLabel")}</span>
            <textarea
              className="code-area mono settings-textarea"
              value={onboardClients}
              rows={3}
              spellCheck={false}
              onChange={(e) => setOnboardClients(e.target.value)}
              onBlur={saveOnboardClients}
            />
          </label>
          {restartRequired.length > 0 && (
            <div className="settings-status">
              {t("settings.restartRequired", { keys: restartRequired.join(", ") })}
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
