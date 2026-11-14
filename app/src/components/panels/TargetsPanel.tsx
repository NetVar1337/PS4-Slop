// app/src/components/panels/TargetsPanel.tsx
// process list and attach flow, stays on the list after attaching so targets
// can be switched without detaching. With no console connected the engine is
// on its local fallback backend; its processes are this PC's, so the panel
// asks for a console instead of listing them (host listing is opt-in)

import { useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { save as saveDialog } from "@tauri-apps/plugin-dialog";
import { Gamepad2, RefreshCw, Search, ShieldAlert, Unplug } from "lucide-react";
import IconButton from "@/components/IconButton";
import ProcessIcon from "@/components/ProcessIcon";
import { useT } from "@/i18n";
import { isTauri } from "@/lib/endpoint";
import { call } from "@/lib/rpc";
import { payloadDownload, payloadLatest, payloadSave, payloadStatus } from "@/lib/ps4debug";
import type { PayloadInfo, PayloadStatus } from "@/lib/ps4debug";
import { matchesFilter, useTargets, type ConsoleRow, type ProcessRow } from "@/store/targets";
import { useEngine } from "@/store/engine";

const kRowHeight = 22;
const kDefaultPs4Port = 744;
const kScanWidths = ["i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64"];

function ConnectForm({
  compact,
  host,
  port,
  onHost,
  onPort,
}: {
  compact: boolean;
  host: string;
  port: number;
  onHost: (v: string) => void;
  onPort: (v: number) => void;
}) {
  const t = useT();
  const connectPs4 = useTargets((s) => s.connectPs4);
  const saveConsole = useTargets((s) => s.saveConsole);
  const [busy, setBusy] = useState(false);
  const [discovering, setDiscovering] = useState(false);
  const [found, setFound] = useState<string[]>([]);
  const [discoverError, setDiscoverError] = useState<string | null>(null);

  // a discovered console can be kept as an endpoint without connecting now
  const saveEndpoint = async (ip: string) => {
    setDiscoverError(null);
    if (!(await saveConsole({ name: ip, host: ip, port })))
      setDiscoverError(t("targets.saveFailed", { ip }));
  };

  const submit = async () => {
    if (host.trim() === "" || busy) return;
    setBusy(true);
    try {
      await connectPs4(host.trim(), port);
    } finally {
      setBusy(false);
    }
  };

  const discover = async () => {
    setDiscovering(true);
    setDiscoverError(null);
    setFound([]);
    try {
      const res = await call<{ consoles?: { ip: string }[] }>("target", "ps4_discover", {
        timeout_ms: 2000,
      });
      const ips = (res.consoles ?? []).map((c) => c.ip).filter((ip) => ip !== "");
      setFound(ips);
      if (ips.length > 0) onHost(ips[0]);
      else setDiscoverError(t("targets.discoverFailed"));
    } catch (e) {
      setDiscoverError(e instanceof Error ? e.message : String(e));
    } finally {
      setDiscovering(false);
    }
  };

  return (
    <form
      className={compact ? "connect-bar" : "connect-form"}
      aria-label={t("targets.connectForm")}
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <input
        className="addr-input"
        aria-label={t("targets.ip")}
        placeholder={t("targets.ipPlaceholder")}
        value={host}
        onChange={(e) => onHost(e.target.value)}
      />
      <input
        className="addr-input"
        style={{ width: 64 }}
        aria-label={t("targets.port")}
        type="number"
        min={1}
        max={65535}
        value={port}
        onChange={(e) => onPort(Number(e.target.value) || kDefaultPs4Port)}
      />
      <button type="submit" className="row-action" disabled={host.trim() === "" || busy}>
        {busy ? t("targets.connecting") : t("targets.connect")}
      </button>
      <button
        type="button"
        className="row-action"
        disabled={discovering}
        onClick={() => void discover()}
      >
        {discovering ? t("targets.searching") : t("targets.discover")}
      </button>
      <button
        type="button"
        className="row-action"
        disabled={host.trim() === ""}
        data-tip={t("targets.saveEndpointTip")}
        onClick={() => void saveEndpoint(host.trim())}
      >
        {t("targets.saveEndpoint")}
      </button>
      {found.length > 1 &&
        found.map((ip) => (
          <button type="button" key={ip} className="link-button" onClick={() => onHost(ip)}>
            {ip}
          </button>
        ))}
      {discoverError !== null && <span className="faint error-text">{discoverError}</span>}
    </form>
  );
}

type ConsoleForm = {
  name: string;
  host: string;
  port: number;
  default_pid: number;
  watchlist: string;
  scan_width: string;
};

const kEmptyConsoleForm: ConsoleForm = {
  name: "",
  host: "",
  port: kDefaultPs4Port,
  default_pid: 0,
  watchlist: "",
  scan_width: "u32",
};

/** Saved endpoints: add/edit/remove, connect or quick-switch, with the
 *  firmware/caps the engine recorded on the last connection. */
function ConsolesCard() {
  const t = useT();
  const consoles = useTargets((s) => s.consoles);
  const activeConsole = useTargets((s) => s.activeConsole);
  const saveConsole = useTargets((s) => s.saveConsole);
  const removeConsole = useTargets((s) => s.removeConsole);
  const switchConsole = useTargets((s) => s.switchConsole);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<ConsoleForm>(kEmptyConsoleForm);
  const [busy, setBusy] = useState(false);

  if (consoles.length === 0 && !open) return null;

  const edit = (c: ConsoleRow) => {
    setForm({
      name: c.name,
      host: c.host,
      port: c.port,
      default_pid: c.default_pid,
      watchlist: c.profile.watchlist,
      scan_width: c.profile.scan_width === "" ? "u32" : c.profile.scan_width,
    });
    setOpen(true);
  };

  const submit = async () => {
    setBusy(true);
    try {
      const ok = await saveConsole({
        name: form.name.trim(),
        host: form.host.trim(),
        port: form.port,
        default_pid: form.default_pid,
        profile: { watchlist: form.watchlist.trim(), scan_width: form.scan_width },
      });
      if (ok) {
        setOpen(false);
        setForm(kEmptyConsoleForm);
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="consoles-card">
      <div className="payload-head">
        <span className="payload-title">{t("targets.consoles")}</span>
        <span className="faint">{t("targets.saved", { count: consoles.length })}</span>
        <div className="spacer" />
        <button
          type="button"
          className="row-action"
          onClick={() => {
            setForm(kEmptyConsoleForm);
            setOpen((v) => !v);
          }}
        >
          {open ? t("common.cancel") : t("common.add")}
        </button>
      </div>
      {consoles.length > 0 && (
        <div className="console-list">
          {consoles.map((c) => (
            <div className="console-row" key={c.name} data-active={c.name === activeConsole}>
              <span className="console-name">{c.name}</span>
              <span className="faint mono">
                {c.host}:{c.port}
              </span>
              <span className="faint">
                {c.last_fw !== ""
                  ? t("targets.fw", { fw: c.last_fw })
                  : t("targets.neverConnected")}
                {c.last_seen_ms > 0 ? ` · ${new Date(c.last_seen_ms).toLocaleDateString()}` : ""}
              </span>
              {c.last_caps !== "" && <span className="pill">{c.last_caps}</span>}
              {c.notes !== "" && <span className="faint console-note">{c.notes}</span>}
              <div className="spacer" />
              <button
                type="button"
                className="row-action"
                data-active={c.name === activeConsole}
                onClick={() => void switchConsole(c.name)}
              >
                {c.name === activeConsole ? t("targets.reconnect") : t("targets.switch")}
              </button>
              <button type="button" className="link-button" onClick={() => edit(c)}>
                {t("common.edit")}
              </button>
              <button
                type="button"
                className="link-button"
                onClick={() => void removeConsole(c.name)}
              >
                {t("common.remove")}
              </button>
            </div>
          ))}
        </div>
      )}
      {open && (
        <form
          className="console-form"
          aria-label={t("targets.saveConsoleForm")}
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <input
            className="addr-input"
            aria-label={t("targets.consoleName")}
            placeholder={t("targets.namePlaceholder")}
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
          />
          <input
            className="addr-input"
            aria-label={t("targets.consoleHost")}
            placeholder={t("targets.hostPlaceholder")}
            value={form.host}
            onChange={(e) => setForm({ ...form, host: e.target.value })}
          />
          <input
            className="addr-input"
            style={{ width: 64 }}
            aria-label={t("targets.consolePort")}
            type="number"
            min={1}
            max={65535}
            value={form.port}
            onChange={(e) => setForm({ ...form, port: Number(e.target.value) || kDefaultPs4Port })}
          />
          <input
            className="addr-input"
            style={{ width: 70 }}
            aria-label={t("targets.defaultPid")}
            type="number"
            min={0}
            value={form.default_pid}
            onChange={(e) => setForm({ ...form, default_pid: Number(e.target.value) || 0 })}
          />
          <input
            className="addr-input"
            aria-label={t("targets.watchlistSet")}
            placeholder={t("targets.watchlistSet")}
            value={form.watchlist}
            onChange={(e) => setForm({ ...form, watchlist: e.target.value })}
          />
          <select
            className="addr-input"
            aria-label={t("targets.scanWidth")}
            value={form.scan_width}
            onChange={(e) => setForm({ ...form, scan_width: e.target.value })}
          >
            {kScanWidths.map((w) => (
              <option key={w} value={w}>
                {w}
              </option>
            ))}
          </select>
          <button
            type="submit"
            className="row-action"
            disabled={busy || form.name.trim() === "" || form.host.trim() === ""}
          >
            {busy ? t("targets.saving") : t("targets.saveConsole")}
          </button>
        </form>
      )}
    </div>
  );
}

function PayloadCard({ host }: { host: string }) {
  const t = useT();
  const [status, setStatus] = useState<PayloadStatus | null>(null);
  const [latest, setLatest] = useState<PayloadInfo | null>(null);
  const [busy, setBusy] = useState<"check" | "download" | "save" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaderPort, setLoaderPort] = useState(9090);
  const [sending, setSending] = useState(false);
  const [sent, setSent] = useState<number | null>(null);
  const [sendError, setSendError] = useState<string | null>(null);
  useEffect(() => {
    void payloadStatus().then(setStatus);
  }, []);
  if (!isTauri()) return null;
  const installed = status?.local ?? status?.bundled ?? null;
  const newer = latest !== null && installed !== null && latest.tag !== installed.tag;
  const check = async () => {
    setBusy("check");
    setError(null);
    try {
      setLatest(await payloadLatest());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };
  const download = async () => {
    setBusy("download");
    setError(null);
    try {
      const info = await payloadDownload();
      setStatus((s) => (s === null ? s : { ...s, local: info }));
      setLatest(info);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };
  const save = async () => {
    if (installed === null) return;
    setBusy("save");
    setError(null);
    try {
      const dest = await saveDialog({
        defaultPath: "ps4debug-ng.bin",
        filters: [{ name: "Payload", extensions: ["bin"] }],
      });
      if (dest !== null) await payloadSave(installed.path, dest);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };
  const send = async () => {
    if (installed === null || host.trim() === "") return;
    setSending(true);
    setSendError(null);
    setSent(null);
    try {
      const res = await call<{ bytes: number }>("target", "ps4_send_payload", {
        host: host.trim(),
        port: loaderPort,
        path: installed.path,
      });
      setSent(res.bytes);
    } catch (e) {
      setSendError(e instanceof Error ? e.message : String(e));
    } finally {
      setSending(false);
    }
  };
  return (
    <div className="payload-card">
      <div className="payload-head">
        <span className="payload-title">{t("targets.payloadTitle")}</span>
        <span className="faint">
          {installed === null
            ? t("targets.notBundled")
            : t("targets.payloadVersion", { tag: installed.tag })}
        </span>
      </div>
      <div className="payload-hint">
        {installed === null
          ? t("targets.payloadMissing")
          : t("targets.payloadBundled", { source: installed.source })}
        {latest !== null ? t("targets.payloadLatest", { tag: latest.tag }) : ""}
      </div>
      <div className="payload-actions">
        <button
          type="button"
          className="row-action"
          disabled={busy !== null}
          onClick={() => void check()}
        >
          {busy === "check" ? t("targets.checking") : t("targets.checkLatest")}
        </button>
        {newer && (
          <button
            type="button"
            className="row-action"
            disabled={busy !== null}
            onClick={() => void download()}
          >
            {busy === "download"
              ? t("targets.downloading")
              : t("targets.download", { tag: latest?.tag ?? "" })}
          </button>
        )}
        {installed !== null && (
          <button
            type="button"
            className="row-action"
            disabled={busy !== null}
            onClick={() => void save()}
          >
            {busy === "save" ? t("targets.saving") : t("targets.savePayload")}
          </button>
        )}
        <input
          className="addr-input"
          style={{ width: 70 }}
          aria-label={t("targets.loaderPort")}
          type="number"
          min={1}
          max={65535}
          value={loaderPort}
          onChange={(e) => setLoaderPort(Number(e.target.value) || 9090)}
        />
        <button
          type="button"
          className="row-action"
          disabled={installed === null || host.trim() === "" || sending}
          onClick={() => void send()}
        >
          {sending ? t("targets.sending") : t("targets.send")}
        </button>
      </div>
      {sent !== null && (
        <div className="payload-hint">
          {t("targets.sent", { bytes: sent, host, port: loaderPort })}
        </div>
      )}
      {sendError !== null && (
        <div className="empty-hint error-text" role="alert">
          {sendError}
        </div>
      )}
      {error !== null && (
        <div className="empty-hint error-text" role="alert">
          {error}
        </div>
      )}
    </div>
  );
}

function elevationLabel(p: ProcessRow): string | null {
  switch (p.elevation) {
    case "admin":
      return "admin";
    case "system":
      return "system";
    default:
      return null;
  }
}

type Ps5Status = {
  endpoint: string;
  branding: string;
  server_version: string;
  caps: string;
  fw: string;
  platform: string;
  connected: boolean;
  lost: boolean;
  lost_reason: string;
  drops: number;
  debug_attached: boolean;
  debug_pid: number;
};

type Ps5AutoReply = {
  pid?: number;
  name?: string;
  debug_attached?: boolean;
  debug_error?: string;
  candidates?: { pid: number; name: string; game: boolean }[];
};

/** PS5 console card: ps5debug-NG connect/auto/reconnect and the console state. */
function Ps5Card() {
  const [host, setHost] = useState("");
  const [port, setPort] = useState(kDefaultPs4Port);
  const [status, setStatus] = useState<Ps5Status | null>(null);
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = async () => {
    try {
      const res = await call<{ ps5?: Ps5Status }>("target", "status");
      setStatus(res.ps5 ?? null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  const run = async (label: string, action: string, params: Record<string, unknown>) => {
    setBusy(label);
    setError(null);
    setNotice(null);
    try {
      const res = await call<Ps5AutoReply & { connected?: boolean }>("target", action, params);
      if (action === "ps5_auto") {
        setNotice(
          `pid ${res.pid ?? "?"} ${res.name ?? ""}${
            res.debug_attached === true ? " · debug attached" : " · debug not attached"
          }${res.debug_error !== undefined ? ` (${res.debug_error})` : ""}`,
        );
      }
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const send = async () => {
    if (msg.trim() === "") return;
    setBusy("notify");
    setError(null);
    setNotice(null);
    try {
      const res = await call<{ bytes: number }>("target", "ps5_notify", { msg: msg.trim() });
      setNotice(`Notification sent (${res.bytes} bytes).`);
      setMsg("");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="payload-card ps5-card" aria-label="PS5 console">
      <div className="payload-head">
        <span className="payload-title">PS5</span>
        {status !== null ? (
          <span className="pill" data-active={status.connected}>
            {status.connected ? "connected" : status.lost ? "lost" : "idle"}
          </span>
        ) : (
          <span className="faint">not connected</span>
        )}
        <div className="spacer" />
        <button type="button" className="row-action" onClick={() => void refresh()}>
          Refresh
        </button>
      </div>

      {status !== null && (
        <div className="payload-hint">
          {status.endpoint !== "" ? `${status.endpoint} · ` : ""}
          {status.branding !== "" ? `${status.branding} · ` : ""}
          fw {status.fw !== "" ? status.fw : "unknown"}
          {status.platform !== "" ? ` · platform ${status.platform}` : ""}
          {status.server_version !== "" ? ` · server ${status.server_version}` : ""}
          {status.caps !== "" ? ` · caps ${status.caps}` : ""}
          {" · "}
          {status.debug_attached ? `debug pid ${status.debug_pid}` : "debugger idle"}
          {" · "}
          drops {status.drops}
          {status.lost && status.lost_reason !== "" ? ` · lost: ${status.lost_reason}` : ""}
        </div>
      )}

      <div className="payload-actions">
        <input
          className="addr-input"
          aria-label="PS5 IP address"
          placeholder="PS5 IP, e.g. 192.168.1.30"
          value={host}
          onChange={(e) => setHost(e.target.value)}
        />
        <input
          className="addr-input"
          style={{ width: 64 }}
          aria-label="ps5debug port"
          type="number"
          min={1}
          max={65535}
          value={port}
          onChange={(e) => setPort(Number(e.target.value) || kDefaultPs4Port)}
        />
        <button
          type="button"
          className="row-action"
          disabled={busy !== null || host.trim() === ""}
          onClick={() => void run("connect", "ps5_connect", { host: host.trim(), port })}
        >
          {busy === "connect" ? "Connecting…" : "Connect"}
        </button>
        <button
          type="button"
          className="row-action"
          disabled={busy !== null || host.trim() === ""}
          data-tip="Connect, pick the game process, attach a session and the debugger"
          onClick={() => void run("auto", "ps5_auto", { host: host.trim(), port })}
        >
          {busy === "auto" ? "Setting up…" : "Auto connect"}
        </button>
        <button
          type="button"
          className="row-action"
          disabled={busy !== null || status?.connected !== true}
          onClick={() => void run("disconnect", "ps5_disconnect", {})}
        >
          Disconnect
        </button>
        <button
          type="button"
          className="row-action"
          disabled={busy !== null || status?.lost !== true}
          onClick={() => void run("reconnect", "ps5_reconnect", {})}
        >
          Reconnect
        </button>
      </div>

      <div className="payload-actions">
        <input
          className="addr-input"
          style={{ flex: 1, minWidth: 120 }}
          aria-label="PS5 notification message"
          placeholder="on-screen message"
          value={msg}
          onChange={(e) => setMsg(e.target.value)}
        />
        <button
          type="button"
          className="row-action"
          disabled={busy !== null || msg.trim() === "" || status?.connected !== true}
          onClick={() => void send()}
        >
          {busy === "notify" ? "Sending…" : "Notify"}
        </button>
      </div>

      {notice !== null && <div className="payload-hint">{notice}</div>}
      {error !== null && (
        <div className="empty-hint error-text" role="alert">
          {error}
        </div>
      )}
    </div>
  );
}

export default function TargetsPanel() {
  const t = useT();
  const {
    processes,
    filter,
    loading,
    error,
    setFilter,
    refresh,
    attach,
    detach,
    ps4,
    disconnectPs4,
    showHost,
    setShowHost,
    loadConsoles,
  } = useTargets();
  const target = useEngine((s) => s.target);
  const backend = useEngine((s) => s.backend);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [showConnect, setShowConnect] = useState(false);
  const [host, setHost] = useState("");
  const [port, setPort] = useState(kDefaultPs4Port);
  const listing = backend.ps4 || showHost;

  useEffect(() => {
    void loadConsoles();
  }, [loadConsoles]);

  useEffect(() => {
    if (listing) void refresh();
  }, [refresh, listing, backend.ps4]);

  const rows = useMemo(
    () => (listing ? processes.filter((p) => matchesFilter(p, filter)) : []),
    [processes, filter, listing],
  );

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => kRowHeight,
    overscan: 12,
  });

  const banner = backend.ps4 ? (
    <div className="connect-bar" role="status">
      <span className="faint connect-text">
        PS4 {ps4?.endpoint ?? ""}
        {ps4?.branding ? ` · ${ps4.branding}` : ""}
      </span>
      <div className="spacer" />
      <button type="button" className="row-action" onClick={() => void disconnectPs4()}>
        {t("targets.detach")}
      </button>
    </div>
  ) : showConnect && showHost ? (
    <ConnectForm compact host={host} port={port} onHost={setHost} onPort={setPort} />
  ) : null;

  return (
    <div className="panel targets-panel">
      <div className="panel-head">
        <span className="panel-title">
          {backend.ps4
            ? t("targets.ps4Processes")
            : showHost
              ? t("targets.hostProcesses")
              : t("targets.title")}
        </span>
        <div className="spacer" />
        {listing && (
          <span className="faint" style={{ fontSize: "var(--type-small)" }}>
            {t("targets.processCount", { count: processes.length })}
          </span>
        )}
        {target.attached && (
          <IconButton
            tip={t("targets.detachNamed", { name: target.name ?? "" })}
            onClick={() => void detach()}
          >
            <Unplug size={14} />
          </IconButton>
        )}
        {!backend.ps4 && showHost && (
          <IconButton
            tip={t("targets.connectTip")}
            pressed={showConnect}
            onClick={() => setShowConnect((v) => !v)}
          >
            <Gamepad2 size={14} />
          </IconButton>
        )}
        {listing && (
          <IconButton tip={t("targets.refresh")} onClick={() => void refresh()}>
            <RefreshCw size={14} className={loading ? "spin" : undefined} />
          </IconButton>
        )}
      </div>

      {/* Always present so the grid rows stay head / banner (auto) / list (1fr):
          a bare banner child used to land in the 1fr track and stretch */}
      <div className="banner-slot">
        {banner}
        <ConsolesCard />
        <Ps5Card />
      </div>

      {!listing ? (
        <div className="empty connect-empty">
          <div className="empty-glyph">
            <Gamepad2 size={28} strokeWidth={1.5} />
          </div>
          <div className="empty-title">{t("targets.connectConsole")}</div>
          <div className="empty-hint">{t("targets.connectHint")}</div>
          <ConnectForm compact={false} host={host} port={port} onHost={setHost} onPort={setPort} />
          <PayloadCard host={host} />
          {error !== null && (
            <div className="empty-hint error-text" role="alert">
              {error}
            </div>
          )}
          <button type="button" className="link-button" onClick={() => setShowHost(true)}>
            {t("targets.listHost")}
          </button>
        </div>
      ) : (
        <div className="targets-list">
          <div className="search">
            <Search size={13} aria-hidden />
            <input
              value={filter}
              aria-label={t("targets.filter")}
              placeholder={t("targets.filterPlaceholder")}
              onChange={(e) => setFilter(e.target.value)}
            />
            {!backend.ps4 && (
              <button type="button" className="link-button" onClick={() => setShowHost(false)}>
                {t("targets.hideHost")}
              </button>
            )}
          </div>
          {error !== null && (
            <div
              className="empty-hint error-text"
              role="alert"
              style={{ padding: "var(--pad-sm) var(--pad-md)" }}
            >
              {error}
            </div>
          )}

          <div className="panel-body" ref={scrollRef}>
            <table className="table">
              <caption className="sr-only">
                {backend.ps4 ? t("targets.captionPs4") : t("targets.captionHost")}
              </caption>
              <thead>
                <tr>
                  <th scope="col" style={{ width: 58 }}>
                    {t("targets.colPid")}
                  </th>
                  <th scope="col">{t("targets.colName")}</th>
                  <th scope="col" style={{ width: 44 }}>
                    {t("targets.colArch")}
                  </th>
                  <th scope="col" style={{ width: 60 }}>
                    {t("targets.colAction")}
                  </th>
                </tr>
              </thead>
              <tbody style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
                {virtualizer.getVirtualItems().map((v) => {
                  const p = rows[v.index];
                  const isTarget = target.attached && target.pid === p.pid;
                  const elevated = elevationLabel(p);
                  return (
                    <tr
                      key={p.pid}
                      data-selected={isTarget}
                      style={{
                        position: "absolute",
                        top: v.start,
                        left: 0,
                        width: "100%",
                        height: kRowHeight,
                        display: "table",
                        tableLayout: "fixed",
                      }}
                      data-tip={p.path ?? p.name}
                    >
                      <td style={{ width: 58 }} className="mono faint">
                        {p.pid}
                      </td>
                      <td>
                        <span className="proc-name">
                          <ProcessIcon path={p.path} />
                          <span className="proc-name-text">{p.name}</span>
                          {elevated !== null && (
                            <span
                              className="pill elevation"
                              data-elevation={p.elevation}
                              data-tip={
                                p.elevation === "system"
                                  ? t("targets.systemTip")
                                  : t("targets.adminTip")
                              }
                            >
                              <ShieldAlert size={10} aria-hidden /> {elevated}
                            </span>
                          )}
                        </span>
                      </td>
                      <td style={{ width: 44 }}>
                        {p.arch === "unknown" ? (
                          <span className="faint">-</span>
                        ) : (
                          <span className="pill">{p.arch}</span>
                        )}
                      </td>
                      <td style={{ width: 60 }}>
                        {isTarget ? (
                          <button
                            type="button"
                            className="row-action"
                            data-active="true"
                            onClick={() => void detach()}
                          >
                            {t("targets.detach")}
                          </button>
                        ) : (
                          <button
                            type="button"
                            className="row-action"
                            onClick={() => void attach(p.pid)}
                          >
                            {t("targets.attach")}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
