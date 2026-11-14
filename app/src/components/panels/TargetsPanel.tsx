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
import { isTauri } from "@/lib/endpoint";
import { call } from "@/lib/rpc";
import { payloadDownload, payloadLatest, payloadSave, payloadStatus } from "@/lib/ps4debug";
import type { PayloadInfo, PayloadStatus } from "@/lib/ps4debug";
import { matchesFilter, useTargets, type ProcessRow } from "@/store/targets";
import { useEngine } from "@/store/engine";

const kRowHeight = 22;
const kDefaultPs4Port = 744;

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
  const connectPs4 = useTargets((s) => s.connectPs4);
  const [busy, setBusy] = useState(false);
  const [discovering, setDiscovering] = useState(false);
  const [found, setFound] = useState<string[]>([]);
  const [discoverError, setDiscoverError] = useState<string | null>(null);

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
      else setDiscoverError("No console answered the discovery probe.");
    } catch (e) {
      setDiscoverError(e instanceof Error ? e.message : String(e));
    } finally {
      setDiscovering(false);
    }
  };

  return (
    <form
      className={compact ? "connect-bar" : "connect-form"}
      aria-label="Connect to a PS4"
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <input
        className="addr-input"
        aria-label="PS4 IP address"
        placeholder="PS4 IP, e.g. 192.168.1.20"
        value={host}
        onChange={(e) => onHost(e.target.value)}
      />
      <input
        className="addr-input"
        style={{ width: 64 }}
        aria-label="ps4debug port"
        type="number"
        min={1}
        max={65535}
        value={port}
        onChange={(e) => onPort(Number(e.target.value) || kDefaultPs4Port)}
      />
      <button type="submit" className="row-action" disabled={host.trim() === "" || busy}>
        {busy ? "Connecting…" : "Connect"}
      </button>
      <button
        type="button"
        className="row-action"
        disabled={discovering}
        onClick={() => void discover()}
      >
        {discovering ? "Searching…" : "Discover"}
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

function PayloadCard({ host }: { host: string }) {
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
        <span className="payload-title">ps4debug-NG payload</span>
        <span className="faint">{installed === null ? "not bundled" : `v${installed.tag}`}</span>
      </div>
      <div className="payload-hint">
        {installed === null
          ? "Download the latest release, then send it with your console loader."
          : `Bundled from ${installed.source}. Send it with BinLoader/FTP.`}
        {latest !== null ? ` · latest v${latest.tag}` : ""}
      </div>
      <div className="payload-actions">
        <button type="button" className="row-action" disabled={busy !== null} onClick={() => void check()}>
          {busy === "check" ? "Checking…" : "Check latest"}
        </button>
        {newer && (
          <button
            type="button"
            className="row-action"
            disabled={busy !== null}
            onClick={() => void download()}
          >
            {busy === "download" ? "Downloading…" : `Download v${latest?.tag ?? ""}`}
          </button>
        )}
        {installed !== null && (
          <button
            type="button"
            className="row-action"
            disabled={busy !== null}
            onClick={() => void save()}
          >
            {busy === "save" ? "Saving…" : "Save payload…"}
          </button>
        )}
        <input
          className="addr-input"
          style={{ width: 70 }}
          aria-label="Payload loader port"
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
          {sending ? "Sending…" : "Send to console"}
        </button>
      </div>
      {sent !== null && (
        <div className="payload-hint">
          Sent {sent} bytes to {host}:{loaderPort}.
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

export default function TargetsPanel() {
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
  } = useTargets();
  const target = useEngine((s) => s.target);
  const backend = useEngine((s) => s.backend);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [showConnect, setShowConnect] = useState(false);
  const [host, setHost] = useState("");
  const [port, setPort] = useState(kDefaultPs4Port);
  const listing = backend.ps4 || showHost;

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
        Disconnect
      </button>
    </div>
  ) : showConnect && showHost ? (
    <ConnectForm compact host={host} port={port} onHost={setHost} onPort={setPort} />
  ) : null;

  return (
    <div className="panel targets-panel">
      <div className="panel-head">
        <span className="panel-title">
          {backend.ps4 ? "PS4 processes" : showHost ? "Host processes (this PC)" : "Targets"}
        </span>
        <div className="spacer" />
        {listing && (
          <span className="faint" style={{ fontSize: "var(--type-small)" }}>
            {processes.length} processes
          </span>
        )}
        {target.attached && (
          <IconButton tip={`Detach ${target.name ?? ""}`} onClick={() => void detach()}>
            <Unplug size={14} />
          </IconButton>
        )}
        {!backend.ps4 && showHost && (
          <IconButton
            tip="Connect to a PS4 running ps4debug-NG"
            pressed={showConnect}
            onClick={() => setShowConnect((v) => !v)}
          >
            <Gamepad2 size={14} />
          </IconButton>
        )}
        {listing && (
          <IconButton tip="Refresh" onClick={() => void refresh()}>
            <RefreshCw size={14} className={loading ? "spin" : undefined} />
          </IconButton>
        )}
      </div>

      {/* Always present so the grid rows stay head / banner (auto) / list (1fr):
          a bare banner child used to land in the 1fr track and stretch */}
      <div className="banner-slot">{banner}</div>

      {!listing ? (
        <div className="empty connect-empty">
          <div className="empty-glyph">
            <Gamepad2 size={28} strokeWidth={1.5} />
          </div>
          <div className="empty-title">Connect a console</div>
          <div className="empty-hint">
            Run the ps4debug-NG payload on the PS4 and enter its address. Processes, modules and the
            debugger then come from the console.
          </div>
          <ConnectForm compact={false} host={host} port={port} onHost={setHost} onPort={setPort} />
          <PayloadCard host={host} />
          {error !== null && (
            <div className="empty-hint error-text" role="alert">
              {error}
            </div>
          )}
          <button type="button" className="link-button" onClick={() => setShowHost(true)}>
            List this PC&apos;s processes instead
          </button>
        </div>
      ) : (
        <div className="targets-list">
          <div className="search">
            <Search size={13} aria-hidden />
            <input
              value={filter}
              aria-label="Filter processes"
              placeholder="Filter processes…"
              onChange={(e) => setFilter(e.target.value)}
            />
            {!backend.ps4 && (
              <button type="button" className="link-button" onClick={() => setShowHost(false)}>
                hide host list
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
                {backend.ps4 ? "Processes on the connected PS4" : "Processes on this PC"}
              </caption>
              <thead>
                <tr>
                  <th scope="col" style={{ width: 58 }}>
                    PID
                  </th>
                  <th scope="col">Name</th>
                  <th scope="col" style={{ width: 44 }}>
                    Arch
                  </th>
                  <th scope="col" style={{ width: 60 }}>
                    Action
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
                                  ? "Runs as SYSTEM / kernel privileges"
                                  : "Elevated (administrator) process"
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
                            Detach
                          </button>
                        ) : (
                          <button
                            type="button"
                            className="row-action"
                            onClick={() => void attach(p.pid)}
                          >
                            Attach
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
