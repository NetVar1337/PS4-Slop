// app/src/components/panels/TargetsPanel.tsx
// process list and attach flow, stays on the list after attaching so targets
// can be switched without detaching. With no console connected the engine is
// on its local fallback backend; its processes are this PC's, so the panel
// asks for a console instead of listing them (host listing is opt-in)

import { useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Gamepad2, RefreshCw, Search, ShieldAlert, Unplug } from "lucide-react";
import IconButton from "@/components/IconButton";
import ProcessIcon from "@/components/ProcessIcon";
import { matchesFilter, useTargets, type ProcessRow } from "@/store/targets";
import { useEngine } from "@/store/engine";

const kRowHeight = 22;
const kDefaultPs4Port = 744;

function ConnectForm({ compact }: { compact: boolean }) {
  const connectPs4 = useTargets((s) => s.connectPs4);
  const [host, setHost] = useState("");
  const [port, setPort] = useState(kDefaultPs4Port);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (host.trim() === "" || busy) return;
    setBusy(true);
    try {
      await connectPs4(host.trim(), port);
    } finally {
      setBusy(false);
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
        onChange={(e) => setHost(e.target.value)}
      />
      <input
        className="addr-input"
        style={{ width: 64 }}
        aria-label="ps4debug port"
        type="number"
        min={1}
        max={65535}
        value={port}
        onChange={(e) => setPort(Number(e.target.value) || kDefaultPs4Port)}
      />
      <button type="submit" className="row-action" disabled={host.trim() === "" || busy}>
        {busy ? "Connecting…" : "Connect"}
      </button>
    </form>
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
    <ConnectForm compact />
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
          <ConnectForm compact={false} />
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
