// app/src/components/panels/NetworkPanel.tsx
// Packet capture (tool: network) and the HTTP proxy (tool: proxy): start and
// stop with a filter, a live packet table, DNS/streams/deep-inspect views,
// PCAP export/import and the proxy log with replay. Engine errors are shown
// verbatim: an Administrator/Npcap failure must not look like an empty table

import { useEffect, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import { isTauri } from "@/lib/endpoint";
import {
  useNetwork,
  type InspectRow,
  type PacketRow,
  type ProxyEntryDetail,
} from "@/store/network";

const kRow = 19;
const kPacketLimit = 2000;

async function pickSavePath(title: string, defaultPath: string): Promise<string | null> {
  if (isTauri()) return saveDialog({ title, defaultPath });
  return window.prompt(title, defaultPath);
}

async function pickOpenPath(title: string): Promise<string | null> {
  if (isTauri()) {
    const picked = await openDialog({ title, multiple: false });
    return typeof picked === "string" ? picked : null;
  }
  return window.prompt(title, "capture.pcap");
}

/** One deep-inspect row's application label, QUIC included. */
function appLabel(row: InspectRow): string {
  switch (row.app_protocol) {
    case "QUIC":
      return `QUIC ${row.quic_version ?? ""} ${row.quic_type ?? ""}`.trim();
    case "TLS":
      return `TLS ${row.tls_version ?? ""} ${row.tls_sni ?? ""}`.trim();
    case "HTTP":
      return row.http_method !== undefined
        ? `${row.http_method} ${row.http_host ?? ""}${row.http_path ?? ""}`
        : `HTTP ${row.http_status ?? ""}`.trim();
    case "DNS":
      return `DNS ${row.dns_domain ?? ""} ${row.dns_resolved ?? ""}`.trim();
    default:
      return "-";
  }
}

function PacketTable({ rows }: { rows: PacketRow[] }) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [selected, setSelected] = useState<PacketRow | null>(null);
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => kRow,
    overscan: 12,
  });

  return (
    <div className="tool-table-wrap">
      <div className="tool-table-scroll" ref={scrollRef}>
        <table className="table">
          <caption className="sr-only">Captured packets</caption>
          <thead>
            <tr>
              <th scope="col" style={{ width: 52 }}>
                #
              </th>
              <th scope="col" style={{ width: 66 }}>
                Time
              </th>
              <th scope="col" style={{ width: 44 }}>
                Proto
              </th>
              <th scope="col" style={{ width: 52 }}>
                Dir
              </th>
              <th scope="col">Local</th>
              <th scope="col">Remote</th>
              <th scope="col" style={{ width: 56 }}>
                Bytes
              </th>
            </tr>
          </thead>
          <tbody style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
            {virtualizer.getVirtualItems().map((v) => {
              const p = rows[v.index];
              return (
                <tr
                  key={p.id}
                  data-selected={selected?.id === p.id}
                  style={{
                    position: "absolute",
                    top: v.start,
                    left: 0,
                    width: "100%",
                    height: kRow,
                    display: "table",
                    tableLayout: "fixed",
                  }}
                  data-tip={p.payload_hex ?? undefined}
                  onClick={() => setSelected(p)}
                >
                  <td className="mono faint">{p.id}</td>
                  <td className="mono faint">{(p.at_ms % 100000) / 1000}</td>
                  <td>
                    <span className="pill">{p.protocol_str}</span>
                  </td>
                  <td className="faint">{p.direction_str === "inbound" ? "in" : "out"}</td>
                  <td className="mono">{p.local}</td>
                  <td className="mono">{p.remote}</td>
                  <td className="mono faint">{p.wire_bytes}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {selected !== null && (
        <div className="tool-summary mono" data-testid="packet-detail">
          #{selected.id} {selected.protocol_str} {selected.local} → {selected.remote} ·{" "}
          {selected.payload_bytes} payload bytes
          {selected.payload_hex !== undefined ? ` · ${selected.payload_hex}` : ""}
        </div>
      )}
    </div>
  );
}

export default function NetworkPanel() {
  const {
    status,
    packets,
    stats,
    dns,
    streams,
    inspect,
    proxy,
    entries,
    error,
    busy,
    refreshStatus,
    start,
    stop,
    refreshPackets,
    refreshStats,
    refreshDns,
    refreshStreams,
    refreshInspect,
    exportPcap,
    importPcap,
    refreshProxy,
    startProxy,
    stopProxy,
    refreshEntries,
    entry,
    replay,
  } = useNetwork();

  const [host, setHost] = useState("");
  const [port, setPort] = useState("");
  const [protocol, setProtocol] = useState("0");
  const [format, setFormat] = useState("pcap");
  const [maxPackets, setMaxPackets] = useState("4096");
  const [notice, setNotice] = useState<string | null>(null);
  const [secondary, setSecondary] = useState<"dns" | "streams" | "inspect">("dns");
  const [proxyPort, setProxyPort] = useState("8080");
  const [proxyBind, setProxyBind] = useState("127.0.0.1");
  const [allowHosts, setAllowHosts] = useState("");
  const [replayText, setReplayText] = useState<string | null>(null);
  const [detail, setDetail] = useState<ProxyEntryDetail | null>(null);

  useEffect(() => {
    void refreshStatus();
    void refreshProxy();
  }, [refreshStatus, refreshProxy]);

  // Poll only while a capture runs: an idle panel must not spin the engine
  const running = status?.capture_running === true;
  useEffect(() => {
    if (!running) return;
    void refreshPackets();
    const timer = setInterval(() => {
      void refreshPackets();
      void refreshStats();
    }, 1000);
    return () => clearInterval(timer);
  }, [running, refreshPackets, refreshStats]);

  const doExport = async () => {
    const path = await pickSavePath("Export capture", `capture.${format}`);
    if (path === null) return;
    const n = Number.parseInt(maxPackets, 10);
    const msg = await exportPcap(path, format, Number.isFinite(n) && n > 0 ? n : 4096);
    setNotice(msg);
  };

  const doImport = async () => {
    const path = await pickOpenPath("Import capture");
    if (path === null) return;
    setNotice(await importPcap(path));
  };

  const shown = packets.slice(-kPacketLimit);

  return (
    <div className="panel tool-panel">
      <div className="panel-head">
        <span className="panel-title">Network</span>
        {status !== null && (
          <span className="pill" data-active={status.capture_running}>
            {status.capture_running ? "capturing" : "idle"}
          </span>
        )}
        <span className="faint" style={{ fontSize: "var(--type-small)" }}>
          {status?.store_packets ?? 0} stored
        </span>
        <div className="spacer" />
        <button type="button" className="row-action" onClick={() => void refreshStatus()}>
          Refresh
        </button>
      </div>
      <div className="panel-body tool-body">
        <div className="tool-form">
          <input
            className="addr-input"
            style={{ width: 120 }}
            aria-label="Capture host filter"
            placeholder="host (e.g. PS4 IP)"
            value={host}
            onChange={(e) => setHost(e.target.value)}
          />
          <input
            className="addr-input"
            style={{ width: 64 }}
            aria-label="Capture port filter"
            placeholder="port"
            inputMode="numeric"
            value={port}
            onChange={(e) => setPort(e.target.value)}
          />
          <select
            className="select"
            aria-label="Capture protocol"
            value={protocol}
            onChange={(e) => setProtocol(e.target.value)}
          >
            <option value="0">any</option>
            <option value="6">tcp</option>
            <option value="17">udp</option>
          </select>
          <button
            type="button"
            className="row-action"
            disabled={busy !== null}
            onClick={() => {
              const p = Number.parseInt(port, 10);
              void start({
                host: host.trim(),
                port: Number.isFinite(p) ? p : 0,
                protocol: Number.parseInt(protocol, 10),
              });
            }}
          >
            Start capture
          </button>
          <button
            type="button"
            className="row-action"
            disabled={busy !== null || !running}
            onClick={() => void stop()}
          >
            Stop
          </button>
        </div>

        {stats !== null && (
          <div className="tool-summary faint">
            in {stats.packets_in} · out {stats.packets_out} · {stats.bytes_in + stats.bytes_out}{" "}
            bytes · dropped {stats.queue_dropped} · filtered {stats.filtered_out} · parse errors{" "}
            {stats.parse_errors} · streams {stats.streams} · QUIC {stats.quic_packets}
          </div>
        )}

        <div className="tool-form">
          <select
            className="select"
            aria-label="PCAP format"
            value={format}
            onChange={(e) => setFormat(e.target.value)}
          >
            <option value="pcap">pcap</option>
            <option value="pcapng">pcapng</option>
          </select>
          <input
            className="addr-input"
            style={{ width: 72 }}
            aria-label="Max packets to export"
            inputMode="numeric"
            value={maxPackets}
            onChange={(e) => setMaxPackets(e.target.value)}
          />
          <button
            type="button"
            className="row-action"
            disabled={busy !== null}
            onClick={() => void doExport()}
          >
            Export PCAP…
          </button>
          <button
            type="button"
            className="row-action"
            disabled={busy !== null}
            onClick={() => void doImport()}
          >
            Import PCAP…
          </button>
          {notice !== null && <span className="faint">{notice}</span>}
        </div>

        {error !== null && (
          <div className="empty-hint error-text" role="alert">
            {error}
          </div>
        )}

        <PacketTable rows={shown} />

        <div className="tool-form">
          {(["dns", "streams", "inspect"] as const).map((kind) => (
            <button
              type="button"
              key={kind}
              className="row-action"
              data-active={secondary === kind}
              onClick={() => {
                setSecondary(kind);
                if (kind === "dns") void refreshDns();
                else if (kind === "streams") void refreshStreams();
                else void refreshInspect();
              }}
            >
              {kind === "dns" ? "DNS" : kind === "streams" ? "Streams" : "Deep inspect"}
            </button>
          ))}
          <button
            type="button"
            className="row-action"
            onClick={() => {
              if (secondary === "dns") void refreshDns();
              else if (secondary === "streams") void refreshStreams();
              else void refreshInspect();
            }}
          >
            Reload
          </button>
        </div>

        {secondary === "dns" && (
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Domain</th>
                <th scope="col">Type</th>
                <th scope="col">Resolved</th>
                <th scope="col">Client</th>
                <th scope="col">TTL</th>
              </tr>
            </thead>
            <tbody>
              {dns.map((d, i) => (
                <tr key={`${d.domain}-${i}`}>
                  <td>{d.domain}</td>
                  <td className="faint">{d.query_type}</td>
                  <td className="mono">{d.resolved !== "" ? d.resolved : d.answers.join(", ")}</td>
                  <td className="mono faint">{d.client}</td>
                  <td className="mono faint">{d.ttl}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {secondary === "streams" && (
          <table className="table">
            <thead>
              <tr>
                <th scope="col">#</th>
                <th scope="col">Proto</th>
                <th scope="col">Client</th>
                <th scope="col">Server</th>
                <th scope="col">Bytes</th>
                <th scope="col">Packets</th>
              </tr>
            </thead>
            <tbody>
              {streams.map((s) => (
                <tr key={s.id}>
                  <td className="mono faint">{s.id}</td>
                  <td>
                    <span className="pill">{s.protocol}</span>
                  </td>
                  <td className="mono">{s.client}</td>
                  <td className="mono">{s.server}</td>
                  <td className="mono faint">{s.bytes}</td>
                  <td className="mono faint">{s.packets}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {secondary === "inspect" && (
          <table className="table">
            <thead>
              <tr>
                <th scope="col">#</th>
                <th scope="col">App</th>
                <th scope="col">Local</th>
                <th scope="col">Remote</th>
                <th scope="col">Payload</th>
              </tr>
            </thead>
            <tbody>
              {inspect.map((r) => (
                <tr key={r.id}>
                  <td className="mono faint">{r.id}</td>
                  <td>
                    <span className="pill" data-app={r.app_protocol ?? "other"}>
                      {appLabel(r)}
                    </span>
                  </td>
                  <td className="mono">{r.local}</td>
                  <td className="mono">{r.remote}</td>
                  <td className="mono faint">{r.payload_size}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div className="tool-section-head">
          <span className="panel-title">Proxy</span>
          {proxy !== null && (
            <>
              <span className="pill" data-active={proxy.running}>
                {proxy.running ? `listening ${proxy.bind}:${proxy.port}` : "stopped"}
              </span>
              {proxy.running && (
                <span className="pill" data-tip="Secret headers and query params are masked">
                  {proxy.redact_secrets ? "secrets redacted" : "secrets visible"}
                </span>
              )}
              {proxy.mitm && <span className="pill sev-warn">MITM</span>}
            </>
          )}
        </div>

        <div className="tool-form">
          <input
            className="addr-input"
            style={{ width: 110 }}
            aria-label="Proxy bind"
            value={proxyBind}
            onChange={(e) => setProxyBind(e.target.value)}
          />
          <input
            className="addr-input"
            style={{ width: 64 }}
            aria-label="Proxy port"
            inputMode="numeric"
            value={proxyPort}
            onChange={(e) => setProxyPort(e.target.value)}
          />
          <input
            className="addr-input"
            style={{ flex: 1, minWidth: 120 }}
            aria-label="Proxy destination allowlist"
            placeholder="allow hosts, comma separated"
            value={allowHosts}
            onChange={(e) => setAllowHosts(e.target.value)}
          />
          <button
            type="button"
            className="row-action"
            disabled={busy !== null}
            onClick={() => {
              const p = Number.parseInt(proxyPort, 10);
              void startProxy({
                port: Number.isFinite(p) ? p : 8080,
                bind: proxyBind.trim() === "" ? "127.0.0.1" : proxyBind.trim(),
                allow_hosts: allowHosts
                  .split(",")
                  .map((s) => s.trim())
                  .filter((s) => s !== ""),
                allow_clients: [],
              });
            }}
          >
            Start proxy
          </button>
          <button
            type="button"
            className="row-action"
            disabled={busy !== null || proxy?.running !== true}
            onClick={() => void stopProxy()}
          >
            Stop
          </button>
          <button type="button" className="row-action" onClick={() => void refreshEntries()}>
            Load log
          </button>
        </div>

        {proxy !== null && (
          <div className="tool-summary faint">
            {proxy.active_connections ?? 0} active · {proxy.total_connections ?? 0} total · rejected{" "}
            {(proxy.rejected?.auth ?? 0) +
              (proxy.rejected?.host ?? 0) +
              (proxy.rejected?.client ?? 0) +
              (proxy.rejected?.capacity ?? 0)}{" "}
            · {proxy.log_entries ?? 0} log entries
          </div>
        )}

        <table className="table">
          <thead>
            <tr>
              <th scope="col">#</th>
              <th scope="col">Method</th>
              <th scope="col">Host</th>
              <th scope="col">Path</th>
              <th scope="col">Status</th>
              <th scope="col">Flags</th>
              <th scope="col">Action</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.id}>
                <td className="mono faint">{e.id}</td>
                <td>{e.method}</td>
                <td className="mono">
                  {e.host}:{e.port}
                </td>
                <td className="mono">{e.path}</td>
                <td className="mono faint">{e.status}</td>
                <td>
                  {e.redacted && <span className="pill sev-warn">redacted</span>}
                  {e.intercepted === true && <span className="pill">MITM</span>}
                  {e.error !== undefined && <span className="pill sev-bad">{e.error}</span>}
                </td>
                <td>
                  <button
                    type="button"
                    className="row-action"
                    onClick={() => void entry(e.id).then(setDetail)}
                  >
                    Detail
                  </button>{" "}
                  <button
                    type="button"
                    className="row-action"
                    disabled={!e.replayable || busy !== null}
                    onClick={() => {
                      void replay(e.id).then(setReplayText);
                    }}
                  >
                    Replay
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {entries.length === 0 && (
          <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
            No proxy entries. Start the proxy and point a client at it.
          </div>
        )}

        {detail !== null && (
          <div className="tool-summary" data-testid="proxy-entry">
            <div className="mono faint">
              #{detail.id} {detail.method} {detail.host}:{detail.port}
              {detail.path}
              {detail.redacted ? " · redacted" : ""}
              {detail.request_truncated === true ? " · request truncated" : ""}
            </div>
            {detail.request_text !== undefined && (
              <pre className="tool-pre">{detail.request_text}</pre>
            )}
            {detail.response_head_text !== undefined && (
              <pre className="tool-pre">{detail.response_head_text}</pre>
            )}
          </div>
        )}

        {replayText !== null && (
          <pre className="tool-pre" data-testid="replay-text">
            {replayText}
          </pre>
        )}
      </div>
    </div>
  );
}
