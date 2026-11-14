// app/src/store/network.ts
// Packet capture, its store and the HTTP proxy. The engine owns the capture
// and the packet store; this keeps the page the panel shows and polls only
// while a capture runs

import { create } from "zustand";
import { call, errorText } from "@/lib/rpc";

export type CaptureFilter = { host: string; port: number; protocol: number };

export type NetworkStatus = {
  capture_running: boolean;
  capture_filter: CaptureFilter;
  store_packets: number;
  proxy_running: boolean;
  proxy_port: number;
  proxy_mitm: boolean;
};

export type PacketRow = {
  id: number;
  at_ms: number;
  protocol: number;
  protocol_str: string;
  direction: number;
  direction_str: string;
  ip_version: number;
  local: string;
  remote: string;
  payload_bytes: number;
  wire_bytes: number;
  payload_truncated?: boolean;
  payload_hex?: string;
};

export type NetworkStats = {
  capture_active: boolean;
  filter: CaptureFilter;
  packets_seen: number;
  packets_in: number;
  packets_out: number;
  bytes_in: number;
  bytes_out: number;
  filtered_out: number;
  parse_errors: number;
  non_tcp_udp: number;
  fragments: number;
  fragments_reassembled: number;
  fragments_dropped: number;
  queue_dropped: number;
  payload_truncated: number;
  dns_logged_total: number;
  store_packets: number;
  store_packets_total: number;
  store_packets_evicted: number;
  streams: number;
  active_streams_60s: number;
  stream_bytes: number;
  quic_packets: number;
};

export type DnsRow = {
  timestamp: number;
  is_response: boolean;
  query_type: string;
  domain: string;
  resolved: string;
  answers: string[];
  response_code: number;
  ttl: number;
  client: string;
  server: string;
};

export type StreamRow = {
  id: number;
  key: string;
  protocol: string;
  client: string;
  server: string;
  bytes: number;
  packets: number;
  truncated: boolean;
  first_ms: number;
  last_ms: number;
};

export type InspectRow = {
  id: number;
  timestamp: number;
  direction: number;
  protocol: number;
  local: string;
  remote: string;
  payload_size: number;
  app_protocol?: string;
  dns_domain?: string;
  dns_resolved?: string;
  http_method?: string;
  http_path?: string;
  http_host?: string;
  http_status?: number;
  tls_version?: string;
  tls_content_type?: string;
  tls_sni?: string;
  quic_version?: string;
  quic_type?: string;
  quic_dcid?: string;
  quic_scid?: string;
};

export type ProxyStatus = {
  running: boolean;
  port: number;
  bind: string;
  token_required: boolean;
  allow_hosts: string[];
  allow_clients: string[];
  mitm: boolean;
  mitm_state?: {
    enabled: boolean;
    ca_exists: boolean;
    ca_path: string;
    ca_thumbprint: string;
    root_installed: boolean;
    leaf_certs_issued: number;
  };
  redact_secrets: boolean;
  active_connections: number;
  total_connections: number;
  rejected?: { capacity: number; auth: number; host: number; client: number };
  log_entries: number;
  log_bytes: number;
};

export type ProxyEntry = {
  id: number;
  at_ms: number;
  kind: string;
  client: string;
  method: string;
  host: string;
  port: number;
  path: string;
  status: number;
  req_bytes: number;
  resp_bytes: number;
  replayable: boolean;
  redacted: boolean;
  sni?: string;
  intercepted?: boolean;
  tls?: string;
  error?: string;
};

export type ProxyEntryDetail = ProxyEntry & {
  request_truncated?: boolean;
  request_text?: string;
  request_bytes_captured?: number;
  response_head_text?: string;
};

export type ProxyOptions = {
  port: number;
  bind: string;
  allow_hosts: string[];
  allow_clients: string[];
};

const kPacketPage = 200;

type NetworkStore = {
  status: NetworkStatus | null;
  packets: PacketRow[];
  lastId: number;
  stats: NetworkStats | null;
  dns: DnsRow[];
  streams: StreamRow[];
  inspect: InspectRow[];
  proxy: ProxyStatus | null;
  entries: ProxyEntry[];
  /** Last engine error, verbatim: capture needs Administrator and says so. */
  error: string | null;
  busy: string | null;
  refreshStatus: () => Promise<void>;
  start: (filter: { host: string; port: number; protocol: number }) => Promise<void>;
  stop: () => Promise<void>;
  refreshPackets: () => Promise<void>;
  refreshStats: () => Promise<void>;
  refreshDns: () => Promise<void>;
  refreshStreams: () => Promise<void>;
  refreshInspect: () => Promise<void>;
  exportPcap: (path: string, format: string, maxPackets: number) => Promise<string | null>;
  importPcap: (path: string) => Promise<string | null>;
  refreshProxy: () => Promise<void>;
  startProxy: (options: ProxyOptions) => Promise<void>;
  stopProxy: () => Promise<void>;
  refreshEntries: () => Promise<void>;
  entry: (id: number) => Promise<ProxyEntryDetail | null>;
  replay: (id: number) => Promise<string | null>;
  reset: () => void;
};

type PacketsReply = { packets?: PacketRow[]; last_id?: number };

export const useNetwork = create<NetworkStore>((set, get) => ({
  status: null,
  packets: [],
  lastId: 0,
  stats: null,
  dns: [],
  streams: [],
  inspect: [],
  proxy: null,
  entries: [],
  error: null,
  busy: null,

  refreshStatus: async () => {
    try {
      set({ status: await call<NetworkStatus>("network", "status") });
    } catch (e) {
      set({ error: errorText(e) });
    }
  },

  start: async (filter) => {
    set({ busy: "capture", error: null });
    try {
      // port 0 and protocol 0 mean "both", the engine's own defaults
      await call("network", "capture_start", {
        ...(filter.host !== "" ? { host: filter.host } : {}),
        ...(filter.port > 0 ? { port: filter.port } : {}),
        ...(filter.protocol > 0 ? { protocol: filter.protocol } : {}),
      });
      await get().refreshStatus();
    } catch (e) {
      set({ error: errorText(e) });
    } finally {
      set({ busy: null });
    }
  },

  stop: async () => {
    set({ busy: "capture", error: null });
    try {
      await call("network", "capture_stop");
      await get().refreshStatus();
    } catch (e) {
      set({ error: errorText(e) });
    } finally {
      set({ busy: null });
    }
  },

  refreshPackets: async () => {
    try {
      const res = await call<PacketsReply>("network", "packets", {
        from: get().lastId,
        limit: kPacketPage,
      });
      const rows = res.packets ?? [];
      if (rows.length === 0) return;
      set({
        packets: [...get().packets, ...rows].slice(-2000),
        lastId: res.last_id ?? rows[rows.length - 1].id,
      });
    } catch (e) {
      set({ error: errorText(e) });
    }
  },

  refreshStats: async () => {
    try {
      set({ stats: await call<NetworkStats>("network", "stats") });
    } catch (e) {
      set({ error: errorText(e) });
    }
  },

  refreshDns: async () => {
    try {
      const res = await call<{ dns?: DnsRow[] }>("network", "dns", { limit: 500 });
      set({ dns: res.dns ?? [] });
    } catch (e) {
      set({ error: errorText(e) });
    }
  },

  refreshStreams: async () => {
    try {
      const res = await call<{ streams?: StreamRow[] }>("network", "streams", { limit: 500 });
      set({ streams: res.streams ?? [] });
    } catch (e) {
      set({ error: errorText(e) });
    }
  },

  refreshInspect: async () => {
    try {
      const res = await call<{ results?: InspectRow[] }>("network", "deep_inspect", {
        limit: 200,
      });
      set({ inspect: res.results ?? [] });
    } catch (e) {
      set({ error: errorText(e) });
    }
  },

  exportPcap: async (path, format, maxPackets) => {
    set({ busy: "export", error: null });
    try {
      const res = await call<{ packets: number }>("network", "export_pcap", {
        path,
        format,
        max_packets: maxPackets,
      });
      return `${res.packets} packets written to ${path}`;
    } catch (e) {
      set({ error: errorText(e) });
      return null;
    } finally {
      set({ busy: null });
    }
  },

  importPcap: async (path) => {
    set({ busy: "import", error: null });
    try {
      const res = await call<{ packets: number; skipped: number }>("network", "import_pcap", {
        path,
      });
      set({ packets: [], lastId: 0 });
      await get().refreshStatus();
      await get().refreshPackets();
      return `${res.packets} packets imported (${res.skipped} skipped)`;
    } catch (e) {
      set({ error: errorText(e) });
      return null;
    } finally {
      set({ busy: null });
    }
  },

  refreshProxy: async () => {
    try {
      set({ proxy: await call<ProxyStatus>("proxy", "status") });
    } catch (e) {
      set({ error: errorText(e) });
    }
  },

  startProxy: async (options) => {
    set({ busy: "proxy", error: null });
    try {
      await call("proxy", "start", {
        port: options.port,
        bind: options.bind,
        allow_hosts: options.allow_hosts,
        allow_clients: options.allow_clients,
      });
      await get().refreshProxy();
    } catch (e) {
      set({ error: errorText(e) });
    } finally {
      set({ busy: null });
    }
  },

  stopProxy: async () => {
    set({ busy: "proxy", error: null });
    try {
      await call("proxy", "stop");
      await get().refreshProxy();
    } catch (e) {
      set({ error: errorText(e) });
    } finally {
      set({ busy: null });
    }
  },

  refreshEntries: async () => {
    try {
      const res = await call<{ entries?: ProxyEntry[] }>("proxy", "entries", { limit: 100 });
      set({ entries: res.entries ?? [] });
    } catch (e) {
      set({ error: errorText(e) });
    }
  },

  entry: async (id) => {
    try {
      return await call<ProxyEntryDetail>("proxy", "entry", { id });
    } catch (e) {
      set({ error: errorText(e) });
      return null;
    }
  },

  replay: async (id) => {
    set({ busy: "replay", error: null });
    try {
      const res = await call<{ status: number; text: string }>("proxy", "replay", { id });
      return `HTTP ${res.status}\n${res.text}`;
    } catch (e) {
      set({ error: errorText(e) });
      return null;
    } finally {
      set({ busy: null });
    }
  },

  reset: () =>
    set({
      status: null,
      packets: [],
      lastId: 0,
      stats: null,
      dns: [],
      streams: [],
      inspect: [],
      proxy: null,
      entries: [],
      error: null,
      busy: null,
    }),
}));
