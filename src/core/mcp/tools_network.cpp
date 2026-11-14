// src/core/mcp/tools_network.cpp
// tools: network (capture) and proxy

#include "core/mcp/tools_common.hpp"

#include "core/infra/paths.hpp"
#include "core/network/parsers.hpp"
#include "core/network/pcap_import.hpp"
#include "core/network/redact.hpp"

namespace slop::core::mcp::detail {

namespace {

namespace parse = network::parse;

// tool: network

const char* proto_str(uint32_t p) {
    return p == 6 ? "tcp" : p == 17 ? "udp" : "other";
}

json packet_to_json(const network::packet_record_t& p) {
    const uint32_t wire = std::max<uint32_t>(p.wire_len, static_cast<uint32_t>(p.payload.size()));
    json o = {{"id", p.id}, {"at_ms", p.at_ms},
              {"protocol", p.protocol}, {"protocol_str", proto_str(p.protocol)},
              {"direction", p.direction}, {"direction_str", p.direction ? "inbound" : "outbound"},
              {"ip_version", p.ip_version},
              {"local", (p.ip_version == 6 ? "[" + p.local_addr + "]" : p.local_addr) + ":" +
                            std::to_string(p.local_port)},
              {"remote", (p.ip_version == 6 ? "[" + p.remote_addr + "]" : p.remote_addr) + ":" +
                             std::to_string(p.remote_port)},
              {"payload_bytes", p.payload.size()},
              {"wire_bytes", wire},
              {"payload_truncated", wire > p.payload.size()}};
    const size_t preview = std::min<size_t>(p.payload.size(), 96);
    if (preview)
        o["payload_hex"] = to_hex(p.payload.data(), preview);
    return o;
}

const char* tls_version_name(uint32_t ver) {
    switch (ver) {
        case 0x0300: return "SSL 3.0"; case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1"; case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3"; default: return "unknown";
    }
}

const char* tls_content_type_name(uint32_t ct) {
    switch (ct) {
        case 20: return "ChangeCipherSpec"; case 21: return "Alert";
        case 22: return "Handshake";        case 23: return "ApplicationData";
        default: return "other";
    }
}

std::string printable(const uint8_t* d, size_t n) {
    std::string text(reinterpret_cast<const char*>(d), n);
    for (char& ch : text)
        if (static_cast<unsigned char>(ch) < 0x20 && ch != '\n' && ch != '\r' && ch != '\t')
            ch = '.';
    return text;
}

// raw capture has no process attribution: reject the old pid parameter loudly
void reject_pid(const json& args) {
    if (args.contains("pid"))
        fail("pid filters are not supported: raw capture cannot attribute packets to processes. "
             "Filter by host (e.g. the console IP) instead");
}

// optional host filter argument (host or console_ip), canonicalized
std::optional<parse::ip_addr_t> host_arg(const json& args) {
    for (const char* k : {"host", "console_ip"}) {
        if (!args.contains(k)) continue;
        const json& v = args.at(k);
        if (!v.is_string()) fail(std::string(k) + " must be an IP address string");
        const std::string s = v.get<std::string>();
        if (s.empty()) return std::nullopt;
        auto ip = parse::parse_ip(s);
        if (!ip) fail(std::string(k) + " must be an IPv4/IPv6 address, got '" + s + "'");
        return ip;
    }
    return std::nullopt;
}

uint32_t protocol_arg(const json& args) {
    if (!args.contains("protocol")) return 0;
    const json& v = args.at("protocol");
    if (v.is_string()) {
        const std::string s = parse::lower(v.get<std::string>());
        if (s == "tcp") return 6;
        if (s == "udp") return 17;
        if (s.empty() || s == "any") return 0;
        fail("protocol must be tcp, udp, 6 or 17");
    }
    const uint32_t p = static_cast<uint32_t>(parse_addr(args, "protocol"));
    if (p != 0 && p != 6 && p != 17) fail("protocol must be tcp, udp, 6 or 17");
    return p;
}

bool packet_has_host(const network::packet_record_t& p, const parse::ip_addr_t& h) {
    const auto l = parse::parse_ip(p.local_addr);
    const auto r = parse::parse_ip(p.remote_addr);
    return (l && *l == h) || (r && *r == h);
}

json filter_json(const network::capture_filter_t& f) {
    return {{"host", f.host}, {"port", f.port}, {"protocol", f.protocol}};
}

json ifaces_json(const std::vector<network::capture_iface_t>& v) {
    json arr = json::array();
    for (const auto& i : v) {
        json o = {{"name", i.name}, {"address", i.address}, {"family", i.family == 6 ? "ipv6" : "ipv4"},
                  {"active", i.active}};
        if (!i.error.empty()) o["error"] = i.error;
        arr.push_back(std::move(o));
    }
    return arr;
}

// proxy / MITM state

std::shared_ptr<network::mitm::pki_t>& pki_slot() {
    static std::shared_ptr<network::mitm::pki_t> p;
    return p;
}

network::mitm::pki_t& pki() {
    auto& p = pki_slot();
    if (!p) {
        network::mitm::pki_options_t o;
        o.dir = infra::paths::app_data() + "\\mitm";
        p = std::make_shared<network::mitm::pki_t>(o);
        p->load_existing();
    }
    return *p;
}

json mitm_status_json() {
    auto& k = pki();
    k.load_existing();
    return {{"enabled", g_proxy.mitm_enabled()},
            {"ca_exists", k.has_ca()},
            {"ca_path", k.has_ca() ? k.ca_path() : std::string{}},
            {"ca_thumbprint", k.has_ca() ? k.ca_thumbprint() : std::string{}},
            {"root_installed", k.root_installed()},
            {"leaf_certs_issued", k.issued()}};
}

std::vector<std::string> string_list(const json& args, const char* key) {
    std::vector<std::string> out;
    if (!args.contains(key)) return out;
    const json& v = args.at(key);
    if (v.is_string()) {
        out.push_back(v.get<std::string>());
        return out;
    }
    if (!v.is_array()) fail(std::string(key) + " must be an array of strings");
    for (const auto& e : v) {
        if (!e.is_string()) fail(std::string(key) + " must be an array of strings");
        out.push_back(e.get<std::string>());
    }
    return out;
}

json entry_summary(const network::proxy_entry_t& e) {
    json o = {{"id", e.id}, {"at_ms", e.at_ms}, {"kind", e.kind}, {"client", e.client},
              {"method", e.method}, {"host", e.host}, {"port", e.port},
              {"path", network::redact::query(e.path)}, {"status", e.status},
              {"req_bytes", e.req_bytes}, {"resp_bytes", e.resp_bytes},
              {"replayable", e.replayable}, {"redacted", e.redacted}};
    if (!e.sni.empty()) o["sni"] = e.sni;
    if (e.intercepted) o["intercepted"] = true;
    if (!e.tls.empty()) o["tls"] = e.tls;
    if (e.tunnel_id) o["tunnel_id"] = e.tunnel_id;
    if (!e.error.empty()) o["error"] = e.error;
    return o;
}

} // namespace


json tool_network(const json& args) {
    const std::string action = require_action(args);
    reject_pid(args);

    if (action == "status") {
        const auto s = network::capture::stats();
        json out;
        out["capture_running"]  = network::capture::running();
        out["capture_filter"]   = filter_json(s.filter);
        out["store_packets"]    = g_traffic.size();
        out["proxy_running"]    = g_proxy.running();
        out["proxy_port"]       = g_proxy.port();
        out["proxy_mitm"]       = g_proxy.mitm_enabled();
        return out;
    }

    if (action == "capture_start") {
        network::capture_filter_t f;
        if (auto h = host_arg(args)) f.host = parse::to_string(*h);
        if (args.contains("port")) {
            const uint64_t port = parse_addr(args, "port");
            if (port > 65535) fail("port must be 0..65535");
            f.port = static_cast<uint16_t>(port);
        }
        f.protocol = static_cast<uint8_t>(protocol_arg(args));
        bool updated = false;
        auto err = network::capture::start(f, &updated);
        if (!err.empty()) fail(err);
        const auto s = network::capture::stats();
        return {{"capture", true}, {"filter_updated", updated},
                {"filter", filter_json(s.filter)}, {"interfaces", ifaces_json(s.interfaces)}};
    }
    if (action == "capture_stop") {
        auto err = network::capture::stop();
        if (!err.empty()) fail(err);
        network::capture::poll(g_traffic, SIZE_MAX);
        return {{"capture", false}};
    }
    if (action == "packets") {
        // pull fresh packets first then serve from the store
        network::capture::poll(g_traffic, 4096);
        const uint64_t from = args.contains("from") ? parse_addr(args, "from") : 0;
        const size_t limit = std::min<size_t>(args.value("limit", 100u), 1000u);
        network::traffic_store_t::page_t page;
        if (args.contains("filter")) {
            std::string err;
            page = g_traffic.packets_filtered(from, limit, args.at("filter").get<std::string>(), &err);
            if (!err.empty()) fail(err);
        } else if (args.value("tail", false)) {
            page = g_traffic.packets_tail(limit);
        } else {
            page = g_traffic.packets(from, limit);
        }
        json arr = json::array();
        for (const auto& p : page.items) arr.push_back(packet_to_json(p));
        return {{"packets", arr}, {"count", arr.size()},
                {"truncated", page.truncated},
                {"last_id", page.items.empty() ? from : page.items.back().id}};
    }
    if (action == "dns") {
        const auto h = host_arg(args);
        auto rows = network::capture::dns_queries(h ? parse::to_string(*h) : std::string{});
        const size_t limit = std::min<size_t>(args.value("limit", 500u), 4096u);
        if (rows.size() > limit) rows.erase(rows.begin(), rows.end() - static_cast<std::ptrdiff_t>(limit));
        json arr = json::array();
        for (const auto& d : rows)
            arr.push_back({{"timestamp", d.timestamp}, {"is_response", d.is_response},
                           {"query_type", d.query_type}, {"domain", d.domain},
                           {"resolved", d.resolved_addr}, {"answers", d.answers},
                           {"response_code", d.response_code}, {"ttl", d.ttl},
                           {"client", d.client_addr}, {"server", d.server_addr}});
        return {{"dns", arr}, {"count", arr.size()}};
    }
    if (action == "stats") {
        network::capture::poll(g_traffic, 4096);
        const auto s = network::capture::stats();
        const auto st = g_traffic.stats();
        const int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch()).count();
        return json{{"capture_active", s.capture_active},
                    {"filter", filter_json(s.filter)},
                    {"packets_seen", s.packets_seen},
                    {"packets_in", s.packets_in},
                    {"packets_out", s.packets_out},
                    {"bytes_in", s.bytes_in},
                    {"bytes_out", s.bytes_out},
                    {"filtered_out", s.filtered_out},
                    {"parse_errors", s.parse_errors},
                    {"non_tcp_udp", s.non_tcp_udp},
                    {"fragments", s.fragments},
                    {"fragments_reassembled", s.fragments_reassembled},
                    {"fragments_dropped", s.fragments_dropped},
                    {"queue_dropped", s.queue_dropped},
                    {"payload_truncated", s.payload_truncated},
                    {"dns_logged_total", s.dns_logged_total},
                    {"dns_buffered", s.dns_buffered},
                    {"interfaces", ifaces_json(s.interfaces)},
                    {"store_packets", st.packets},
                    {"store_packets_total", st.packets_total},
                    {"store_packets_evicted", st.packets_evicted},
                    {"streams", st.streams},
                    {"active_streams_60s", g_traffic.active_streams(now, 60000)},
                    {"stream_bytes", st.stream_bytes},
                    {"streams_evicted", st.streams_evicted},
                    {"stream_bytes_dropped", st.stream_bytes_dropped},
                    {"quic_packets", st.quic_packets}};
    }
    if (action == "export_pcap") {
        if (!args.contains("path")) fail("missing path");
        const std::string format = args.value("format", std::string{"pcap"});
        if (format != "pcap" && format != "pcapng")
            fail("format must be pcap or pcapng");
        const uint64_t maxp = args.contains("max_packets") ? parse_addr(args, "max_packets") : 4096;
        size_t exported = 0;
        bool truncated = false;
        auto err = network::capture::export_pcap(
            g_traffic, args.at("path").get<std::string>(),
            static_cast<uint32_t>(std::min<uint64_t>(maxp, 65536ull)), &exported, &truncated,
            format);
        if (!err.empty()) fail(err);
        json out = {{"exported", true}, {"path", args.at("path")}, {"packets", exported},
                    {"older_omitted", truncated}, {"format", format},
                    {"linktype", "raw (101)"}};
        if (format == "pcapng") out["comments"] = "packet and stream annotations become epb_comment";
        return out;
    }
    if (action == "import_pcap") {
        if (!args.contains("path")) fail("missing path");
        network::pcap::import_result_t r;
        const std::string err =
            network::pcap::import_file(g_traffic, args.at("path").get<std::string>(), &r);
        if (!err.empty()) fail(err);
        return {{"imported", true}, {"path", args.at("path")}, {"format", r.format},
                {"packets", r.packets}, {"skipped", r.skipped}, {"truncated", r.truncated},
                {"store_packets", g_traffic.size()}};
    }
    if (action == "annotate") {
        const uint64_t id = parse_addr(args, "id");
        if (!args.contains("comment") || !args.at("comment").is_string())
            fail("comment must be a string");
        const std::string comment = args.at("comment").get<std::string>();
        if (comment.size() > 512) fail("comment is capped at 512 bytes");
        const std::string kind = args.value("kind", std::string{"packet"});
        if (kind != "packet" && kind != "stream") fail("kind must be packet or stream");
        const bool ok = kind == "stream" ? g_traffic.annotate_stream(id, comment)
                                         : g_traffic.annotate_packet(id, comment);
        if (!ok) fail("unknown " + kind + " id " + std::to_string(id));
        return {{"annotated", true}, {"kind", kind}, {"id", id}, {"comment", comment},
                {"cleared", comment.empty()}};
    }
    if (action == "streams") {
        network::capture::poll(g_traffic, 4096);
        const size_t limit = std::min<size_t>(args.value("limit", 500u), 4096u);
        auto all = g_traffic.streams(limit);
        json arr = json::array();
        for (const auto& s : all) {
            arr.push_back({{"id", s.id}, {"key", s.key}, {"protocol", proto_str(s.protocol)},
                           {"client", s.client_addr + ":" + std::to_string(s.client_port)},
                           {"server", s.server_addr + ":" + std::to_string(s.server_port)},
                           {"bytes", s.bytes}, {"packets", s.packets},
                           {"truncated", s.truncated},
                           {"first_ms", s.first_ms}, {"last_ms", s.last_ms}});
        }
        return {{"streams", arr}, {"count", arr.size()}};
    }
    if (action == "stream_data") {
        const uint64_t id = parse_addr(args, "id");
        const uint64_t off =
            args.contains("offset") ? parse_addr(args, "offset") : 0;
        uint64_t len = args.contains("len") ? parse_addr(args, "len") : 4096;
        len = std::min<uint64_t>(len, 1 << 20);
        auto bytes = g_traffic.stream_bytes(
            id, static_cast<size_t>(off), static_cast<size_t>(len));
        if (!bytes) fail("unknown stream id");
        const auto sum = g_traffic.stream(id);
        json out = {{"id", id}, {"offset", off}, {"bytes", bytes->size()},
                    {"total", sum ? sum->bytes : 0}};
        const size_t text_len = std::min<size_t>(bytes->size(), 4096);
        out["text"] = printable(bytes->data(), text_len);
        out["hex"]  = to_hex(bytes->data(), text_len);
        return out;
    }

    if (action == "reassemble_stream") {
        // host-side reassembly over the capture store (TCP payloads in capture order)
        network::capture::poll(g_traffic, 4096);
        const auto host = host_arg(args);
        const uint32_t src_port = static_cast<uint32_t>(args.value("src_port", 0u));
        const uint32_t dst_port = static_cast<uint32_t>(args.value("dst_port", 0u));
        std::vector<uint8_t> data;
        uint32_t packets = 0;
        bool truncated = false;
        uint64_t from = 0;
        for (;;) {
            auto page = g_traffic.packets(from, 1000);
            if (page.items.empty()) break;
            from = page.items.back().id;
            for (const auto& p : page.items) {
                if (p.protocol != 6 || p.payload.empty()) continue;   // TCP with payload
                if (host && !packet_has_host(p, *host)) continue;
                if (src_port && p.local_port != src_port && p.remote_port != src_port) continue;
                if (dst_port && p.local_port != dst_port && p.remote_port != dst_port) continue;
                if (data.size() + p.payload.size() > (16u << 20)) { truncated = true; break; }
                data.insert(data.end(), p.payload.begin(), p.payload.end());
                ++packets;
            }
            if (truncated || !page.truncated) break;
        }
        const size_t text_len = std::min<size_t>(data.size(), 4096);
        return {{"bytes", data.size()}, {"packets", packets},
                {"truncated", truncated},
                {"hex", to_hex(data.data(), text_len)}, {"text", printable(data.data(), text_len)}};
    }

    if (action == "connections") {
        // unique 4-tuples seen in the capture store
        network::capture::poll(g_traffic, 4096);
        const auto host = host_arg(args);
        const uint32_t protocol = protocol_arg(args);
        struct conn_t { uint32_t protocol = 0; std::string local, remote; uint64_t packets = 0; uint64_t bytes = 0; };
        std::map<std::string, conn_t> by_key;
        uint64_t from = 0;
        for (;;) {
            auto page = g_traffic.packets(from, 1000);
            if (page.items.empty()) break;
            from = page.items.back().id;
            for (const auto& p : page.items) {
                if (host && !packet_has_host(p, *host)) continue;
                if (protocol && p.protocol != protocol) continue;
                const std::string local  = p.local_addr  + ":" + std::to_string(p.local_port);
                const std::string remote = p.remote_addr + ":" + std::to_string(p.remote_port);
                auto& c = by_key[std::to_string(p.protocol) + "|" + local + "|" + remote];
                c.protocol = p.protocol; c.local = local; c.remote = remote;
                c.packets += 1; c.bytes += std::max<uint64_t>(p.wire_len, p.payload.size());
            }
            if (!page.truncated) break;
        }
        json arr = json::array();
        for (const auto& kv : by_key)
            arr.push_back({{"protocol", kv.second.protocol}, {"protocol_str", proto_str(kv.second.protocol)},
                           {"local", kv.second.local}, {"remote", kv.second.remote},
                           {"packets", kv.second.packets}, {"bytes", kv.second.bytes}});
        return {{"connections", arr}, {"count", arr.size()}};
    }

    if (action == "deep_inspect") {
        // per-packet application classification over the capture store
        network::capture::poll(g_traffic, 4096);
        const auto host = host_arg(args);
        const uint32_t protocol = protocol_arg(args);
        const uint32_t port     = static_cast<uint32_t>(args.value("port", 0u));
        const size_t limit      = std::min<size_t>(args.value("limit", 200u), 2000u);
        json arr = json::array();
        uint64_t from = 0;
        for (;;) {
            auto page = g_traffic.packets(from, 1000);
            if (page.items.empty()) break;
            from = page.items.back().id;
            for (const auto& p : page.items) {
                if (arr.size() >= limit) break;
                if (host && !packet_has_host(p, *host)) continue;
                if (protocol && p.protocol != protocol) continue;
                if (port && p.local_port != port && p.remote_port != port) continue;
                if (p.payload.empty()) continue;
                json o = {{"id", p.id}, {"timestamp", p.at_ms}, {"direction", p.direction},
                          {"protocol", p.protocol},
                          {"local", p.local_addr  + ":" + std::to_string(p.local_port)},
                          {"remote", p.remote_addr + ":" + std::to_string(p.remote_port)},
                          {"payload_size", p.payload.size()}};
                const auto& b = p.payload;
                if (p.protocol == 17 && (p.local_port == 53 || p.remote_port == 53)) {
                    o["app_protocol"] = "DNS";
                    if (auto d = parse::parse_dns(b.data(), b.size())) {
                        o["dns_domain"] = d->domain;
                        if (!d->resolved_addr.empty()) o["dns_resolved"] = d->resolved_addr;
                    }
                } else if (p.protocol == 6) {
                    const size_t head_end = parse::find_head_end(b.data(), b.size());
                    const std::string_view text(reinterpret_cast<const char*>(b.data()),
                                                head_end == std::string::npos ? 0 : head_end);
                    if (auto h = text.empty() ? std::nullopt : parse::parse_http_head(text, false)) {
                        o["app_protocol"] = "HTTP";
                        o["http_method"]  = parse::escape_nonprintable(h->method);
                        o["http_path"]    = parse::escape_nonprintable(h->target);
                        if (const std::string* hh = h->get("host"))
                            o["http_host"] = parse::escape_nonprintable(*hh);
                    } else if (auto r = text.empty() ? std::nullopt : parse::parse_http_head(text, true)) {
                        o["app_protocol"] = "HTTP";
                        o["http_status"]  = r->status;
                    } else if (b.size() >= 5 && (b[0] >= 20 && b[0] <= 23) && b[1] == 0x03) {
                        o["app_protocol"]     = "TLS";
                        o["tls_version"]      = tls_version_name((uint32_t(b[1]) << 8) | b[2]);
                        o["tls_content_type"] = tls_content_type_name(b[0]);
                        const std::string sni = parse::extract_sni(b.data(), b.size());
                        if (!sni.empty()) o["tls_sni"] = sni;
                    }
                } else if (p.protocol == 17 && (p.local_port == 443 || p.remote_port == 443)) {
                    // QUIC long header: version and connection ids, no decryption
                    if (auto q = parse::parse_quic(b.data(), b.size())) {
                        o["app_protocol"]  = "QUIC";
                        o["quic_version"]  = parse::quic_version_name(q->version);
                        o["quic_type"]     = parse::quic_type_name(q->type);
                        o["quic_dcid"]     = q->dcid;
                        o["quic_scid"]     = q->scid;
                    }
                }
                arr.push_back(std::move(o));
            }
            if (arr.size() >= limit || !page.truncated) break;
        }
        return {{"results", arr}, {"count", arr.size()}};
    }
    if (action == "clear") {
        network::capture::poll(g_traffic, SIZE_MAX);
        g_traffic.clear();
        return {{"cleared", true}};
    }
    fail("network: unknown action (status|capture_start|capture_stop|packets|dns|"
         "stats|export_pcap|import_pcap|annotate|streams|stream_data|reassemble_stream|"
         "connections|deep_inspect|clear)");
}


// tool: proxy

json tool_proxy(const json& args) {
    const std::string action = require_action(args);

    if (action == "start") {
        network::proxy_options_t o;
        if (args.contains("port")) {
            const uint64_t port = parse_addr(args, "port");
            if (port > 65535) fail("port must be 0..65535");
            o.port = static_cast<uint16_t>(port);
        }
        o.bind = args.value("bind", std::string{"127.0.0.1"});
        o.allow_hosts = string_list(args, "allow_hosts");
        o.allow_clients = string_list(args, "allow_clients");
        if (args.contains("max_connections"))
            o.max_connections = static_cast<size_t>(
                std::clamp<uint64_t>(parse_addr(args, "max_connections"), 1, 1024));
        o.token = infra::settings::get<std::string>("proxy_token", "");
        o.redact_secrets = infra::settings::get<bool>("proxy_redact_secrets", true);
        std::string err;
        if (!g_proxy.start(o, &err)) fail(err);
        return {{"running", true}, {"port", g_proxy.port()}, {"bind", o.bind},
                {"token_required", !o.token.empty()}, {"allow_hosts", o.allow_hosts},
                {"allow_clients", o.allow_clients}, {"mitm", g_proxy.mitm_enabled()}};
    }
    if (action == "stop") {
        g_proxy.stop();
        return {{"running", false}};
    }
    if (action == "status") {
        const auto o = g_proxy.options();
        const auto s = g_proxy.stats();
        auto& k = pki();
        k.load_existing();
        json mitm = {{"enabled", g_proxy.mitm_enabled()},
                     {"ca_exists", k.has_ca()},
                     {"ca_path", k.has_ca() ? k.ca_path() : std::string{}},
                     {"ca_thumbprint", k.has_ca() ? k.ca_thumbprint() : std::string{}},
                     {"root_installed", k.root_installed()},
                     {"leaf_certs_issued", k.issued()},
                     {"key_storage",
                      "the CA private key is a CNG key in the Microsoft Software KSP "
                      "(DPAPI-protected per user); only the public ca.cer is written to disk "
                      "and leaf certificates stay in memory"},
                     {"uninstall_hint",
                      k.root_installed()
                          ? "proxy.mitm_uninstall removes the CA trust, the CNG keys and ca.cer"
                          : "the CA is not trusted; nothing to uninstall"}};
        return json{{"running", g_proxy.running()}, {"port", g_proxy.port()},
                    {"bind", g_proxy.running() ? o.bind : std::string{}},
                    {"token_required", g_proxy.running() && !o.token.empty()},
                    {"allow_hosts", o.allow_hosts}, {"allow_clients", o.allow_clients},
                    {"mitm", g_proxy.mitm_enabled()},
                    {"mitm_state", mitm},
                    {"redact_secrets", o.redact_secrets},
                    {"active_connections", s.active_connections},
                    {"total_connections", s.total_connections},
                    {"rejected", {{"capacity", s.rejected_capacity}, {"auth", s.rejected_auth},
                                  {"host", s.rejected_host}, {"client", s.rejected_client}}},
                    {"log_entries", s.log_entries}, {"log_bytes", s.log_bytes}};
    }
    if (action == "entries") {
        auto entries = g_proxy.recent(std::min<size_t>(args.value("limit", 100u), 512u));
        const std::string kind = args.value("kind", std::string{});
        json arr = json::array();
        for (const auto& e : entries)
            if (kind.empty() || e.kind == kind) arr.push_back(entry_summary(e));
        return {{"entries", arr}, {"count", arr.size()}};
    }
    if (action == "entry") {
        const uint64_t id = parse_addr(args, "id");
        auto e = g_proxy.entry(id);
        if (!e) fail("unknown entry id");
        json o = entry_summary(*e);
        o["request_truncated"] = e->request_truncated;
        // A redacted entry stores only the masked form; reveal:true returns the
        // unmasked request kept in memory, and stays redacted for the audit log.
        const bool reveal = args.value("reveal", false);
        std::vector<uint8_t> raw = e->raw_request;
        if (reveal && e->redacted) {
            auto kept = g_proxy.raw_request(id);
            if (!kept.empty()) raw = std::move(kept);
        }
        o["redacted"] = e->redacted && !reveal;
        if (!raw.empty()) {
            const size_t n = std::min<size_t>(raw.size(), 4096);
            std::string head = printable(raw.data(), n);
            o["request_text"] = reveal ? head : network::redact::http_head(head);
            o["request_bytes_captured"] = raw.size();
        }
        if (!e->response_head.empty()) {
            std::string head = printable(e->response_head.data(),
                                         std::min<size_t>(e->response_head.size(), 4096));
            o["response_head_text"] = reveal ? head : network::redact::http_head(head);
        }
        return o;
    }
    if (action == "replay") {
        std::string err;
        const int timeout = static_cast<int>(std::clamp<uint64_t>(
            args.contains("timeout_ms") ? parse_addr(args, "timeout_ms") : 15000, 1000, 60000));
        const bool with_secrets = args.value("with_secrets", false);
        auto r = g_proxy.replay(parse_addr(args, "id"), &err, timeout, with_secrets);
        if (!r) fail(err);
        const size_t n = std::min<size_t>(r->bytes.size(), 16384);
        json out = {{"status", r->status}, {"bytes", r->bytes.size()}, {"complete", r->complete},
                    {"truncated", r->truncated}, {"text_truncated", r->bytes.size() > n},
                    {"with_secrets", with_secrets},
                    {"text", printable(r->bytes.data(), n)}};
        if (!r->note.empty()) out["note"] = r->note;
        return out;
    }
    if (action == "clear") {
        g_proxy.clear_log();
        return {{"cleared", true}};
    }
    if (action == "mitm_status") return mitm_status_json();
    if (action == "mitm_enable") {
        if (!args.contains("consent") || !args.at("consent").is_boolean() ||
            !args.at("consent").get<bool>())
            fail("mitm_enable decrypts TLS inside proxy tunnels with a locally generated CA and "
                 "(unless install_root=false) adds that CA to CurrentUser\\ROOT, which Windows "
                 "confirms with its own dialog. Pass consent:true after the user agreed");
        auto& k = pki();
        std::string err;
        if (!k.ensure_ca(&err)) fail("CA setup failed: " + err);
        if (args.value("install_root", true) && !k.root_installed() && !k.install_root(&err))
            fail(err);
        g_proxy.set_mitm(pki_slot());
        json out = mitm_status_json();
        out["note"] = "clients must trust the CA (ca_path) for interception to succeed; "
                      "untrusting clients fail their TLS handshake and are logged with an error";
        return out;
    }
    if (action == "mitm_disable") {
        g_proxy.set_mitm(nullptr);
        return mitm_status_json();
    }
    if (action == "mitm_uninstall") {
        g_proxy.set_mitm(nullptr);
        auto& k = pki();
        std::string err;
        const bool ok = k.destroy(&err);
        std::string legacy_err;
        const size_t legacy = network::mitm::remove_legacy_artifacts(&legacy_err);
        if (!ok) fail("uninstall incomplete: " + err);
        json out = mitm_status_json();
        out["uninstalled"] = true;
        out["legacy_artifacts_removed"] = legacy;
        if (!legacy_err.empty()) out["legacy_error"] = legacy_err;
        return out;
    }

    fail("proxy: unknown action (start|stop|status|entries|entry|replay|clear|mitm_status|"
         "mitm_enable|mitm_disable|mitm_uninstall)");
}

} // namespace slop::core::mcp::detail
