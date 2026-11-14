// src/tests/test_network.cpp
// Network slice: parsers (IP/L4/fragments/DNS/SNI/HTTP framing) incl. a
// deterministic mutation fuzz pass, the capture pipeline through its test
// hooks (no sockets, no admin), the traffic store (ring, LRU byte budget,
// filters, pcap records), and the proxy over real loopback sockets (plain
// HTTP, CONNECT, auth, allowlists, caps, timeouts, replay, TLS interception)

#include "harness.hpp"

#include "core/network/capture_service.hpp"
#include "core/network/http_proxy.hpp"
#include "core/network/mitm_pki.hpp"
#include "core/network/net_socket.hpp"
#include "core/network/parsers.hpp"
#include "core/network/pcap_import.hpp"
#include "core/network/redact.hpp"
#include "core/network/tls_stream.hpp"
#include "core/network/traffic_store.hpp"
#include "core/mcp/mcp_tools.hpp"

#include <httplib.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>

using namespace slop::core::network;

namespace {

// packet builders

std::vector<uint8_t> addr_bytes(const char* a) {
    const auto ip = parse::parse_ip(a);
    if (!ip) return {};
    return std::vector<uint8_t>(ip->b.begin(), ip->b.begin() + (ip->family == 4 ? 4 : 16));
}

void put16(std::vector<uint8_t>& v, size_t at, uint32_t x) {
    v[at] = static_cast<uint8_t>((x >> 8) & 0xFF);
    v[at + 1] = static_cast<uint8_t>(x & 0xFF);
}

std::vector<uint8_t> tcp_seg(uint16_t sp, uint16_t dp, const std::string& payload, uint32_t seq = 1000) {
    std::vector<uint8_t> t(20, 0);
    put16(t, 0, sp);
    put16(t, 2, dp);
    t[4] = static_cast<uint8_t>(seq >> 24);
    t[5] = static_cast<uint8_t>((seq >> 16) & 0xFF);
    t[6] = static_cast<uint8_t>((seq >> 8) & 0xFF);
    t[7] = static_cast<uint8_t>(seq & 0xFF);
    t[12] = 0x50;
    t[13] = 0x18;
    t.insert(t.end(), payload.begin(), payload.end());
    return t;
}

std::vector<uint8_t> udp_dgram(uint16_t sp, uint16_t dp, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> u(8, 0);
    put16(u, 0, sp);
    put16(u, 2, dp);
    put16(u, 4, static_cast<uint32_t>(8 + payload.size()));
    u.insert(u.end(), payload.begin(), payload.end());
    return u;
}

std::vector<uint8_t> ipv4(const char* src, const char* dst, uint8_t proto,
                          const std::vector<uint8_t>& l4, uint16_t id = 7,
                          uint16_t frag = 0x4000, size_t pad = 0) {
    std::vector<uint8_t> p(20, 0);
    p[0] = 0x45;
    put16(p, 2, static_cast<uint32_t>(20 + l4.size()));
    put16(p, 4, id);
    put16(p, 6, frag);
    p[8] = 64;
    p[9] = proto;
    const auto s = addr_bytes(src), d = addr_bytes(dst);
    std::memcpy(p.data() + 12, s.data(), 4);
    std::memcpy(p.data() + 16, d.data(), 4);
    p.insert(p.end(), l4.begin(), l4.end());
    p.insert(p.end(), pad, 0xEE);
    return p;
}

std::vector<uint8_t> ipv6(const char* src, const char* dst, uint8_t next,
                          const std::vector<uint8_t>& rest) {
    std::vector<uint8_t> p(40, 0);
    p[0] = 0x60;
    put16(p, 4, static_cast<uint32_t>(rest.size()));
    p[6] = next;
    p[7] = 64;
    const auto s = addr_bytes(src), d = addr_bytes(dst);
    std::memcpy(p.data() + 8, s.data(), 16);
    std::memcpy(p.data() + 24, d.data(), 16);
    p.insert(p.end(), rest.begin(), rest.end());
    return p;
}

std::vector<uint8_t> dns_response(const char* name, const std::vector<std::vector<uint8_t>>& a4,
                                  const std::vector<std::vector<uint8_t>>& a6) {
    std::vector<uint8_t> m = {0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0};
    put16(m, 6, static_cast<uint32_t>(a4.size() + a6.size()));
    std::string n = name;
    size_t start = 0;
    while (start <= n.size()) {
        size_t dot = n.find('.', start);
        if (dot == std::string::npos) dot = n.size();
        m.push_back(static_cast<uint8_t>(dot - start));
        m.insert(m.end(), n.begin() + static_cast<std::ptrdiff_t>(start),
                 n.begin() + static_cast<std::ptrdiff_t>(dot));
        start = dot + 1;
    }
    m.push_back(0);
    m.insert(m.end(), {0, 1, 0, 1});
    auto answer = [&](uint16_t type, const std::vector<uint8_t>& rd) {
        m.insert(m.end(), {0xC0, 0x0C});                  // pointer to the question name
        m.push_back(0);
        m.push_back(static_cast<uint8_t>(type));
        m.insert(m.end(), {0, 1, 0, 0, 0x0E, 0x10});      // class IN, ttl 3600
        m.push_back(0);
        m.push_back(static_cast<uint8_t>(rd.size()));
        m.insert(m.end(), rd.begin(), rd.end());
    };
    for (const auto& a : a4) answer(1, a);
    for (const auto& a : a6) answer(28, a);
    return m;
}

std::vector<uint8_t> client_hello(const std::string& sni) {
    std::vector<uint8_t> ext;
    if (!sni.empty()) {
        std::vector<uint8_t> list;
        list.push_back(0);
        list.push_back(static_cast<uint8_t>(sni.size() >> 8));
        list.push_back(static_cast<uint8_t>(sni.size() & 0xFF));
        list.insert(list.end(), sni.begin(), sni.end());
        std::vector<uint8_t> body = {static_cast<uint8_t>(list.size() >> 8),
                                     static_cast<uint8_t>(list.size() & 0xFF)};
        body.insert(body.end(), list.begin(), list.end());
        ext = {0, 0, static_cast<uint8_t>(body.size() >> 8), static_cast<uint8_t>(body.size() & 0xFF)};
        ext.insert(ext.end(), body.begin(), body.end());
    }
    std::vector<uint8_t> hello = {0x03, 0x03};
    hello.insert(hello.end(), 32, 0xAB);                   // random
    hello.push_back(0);                                     // session id
    hello.insert(hello.end(), {0, 2, 0x13, 0x01});          // one suite
    hello.insert(hello.end(), {1, 0});                      // null compression
    hello.push_back(static_cast<uint8_t>(ext.size() >> 8));
    hello.push_back(static_cast<uint8_t>(ext.size() & 0xFF));
    hello.insert(hello.end(), ext.begin(), ext.end());
    std::vector<uint8_t> hs = {1, 0, static_cast<uint8_t>(hello.size() >> 8),
                               static_cast<uint8_t>(hello.size() & 0xFF)};
    hs.insert(hs.end(), hello.begin(), hello.end());
    std::vector<uint8_t> rec = {0x16, 0x03, 0x01, static_cast<uint8_t>(hs.size() >> 8),
                                static_cast<uint8_t>(hs.size() & 0xFF)};
    rec.insert(rec.end(), hs.begin(), hs.end());
    return rec;
}

packet_record_t mk_packet(int sport, int dport, const char* local = "10.0.0.2",
                          const char* remote = "93.184.216.34", uint32_t dir = 0,
                          const std::string& body = "hello") {
    packet_record_t p;
    p.at_ms = 1700000000000;
    p.protocol = 6;
    p.direction = dir;
    p.local_addr = local;
    p.local_port = static_cast<uint16_t>(sport);
    p.remote_addr = remote;
    p.remote_port = static_cast<uint16_t>(dport);
    p.payload.assign(body.begin(), body.end());
    return p;
}

std::string temp_path(const char* name) {
    char path[MAX_PATH];
    std::snprintf(path, sizeof(path), "%s\\slop_net_%u_%s", std::getenv("TEMP"),
                  static_cast<unsigned>(::_getpid()), name);
    return path;
}

std::vector<uint8_t> read_all(const std::string& path) {
    std::vector<uint8_t> out;
    std::FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "rb") != 0 || !f) return out;
    uint8_t buf[4096];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) out.insert(out.end(), buf, buf + n);
    std::fclose(f);
    return out;
}

uint32_t le32(const std::vector<uint8_t>& v, size_t at) {
    return static_cast<uint32_t>(v[at]) | (static_cast<uint32_t>(v[at + 1]) << 8) |
           (static_cast<uint32_t>(v[at + 2]) << 16) | (static_cast<uint32_t>(v[at + 3]) << 24);
}

uint32_t be16v(const std::vector<uint8_t>& v, size_t at) {
    return (static_cast<uint32_t>(v[at]) << 8) | v[at + 1];
}

// loopback socket helpers (every socket gets timeouts so a regression fails
// instead of hanging the suite)

SOCKET dial(uint16_t port) {
    SOCKET c = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (c == INVALID_SOCKET) return c;
    DWORD tv = 5000;
    ::setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    ::setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(c, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        ::closesocket(c);
        return INVALID_SOCKET;
    }
    return c;
}

void send_str(SOCKET s, const std::string& d) {
    ::send(s, d.data(), static_cast<int>(d.size()), 0);
}

std::string recv_all(SOCKET s) {
    std::string out;
    char buf[4096];
    int r;
    while ((r = ::recv(s, buf, sizeof(buf), 0)) > 0) out.append(buf, static_cast<size_t>(r));
    return out;
}

std::string recv_head(SOCKET s) {
    std::string out;
    char c;
    while (out.find("\r\n\r\n") == std::string::npos && ::recv(s, &c, 1, 0) == 1) out.push_back(c);
    return out;
}

std::string exchange(uint16_t port, const std::string& req) {
    SOCKET c = dial(port);
    if (c == INVALID_SOCKET) return {};
    send_str(c, req);
    std::string resp = recv_all(c);
    ::closesocket(c);
    return resp;
}

struct origin_t {
    httplib::Server srv;
    int port = 0;
    std::thread th;
    origin_t() {
        srv.Get("/hi", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("origin-body", "text/plain");
        });
        srv.Post("/echo", [](const httplib::Request& req, httplib::Response& res) {
            res.set_content("echo:" + req.body, "text/plain");
        });
        // echoes the credential headers so a replay can be checked for them
        srv.Get("/auth", [](const httplib::Request& req, httplib::Response& res) {
            res.set_header("Set-Cookie", "sid=set-cookie-secret; HttpOnly");
            res.set_content("auth:" + req.get_header_value("Authorization") +
                                "|cookie:" + req.get_header_value("Cookie") +
                                "|target:" + req.target,
                            "text/plain");
        });
        port = srv.bind_to_any_port("127.0.0.1");
        th = std::thread([this] { srv.listen_after_bind(); });
        srv.wait_until_ready();
    }
    ~origin_t() {
        srv.stop();
        if (th.joinable()) th.join();
    }
};

const proxy_entry_t* find_entry(const std::vector<proxy_entry_t>& v, const char* kind,
                                const char* path) {
    for (const auto& e : v)
        if (e.kind == kind && (!path || e.path == path)) return &e;
    return nullptr;
}

// xorshift: deterministic fuzz input
struct rng_t {
    uint64_t s;
    explicit rng_t(uint64_t seed) : s(seed ? seed : 0x9E3779B97F4A7C15ull) {}
    uint64_t next() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        return s;
    }
    size_t below(size_t n) { return n ? static_cast<size_t>(next() % n) : 0; }
};

std::vector<uint8_t> mutate(rng_t& r, std::vector<uint8_t> v) {
    const size_t ops = 1 + r.below(4);
    for (size_t k = 0; k < ops; ++k) {
        switch (r.below(5)) {
        case 0: if (!v.empty()) v[r.below(v.size())] ^= static_cast<uint8_t>(1u << r.below(8)); break;
        case 1: if (!v.empty()) v[r.below(v.size())] = static_cast<uint8_t>(r.next()); break;
        case 2: if (!v.empty()) v.resize(r.below(v.size() + 1)); break;
        case 3: v.insert(v.begin() + static_cast<std::ptrdiff_t>(r.below(v.size() + 1)),
                         static_cast<uint8_t>(r.next())); break;
        default:
            if (v.size() >= 2) {   // stomp a 16-bit length-like field with an extreme value
                const size_t at = r.below(v.size() - 1);
                const uint16_t vals[] = {0, 1, 0x7F, 0x80, 0xFF, 0xFFFF, 0x8000};
                const uint16_t x = vals[r.below(7)];
                v[at] = static_cast<uint8_t>(x >> 8);
                v[at + 1] = static_cast<uint8_t>(x & 0xFF);
            }
            break;
        }
    }
    return v;
}

bool printable_ascii(const std::string& s) {
    for (char c : s)
        if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) > 0x7E) return false;
    return true;
}

} // namespace

// traffic store

TEST_CASE(network_store_ring_and_ids) {
    traffic_store_t s(4);
    for (int i = 0; i < 10; ++i) s.add(mk_packet(1000 + i, 80));
    REQUIRE_EQ(s.size(), 4u);
    auto page = s.packets(0, 100);
    REQUIRE_EQ(page.items.size(), 4u);
    REQUIRE_GT(page.items.back().id, page.items.front().id);
    REQUIRE_EQ(page.items.front().id, 7u);
    // from-id paging jumps straight into the ring
    auto after = s.packets(8, 100);
    REQUIRE_EQ(after.items.size(), 2u);
    REQUIRE_EQ(after.items.front().id, 9u);
    auto capped = s.packets(0, 2);
    REQUIRE(capped.truncated);
    REQUIRE_EQ(s.stats().packets_evicted, 6u);
    REQUIRE_EQ(s.stats().packets_total, 10u);
}

TEST_CASE(network_store_tail_is_newest) {
    traffic_store_t s(100);
    for (int i = 0; i < 10; ++i) s.add(mk_packet(1000 + i, 80));
    auto tail = s.packets_tail(3);
    REQUIRE_EQ(tail.items.size(), 3u);
    REQUIRE(tail.truncated);
    REQUIRE_EQ(tail.items.front().id, 8u);
    REQUIRE_EQ(tail.items.back().id, 10u);
    REQUIRE_FALSE(s.packets_tail(50).truncated);
}

TEST_CASE(network_store_stream_reassembly) {
    traffic_store_t s;
    s.add(mk_packet(1234, 80, "10.0.0.2", "1.1.1.1", 0, "GET / HT"));
    s.add(mk_packet(1234, 80, "10.0.0.2", "1.1.1.1", 1, "HTTP/1.1 200 OK"));

    auto streams = s.streams();
    REQUIRE_EQ(streams.size(), 1u);
    REQUIRE_EQ(streams[0].bytes, 23u);
    REQUIRE_EQ(streams[0].packets, 2u);
    REQUIRE_STR_EQ(streams[0].client_addr, "10.0.0.2");
    REQUIRE_EQ(streams[0].server_port, 80);

    auto bytes = s.stream_bytes(streams[0].id, 0, 1024);
    REQUIRE(bytes.has_value());
    std::string merged(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    REQUIRE(merged.find("GET / HT") == 0);
    REQUIRE(merged.find("200 OK") != std::string::npos);
    REQUIRE(s.stream(streams[0].id).has_value());
    REQUIRE(!s.stream(999).has_value());

    auto empty_tail = s.stream_bytes(streams[0].id, 9999, 10);
    REQUIRE(empty_tail.has_value());
    REQUIRE(empty_tail->empty());
    REQUIRE(!s.stream_bytes(9999, 0, 1).has_value());
}

TEST_CASE(network_store_byte_budget_lru) {
    traffic_store_t::limits_t lim;
    lim.max_packets = 1000;
    lim.max_streams = 3;
    lim.max_direction_bytes = 1000;
    lim.max_stream_bytes = 3000;
    traffic_store_t s(lim);
    const std::string k1000(1000, 'x');

    // per-direction cap: 1500 bytes keep 1000, the stream is marked truncated
    s.add(mk_packet(1001, 80, "10.0.0.2", "1.1.1.1", 0, k1000 + std::string(500, 'y')));
    auto first = s.streams();
    REQUIRE_EQ(first.size(), 1u);
    REQUIRE_EQ(first[0].bytes, 1000u);
    REQUIRE(first[0].truncated);
    REQUIRE_EQ(s.stats().stream_bytes_dropped, 500u);
    const uint64_t a = first[0].id;

    s.add(mk_packet(1002, 80, "10.0.0.2", "1.1.1.2", 0, k1000));
    s.add(mk_packet(1003, 80, "10.0.0.2", "1.1.1.3", 0, k1000));
    // touch stream a (1 byte, now most recent): 3001 bytes > budget, so the
    // least recently active stream b is evicted
    s.add(mk_packet(1001, 80, "10.0.0.2", "1.1.1.1", 1, "z"));
    REQUIRE_EQ(s.stats().stream_bytes, 2001u);
    REQUIRE_EQ(s.stats().streams_evicted, 1u);
    s.add(mk_packet(1004, 80, "10.0.0.2", "1.1.1.4", 0, k1000));

    const auto st = s.stats();
    REQUIRE_LE(st.stream_bytes, 3000u);
    REQUIRE_LE(st.streams, 3u);
    REQUIRE_GE(st.streams_evicted, 2u);
    REQUIRE(s.stream(a).has_value());            // recently touched survives
    bool has_b = false, has_d = false;
    for (const auto& x : s.streams()) {
        if (x.server_addr == "1.1.1.2") has_b = true;
        if (x.server_addr == "1.1.1.4") has_d = true;
    }
    REQUIRE_FALSE(has_b);
    REQUIRE(has_d);
    // most recent first
    REQUIRE_STR_EQ(s.streams().front().server_addr, "1.1.1.4");
}

TEST_CASE(network_store_filter_expressions) {
    traffic_store_t s;
    auto http = mk_packet(1234, 80, "10.0.0.2", "1.1.1.1", 0, "GET /a");
    auto dns = mk_packet(5555, 53, "10.0.0.2", "8.8.8.8", 0, std::string("\x00\x01query", 7));
    dns.protocol = 17;
    auto near_miss = mk_packet(4444, 443, "10.0.0.2", "18.8.8.88", 1, "tls");
    auto v6 = mk_packet(4445, 443, "fe80::1", "2001:db8::5", 0, "v6");
    v6.ip_version = 6;
    s.add(http);
    s.add(dns);
    s.add(near_miss);
    s.add(v6);

    std::string err;
    REQUIRE_EQ(s.packets_filtered(0, 100, "port=80", &err).items.size(), 1u);
    REQUIRE_EQ(s.packets_filtered(0, 100, "port==80", &err).items.size(), 1u);
    REQUIRE_EQ(s.packets_filtered(0, 100, "proto:udp", &err).items.size(), 1u);
    REQUIRE_EQ(s.packets_filtered(0, 100, "text:GET", &err).items.size(), 1u);
    // exact address match: 8.8.8.8 no longer substring-matches 18.8.8.88
    REQUIRE_EQ(s.packets_filtered(0, 100, "host:8.8.8.8", &err).items.size(), 1u);
    REQUIRE_EQ(s.packets_filtered(0, 100, "host:18.0.0.0/8", &err).items.size(), 1u);
    REQUIRE_EQ(s.packets_filtered(0, 100, "host:2001:db8::/32", &err).items.size(), 1u);
    REQUIRE_EQ(s.packets_filtered(0, 100, "dir:in", &err).items.size(), 1u);
    REQUIRE_EQ(s.packets_filtered(0, 100, "port=53;host:8.8.8.8", &err).items.size(), 1u);
    REQUIRE_EQ(s.packets_filtered(0, 100, "port=80;port=53", &err).items.size(), 0u);
    REQUIRE(err.empty());

    for (const char* bad : {"bogus:x", "port=80junk", "port=70000", "host:example.com",
                            "proto:icmpv9", "dir:sideways", "text:", "port"}) {
        err.clear();
        REQUIRE_EQ(s.packets_filtered(0, 100, bad, &err).items.size(), 0u);
        REQUIRE(!err.empty());
    }
    err.clear();
    s.packets_filtered(0, 100, "pid:222", &err);
    REQUIRE(err.find("host:") != std::string::npos);
}

TEST_CASE(network_pcap_records_are_valid) {
    traffic_store_t s;
    std::vector<packet_record_t> pkts;
    auto out = mk_packet(1234, 80, "10.0.0.2", "1.2.3.4", 0, "abcd");
    out.id = 1;
    out.tcp_seq = 0x01020304;
    pkts.push_back(out);
    auto in = mk_packet(1234, 80, "10.0.0.2", "1.2.3.4", 1, "xyz");
    in.id = 2;
    in.wire_len = 1400;                      // capture kept a 3-byte prefix
    pkts.push_back(in);
    auto v6 = mk_packet(5353, 53, "fe80::1", "2001:db8::53", 0, "dnsq");
    v6.protocol = 17;
    v6.ip_version = 6;
    v6.id = 3;
    pkts.push_back(v6);
    auto huge = mk_packet(1, 2, "10.0.0.2", "1.2.3.4", 0, "");
    huge.id = 4;
    huge.payload.assign(70000, 0x41);        // larger than one IP datagram can carry
    pkts.push_back(huge);

    const std::string path = temp_path("ok.pcap");
    std::string err;
    REQUIRE(s.write_pcap(path, pkts, &err));
    REQUIRE(err.empty());
    const auto f = read_all(path);
    std::remove(path.c_str());
    REQUIRE_GE(f.size(), 24u);
    REQUIRE_EQ(le32(f, 0), 0xa1b2c3d4u);
    REQUIRE_EQ(le32(f, 16), 65535u);         // snaplen
    REQUIRE_EQ(le32(f, 20), 101u);           // LINKTYPE_RAW

    size_t off = 24;
    // record 1: IPv4/TCP outbound
    REQUIRE_EQ(le32(f, off + 8), 20u + 20u + 4u);
    REQUIRE_EQ(le32(f, off + 12), 20u + 20u + 4u);
    size_t ip = off + 16;
    REQUIRE_EQ(f[ip], 0x45);
    REQUIRE_EQ(be16v(f, ip + 2), 44u);
    {   // header checksum verifies to zero
        uint32_t sum = 0;
        for (size_t i = 0; i < 20; i += 2) sum += be16v(f, ip + i);
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        REQUIRE_EQ(sum, 0xFFFFu);
    }
    REQUIRE(f[ip + 12] == 10 && f[ip + 15] == 2);       // src = local
    REQUIRE(f[ip + 16] == 1 && f[ip + 19] == 4);        // dst = remote
    REQUIRE_EQ(be16v(f, ip + 20), 1234u);
    REQUIRE_EQ(be16v(f, ip + 22), 80u);
    REQUIRE_EQ(f[ip + 24], 1);                          // seq MSB
    off = ip + le32(f, off + 8);

    // record 2: inbound, orig_len carries the wire length
    REQUIRE_EQ(le32(f, off + 8), 43u);
    REQUIRE_EQ(le32(f, off + 12), 40u + 1400u);
    ip = off + 16;
    REQUIRE_EQ(be16v(f, ip + 2), 1440u);
    REQUIRE(f[ip + 12] == 1 && f[ip + 16] == 10);       // src = remote now
    REQUIRE_EQ(be16v(f, ip + 20), 80u);
    off = ip + le32(f, off + 8);

    // record 3: IPv6/UDP
    REQUIRE_EQ(le32(f, off + 8), 40u + 8u + 4u);
    ip = off + 16;
    REQUIRE_EQ(f[ip] >> 4, 6);
    REQUIRE_EQ(be16v(f, ip + 4), 12u);
    REQUIRE_EQ(f[ip + 6], 17);
    REQUIRE_EQ(f[ip + 8], 0xFE);
    REQUIRE_EQ(be16v(f, ip + 40 + 4), 12u);              // udp length
    off = ip + le32(f, off + 8);

    // record 4: clamped to what a 16-bit total length can describe
    REQUIRE_EQ(le32(f, off + 8), 65535u);
    REQUIRE_EQ(be16v(f, off + 16 + 2), 65535u);
    off = off + 16 + le32(f, off + 8);
    REQUIRE_EQ(off, f.size());

    // unparseable and mixed-family addresses are errors and leave no file
    const std::string bad_path = temp_path("bad.pcap");
    auto bad = mk_packet(1, 2, "not-an-ip", "1.2.3.4");
    REQUIRE_FALSE(s.write_pcap(bad_path, {bad}, &err));
    REQUIRE(err.find("unparseable") != std::string::npos);
    REQUIRE(read_all(bad_path).empty());
    auto mixed = mk_packet(1, 2, "10.0.0.1", "::1");
    REQUIRE_FALSE(s.write_pcap(bad_path, {mixed}, &err));
    REQUIRE(err.find("mixed") != std::string::npos);
    // an unwritable path is an error
    REQUIRE_FALSE(s.write_pcap("Z:\\definitely\\missing\\dir\\x.pcap", {out}, &err));
}

// parsers

TEST_CASE(network_parse_ip_l4_lengths) {
    // IPv4 total_len shorter than the buffer: Ethernet padding is not payload
    auto pkt = ipv4("10.0.0.2", "1.2.3.4", 6, tcp_seg(1234, 80, "hello"), 7, 0x4000, 6);
    parse::ip_info_t ip;
    REQUIRE(parse::parse_ip(pkt.data(), pkt.size(), ip) == parse::status_t::ok);
    REQUIRE_EQ(ip.proto, 6);
    REQUIRE_FALSE(ip.fragment);
    REQUIRE_STR_EQ(parse::to_string(ip.src), "10.0.0.2");
    parse::l4_info_t l;
    REQUIRE(parse::parse_l4(ip.proto, ip.l4, ip.l4_len, ip.l4_wire_len, l) == parse::status_t::ok);
    REQUIRE_EQ(l.payload_len, 5u);
    REQUIRE_EQ(l.payload_wire_len, 5u);
    REQUIRE_EQ(l.src_port, 1234);
    REQUIRE_EQ(l.tcp_seq, 1000u);

    // UDP payload clamps to udp.len even when total_len is larger
    auto u = udp_dgram(5000, 53, {1, 2, 3, 4});
    u.insert(u.end(), {9, 9});                              // junk inside the IP payload
    auto pu = ipv4("10.0.0.2", "8.8.8.8", 17, u);
    REQUIRE(parse::parse_ip(pu.data(), pu.size(), ip) == parse::status_t::ok);
    REQUIRE(parse::parse_l4(ip.proto, ip.l4, ip.l4_len, ip.l4_wire_len, l) == parse::status_t::ok);
    REQUIRE_EQ(l.payload_len, 4u);

    // snapped capture: wire length survives, captured length is honest
    auto big = ipv4("10.0.0.2", "1.2.3.4", 6, tcp_seg(1, 2, std::string(300, 'q')));
    REQUIRE(parse::parse_ip(big.data(), 100, ip) == parse::status_t::ok);
    REQUIRE(parse::parse_l4(ip.proto, ip.l4, ip.l4_len, ip.l4_wire_len, l) == parse::status_t::ok);
    REQUIRE_EQ(l.payload_len, 60u);
    REQUIRE_EQ(l.payload_wire_len, 300u);

    // bad header fields
    auto bad = pkt;
    bad[0] = 0x44;                                          // ihl 16 bytes
    REQUIRE(parse::parse_ip(bad.data(), bad.size(), ip) == parse::status_t::malformed);
    bad = pkt;
    put16(bad, 2, 10);                                      // total_len < ihl
    REQUIRE(parse::parse_ip(bad.data(), bad.size(), ip) == parse::status_t::malformed);
    bad = pkt;
    bad[0] = 0x15;
    REQUIRE(parse::parse_ip(bad.data(), bad.size(), ip) == parse::status_t::not_ip);
    REQUIRE(parse::parse_ip(pkt.data(), 10, ip) == parse::status_t::truncated);

    // IPv4 fragments are flagged, never parsed as L4
    auto frag = ipv4("10.0.0.2", "1.2.3.4", 17, udp_dgram(1, 2, {1}), 9, 0x2000);
    REQUIRE(parse::parse_ip(frag.data(), frag.size(), ip) == parse::status_t::ok);
    REQUIRE(ip.fragment);
    REQUIRE(ip.more_fragments);

    // IPv6 with a hop-by-hop header before TCP
    std::vector<uint8_t> hbh = {6, 0, 1, 4, 0, 0, 0, 0};
    auto seg = tcp_seg(443, 50000, "v6data");
    hbh.insert(hbh.end(), seg.begin(), seg.end());
    auto p6 = ipv6("2001:db8::1", "2001:db8::2", 0, hbh);
    REQUIRE(parse::parse_ip(p6.data(), p6.size(), ip) == parse::status_t::ok);
    REQUIRE_EQ(ip.proto, 6);
    REQUIRE_EQ(ip.src.family, 6);
    REQUIRE(parse::parse_l4(ip.proto, ip.l4, ip.l4_len, ip.l4_wire_len, l) == parse::status_t::ok);
    REQUIRE_EQ(l.payload_len, 6u);
    REQUIRE_EQ(l.src_port, 443);

    // ICMP is valid IP but unsupported at L4
    auto icmp = ipv4("10.0.0.2", "1.2.3.4", 1, {8, 0, 0, 0});
    REQUIRE(parse::parse_ip(icmp.data(), icmp.size(), ip) == parse::status_t::ok);
    REQUIRE(parse::parse_l4(ip.proto, ip.l4, ip.l4_len, ip.l4_wire_len, l) == parse::status_t::unsupported);
}

TEST_CASE(network_fragment_reassembly) {
    // one 40-byte UDP datagram (8 header + 32 payload) in three fragments, out of order
    std::vector<uint8_t> payload(32);
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<uint8_t>(i);
    const auto whole = udp_dgram(4000, 9000, payload);
    auto slice = [&](size_t a, size_t b) {
        return std::vector<uint8_t>(whole.begin() + static_cast<std::ptrdiff_t>(a),
                                    whole.begin() + static_cast<std::ptrdiff_t>(b));
    };
    const auto f1 = ipv4("10.0.0.9", "10.0.0.2", 17, slice(0, 16), 77, 0x2000 | 0);
    const auto f2 = ipv4("10.0.0.9", "10.0.0.2", 17, slice(16, 32), 77, 0x2000 | 2);
    const auto f3 = ipv4("10.0.0.9", "10.0.0.2", 17, slice(32, 40), 77, 4);

    parse::reassembler_t r;
    parse::ip_info_t ip;
    for (const auto* f : {&f3, &f1}) {
        REQUIRE(parse::parse_ip(f->data(), f->size(), ip) == parse::status_t::ok);
        REQUIRE(!r.add(ip, 1000).has_value());
    }
    REQUIRE_EQ(r.pending(), 1u);
    REQUIRE(parse::parse_ip(f2.data(), f2.size(), ip) == parse::status_t::ok);
    auto dg = r.add(ip, 1001);
    REQUIRE(dg.has_value());
    REQUIRE_EQ(dg->proto, 17);
    REQUIRE(dg->l4 == whole);
    REQUIRE_EQ(r.pending(), 0u);
    REQUIRE_EQ(r.bytes(), 0u);
    REQUIRE_EQ(r.completed(), 1u);

    // expiry and the datagram cap drop incomplete datagrams
    parse::reassembler_t::limits_t lim;
    lim.max_datagrams = 2;
    lim.timeout_ms = 100;
    parse::reassembler_t small(lim);
    for (uint16_t id = 1; id <= 3; ++id) {
        auto f = ipv4("10.0.0.9", "10.0.0.2", 17, slice(0, 16), id, 0x2000);
        REQUIRE(parse::parse_ip(f.data(), f.size(), ip) == parse::status_t::ok);
        small.add(ip, 0);
    }
    REQUIRE_EQ(small.pending(), 2u);
    REQUIRE_EQ(small.dropped(), 1u);
    auto late = ipv4("10.0.0.9", "10.0.0.2", 17, slice(0, 16), 50, 0x2000);
    REQUIRE(parse::parse_ip(late.data(), late.size(), ip) == parse::status_t::ok);
    small.add(ip, 1000);                                    // expires the two old ones
    REQUIRE_EQ(small.pending(), 1u);
    REQUIRE_EQ(small.dropped(), 3u);

    // inconsistent last fragment (data beyond the declared end) is dropped
    parse::reassembler_t r2;
    REQUIRE(parse::parse_ip(f2.data(), f2.size(), ip) == parse::status_t::ok);
    r2.add(ip, 0);
    auto short_last = ipv4("10.0.0.9", "10.0.0.2", 17, slice(0, 8), 77, 1);
    REQUIRE(parse::parse_ip(short_last.data(), short_last.size(), ip) == parse::status_t::ok);
    REQUIRE(!r2.add(ip, 0).has_value());
    REQUIRE_EQ(r2.pending(), 0u);

    // IPv6 fragment header path
    std::vector<uint8_t> fh1 = {17, 0, 0, 1, 0, 0, 0, 5};   // offset 0, M=1, id 5
    auto a = slice(0, 16);
    fh1.insert(fh1.end(), a.begin(), a.end());
    std::vector<uint8_t> fh2 = {17, 0, 0, 16, 0, 0, 0, 5};  // offset 16 (2 units), M=0
    auto b = slice(16, 40);
    fh2.insert(fh2.end(), b.begin(), b.end());
    const auto p1 = ipv6("2001:db8::9", "2001:db8::2", 44, fh1);
    const auto p2 = ipv6("2001:db8::9", "2001:db8::2", 44, fh2);
    parse::reassembler_t r6;
    REQUIRE(parse::parse_ip(p2.data(), p2.size(), ip) == parse::status_t::ok);
    REQUIRE(ip.fragment);
    REQUIRE(!r6.add(ip, 0).has_value());
    REQUIRE(parse::parse_ip(p1.data(), p1.size(), ip) == parse::status_t::ok);
    auto d6 = r6.add(ip, 0);
    REQUIRE(d6.has_value());
    REQUIRE(d6->l4 == whole);
}

TEST_CASE(network_parse_dns_messages) {
    const auto resp = dns_response("cdn.playstation.net", {{1, 2, 3, 4}},
                                   {addr_bytes("2001:db8::7")});
    auto r = parse::parse_dns(resp.data(), resp.size());
    REQUIRE(r.has_value());
    REQUIRE(r->is_response);
    REQUIRE_STR_EQ(r->domain, "cdn.playstation.net");
    REQUIRE_STR_EQ(r->resolved_addr, "1.2.3.4");
    REQUIRE_EQ(r->answers.size(), 2u);
    REQUIRE_STR_EQ(r->answers[1], "2001:db8::7");
    REQUIRE_EQ(r->ttl, 3600u);

    // forward / self compression pointers are rejected (no loops)
    auto loop = resp;
    loop[12] = 0xC0;
    loop[13] = 12;                                          // points at itself
    REQUIRE(!parse::parse_dns(loop.data(), loop.size()).has_value());
    // non-printable label bytes are escaped
    auto odd = resp;
    odd[13] = 0x01;
    auto ro = parse::parse_dns(odd.data(), odd.size());
    REQUIRE(ro.has_value());
    REQUIRE(ro->domain.find("\\x01") != std::string::npos);
    REQUIRE(!parse::parse_dns(resp.data(), 11).has_value());
}

TEST_CASE(network_extract_sni_bounds) {
    const auto hello = client_hello("psn.example.com");
    REQUIRE_STR_EQ(parse::extract_sni(hello.data(), hello.size()), "psn.example.com");
    REQUIRE(parse::extract_sni(client_hello("").data(), client_hello("").size()).empty());
    // every truncation of a valid hello is safe and never returns garbage
    for (size_t n = 0; n < hello.size(); ++n) {
        const std::string s = parse::extract_sni(hello.data(), n);
        CHECK(s.empty() || s == "psn.example.com");
    }
    // a lying name length cannot read past the buffer
    auto lie = hello;
    lie[lie.size() - 16] = 0x7F;
    CHECK(parse::extract_sni(lie.data(), lie.size()).empty());
    // a name that is not a hostname is rejected
    const auto bad = client_hello("../../evil");
    REQUIRE(parse::extract_sni(bad.data(), bad.size()).empty());
}

TEST_CASE(network_http_framer_and_chunked) {
    using ev_t = parse::http_framer_t::event_t;
    parse::http_framer_t req(false);
    const std::string pipelined =
        "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhelloGET /b HTTP/1.1\r\nHost: x\r\n\r\n";
    std::vector<ev_t> ev;
    // feed in odd-sized pieces: offsets are per chunk
    size_t heads = 0, ends = 0;
    for (size_t i = 0; i < pipelined.size(); i += 7) {
        ev.clear();
        const size_t n = std::min<size_t>(7, pipelined.size() - i);
        req.feed(reinterpret_cast<const uint8_t*>(pipelined.data() + i), n, &ev);
        for (const auto& e : ev) {
            REQUIRE_LE(e.at, n);
            (e.kind == ev_t::kind_t::head ? heads : ends)++;
        }
    }
    REQUIRE_EQ(heads, 2u);
    REQUIRE_EQ(ends, 2u);
    REQUIRE(req.idle());

    parse::http_framer_t resp(true);
    resp.expect_response_to("HEAD");
    resp.expect_response_to("GET");
    resp.expect_response_to("GET");
    const std::string rs =
        "HTTP/1.1 100 Continue\r\n\r\n"
        "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n"           // HEAD: no body
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\n\r\n"
        "HTTP/1.1 200 OK\r\n\r\ntail-until-close";
    ev.clear();
    resp.feed(reinterpret_cast<const uint8_t*>(rs.data()), rs.size(), &ev);
    REQUIRE_EQ(resp.messages_completed(), 2u);
    REQUIRE(resp.until_close());
    size_t interim = 0;
    for (const auto& e : ev) interim += e.interim ? 1 : 0;
    REQUIRE_EQ(interim, 1u);
    ev.clear();
    resp.finish(&ev);
    REQUIRE_EQ(resp.messages_completed(), 3u);
    REQUIRE_EQ(ev.size(), 1u);

    parse::http_framer_t broken(true);
    const std::string conflict = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n";
    broken.feed(reinterpret_cast<const uint8_t*>(conflict.data()), conflict.size());
    REQUIRE(broken.broken());

    std::vector<uint8_t> out;
    const std::string ch = "4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nX-T: 1\r\n\r\n";
    REQUIRE(parse::decode_chunked(reinterpret_cast<const uint8_t*>(ch.data()), ch.size(), out));
    REQUIRE(std::string(out.begin(), out.end()) == "Wikipedia");
    REQUIRE_FALSE(parse::decode_chunked(reinterpret_cast<const uint8_t*>(ch.data()), ch.size() - 3, out));
    const std::string lie = "FFFF\r\nab\r\n0\r\n\r\n";
    REQUIRE_FALSE(parse::decode_chunked(reinterpret_cast<const uint8_t*>(lie.data()), lie.size(), out));
}

TEST_CASE(network_address_helpers) {
    for (const char* np : {"127.0.0.1", "10.1.2.3", "172.31.0.1", "192.168.1.1", "169.254.169.254",
                           "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "::1", "::",
                           "fe80::1", "fc00::1", "fd12::1", "ff02::1", "::ffff:127.0.0.1",
                           "64:ff9b::a00:1", "2002:c0a8:101::1"}) {
        const auto ip = parse::parse_ip(np);
        REQUIRE(ip.has_value());
        CHECK(parse::is_non_public(*ip));
    }
    for (const char* pub : {"8.8.8.8", "1.1.1.1", "172.32.0.1", "2001:4860:4860::8888",
                            "::ffff:8.8.8.8"}) {
        const auto ip = parse::parse_ip(pub);
        REQUIRE(ip.has_value());
        CHECK(!parse::is_non_public(*ip));
    }
    REQUIRE(!parse::parse_ip("1.2.3").has_value());
    REQUIRE(!parse::parse_ip("01.2.3.4x").has_value());
    REQUIRE(parse::parse_ip("[::1]").has_value());
    const auto ten = parse::parse_ip("10.9.8.7");
    REQUIRE(parse::host_pattern_match("10.0.0.0/8", "x", &*ten));
    REQUIRE(parse::host_pattern_match("*.example.com", "a.b.example.com", nullptr));
    REQUIRE_FALSE(parse::host_pattern_match("*.example.com", "example.com", nullptr));
    REQUIRE_FALSE(parse::host_pattern_match("*.example.com", "badexample.com", nullptr));
    REQUIRE(parse::host_pattern_match("LocalHost", "localhost", nullptr));
    REQUIRE(parse::valid_host("a-b.c_d.example"));
    REQUIRE_FALSE(parse::valid_host("..\\..\\x"));
    REQUIRE_FALSE(parse::valid_host("-bad.example"));
    REQUIRE_FALSE(parse::valid_host("a b"));
    REQUIRE(parse::base64_decode("dXNlcjpzM2NyZXQ=").value_or("") == "user:s3cret");
    REQUIRE(!parse::base64_decode("!!!").has_value());
    const uint8_t raw[] = {0xFF, 0x00, 0x10};
    REQUIRE(parse::base64_encode(raw, 3) == "/wAQ");
}

namespace {

// fills the transport checksum the way the sender's stack would for IPv6
void v6_checksum(const char* src, const char* dst, uint8_t proto, std::vector<uint8_t>& t,
                 size_t at) {
    t[at] = t[at + 1] = 0;
    uint64_t sum = 0;
    const auto s = addr_bytes(src), d = addr_bytes(dst);
    for (size_t i = 0; i < 16; i += 2) sum += be16v(s, i) + be16v(d, i);
    sum += (t.size() >> 16) + (t.size() & 0xFFFF) + proto;
    for (size_t i = 0; i + 1 < t.size(); i += 2) sum += be16v(t, i);
    if (t.size() & 1) sum += static_cast<uint32_t>(t.back()) << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    put16(t, at, static_cast<uint32_t>(~sum & 0xFFFF));
}

} // namespace

TEST_CASE(network_ipv6_transport_inference) {
    const char* a = "2001:db8::10";
    const char* b = "2001:db8::20";
    const auto pa = *parse::parse_ip(a), pb = *parse::parse_ip(b);
    auto udp = udp_dgram(5000, 3478, {1, 2, 3, 4, 5});
    v6_checksum(a, b, 17, udp, 6);
    REQUIRE_EQ(parse::infer_v6_transport(pa, pb, udp.data(), udp.size()), 17);
    auto tcp = tcp_seg(51000, 443, "tls-bytes");
    v6_checksum(a, b, 6, tcp, 16);
    REQUIRE_EQ(parse::infer_v6_transport(pa, pb, tcp.data(), tcp.size()), 6);
    std::vector<uint8_t> icmp = {128, 0, 0, 0, 0, 1, 0, 1, 'p', 'i', 'n', 'g'};
    v6_checksum(a, b, 58, icmp, 2);
    REQUIRE_EQ(parse::infer_v6_transport(pa, pb, icmp.data(), icmp.size()), 58);
    // offloaded (unset) TCP checksum still classifies by shape
    auto off = tcp_seg(51000, 443, "outbound");
    REQUIRE_EQ(parse::infer_v6_transport(pa, pb, off.data(), off.size()), 6);
    std::vector<uint8_t> frag = {17, 0, 0, 1, 0, 0, 0, 3, 9, 9, 9, 9, 9, 9, 9, 9};
    REQUIRE_EQ(parse::infer_v6_transport(pa, pb, frag.data(), frag.size()), 44);

    // the capture path stores it as an IPv6 packet with socket-reported addresses
    namespace cap = slop::core::network::capture;
    cap::testing::reset();
    cap::testing::set_local_addresses({a});
    cap::testing::inject_v6_transport(a, b, udp.data(), udp.size(), 10);
    cap::testing::inject_v6_transport(b, a, tcp.data(), tcp.size(), 11);
    cap::testing::inject_v6_transport(a, b, icmp.data(), icmp.size(), 12);
    traffic_store_t store;
    REQUIRE_EQ(cap::poll(store, 10), 2u);
    const auto items = store.packets(0, 10).items;
    REQUIRE_EQ(items[0].ip_version, 6);
    REQUIRE_EQ(items[0].protocol, 17u);
    REQUIRE_EQ(items[0].direction, 0u);
    REQUIRE_EQ(items[0].payload.size(), 5u);
    REQUIRE_EQ(items[1].protocol, 6u);
    REQUIRE_EQ(items[1].direction, 1u);
    REQUIRE_STR_EQ(items[1].remote_addr, b);
    REQUIRE_EQ(cap::stats().non_tcp_udp, 1u);
    cap::testing::reset();
}

// deterministic mutation fuzzing of every parser that sees hostile bytes

TEST_CASE(network_fuzz_parsers) {
    std::vector<std::vector<uint8_t>> seeds;
    seeds.push_back(ipv4("10.0.0.2", "1.2.3.4", 6, tcp_seg(1234, 80, "GET / HTTP/1.1\r\n\r\n")));
    seeds.push_back(ipv4("10.0.0.2", "8.8.8.8", 17, udp_dgram(5353, 53, dns_response("a.b", {{1, 2, 3, 4}}, {}))));
    seeds.push_back(ipv4("10.0.0.2", "1.2.3.4", 17, udp_dgram(1, 2, {1, 2, 3, 4, 5, 6, 7, 8}), 3, 0x2000));
    {
        std::vector<uint8_t> hbh = {6, 0, 1, 4, 0, 0, 0, 0};
        const auto seg = tcp_seg(1, 2, "x");
        hbh.insert(hbh.end(), seg.begin(), seg.end());
        seeds.push_back(ipv6("2001:db8::1", "2001:db8::2", 0, hbh));
        std::vector<uint8_t> fh = {17, 0, 0, 1, 0, 0, 0, 9, 1, 2, 3, 4, 5, 6, 7, 8};
        seeds.push_back(ipv6("2001:db8::1", "2001:db8::2", 44, fh));
    }
    const auto dns_seed = dns_response("cdn.example.net", {{9, 9, 9, 9}}, {addr_bytes("::1")});
    const auto hello_seed = client_hello("fuzz.example.org");
    const std::string http_seed =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
    const std::vector<uint8_t> http_bytes(http_seed.begin(), http_seed.end());
    const std::string req_seed = "GET /x HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc";
    const std::vector<uint8_t> req_bytes(req_seed.begin(), req_seed.end());

    rng_t rng(0x5EED5EEDull);
    parse::reassembler_t reasm;
    traffic_store_t::limits_t lim;
    lim.max_packets = 256;
    lim.max_streams = 16;
    lim.max_stream_bytes = 64 * 1024;
    lim.max_direction_bytes = 4096;
    traffic_store_t store(lim);
    for (int iter = 0; iter < 20000; ++iter) {
        // IP + L4 + reassembly + store
        const auto pkt = mutate(rng, seeds[rng.below(seeds.size())]);
        parse::ip_info_t ip;
        if (parse::parse_ip(pkt.data(), pkt.size(), ip) == parse::status_t::ok) {
            CHECK(ip.l4 >= pkt.data() && ip.l4 + ip.l4_len <= pkt.data() + pkt.size());
            CHECK(ip.l4_len <= ip.l4_wire_len || ip.fragment);
            if (ip.fragment) {
                if (auto dg = reasm.add(ip, iter)) {
                    uint8_t proto = dg->proto;
                    const uint8_t* p = dg->l4.data();
                    size_t n = dg->l4.size();
                    if (ip.src.family == 6) parse::skip_v6_ext(proto, p, n);
                    parse::l4_info_t l;
                    parse::parse_l4(proto, p, n, static_cast<uint32_t>(n), l);
                }
                CHECK(reasm.pending() <= 64);
                CHECK(reasm.bytes() <= (4u << 20));
            } else {
                parse::l4_info_t l;
                if (parse::parse_l4(ip.proto, ip.l4, ip.l4_len, ip.l4_wire_len, l) == parse::status_t::ok) {
                    CHECK(l.payload >= ip.l4 && l.payload + l.payload_len <= ip.l4 + ip.l4_len);
                    CHECK(l.payload_len <= l.payload_wire_len);
                    packet_record_t rec;
                    rec.protocol = ip.proto;
                    rec.direction = static_cast<uint32_t>(rng.below(2));
                    rec.local_addr = parse::to_string(ip.src);
                    rec.remote_addr = parse::to_string(ip.dst);
                    rec.local_port = l.src_port;
                    rec.remote_port = l.dst_port;
                    rec.payload.assign(l.payload, l.payload + l.payload_len);
                    store.add(std::move(rec));
                }
            }
        }
        // DNS
        const auto dns = mutate(rng, dns_seed);
        if (auto r = parse::parse_dns(dns.data(), dns.size())) {
            CHECK(printable_ascii(r->domain));
            CHECK(r->answers.size() <= 16);
        }
        // IPv6 transport-only datagrams (what Windows raw v6 sockets deliver)
        {
            static const auto v6a = *parse::parse_ip("2001:db8::1");
            static const auto v6b = *parse::parse_ip("2001:db8::2");
            const auto t = mutate(rng, tcp_seg(1, 2, "abc"));
            const uint8_t proto = parse::infer_v6_transport(v6a, v6b, t.data(), t.size());
            CHECK(proto == 0 || proto == 6 || proto == 17 || proto == 44 || proto == 58);
            namespace cap = slop::core::network::capture;
            cap::testing::inject_v6_transport("2001:db8::1", "2001:db8::2", t.data(), t.size(), iter);
        }
        // SNI
        const auto hello = mutate(rng, hello_seed);
        const std::string sni = parse::extract_sni(hello.data(), hello.size());
        CHECK(sni.empty() || parse::valid_host(sni));
        // HTTP framing in random chunking, plus chunked decoding
        const auto hb = mutate(rng, rng.below(2) ? http_bytes : req_bytes);
        parse::http_framer_t fr(rng.below(2) == 0);
        fr.expect_response_to("GET");
        std::vector<parse::http_framer_t::event_t> ev;
        for (size_t i = 0; i < hb.size();) {
            const size_t n = std::min(hb.size() - i, 1 + rng.below(19));
            ev.clear();
            fr.feed(hb.data() + i, n, &ev);
            for (const auto& e : ev) CHECK(e.at <= n);
            i += n;
        }
        fr.finish();
        std::vector<uint8_t> dec;
        if (hb.size() > 40) parse::decode_chunked(hb.data() + 40, hb.size() - 40, dec);
        parse::parse_http_head(std::string_view(reinterpret_cast<const char*>(hb.data()), hb.size()),
                               rng.below(2) == 0);
        // text parsers
        const std::string text(reinterpret_cast<const char*>(hello.data()),
                               std::min<size_t>(hello.size(), 40));
        parse::parse_cidr(text);
        parse::base64_decode(text);
        std::string ferr;
        traffic_store_t::compile_filter(text, &ferr);
    }
    const auto st = store.stats();
    CHECK(st.stream_bytes <= lim.max_stream_bytes);
    CHECK(st.streams <= lim.max_streams);
    slop::core::network::capture::testing::reset();
}

// capture pipeline through the socket-thread code path

TEST_CASE(network_capture_pipeline_console_filter) {
    namespace cap = slop::core::network::capture;
    cap::testing::reset();
    cap::testing::set_local_addresses({"192.168.137.1", "fe80::1"});
    capture_filter_t f;
    f.host = "192.168.137.50";                               // the console behind ICS
    REQUIRE(cap::testing::set_filter(f).empty());
    capture_filter_t bad;
    bad.host = "console.local";
    REQUIRE(!cap::testing::set_filter(bad).empty());
    bad.host.clear();
    bad.protocol = 1;
    REQUIRE(!cap::testing::set_filter(bad).empty());
    REQUIRE(cap::testing::set_filter(f).empty());

    auto inject = [](const std::vector<uint8_t>& p, int64_t t) { cap::testing::inject(p.data(), p.size(), t); };
    // console -> internet (routed through this PC): outbound, local = console
    inject(ipv4("192.168.137.50", "52.1.2.3", 6, tcp_seg(50000, 443, "client-hello")), 1000);
    // internet -> console: inbound
    inject(ipv4("52.1.2.3", "192.168.137.50", 6, tcp_seg(443, 50000, "server-hello")), 1001);
    // PC -> console (ps4debug): outbound from this host
    inject(ipv4("192.168.137.1", "192.168.137.50", 6, tcp_seg(60000, 744, "cmd")), 1002);
    // unrelated host: filtered out
    inject(ipv4("192.168.137.77", "8.8.8.8", 6, tcp_seg(1, 2, "noise")), 1003);
    // DNS answer to the console (A + AAAA)
    inject(ipv4("192.168.137.1", "192.168.137.50", 17,
                udp_dgram(53, 40000, dns_response("np.playstation.net", {{23, 1, 2, 3}},
                                                  {addr_bytes("2600::1")}))), 1004);
    // padded frame: the 0xEE padding must not become payload
    inject(ipv4("192.168.137.50", "52.1.2.3", 6, tcp_seg(50000, 443, "pad"), 8, 0x4000, 10), 1005);
    // fragmented UDP from the console, reassembled
    {
        const auto whole = udp_dgram(3658, 3658, std::vector<uint8_t>(24, 0x5A));
        const std::vector<uint8_t> a(whole.begin(), whole.begin() + 16), b(whole.begin() + 16, whole.end());
        inject(ipv4("192.168.137.50", "52.9.9.9", 17, b, 99, 2), 1006);
        inject(ipv4("192.168.137.50", "52.9.9.9", 17, a, 99, 0x2000), 1007);
    }
    // garbage and ICMP
    const std::vector<uint8_t> junk = {0x00, 0x01, 0x02};
    inject(junk, 1008);
    inject(ipv4("192.168.137.50", "52.1.2.3", 1, {8, 0, 0, 0}), 1009);

    traffic_store_t store;
    REQUIRE_EQ(cap::poll(store, 100), 6u);
    const auto page = store.packets(0, 100);
    REQUIRE_EQ(page.items.size(), 6u);
    const auto& p0 = page.items[0];
    REQUIRE_EQ(p0.direction, 0u);
    REQUIRE_STR_EQ(p0.local_addr, "192.168.137.50");
    REQUIRE_EQ(p0.remote_port, 443);
    REQUIRE_EQ(page.items[1].direction, 1u);
    REQUIRE_STR_EQ(page.items[1].local_addr, "192.168.137.50");
    REQUIRE_STR_EQ(page.items[2].local_addr, "192.168.137.1");
    REQUIRE_EQ(page.items[2].direction, 0u);
    REQUIRE(std::string(page.items[4].payload.begin(), page.items[4].payload.end()) == "pad");
    REQUIRE_EQ(page.items[5].protocol, 17u);
    REQUIRE_EQ(page.items[5].payload.size(), 24u);
    // the console stream pairs both directions
    bool paired = false;
    for (const auto& st : store.streams())
        if (st.server_port == 443 && st.packets >= 2 && st.client_addr == "192.168.137.50") paired = true;
    REQUIRE(paired);

    const auto dns = cap::dns_queries("192.168.137.50");
    REQUIRE_EQ(dns.size(), 1u);
    REQUIRE_STR_EQ(dns[0].domain, "np.playstation.net");
    REQUIRE_STR_EQ(dns[0].client_addr, "192.168.137.50");
    REQUIRE_EQ(dns[0].answers.size(), 2u);
    REQUIRE(cap::dns_queries("10.0.0.1").empty());

    const auto s = cap::stats();
    REQUIRE_EQ(s.packets_seen, 10u);
    REQUIRE_EQ(s.filtered_out, 1u);
    REQUIRE_EQ(s.parse_errors, 1u);
    REQUIRE_EQ(s.non_tcp_udp, 1u);
    REQUIRE_EQ(s.fragments, 2u);
    REQUIRE_EQ(s.fragments_reassembled, 1u);
    REQUIRE_EQ(s.packets_out, 5u);                          // console->net, PC->console, DNS, pad, frag
    REQUIRE_EQ(s.packets_in, 1u);
    REQUIRE_EQ(s.dns_logged_total, 1u);

    // newest-N export drains pending first
    inject(ipv4("192.168.137.50", "52.1.2.3", 6, tcp_seg(50000, 443, "late")), 2000);
    const std::string path = temp_path("tail.pcap");
    size_t exported = 0;
    bool older = false;
    REQUIRE(cap::export_pcap(store, path, 2, &exported, &older).empty());
    REQUIRE_EQ(exported, 2u);
    REQUIRE(older);
    const auto pcap = read_all(path);
    std::remove(path.c_str());
    const std::string tail(pcap.begin(), pcap.end());
    REQUIRE(tail.find("late") != std::string::npos);        // newest included
    REQUIRE(tail.find("client-hello") == std::string::npos); // oldest omitted

    // IPv6 traffic of a local host flows through as well
    cap::testing::reset();
    cap::testing::set_local_addresses({"fe80::1"});
    inject(ipv6("fe80::1", "2001:db8::8", 17, udp_dgram(5000, 5001, {1, 2, 3})), 3000);
    traffic_store_t s6;
    REQUIRE_EQ(cap::poll(s6, 10), 1u);
    REQUIRE_EQ(s6.packets(0, 10).items[0].ip_version, 6);
    REQUIRE_STR_EQ(s6.packets(0, 10).items[0].remote_addr, "2001:db8::8");
    cap::testing::reset();
}

// MCP surface: the pid fiction is gone, filters and egress fail loudly

TEST_CASE(network_mcp_tool_contracts) {
    namespace mcp = slop::core::mcp;
    using json = nlohmann::json;
    bool error = false;
    json r = mcp::call_tool("network", {{"action", "capture_start"}, {"pid", 4242}}, error);
    REQUIRE(error);
    REQUIRE(r.dump().find("pid filters are not supported") != std::string::npos);
    r = mcp::call_tool("network", {{"action", "capture_start"}, {"host", "console.local"}}, error);
    REQUIRE(error);
    r = mcp::call_tool("network", {{"action", "packets"}, {"filter", "pid:1"}}, error);
    REQUIRE(error);
    REQUIRE(r.dump().find("host:") != std::string::npos);
    r = mcp::call_tool("network", {{"action", "packets"}, {"filter", "port=80"}, {"tail", true}}, error);
    REQUIRE_FALSE(error);
    r = mcp::call_tool("network", {{"action", "stats"}}, error);
    REQUIRE_FALSE(error);
    REQUIRE(r.contains("packets_in"));
    REQUIRE(r.contains("active_streams_60s"));

    // web refuses loopback by default (web_allow_private unset)
    r = mcp::call_tool("web", {{"action", "fetch"}, {"url", "http://127.0.0.1:9/"}}, error);
    REQUIRE(error);
    REQUIRE(r.dump().find("blocked") != std::string::npos);

    // proxy: LAN bind needs a token or client allowlist; MITM needs consent
    r = mcp::call_tool("proxy", {{"action", "start"}, {"port", 0}, {"bind", "0.0.0.0"}}, error);
    REQUIRE(error);
    r = mcp::call_tool("proxy", {{"action", "mitm_enable"}}, error);
    REQUIRE(error);
    REQUIRE(r.dump().find("consent") != std::string::npos);
    r = mcp::call_tool("proxy", {{"action", "mitm_enable"}, {"consent", "yes"}}, error);
    REQUIRE(error);
}

// proxy over real loopback sockets

TEST_CASE(network_proxy_http_forward_log_replay) {
    origin_t origin;
    REQUIRE_GT(origin.port, 0);
    http_proxy_t proxy;
    proxy_options_t o;
    o.port = 0;
    std::string err;
    REQUIRE(proxy.start(o, &err));
    REQUIRE(proxy.running());
    REQUIRE_GT(proxy.port(), 0);
    const std::string op = std::to_string(origin.port);

    // absolute-form GET, keep-alive requested: the proxy still closes after one request
    std::string resp = exchange(proxy.port(), "GET http://127.0.0.1:" + op +
                                                  "/hi HTTP/1.1\r\nHost: 127.0.0.1:" + op +
                                                  "\r\nProxy-Connection: keep-alive\r\n\r\n");
    REQUIRE(resp.find("origin-body") != std::string::npos);
    // origin-form with Host (legacy transparent use) works too
    resp = exchange(proxy.port(), "GET /hi HTTP/1.1\r\nHost: 127.0.0.1:" + op + "\r\n\r\n");
    REQUIRE(resp.find("origin-body") != std::string::npos);
    // POST with a body, replayable verbatim
    resp = exchange(proxy.port(), "POST http://127.0.0.1:" + op +
                                      "/echo HTTP/1.1\r\nHost: 127.0.0.1:" + op +
                                      "\r\nContent-Type: text/plain\r\nContent-Length: 7\r\n\r\npayload");
    REQUIRE(resp.find("echo:payload") != std::string::npos);

    auto entries = proxy.recent(16);
    const proxy_entry_t* get = find_entry(entries, "http", "/hi");
    const proxy_entry_t* post = find_entry(entries, "http", "/echo");
    REQUIRE(get && post);
    REQUIRE_EQ(get->status, 200u);
    REQUIRE(get->replayable);
    REQUIRE(post->replayable);
    REQUIRE_EQ(post->method, std::string("POST"));
    const std::string raw(post->raw_request.begin(), post->raw_request.end());
    REQUIRE(raw.rfind("POST /echo HTTP/1.1\r\n", 0) == 0);
    REQUIRE(raw.find("Connection: close") != std::string::npos);
    REQUIRE(raw.find("Proxy-Connection") == std::string::npos);
    REQUIRE(raw.find("\r\n\r\npayload") != std::string::npos);

    auto r = proxy.replay(get->id, &err);
    REQUIRE(r.has_value());
    REQUIRE(r->complete);
    REQUIRE_FALSE(r->truncated);
    REQUIRE_EQ(r->status, 200u);
    REQUIRE(std::string(r->bytes.begin(), r->bytes.end()).find("origin-body") != std::string::npos);
    auto rp = proxy.replay(post->id, &err);
    REQUIRE(rp.has_value());
    REQUIRE(std::string(rp->bytes.begin(), rp->bytes.end()).find("echo:payload") != std::string::npos);
    REQUIRE(!proxy.replay(999999, &err).has_value());

    // unreachable upstream is logged with a 502
    resp = exchange(proxy.port(), "GET http://127.0.0.1:1/x HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n");
    REQUIRE(resp.find(" 502 ") != std::string::npos);
    // a request aimed back at the proxy is refused instead of looping
    resp = exchange(proxy.port(), "GET http://127.0.0.1:" + std::to_string(proxy.port()) +
                                      "/ HTTP/1.1\r\nHost: x\r\n\r\n");
    REQUIRE(resp.find(" 508 ") != std::string::npos);
    // starting twice is an error, stop/start works
    REQUIRE_FALSE(proxy.start(o, &err));
    proxy.stop();
    REQUIRE_FALSE(proxy.running());
    REQUIRE(proxy.start(o, &err));
    proxy.stop();
}

TEST_CASE(network_proxy_access_control) {
    origin_t origin;
    const std::string op = std::to_string(origin.port);
    const std::string get = "GET http://127.0.0.1:" + op + "/hi HTTP/1.1\r\nHost: 127.0.0.1:" + op;

    http_proxy_t proxy;
    proxy_options_t o;
    o.port = 0;
    o.token = "s3cret";
    o.allow_hosts = {"127.0.0.1"};
    std::string err;
    REQUIRE(proxy.start(o, &err));

    std::string resp = exchange(proxy.port(), get + "\r\n\r\n");
    REQUIRE(resp.find(" 407 ") != std::string::npos);
    REQUIRE(resp.find("Proxy-Authenticate") != std::string::npos);
    resp = exchange(proxy.port(), get + "\r\nProxy-Authorization: Bearer wrong\r\n\r\n");
    REQUIRE(resp.find(" 407 ") != std::string::npos);
    resp = exchange(proxy.port(), get + "\r\nProxy-Authorization: Bearer s3cret\r\n\r\n");
    REQUIRE(resp.find("origin-body") != std::string::npos);
    // Basic with the token as password ("user:s3cret")
    resp = exchange(proxy.port(), get + "\r\nProxy-Authorization: Basic dXNlcjpzM2NyZXQ=\r\n\r\n");
    REQUIRE(resp.find("origin-body") != std::string::npos);
    // the credential never reaches the origin / the log
    for (const auto& e : proxy.recent(32)) {
        const std::string raw(e.raw_request.begin(), e.raw_request.end());
        REQUIRE(raw.find("s3cret") == std::string::npos);
        REQUIRE(raw.find("Proxy-Authorization") == std::string::npos);
    }
    // destinations outside the allowlist are refused (http and CONNECT)
    resp = exchange(proxy.port(), "GET http://localhost:" + op +
                                      "/hi HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: Bearer s3cret\r\n\r\n");
    REQUIRE(resp.find(" 200 ") != std::string::npos);       // localhost resolves to the allowed IP
    resp = exchange(proxy.port(), "CONNECT 10.255.255.1:443 HTTP/1.1\r\nProxy-Authorization: Bearer s3cret\r\n\r\n");
    REQUIRE(resp.find(" 403 ") != std::string::npos);
    const auto st = proxy.stats();
    REQUIRE_GE(st.rejected_auth, 2u);
    REQUIRE_GE(st.rejected_host, 1u);
    proxy.stop();

    // client allowlist and the LAN-bind guard
    proxy_options_t lan;
    lan.port = 0;
    lan.bind = "0.0.0.0";
    REQUIRE_FALSE(proxy.start(lan, &err));
    REQUIRE(err.find("allow_clients") != std::string::npos);
    proxy_options_t only;
    only.port = 0;
    only.allow_clients = {"10.0.0.0/8"};                    // loopback client not allowed
    REQUIRE(proxy.start(only, &err));
    resp = exchange(proxy.port(), get + "\r\n\r\n");
    REQUIRE(resp.empty());
    REQUIRE_GE(proxy.stats().rejected_client, 1u);
    proxy.stop();
    proxy_options_t bad;
    bad.allow_hosts = {"bad host!"};
    REQUIRE_FALSE(proxy.start(bad, &err));
}

TEST_CASE(network_proxy_caps_timeouts_and_stop) {
    origin_t origin;
    http_proxy_t proxy;
    proxy_options_t o;
    o.port = 0;
    o.max_connections = 2;
    o.header_timeout_ms = 400;
    std::string err;
    REQUIRE(proxy.start(o, &err));

    // slowloris: an unfinished head is dropped after header_timeout_ms
    SOCKET slow = dial(proxy.port());
    REQUIRE(slow != INVALID_SOCKET);
    send_str(slow, "GET http://127.0.0.1/ HTTP/1.1\r\nHost: x\r\n");
    const auto t0 = std::chrono::steady_clock::now();
    char c;
    const int r = ::recv(slow, &c, 1, 0);
    const auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - t0).count();
    REQUIRE(r <= 0);
    REQUIRE_LT(waited, 3000);
    ::closesocket(slow);

    // two open blind tunnels fill the cap; the third connection gets a 503
    const std::string connect = "CONNECT 127.0.0.1:" + std::to_string(origin.port) + " HTTP/1.1\r\n\r\n";
    SOCKET t1 = dial(proxy.port()), t2 = dial(proxy.port());
    REQUIRE(t1 != INVALID_SOCKET && t2 != INVALID_SOCKET);
    send_str(t1, connect);
    send_str(t2, connect);
    REQUIRE(recv_head(t1).find(" 200 ") != std::string::npos);
    REQUIRE(recv_head(t2).find(" 200 ") != std::string::npos);
    // traffic flows through a blind tunnel
    send_str(t1, "GET /hi HTTP/1.1\r\nHost: x\r\n\r\n");
    char buf[512];
    std::string got;
    while (got.find("origin-body") == std::string::npos) {
        const int n = ::recv(t1, buf, sizeof(buf), 0);
        if (n <= 0) break;
        got.append(buf, static_cast<size_t>(n));
    }
    REQUIRE(got.find("origin-body") != std::string::npos);
    const std::string third = exchange(proxy.port(), connect);
    REQUIRE(third.find(" 503 ") != std::string::npos);
    REQUIRE_GE(proxy.stats().rejected_capacity, 1u);

    // stop() unblocks and joins the live tunnel threads promptly
    const auto s0 = std::chrono::steady_clock::now();
    proxy.stop();
    const auto stop_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - s0).count();
    REQUIRE_LT(stop_ms, 3000);
    REQUIRE_EQ(proxy.stats().active_connections, 0u);
    ::closesocket(t1);
    ::closesocket(t2);
    const auto entries = proxy.recent(16);
    const proxy_entry_t* tunnel = nullptr;
    for (const auto& e : entries)
        if (e.kind == "connect" && e.req_bytes > 0) tunnel = &e;
    REQUIRE(tunnel != nullptr);
    REQUIRE_GT(tunnel->resp_bytes, 0u);
}

TEST_CASE(network_proxy_log_is_bounded) {
    origin_t origin;
    http_proxy_t proxy;
    proxy_options_t o;
    o.port = 0;
    std::string err;
    REQUIRE(proxy.start(o, &err));
    const std::string op = std::to_string(origin.port);
    // a 100 KiB body: forwarded fully, logged capped and marked not replayable
    const std::string big(100 * 1024, 'b');
    const std::string resp = exchange(proxy.port(), "POST http://127.0.0.1:" + op +
                                                        "/echo HTTP/1.1\r\nHost: x\r\nContent-Length: " +
                                                        std::to_string(big.size()) + "\r\n\r\n" + big);
    REQUIRE(resp.find("echo:bbbb") != std::string::npos);
    const auto entries = proxy.recent(4);
    const proxy_entry_t* e = find_entry(entries, "http", "/echo");
    REQUIRE(e != nullptr);
    REQUIRE(e->request_truncated);
    REQUIRE_FALSE(e->replayable);
    REQUIRE_LE(e->raw_request.size(), 16u * 1024 + 64u * 1024);
    REQUIRE_GE(e->req_bytes, big.size());
    REQUIRE(!proxy.replay(e->id, &err).has_value());
    REQUIRE(err.find("not captured completely") != std::string::npos);
    REQUIRE_LE(proxy.stats().log_bytes, 16u << 20);
    proxy.stop();
}

// TLS interception end to end: client -> proxy (leaf from the proxy CA) ->
// origin (leaf from an origin CA). Trust uses exclusive in-memory root stores;
// the CNG keys are uniquely named and deleted by destroy()

namespace {

struct tls_origin_t {
    SOCKET l = INVALID_SOCKET;
    uint16_t port = 0;
    std::atomic<bool> quit{false};
    std::thread th;
    std::shared_ptr<tls::server_cred_t> cred;
    std::atomic<int> served{0};

    bool start(std::shared_ptr<tls::server_cred_t> c) {
        cred = std::move(c);
        l = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::bind(l, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 || ::listen(l, 8) != 0) return false;
        int len = sizeof(a);
        ::getsockname(l, reinterpret_cast<sockaddr*>(&a), &len);
        port = ntohs(a.sin_port);
        th = std::thread([this] { run(); });
        return true;
    }
    void run() {
        while (!quit.load()) {
            WSAPOLLFD fd{l, POLLRDNORM, 0};
            if (::WSAPoll(&fd, 1, 100) <= 0) continue;
            SOCKET c = ::accept(l, nullptr, nullptr);
            if (c == INVALID_SOCKET) continue;
            std::string err;
            auto s = tls::stream_t::accept(static_cast<tls::socket_t>(c), *cred, 5000, &err);
            if (s) {
                std::string in;
                uint8_t buf[4096];
                for (;;) {
                    const size_t he = in.find("\r\n\r\n");
                    if (he != std::string::npos) {
                        in.erase(0, he + 4);
                        const std::string body = "secret-body";
                        const std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: " +
                                                 std::to_string(body.size()) + "\r\n\r\n" + body;
                        s->write(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
                        ++served;
                        continue;
                    }
                    const int n = s->read(buf, sizeof(buf));
                    if (n <= 0) break;
                    in.append(reinterpret_cast<char*>(buf), static_cast<size_t>(n));
                }
            }
            ::closesocket(c);
        }
    }
    ~tls_origin_t() {
        quit.store(true);
        if (th.joinable()) th.join();
        if (l != INVALID_SOCKET) ::closesocket(l);
    }
};

struct mem_store_t {
    HCERTSTORE h = ::CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
    ~mem_store_t() { ::CertCloseStore(h, 0); }
    void add(const std::vector<uint8_t>& der) {
        ::CertAddEncodedCertificateToStore(h, X509_ASN_ENCODING, der.data(),
                                           static_cast<DWORD>(der.size()),
                                           CERT_STORE_ADD_REPLACE_EXISTING, nullptr);
    }
};

std::wstring test_prefix(const wchar_t* tag) {
    return L"reverse-slop-test-" + std::to_wstring(::GetCurrentProcessId()) + L"-" + tag;
}

} // namespace

TEST_CASE(network_proxy_mitm_intercepts_https) {
    sock::ensure_wsa();
    mem_store_t origin_trust, client_trust, untrusted, origin_roots, proxy_roots;
    mitm::pki_options_t oo;
    oo.key_prefix = test_prefix(L"origin");
    oo.trust_store = origin_roots.h;
    mitm::pki_options_t po;
    po.key_prefix = test_prefix(L"proxy");
    po.trust_store = proxy_roots.h;
    auto origin_pki = std::make_shared<mitm::pki_t>(oo);
    auto proxy_pki = std::make_shared<mitm::pki_t>(po);
    struct cleanup_t {
        std::shared_ptr<mitm::pki_t> a, b;
        ~cleanup_t() { a->destroy(); b->destroy(); }
    } cleanup{origin_pki, proxy_pki};

    std::string err;
    REQUIRE(origin_pki->ensure_ca(&err));
    REQUIRE(proxy_pki->ensure_ca(&err));
    origin_trust.add(origin_pki->ca_der());
    client_trust.add(proxy_pki->ca_der());

    auto origin_leaf = origin_pki->leaf_for("127.0.0.1", &err);
    REQUIRE(origin_leaf != nullptr);
    auto origin_cred = tls::server_cred_t::create(origin_leaf.get(), &err);
    if (!origin_cred) std::printf("  [mitm] server cred: %s\n", err.c_str());
    REQUIRE(origin_cred != nullptr);
    tls_origin_t origin;
    REQUIRE(origin.start(origin_cred));

    http_proxy_t proxy;
    proxy_options_t o;
    o.port = 0;
    o.upstream_roots = origin_trust.h;
    REQUIRE(proxy.start(o, &err));
    proxy.set_mitm(proxy_pki);
    REQUIRE(proxy.mitm_enabled());

    auto tunnel = [&](void* roots, std::string* out_err) -> std::string {
        SOCKET c = dial(proxy.port());
        if (c == INVALID_SOCKET) return "dial failed";
        send_str(c, "CONNECT 127.0.0.1:" + std::to_string(origin.port) + " HTTP/1.1\r\n\r\n");
        const std::string head = recv_head(c);
        std::string body;
        if (head.find(" 200 ") != std::string::npos) {
            tls::client_options_t copt;
            copt.exclusive_roots = roots;
            auto t = tls::stream_t::connect(static_cast<tls::socket_t>(c), "127.0.0.1", copt, 5000, out_err);
            if (t) {
                const std::string req = "GET /secret HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
                t->write(reinterpret_cast<const uint8_t*>(req.data()), req.size());
                uint8_t buf[4096];
                int n;
                while ((n = t->read(buf, sizeof(buf))) > 0) {
                    body.append(reinterpret_cast<char*>(buf), static_cast<size_t>(n));
                    if (body.find("secret-body") != std::string::npos) break;
                }
                t->close_notify();
            }
        }
        ::closesocket(c);
        return body;
    };

    std::string cerr;
    const std::string body = tunnel(client_trust.h, &cerr);
    if (body.empty()) std::printf("  [mitm] client: %s\n", cerr.c_str());
    REQUIRE(body.find("secret-body") != std::string::npos);

    // the decrypted request is logged and replayable over TLS
    const proxy_entry_t* https = nullptr;
    std::vector<proxy_entry_t> entries;
    for (int i = 0; i < 50 && !https; ++i) {
        entries = proxy.recent(32);
        https = find_entry(entries, "https", "/secret");
        if (!https || https->status == 0) {
            https = nullptr;
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }
    REQUIRE(https != nullptr);
    REQUIRE_EQ(https->status, 200u);
    REQUIRE(https->intercepted);
    REQUIRE(https->replayable);
    REQUIRE_STR_EQ(https->host, "127.0.0.1");
    REQUIRE_GT(https->tunnel_id, 0u);
    auto r = proxy.replay(https->id, &err);
    REQUIRE(r.has_value());
    REQUIRE(r->complete);
    REQUIRE_EQ(r->status, 200u);
    REQUIRE(std::string(r->bytes.begin(), r->bytes.end()).find("secret-body") != std::string::npos);

    // a client that does not trust the proxy CA rejects the interception cert
    // and never sends its request (nothing new is logged as https)
    size_t https_before = 0;
    for (const auto& e : proxy.recent(64)) https_before += e.kind == "https" ? 1 : 0;
    std::string uerr;
    REQUIRE(tunnel(untrusted.h, &uerr).empty());
    REQUIRE(uerr.find("certificate") != std::string::npos);
    size_t https_after = 0;
    for (const auto& e : proxy.recent(64)) https_after += e.kind == "https" ? 1 : 0;
    REQUIRE_EQ(https_after, https_before);

    // a client whose handshake the proxy cannot complete is logged with the reason
    {
        SOCKET c = dial(proxy.port());
        REQUIRE(c != INVALID_SOCKET);
        send_str(c, "CONNECT 127.0.0.1:" + std::to_string(origin.port) + " HTTP/1.1\r\n\r\n");
        REQUIRE(recv_head(c).find(" 200 ") != std::string::npos);
        const auto bogus = client_hello("bogus.example");    // TLS 1.3-only suite, no extensions
        ::send(c, reinterpret_cast<const char*>(bogus.data()), static_cast<int>(bogus.size()), 0);
        recv_all(c);
        ::closesocket(c);
    }
    bool logged = false;
    for (int i = 0; i < 100 && !logged; ++i) {
        for (const auto& e : proxy.recent(32))
            if (e.kind == "connect" && e.sni == "bogus.example" &&
                e.error.find("client TLS handshake failed") != std::string::npos)
                logged = true;
        if (!logged) std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    REQUIRE(logged);

    // interception off: tunnels are blind again
    proxy.set_mitm(nullptr);
    REQUIRE_FALSE(proxy.mitm_enabled());
    proxy.stop();
}

// redaction, pcap import/export, QUIC

TEST_CASE(network_redact_secrets_helpers) {
    using namespace slop::core::network::redact;
    const std::string head =
        "GET /x?token=abc&ok=1 HTTP/1.1\r\n"
        "Host: h\r\n"
        "Authorization: Bearer s3cret\r\n"
        "Cookie: sid=s3cret\r\n"
        "Accept: */*\r\n"
        "\r\n"
        "body Authorization: Bearer s3cret";
    const std::string masked = http_head(head);
    // the head carries no secret; the body keeps its bytes verbatim
    const size_t blank = masked.find("\r\n\r\n");
    REQUIRE(blank != std::string::npos);
    REQUIRE(masked.substr(0, blank).find("s3cret") == std::string::npos);
    REQUIRE(masked.find("Authorization: <redacted>") != std::string::npos);
    REQUIRE(masked.find("Cookie: <redacted>") != std::string::npos);
    REQUIRE(masked.find("token=<redacted>") != std::string::npos);
    REQUIRE(masked.find("ok=1") != std::string::npos);
    REQUIRE(masked.find("Accept: */*") != std::string::npos);
    // the body is never rewritten
    REQUIRE(masked.find("body Authorization: Bearer s3cret") != std::string::npos);

    const std::string stripped = strip_secrets(head);
    const size_t sblank = stripped.find("\r\n\r\n");
    REQUIRE(sblank != std::string::npos);
    const std::string shead = stripped.substr(0, sblank);
    REQUIRE(shead.find("Authorization") == std::string::npos);
    REQUIRE(shead.find("Cookie") == std::string::npos);
    REQUIRE(shead.find("token") == std::string::npos);
    REQUIRE(shead.find("GET /x?ok=1 HTTP/1.1") != std::string::npos);
    REQUIRE(stripped.find("body Authorization: Bearer s3cret") != std::string::npos);

    // a head without secrets is unchanged, and a response line is not a target
    const std::string plain = "GET /a HTTP/1.1\r\nHost: h\r\n\r\n";
    REQUIRE_STR_EQ(http_head(plain), plain);
    REQUIRE_STR_EQ(strip_secrets(plain), plain);
    REQUIRE_STR_EQ(http_head("HTTP/1.1 200 OK\r\nSet-Cookie: a=b\r\n\r\n"),
                   std::string("HTTP/1.1 200 OK\r\nSet-Cookie: <redacted>\r\n\r\n"));
    REQUIRE_STR_EQ(query("/p?key=1&x=2"), std::string("/p?key=<redacted>&x=2"));
    REQUIRE_STR_EQ(query("/p"), std::string("/p"));
}

TEST_CASE(network_proxy_redacts_and_replays_without_secrets) {
    origin_t origin;
    const std::string op = std::to_string(origin.port);
    http_proxy_t proxy;
    proxy_options_t o;
    o.port = 0;
    std::string err;
    REQUIRE(proxy.start(o, &err));
    REQUIRE(o.redact_secrets);

    const std::string req = "GET http://127.0.0.1:" + op +
                            "/auth?token=abc HTTP/1.1\r\nHost: 127.0.0.1:" + op +
                            "\r\nAuthorization: Bearer s3cret\r\nCookie: sid=s3cret\r\n\r\n";
    const std::string resp = exchange(proxy.port(), req);
    REQUIRE(resp.find(" 200 ") != std::string::npos);

    auto entries = proxy.recent(8);
    REQUIRE_EQ(entries.size(), 1u);
    const proxy_entry_t& e = entries.back();
    REQUIRE(e.redacted);
    REQUIRE(e.replayable);
    const std::string stored(e.raw_request.begin(), e.raw_request.end());
    REQUIRE(stored.find("s3cret") == std::string::npos);
    REQUIRE(stored.find("Authorization: <redacted>") != std::string::npos);
    REQUIRE(stored.find("token=<redacted>") != std::string::npos);
    REQUIRE(e.path.find("token=<redacted>") != std::string::npos);
    const std::string rhead(e.response_head.begin(), e.response_head.end());
    REQUIRE(rhead.find("set-cookie-secret") == std::string::npos);
    REQUIRE(rhead.find("Set-Cookie: <redacted>") != std::string::npos);

    // the unmasked copy is memory only and reachable by id
    const auto raw = proxy.raw_request(e.id);
    REQUIRE(std::string(raw.begin(), raw.end()).find("Bearer s3cret") != std::string::npos);

    // default replay strips the secret headers and query params
    auto r = proxy.replay(e.id, &err);
    REQUIRE(r.has_value());
    const std::string text(r->bytes.begin(), r->bytes.end());
    REQUIRE(text.find("auth:") != std::string::npos);
    REQUIRE(text.find("s3cret") == std::string::npos);
    REQUIRE(text.find("target:/auth") != std::string::npos);

    // with_secrets re-sends the captured request verbatim
    auto rs = proxy.replay(e.id, &err, 15000, true);
    REQUIRE(rs.has_value());
    const std::string stext(rs->bytes.begin(), rs->bytes.end());
    REQUIRE(stext.find("auth:Bearer s3cret") != std::string::npos);
    REQUIRE(stext.find("target:/auth?token=abc") != std::string::npos);

    // redaction off keeps the legacy behaviour: the request is stored verbatim
    proxy.stop();
    proxy_options_t plain_o;
    plain_o.port = 0;
    plain_o.redact_secrets = false;
    REQUIRE(proxy.start(plain_o, &err));
    exchange(proxy.port(), req);
    auto plain_entries = proxy.recent(8);
    REQUIRE_EQ(plain_entries.size(), 2u);
    REQUIRE_FALSE(plain_entries.back().redacted);
    const std::string praw(plain_entries.back().raw_request.begin(),
                           plain_entries.back().raw_request.end());
    REQUIRE(praw.find("Bearer s3cret") != std::string::npos);
    proxy.stop();
}

namespace {

void put_le32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(static_cast<uint8_t>(x & 0xFF));
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
    v.push_back(static_cast<uint8_t>((x >> 16) & 0xFF));
    v.push_back(static_cast<uint8_t>((x >> 24) & 0xFF));
}

void put_be32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(static_cast<uint8_t>(x >> 24));
    v.push_back(static_cast<uint8_t>((x >> 16) & 0xFF));
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
    v.push_back(static_cast<uint8_t>(x & 0xFF));
}

// classic pcap with one Ethernet-framed IPv4/TCP record
std::vector<uint8_t> classic_pcap(bool big_endian, bool nano) {
    std::vector<uint8_t> f;
    const uint32_t magic = nano ? 0xa1b23c4du : 0xa1b2c3d4u;
    if (big_endian) put_be32(f, magic); else put_le32(f, magic);
    // version 2.4 as one u32, then thiszone, sigfigs, snaplen, linktype
    if (big_endian) put_be32(f, 0x00040002u); else put_le32(f, 0x00040002u);
    if (big_endian) { put_be32(f, 0); put_be32(f, 0); } else { put_le32(f, 0); put_le32(f, 0); }
    if (big_endian) put_be32(f, 65535); else put_le32(f, 65535);
    if (big_endian) put_be32(f, 1); else put_le32(f, 1);          // LINKTYPE_ETHERNET

    std::vector<uint8_t> frame = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,   // dst
                                  0x11, 0x22, 0x33, 0x44, 0x55, 0x66,   // src
                                  0x08, 0x00};                          // IPv4
    const auto ip = ipv4("10.0.0.2", "1.2.3.4", 6, tcp_seg(1234, 80, "GET / HTTP/1.1\r\n\r\n"));
    frame.insert(frame.end(), ip.begin(), ip.end());

    if (big_endian) { put_be32(f, 1700000000); put_be32(f, 500000); }
    else { put_le32(f, 1700000000); put_le32(f, 500000); }
    if (big_endian) { put_be32(f, static_cast<uint32_t>(frame.size())); put_be32(f, static_cast<uint32_t>(frame.size())); }
    else { put_le32(f, static_cast<uint32_t>(frame.size())); put_le32(f, static_cast<uint32_t>(frame.size())); }
    f.insert(f.end(), frame.begin(), frame.end());
    return f;
}

} // namespace

TEST_CASE(network_pcap_import_roundtrip) {
    // export -> import keeps addresses, ports, protocol and payload
    traffic_store_t src;
    src.add(mk_packet(1234, 80, "10.0.0.2", "1.2.3.4", 0, "hello-http"));
    auto udp = mk_packet(5353, 53, "fe80::1", "2001:db8::53", 0, "dnsq");
    udp.protocol = 17;
    udp.ip_version = 6;
    src.add(udp);

    const std::string path = temp_path("roundtrip.pcap");
    std::string err;
    REQUIRE(src.write_pcap(path, src.packets(0, 10).items, &err));
    traffic_store_t dst;
    slop::core::network::pcap::import_result_t r;
    REQUIRE_STR_EQ(slop::core::network::pcap::import_file(dst, path, &r), std::string{});
    REQUIRE_STR_EQ(r.format, std::string("pcap"));
    REQUIRE_EQ(r.packets, 2u);
    REQUIRE_EQ(r.skipped, 0u);
    const auto page = dst.packets(0, 10);
    REQUIRE_EQ(page.items.size(), 2u);
    REQUIRE_STR_EQ(page.items[0].local_addr, "10.0.0.2");
    REQUIRE_STR_EQ(page.items[0].remote_addr, "1.2.3.4");
    REQUIRE_EQ(page.items[0].local_port, 1234);
    REQUIRE_EQ(page.items[0].remote_port, 80);
    REQUIRE_EQ(page.items[0].protocol, 6u);
    REQUIRE_STR_EQ(std::string(page.items[0].payload.begin(), page.items[0].payload.end()),
                   "hello-http");
    REQUIRE_STR_EQ(page.items[1].local_addr, "fe80::1");
    REQUIRE_EQ(page.items[1].ip_version, 6);
    REQUIRE_EQ(page.items[1].protocol, 17u);
    // streams and stats work on imported captures
    REQUIRE_EQ(dst.streams().size(), 2u);
    REQUIRE_EQ(dst.stats().packets, 2u);

    // pcapng with a stream annotation becomes an epb_comment and survives import
    const auto streams = dst.streams();
    REQUIRE(dst.annotate_stream(streams.front().id, "login flow"));
    const std::string ng = temp_path("roundtrip.pcapng");
    REQUIRE(dst.write_pcapng(ng, page.items, &err));
    const auto bytes = read_all(ng);
    REQUIRE_GE(bytes.size(), 28u);
    REQUIRE_EQ(le32(bytes, 0), 0x0A0D0D0Au);
    REQUIRE(std::string(bytes.begin(), bytes.end()).find("login flow") != std::string::npos);
    traffic_store_t dst2;
    slop::core::network::pcap::import_result_t r2;
    REQUIRE_STR_EQ(slop::core::network::pcap::import_file(dst2, ng, &r2), std::string{});
    REQUIRE_STR_EQ(r2.format, std::string("pcapng"));
    REQUIRE_EQ(r2.packets, 2u);
    const auto page2 = dst2.packets(0, 10);
    REQUIRE_EQ(page2.items.size(), 2u);
    REQUIRE_STR_EQ(page2.items[0].local_addr, "10.0.0.2");
    REQUIRE_STR_EQ(std::string(page2.items[0].payload.begin(), page2.items[0].payload.end()),
                   "hello-http");

    // both classic byte orders and nanosecond timestamps import
    for (int variant = 0; variant < 4; ++variant) {
        const std::string p = temp_path("variant.pcap");
        const auto file = classic_pcap(variant >= 2, (variant & 1) != 0);
        std::FILE* fp = nullptr;
        REQUIRE(fopen_s(&fp, p.c_str(), "wb") == 0);
        REQUIRE(fp != nullptr);
        std::fwrite(file.data(), 1, file.size(), fp);
        std::fclose(fp);
        traffic_store_t v;
        slop::core::network::pcap::import_result_t vr;
        REQUIRE_STR_EQ(slop::core::network::pcap::import_file(v, p, &vr), std::string{});
        REQUIRE_EQ(vr.packets, 1u);
        REQUIRE_EQ(v.size(), 1u);
        const auto vp = v.packets(0, 1);
        REQUIRE_STR_EQ(vp.items[0].local_addr, "10.0.0.2");
        REQUIRE_EQ(vp.items[0].local_port, 1234);
        std::remove(p.c_str());
    }
    std::remove(path.c_str());
    std::remove(ng.c_str());
}

TEST_CASE(network_pcap_import_rejects_malformed) {
    namespace pcap = slop::core::network::pcap;
    traffic_store_t store;
    auto write = [](const char* name, const std::vector<uint8_t>& bytes) {
        const std::string p = temp_path(name);
        std::FILE* fp = nullptr;
        if (fopen_s(&fp, p.c_str(), "wb") != 0 || !fp) return std::string{};
        std::fwrite(bytes.data(), 1, bytes.size(), fp);
        std::fclose(fp);
        return p;
    };

    // empty file
    std::string p = write("empty.pcap", {});
    REQUIRE(pcap::import_file(store, p).find("empty") != std::string::npos);
    std::remove(p.c_str());

    // bad magic
    p = write("magic.pcap", {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                             16, 17, 18, 19, 20, 21, 22, 23});
    REQUIRE(pcap::import_file(store, p).find("bad magic") != std::string::npos);
    std::remove(p.c_str());

    // truncated global header
    p = write("short.pcap", {0xd4, 0xc3, 0xb2, 0xa1, 0, 0, 0, 0, 0, 0});
    REQUIRE(pcap::import_file(store, p).find("truncated global header") != std::string::npos);
    std::remove(p.c_str());

    // unsupported link type
    {
        std::vector<uint8_t> f;
        put_le32(f, 0xa1b2c3d4u);
        put_le32(f, 0x00040002u); put_le32(f, 0); put_le32(f, 0);
        put_le32(f, 65535); put_le32(f, 105);
        p = write("link.pcap", f);
        REQUIRE(pcap::import_file(store, p).find("unsupported link type") != std::string::npos);
        std::remove(p.c_str());
    }

    // a record claiming more bytes than the cap
    {
        std::vector<uint8_t> f;
        put_le32(f, 0xa1b2c3d4u);
        put_le32(f, 0x00040002u); put_le32(f, 0); put_le32(f, 0);
        put_le32(f, 65535); put_le32(f, 101);
        put_le32(f, 1); put_le32(f, 0); put_le32(f, 0x7FFFFFFFu); put_le32(f, 0x7FFFFFFFu);
        p = write("huge.pcap", f);
        REQUIRE(pcap::import_file(store, p).find("exceeds the cap") != std::string::npos);
        std::remove(p.c_str());
    }

    // a record whose data is cut short
    {
        std::vector<uint8_t> f;
        put_le32(f, 0xa1b2c3d4u);
        put_le32(f, 0x00040002u); put_le32(f, 0); put_le32(f, 0);
        put_le32(f, 65535); put_le32(f, 101);
        put_le32(f, 1); put_le32(f, 0); put_le32(f, 100); put_le32(f, 100);
        f.insert(f.end(), 10, 0x45);
        p = write("cut.pcap", f);
        REQUIRE(pcap::import_file(store, p).find("truncated record") != std::string::npos);
        std::remove(p.c_str());
    }

    // pcapng: truncated section header, block length mismatch, unknown interface
    {
        std::vector<uint8_t> f = {0x0a, 0x0d, 0x0d, 0x0a, 0x1c, 0x00, 0x00, 0x00};
        p = write("shb.pcapng", f);
        REQUIRE(pcap::import_file(store, p).find("truncated section header") != std::string::npos);
        std::remove(p.c_str());
    }
    {
        std::vector<uint8_t> f;
        put_le32(f, 0x0A0D0D0Au); put_le32(f, 28); put_le32(f, 0x1A2B3C4Du);
        f.push_back(1); f.push_back(0); f.push_back(0); f.push_back(0);
        put_le32(f, 0xFFFFFFFFu); put_le32(f, 0xFFFFFFFFu);
        put_le32(f, 32);                                    // does not match the leading length
        p = write("mismatch.pcapng", f);
        REQUIRE(pcap::import_file(store, p).find("block length mismatch") != std::string::npos);
        std::remove(p.c_str());
    }
    {
        // SHB + IDB + EPB for interface 7
        std::vector<uint8_t> f;
        put_le32(f, 0x0A0D0D0Au); put_le32(f, 28); put_le32(f, 0x1A2B3C4Du);
        f.push_back(1); f.push_back(0); f.push_back(0); f.push_back(0);
        put_le32(f, 0xFFFFFFFFu); put_le32(f, 0xFFFFFFFFu); put_le32(f, 28);
        put_le32(f, 1); put_le32(f, 20); put_le32(f, 101);   // IDB: linktype + reserved
        put_le32(f, 65535); put_le32(f, 20);                  // snaplen, trailing length
        std::vector<uint8_t> body;
        put_le32(body, 7); put_le32(body, 0); put_le32(body, 0);
        put_le32(body, 0); put_le32(body, 0);
        put_le32(f, 6); put_le32(f, static_cast<uint32_t>(12 + body.size()));
        f.insert(f.end(), body.begin(), body.end());
        put_le32(f, static_cast<uint32_t>(12 + body.size()));
        p = write("iface.pcapng", f);
        REQUIRE(pcap::import_file(store, p).find("unknown interface") != std::string::npos);
        std::remove(p.c_str());
    }

    // a missing file is an error, not a crash
    REQUIRE(pcap::import_file(store, temp_path("nope.pcap")).find("cannot open") !=
            std::string::npos);
    REQUIRE_EQ(store.size(), 0u);
}

TEST_CASE(network_quic_long_headers) {
    // initial: long header, version 1, 8-byte DCID, empty SCID, no token
    std::vector<uint8_t> init = {0xC0, 0x00, 0x00, 0x00, 0x01, 0x08};
    for (int i = 0; i < 8; ++i) init.push_back(static_cast<uint8_t>(0xA0 + i));
    init.push_back(0x00);          // scid length
    init.push_back(0x00);          // token length
    init.push_back(0x08);          // payload length varint
    init.insert(init.end(), 8, 0x00);
    const auto q = parse::parse_quic(init.data(), init.size());
    REQUIRE(q.has_value());
    REQUIRE_EQ(q->version, 1u);
    REQUIRE_EQ(q->type, 0);
    REQUIRE_STR_EQ(q->dcid, std::string("a0a1a2a3a4a5a6a7"));
    REQUIRE(q->scid.empty());
    REQUIRE(q->has_length);
    REQUIRE_EQ(q->length, 8u);
    REQUIRE_STR_EQ(parse::quic_version_name(q->version), std::string("1"));
    REQUIRE_STR_EQ(parse::quic_type_name(q->type), std::string("initial"));

    // retry: no length field
    std::vector<uint8_t> retry = {0xF0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00};
    retry.insert(retry.end(), 16, 0x00);
    const auto qr = parse::parse_quic(retry.data(), retry.size());
    REQUIRE(qr.has_value());
    REQUIRE_EQ(qr->type, 3);
    REQUIRE_FALSE(qr->has_length);

    // version negotiation (version 0) and short headers / truncation
    std::vector<uint8_t> vn = {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    REQUIRE(parse::parse_quic(vn.data(), vn.size()).has_value());
    std::vector<uint8_t> short_hdr = {0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    REQUIRE_FALSE(parse::parse_quic(short_hdr.data(), short_hdr.size()).has_value());
    REQUIRE_FALSE(parse::parse_quic(init.data(), 4).has_value());
    REQUIRE_FALSE(parse::parse_quic(init.data(), 6).has_value());   // DCID cut short

    // the store counts QUIC and deep_inspect labels it
    traffic_store_t s;
    auto p = mk_packet(50000, 443, "10.0.0.2", "1.2.3.4");
    p.protocol = 17;
    p.payload = init;
    s.add(p);
    REQUIRE_EQ(s.stats().quic_packets, 1u);
    auto plain = mk_packet(50000, 443, "10.0.0.2", "1.2.3.4");
    plain.protocol = 17;
    plain.payload.assign({0x01, 0x02, 0x03, 0x04});
    s.add(plain);
    REQUIRE_EQ(s.stats().quic_packets, 1u);

    namespace cap = slop::core::network::capture;
    namespace mcp = slop::core::mcp;
    using json = nlohmann::json;
    bool error = false;
    mcp::call_tool("network", {{"action", "clear"}}, error);
    cap::testing::reset();
    REQUIRE(cap::testing::set_filter({}).empty());
    const auto dgram = ipv4("10.0.0.2", "1.2.3.4", 17, udp_dgram(50000, 443, init));
    cap::testing::inject(dgram.data(), dgram.size(), 2000);
    json r = mcp::call_tool("network", {{"action", "packets"}}, error);
    REQUIRE_FALSE(error);
    r = mcp::call_tool("network", {{"action", "stats"}}, error);
    REQUIRE_FALSE(error);
    REQUIRE_EQ(r["quic_packets"].get<size_t>(), 1u);
    r = mcp::call_tool("network", {{"action", "deep_inspect"}, {"port", 443}}, error);
    REQUIRE_FALSE(error);
    REQUIRE_EQ(r["count"].get<size_t>(), 1u);
    REQUIRE_STR_EQ(r["results"][0]["app_protocol"].get<std::string>(), "QUIC");
    REQUIRE_STR_EQ(r["results"][0]["quic_version"].get<std::string>(), "1");
    REQUIRE_STR_EQ(r["results"][0]["quic_type"].get<std::string>(), "initial");
    mcp::call_tool("network", {{"action", "clear"}}, error);
    cap::testing::reset();
}
