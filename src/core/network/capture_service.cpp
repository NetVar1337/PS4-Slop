// src/core/network/capture_service.cpp
// host-side raw-socket capture (SIO_RCVALL promiscuous mode) feeding the
// traffic store; replaces the old kernel/WFP front end. RCVALL needs admin.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "core/network/capture_service.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>

namespace slop::core::network {
namespace capture {
namespace {

#pragma pack(push, 1)
struct eth_hdr_t { uint8_t dst[6]; uint8_t src[6]; uint16_t type; };
struct ipv4_hdr_t {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
};
struct tcp_hdr_t {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_off;   // high nibble
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg;
};
struct udp_hdr_t {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
};
#pragma pack(pop)

struct state_t {
    std::mutex mu;
    SOCKET sock = INVALID_SOCKET;
    std::thread th;
    std::atomic<bool> stop_flag{false};
    std::atomic<bool> active{false};

    // filters
    uint32_t filter_pid = 0, filter_port = 0, filter_protocol = 0;

    // raw captured packets waiting to be pulled into the store
    std::deque<packet_record_t> pending;
    size_t pending_cap = 65536;

    // parsed dns
    std::deque<dns_record_t> dns;
    size_t dns_cap = 4096;

    // counters
    std::atomic<uint64_t> total_captured{0};
    std::atomic<uint64_t> total_dropped{0};
    std::atomic<uint64_t> bytes_in{0};
    std::atomic<uint64_t> bytes_out{0};
};

state_t& st() {
    static state_t s;
    return s;
}

std::string ip_str(uint32_t addr) {
    in_addr a{};
    a.s_addr = addr;
    char buf[INET_ADDRSTRLEN]{};
    return inet_ntop(AF_INET, &a, buf, sizeof(buf)) ? buf : std::string{};
}

// local addresses of this host, for direction classification
std::vector<uint32_t> local_addrs() {
    std::vector<uint32_t> out;
    char host[256]{};
    if (::gethostname(host, sizeof(host)) != 0) return out;
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* res = nullptr;
    if (::getaddrinfo(host, nullptr, &hints, &res) == 0) {
        for (addrinfo* p = res; p; p = p->ai_next) {
            if (p->ai_addr && p->ai_addrlen >= sizeof(sockaddr_in)) {
                const auto* sin = reinterpret_cast<const sockaddr_in*>(p->ai_addr);
                if (sin->sin_addr.s_addr != 0)
                    out.push_back(sin->sin_addr.s_addr);
            }
        }
        ::freeaddrinfo(res);
    }
    return out;
}

// minimal dns message parser: collect QNAMEs of queries and A answers.
// caller holds st().mu
void parse_dns(const uint8_t* payload, size_t len, bool is_response,
               std::deque<dns_record_t>& out, size_t dns_cap) {
    if (len < 12) return;
    const uint16_t flags = (payload[2] << 8) | payload[3];
    const uint16_t qd = (payload[4] << 8) | payload[5];
    const uint16_t an = (payload[6] << 8) | payload[7];
    const bool qr = (flags >> 15) & 1;
    if (qr != is_response) return;
    size_t off = 12;
    auto read_name = [&](size_t& o, std::string& name) -> bool {
        name.clear();
        int jumps = 0;
        size_t pos = o;
        size_t end = 0;
        while (true) {
            if (pos >= len) return false;
            const uint8_t l = payload[pos];
            if (l == 0) {
                if (end == 0) end = pos + 1;
                break;
            }
            if ((l & 0xC0) == 0xC0) {
                if (pos + 1 >= len) return false;
                const size_t ptr = ((l & 0x3F) << 8) | payload[pos + 1];
                if (end == 0) end = pos + 2;
                pos = ptr;
                if (++jumps > 16) return false;
                continue;
            }
            if (pos + 1 + l > len) return false;
            if (!name.empty()) name += '.';
            name.append(reinterpret_cast<const char*>(payload + pos + 1), l);
            pos += 1 + l;
        }
        o = end;
        return true;
    };
    auto now_ms = [] {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
    };
    std::string qname;
    uint16_t qtype = 0;
    for (uint16_t i = 0; i < qd && off < len; ++i) {
        if (!read_name(off, qname)) return;
        if (off + 4 > len) return;
        qtype = (payload[off] << 8) | payload[off + 1];
        off += 4;
    }
    if (qname.empty()) return;
    if (!is_response) {
        dns_record_t r{};
        r.timestamp = now_ms();
        r.query_type = qtype;
        r.domain = qname;
        out.push_back(r);
        if (out.size() > dns_cap) out.pop_front();
        return;
    }
    // response: walk answers for A records
    const uint16_t rcode = flags & 0xF;
    uint32_t ttl = 0;
    std::string resolved;
    for (uint16_t i = 0; i < an && off + 10 <= len; ++i) {
        std::string aname;
        if (!read_name(off, aname)) break;
        const uint16_t type = (payload[off] << 8) | payload[off + 1];
        ttl = (payload[off + 4] << 24) | (payload[off + 5] << 16) |
              (payload[off + 6] << 8) | payload[off + 7];
        const uint16_t rdlen = (payload[off + 8] << 8) | payload[off + 9];
        off += 10;
        if (off + rdlen > len) break;
        if (type == 1 && rdlen == 4) {
            resolved = ip_str((payload[off] << 24) | (payload[off + 1] << 16) |
                              (payload[off + 2] << 8) | payload[off + 3]);
            break;
        }
        off += rdlen;
    }
    dns_record_t r{};
    r.timestamp = now_ms();
    r.query_type = qtype;
    r.domain = qname;
    r.resolved_addr = resolved;
    r.response_code = rcode;
    r.ttl = ttl;
    out.push_back(r);
    if (out.size() > dns_cap) out.pop_front();
}

void handle_frame(const uint8_t* frame, size_t len) {
    state_t& s = st();
    if (len < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t)) return;
    const auto* eth = reinterpret_cast<const eth_hdr_t*>(frame);
    if (ntohs(eth->type) != 0x0800) return;   // ipv4 only
    const auto* ip = reinterpret_cast<const ipv4_hdr_t*>(frame + sizeof(eth_hdr_t));
    const size_t ihl = (ip->ver_ihl & 0x0F) * 4;
    if (ihl < 20 || len < sizeof(eth_hdr_t) + ihl) return;
    const uint8_t proto = ip->proto;
    if (proto != 6 && proto != 17) return;
    const uint8_t* l4 = frame + sizeof(eth_hdr_t) + ihl;
    const size_t l4_len = len - sizeof(eth_hdr_t) - ihl;
    uint16_t src_port = 0, dst_port = 0;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
    if (proto == 6) {
        if (l4_len < sizeof(tcp_hdr_t)) return;
        const auto* tcp = reinterpret_cast<const tcp_hdr_t*>(l4);
        src_port = ntohs(tcp->src_port);
        dst_port = ntohs(tcp->dst_port);
        const size_t doff = (tcp->data_off >> 4) * 4;
        if (doff < sizeof(tcp_hdr_t) || doff > l4_len) return;
        payload = l4 + doff;
        payload_len = l4_len - doff;
        if (payload_len == 0) return;   // pure ack, no payload to store
    } else {
        if (l4_len < sizeof(udp_hdr_t)) return;
        const auto* udp = reinterpret_cast<const udp_hdr_t*>(l4);
        src_port = ntohs(udp->src_port);
        dst_port = ntohs(udp->dst_port);
        payload = l4 + sizeof(udp_hdr_t);
        payload_len = l4_len - sizeof(udp_hdr_t);
    }

    static const auto locals = local_addrs();
    const bool inbound = std::find(locals.begin(), locals.end(), ip->dst) != locals.end();

    packet_record_t rec{};
    rec.at_ms = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
    rec.protocol = proto;
    rec.direction = inbound ? 1 : 0;
    rec.local_addr = inbound ? ip_str(ip->dst) : ip_str(ip->src);
    rec.local_port = inbound ? dst_port : src_port;
    rec.remote_addr = inbound ? ip_str(ip->src) : ip_str(ip->dst);
    rec.remote_port = inbound ? src_port : dst_port;
    rec.payload.assign(payload, payload + std::min<size_t>(payload_len, 1536));

    s.total_captured.fetch_add(1);
    if (inbound) s.bytes_in.fetch_add(len); else s.bytes_out.fetch_add(len);
    {
        std::lock_guard lk(s.mu);
        if (proto == 17 && payload_len > 0 && (src_port == 53 || dst_port == 53))
            parse_dns(payload, payload_len, src_port == 53, s.dns, s.dns_cap);
        if (s.pending.size() >= s.pending_cap) {
            s.pending.pop_front();
            s.total_dropped.fetch_add(1);
        }
        s.pending.push_back(std::move(rec));
    }
}

void capture_thread() {
    state_t& s = st();
    // RCVALL promiscuous mode: needs admin
    DWORD rcvall = 1;
    DWORD bytes = 0;
    if (::WSAIoctl(s.sock, SIO_RCVALL, &rcvall, sizeof(rcvall), nullptr, 0,
                   &bytes, nullptr, nullptr) == SOCKET_ERROR) {
        s.active.store(false);
        return;
    }
    uint8_t buf[65536];
    while (!s.stop_flag.load()) {
        const int n = ::recv(s.sock, reinterpret_cast<char*>(buf), sizeof(buf), 0);
        if (n <= 0) {
            if (s.stop_flag.load()) break;
            const int err = ::WSAGetLastError();
            if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) continue;
            break;
        }
        handle_frame(buf, static_cast<size_t>(n));
    }
    rcvall = 0;
    ::WSAIoctl(s.sock, SIO_RCVALL, &rcvall, sizeof(rcvall), nullptr, 0, &bytes,
               nullptr, nullptr);
    s.active.store(false);
}

} // namespace

bool running() {
    return st().active.load();
}

std::string start(uint32_t filter_pid, uint32_t filter_port,
                  uint32_t filter_protocol) {
    state_t& s = st();
    if (s.active.load()) return {};
    {
        WSADATA wsa{};
        if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            return "WSAStartup failed";
    }
    SOCKET sock = ::socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (sock == INVALID_SOCKET)
        return "raw socket failed (error " + std::to_string(::WSAGetLastError()) +
               ") - run elevated for SIO_RCVALL capture";
    // bind to any so we receive on all interfaces
    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = 0;
    if (::bind(sock, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) != 0) {
        const int e = ::WSAGetLastError();
        ::closesocket(sock);
        return "raw socket bind failed (error " + std::to_string(e) + ")";
    }
    // receive timeout so the thread notices stop_flag
    DWORD tv = 500;
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv),
                 sizeof(tv));
    {
        std::lock_guard lk(s.mu);
        s.sock = sock;
        s.filter_pid = filter_pid;
        s.filter_port = filter_port;
        s.filter_protocol = filter_protocol;
    }
    s.stop_flag.store(false);
    s.active.store(true);
    s.th = std::thread(capture_thread);
    return {};
}

std::string stop() {
    state_t& s = st();
    s.stop_flag.store(true);
    if (s.th.joinable()) s.th.join();
    {
        std::lock_guard lk(s.mu);
        if (s.sock != INVALID_SOCKET) {
            ::closesocket(s.sock);
            s.sock = INVALID_SOCKET;
        }
    }
    s.active.store(false);
    ::WSACleanup();
    return {};
}

size_t poll(traffic_store_t& sink, size_t max_packets) {
    state_t& s = st();
    size_t pulled = 0;
    std::lock_guard lk(s.mu);
    while (!s.pending.empty() && pulled < max_packets) {
        packet_record_t rec = std::move(s.pending.front());
        s.pending.pop_front();
        // apply filters
        if (s.filter_protocol != 0 && rec.protocol != s.filter_protocol) continue;
        if (s.filter_port != 0 &&
            rec.local_port != s.filter_port && rec.remote_port != s.filter_port)
            continue;
        sink.add(std::move(rec));
        ++pulled;
    }
    return pulled;
}

std::vector<dns_record_t> dns_queries(uint32_t filter_pid) {
    (void)filter_pid;   // raw capture has no pid attribution; return all
    state_t& s = st();
    std::lock_guard lk(s.mu);
    return {s.dns.begin(), s.dns.end()};
}

net_stats_t stats() {
    state_t& s = st();
    net_stats_t out{};
    out.capture_active = s.active.load();
    out.total_captured = static_cast<uint32_t>(s.total_captured.load());
    out.total_dropped = static_cast<uint32_t>(s.total_dropped.load());
    out.bytes_received = s.bytes_in.load();
    out.bytes_sent = s.bytes_out.load();
    out.packets_received = out.total_captured;
    std::lock_guard lk(s.mu);
    out.total_dns_logged = static_cast<uint32_t>(s.dns.size());
    return out;
}

std::string export_pcap(const traffic_store_t& store, const std::string& path,
                        uint32_t max_packets) {
    const auto page = store.packets(0, max_packets);
    std::string err;
    if (!store.write_pcap(path, page.items, &err))
        return err.empty() ? "pcap write failed" : err;
    return {};
}

} // namespace capture
} // namespace slop::core::network
