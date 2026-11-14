// src/core/network/capture_service.cpp
// host-side raw-socket capture (SIO_RCVALL) feeding the traffic store

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <iphlpapi.h>
#include <mswsock.h>
#else
#include "core/compat/posix_socket.hpp"
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#endif

#include "core/network/capture_service.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <thread>

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#endif

namespace slop::core::network {
namespace capture {
namespace {

constexpr int64_t kIfaceRefreshMs = 15000;
constexpr size_t  kPendingCap = 16384;
constexpr size_t  kDnsCap = 4096;

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

struct sock_t {
    SOCKET          s = INVALID_SOCKET;
    capture_iface_t info;
    std::string     key;      // adapter name + family
};

struct state_t {
    std::mutex mu;                         // everything below except atomics
    std::thread th;
    std::atomic<bool> stop_flag{false};
    std::atomic<bool> active{false};
    bool wsa = false;

    std::vector<sock_t> socks;             // owned by the capture thread while active
    std::vector<capture_iface_t> ifaces;   // last enumeration result (incl. failures)
    std::vector<parse::ip_addr_t> locals;  // every unicast address of this host
    int64_t locals_at = 0;

    capture_filter_t filter;
    std::optional<parse::ip_addr_t> filter_host;

    parse::reassembler_t frags;
    std::deque<packet_record_t> pending;
    std::deque<dns_record_t> dns;

    uint64_t packets_seen = 0, packets_in = 0, packets_out = 0;
    uint64_t bytes_in = 0, bytes_out = 0, filtered_out = 0, parse_errors = 0;
    uint64_t non_tcp_udp = 0, fragments = 0, queue_dropped = 0, payload_truncated = 0;
    uint64_t dns_total = 0;
};

state_t& st() {
    static state_t s;
    return s;
}

#ifdef _WIN32
std::string wsa_error_text(int e) {
    switch (e) {
        case WSAEACCES: return "access denied - run the engine elevated for SIO_RCVALL";
        case WSAEINVAL: return "invalid argument (interface does not support SIO_RCVALL)";
        case WSAEADDRNOTAVAIL: return "address not available";
        case WSAEAFNOSUPPORT: return "address family not supported";
        default: return "winsock error " + std::to_string(e);
    }
}

std::string narrow(const wchar_t* w) {
    if (!w) return {};
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string out(static_cast<size_t>(n - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), n, nullptr, nullptr);
    return out;
}
#endif

struct adapter_addr_t {
    std::string key, name;
    sockaddr_storage sa{};
    int sa_len = 0;
    uint8_t family = 4;
    parse::ip_addr_t ip;
};

// up, non-loopback adapters: one bind address per family; every unicast
// address (loopback included) goes into `locals`
#ifdef _WIN32
std::vector<adapter_addr_t> enumerate(std::vector<parse::ip_addr_t>& locals) {
    std::vector<adapter_addr_t> out;
    locals.clear();
    ULONG size = 16 * 1024;
    std::vector<uint8_t> buf;
    ULONG rc = ERROR_BUFFER_OVERFLOW;
    for (int tries = 0; tries < 4 && rc == ERROR_BUFFER_OVERFLOW; ++tries) {
        buf.resize(size);
        rc = ::GetAdaptersAddresses(AF_UNSPEC,
                                    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                        GAA_FLAG_SKIP_DNS_SERVER,
                                    nullptr,
                                    reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &size);
    }
    if (rc != NO_ERROR) return out;
    for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()); a; a = a->Next) {
        const bool usable = a->OperStatus == IfOperStatusUp &&
                            a->IfType != IF_TYPE_SOFTWARE_LOOPBACK;
        bool have4 = false, have6 = false;
        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            const sockaddr* sa = u->Address.lpSockaddr;
            if (!sa) continue;
            adapter_addr_t aa;
            if (sa->sa_family == AF_INET) {
                const auto* sin = reinterpret_cast<const sockaddr_in*>(sa);
                aa.ip = parse::make_v4(reinterpret_cast<const uint8_t*>(&sin->sin_addr));
                aa.family = 4;
                aa.sa_len = sizeof(sockaddr_in);
            } else if (sa->sa_family == AF_INET6) {
                const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(sa);
                aa.ip = parse::make_v6(reinterpret_cast<const uint8_t*>(&sin6->sin6_addr));
                aa.family = 6;
                aa.sa_len = sizeof(sockaddr_in6);
            } else {
                continue;
            }
            locals.push_back(aa.ip);
            if (!usable) continue;
            bool& have = aa.family == 4 ? have4 : have6;
            if (have) continue;
            have = true;
            std::memcpy(&aa.sa, sa, static_cast<size_t>(aa.sa_len));
            aa.name = narrow(a->FriendlyName);
            aa.key = std::string(a->AdapterName ? a->AdapterName : "") + (aa.family == 4 ? "/4" : "/6");
            out.push_back(std::move(aa));
        }
    }
    return out;
}
#else
// one AF_PACKET socket per interface (both families arrive on it), every
// unicast address goes into `locals`
std::vector<adapter_addr_t> enumerate(std::vector<parse::ip_addr_t>& locals) {
    std::vector<adapter_addr_t> out;
    locals.clear();
    ifaddrs* ifs = nullptr;
    if (::getifaddrs(&ifs) != 0) return out;
    for (ifaddrs* i = ifs; i; i = i->ifa_next) {
        if (!i->ifa_addr) continue;
        const int fam = i->ifa_addr->sa_family;
        adapter_addr_t aa;
        if (fam == AF_INET) {
            const auto* sin = reinterpret_cast<const sockaddr_in*>(i->ifa_addr);
            aa.ip = parse::make_v4(reinterpret_cast<const uint8_t*>(&sin->sin_addr));
            aa.family = 4;
        } else if (fam == AF_INET6) {
            const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(i->ifa_addr);
            aa.ip = parse::make_v6(reinterpret_cast<const uint8_t*>(&sin6->sin6_addr));
            aa.family = 6;
        } else {
            continue;
        }
        locals.push_back(aa.ip);
        if ((i->ifa_flags & IFF_UP) == 0 || (i->ifa_flags & IFF_LOOPBACK) != 0) continue;
        aa.name = i->ifa_name;
        aa.key = aa.name;
        if (std::any_of(out.begin(), out.end(),
                        [&](const adapter_addr_t& e) { return e.key == aa.key; }))
            continue;
        out.push_back(std::move(aa));
    }
    ::freeifaddrs(ifs);
    return out;
}
#endif

#ifdef _WIN32
// opens a raw socket on one adapter address with RCVALL enabled
sock_t open_socket(const adapter_addr_t& a) {
    sock_t s;
    s.key = a.key;
    s.info.name = a.name;
    s.info.address = parse::to_string(a.ip);
    s.info.family = a.family;
    const int af = a.family == 4 ? AF_INET : AF_INET6;
    SOCKET sk = ::socket(af, SOCK_RAW, IPPROTO_IP);
    if (sk == INVALID_SOCKET && af == AF_INET6) sk = ::socket(af, SOCK_RAW, IPPROTO_IPV6);
    if (sk == INVALID_SOCKET) {
        s.info.error = "raw socket: " + wsa_error_text(::WSAGetLastError());
        return s;
    }
    if (::bind(sk, reinterpret_cast<const sockaddr*>(&a.sa), a.sa_len) != 0) {
        s.info.error = "bind: " + wsa_error_text(::WSAGetLastError());
        ::closesocket(sk);
        return s;
    }
    DWORD on = RCVALL_ON, bytes = 0;
    if (::WSAIoctl(sk, SIO_RCVALL, &on, sizeof(on), nullptr, 0, &bytes, nullptr, nullptr) ==
        SOCKET_ERROR) {
        s.info.error = "SIO_RCVALL: " + wsa_error_text(::WSAGetLastError());
        ::closesocket(sk);
        return s;
    }
    u_long nonblock = 1;
    ::ioctlsocket(sk, FIONBIO, &nonblock);
    int rcvbuf = 4 << 20;
    ::setsockopt(sk, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcvbuf), sizeof(rcvbuf));
    if (af == AF_INET6) {
        DWORD on6 = 1;   // destination address of each datagram via WSARecvMsg
        ::setsockopt(sk, IPPROTO_IPV6, IPV6_PKTINFO, reinterpret_cast<const char*>(&on6), sizeof(on6));
    }
    s.s = sk;
    s.info.active = true;
    return s;
}

void close_socket(sock_t& s) {
    if (s.s == INVALID_SOCKET) return;
    DWORD off = RCVALL_OFF, bytes = 0;
    ::WSAIoctl(s.s, SIO_RCVALL, &off, sizeof(off), nullptr, 0, &bytes, nullptr, nullptr);
    ::closesocket(s.s);
    s.s = INVALID_SOCKET;
    s.info.active = false;
}
#else
// AF_PACKET socket bound to one interface: receives both families' frames.
// Needs CAP_NET_RAW (root or `setcap cap_net_raw+ep`); the error says so.
sock_t open_socket(const adapter_addr_t& a) {
    sock_t s;
    s.key = a.key;
    s.info.name = a.name;
    s.info.address = parse::to_string(a.ip);
    s.info.family = 4;
    const int sk = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sk < 0) {
        s.info.error = "AF_PACKET raw socket: " + std::string(std::strerror(errno)) +
                       " (capture needs CAP_NET_RAW)";
        return s;
    }
    sockaddr_ll ll{};
    ll.sll_family = AF_PACKET;
    ll.sll_protocol = htons(ETH_P_ALL);
    ll.sll_ifindex = static_cast<int>(::if_nametoindex(a.name.c_str()));
    if (ll.sll_ifindex == 0 ||
        ::bind(sk, reinterpret_cast<sockaddr*>(&ll), sizeof(ll)) != 0) {
        s.info.error = "bind to " + a.name + ": " + std::strerror(errno);
        ::close(sk);
        return s;
    }
    const int flags = ::fcntl(sk, F_GETFL, 0);
    ::fcntl(sk, F_SETFL, flags | O_NONBLOCK);
    int rcvbuf = 4 << 20;
    ::setsockopt(sk, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    s.s = sk;
    s.info.active = true;
    return s;
}

void close_socket(sock_t& s) {
    if (s.s == INVALID_SOCKET) return;
    ::close(s.s);
    s.s = INVALID_SOCKET;
    s.info.active = false;
}
#endif

bool is_local(const state_t& s, const parse::ip_addr_t& a) {
    return std::find(s.locals.begin(), s.locals.end(), a) != s.locals.end();
}

// caller holds s.mu
void handle_l4(state_t& s, const parse::ip_addr_t& src, const parse::ip_addr_t& dst,
               uint8_t proto, const uint8_t* l4, size_t l4_len, uint32_t l4_wire_len,
               size_t ip_bytes, int64_t at) {
    if (proto != 6 && proto != 17) {
        ++s.non_tcp_udp;
        return;
    }
    parse::l4_info_t l;
    if (parse::parse_l4(proto, l4, l4_len, l4_wire_len, l) != parse::status_t::ok) {
        ++s.parse_errors;
        return;
    }
    if (s.filter_host && !(src == *s.filter_host || dst == *s.filter_host)) {
        ++s.filtered_out;
        return;
    }

    // direction: this host first, then the filtered peer (a console behind
    // ICS / a mirror port), then the ephemeral-port side as the client
    bool outbound;
    if (is_local(s, src)) outbound = true;
    else if (is_local(s, dst)) outbound = false;
    else if (s.filter_host) outbound = src == *s.filter_host;
    else outbound = l.src_port >= l.dst_port;

    if (proto == 17 && (l.src_port == 53 || l.dst_port == 53) && l.payload_len) {
        if (auto r = parse::parse_dns(l.payload, l.payload_len)) {
            r->timestamp = static_cast<uint64_t>(at);
            const bool from_server = l.src_port == 53;
            r->client_addr = parse::to_string(from_server ? dst : src);
            r->server_addr = parse::to_string(from_server ? src : dst);
            s.dns.push_back(std::move(*r));
            if (s.dns.size() > kDnsCap) s.dns.pop_front();
            ++s.dns_total;
        }
    }

    if (s.filter.protocol && s.filter.protocol != proto) { ++s.filtered_out; return; }
    if (s.filter.port && l.src_port != s.filter.port && l.dst_port != s.filter.port) {
        ++s.filtered_out;
        return;
    }
    if (proto == 6 && l.payload_wire_len == 0) return;   // bare ACK / handshake

    packet_record_t rec;
    rec.at_ms = at;
    rec.protocol = proto;
    rec.ip_version = src.family;
    rec.direction = outbound ? 0 : 1;
    rec.local_addr = parse::to_string(outbound ? src : dst);
    rec.local_port = outbound ? l.src_port : l.dst_port;
    rec.remote_addr = parse::to_string(outbound ? dst : src);
    rec.remote_port = outbound ? l.dst_port : l.src_port;
    rec.wire_len = l.payload_wire_len;
    rec.tcp_seq = l.tcp_seq;
    rec.tcp_ack = l.tcp_ack;
    rec.tcp_flags = l.tcp_flags;
    const size_t keep = std::min(l.payload_len, kMaxPayload);
    if (l.payload_wire_len > keep) ++s.payload_truncated;
    rec.payload.assign(l.payload, l.payload + keep);

    if (outbound) { ++s.packets_out; s.bytes_out += ip_bytes; }
    else          { ++s.packets_in;  s.bytes_in += ip_bytes; }
    if (s.pending.size() >= kPendingCap) {
        s.pending.pop_front();
        ++s.queue_dropped;
    }
    s.pending.push_back(std::move(rec));
}

// caller holds s.mu
void handle_fragment(state_t& s, const parse::ip_info_t& ip, int64_t at) {
    ++s.fragments;
    auto dg = s.frags.add(ip, at);
    if (!dg) return;
    uint8_t proto = dg->proto;
    const uint8_t* p = dg->l4.data();
    size_t len = dg->l4.size();
    if (ip.src.family == 6 && parse::skip_v6_ext(proto, p, len) != parse::status_t::ok) {
        ++s.parse_errors;
        return;
    }
    handle_l4(s, ip.src, ip.dst, proto, p, len, static_cast<uint32_t>(len),
              dg->l4.size() + (ip.src.family == 4 ? 20 : 40), at);
}

void handle_datagram(state_t& s, const uint8_t* d, size_t n, int64_t at) {
    ++s.packets_seen;
    parse::ip_info_t ip;
    if (parse::parse_ip(d, n, ip) != parse::status_t::ok) {
        ++s.parse_errors;
        return;
    }
    if (ip.fragment) return handle_fragment(s, ip, at);
    handle_l4(s, ip.src, ip.dst, ip.proto, ip.l4, ip.l4_len, ip.l4_wire_len, n, at);
}

// IPv6 raw sockets hand over the bytes after the last IPv6 header only; the
// addresses come from WSARecvMsg and the transport is inferred
void handle_v6_transport(state_t& s, const parse::ip_addr_t& src, const parse::ip_addr_t& dst,
                         const uint8_t* d, size_t n, int64_t at) {
    ++s.packets_seen;
    const uint8_t proto = parse::infer_v6_transport(src, dst, d, n);
    if (proto == 6 || proto == 17)
        return handle_l4(s, src, dst, proto, d, n, static_cast<uint32_t>(n), n + 40, at);
    if (proto == 58) {
        ++s.non_tcp_udp;
        return;
    }
    if (proto != 44) {
        ++s.parse_errors;
        return;
    }
    parse::ip_info_t ip;
    ip.src = src;
    ip.dst = dst;
    ip.proto = d[0];
    ip.l4 = d + 8;
    ip.l4_len = n - 8;
    ip.l4_wire_len = static_cast<uint32_t>(n - 8);
    const uint16_t fo = static_cast<uint16_t>((static_cast<uint16_t>(d[2]) << 8) | d[3]);
    ip.frag_offset = fo & 0xFFF8u;
    ip.more_fragments = (fo & 1) != 0;
    ip.frag_id = (static_cast<uint32_t>(d[4]) << 24) | (static_cast<uint32_t>(d[5]) << 16) |
                 (static_cast<uint32_t>(d[6]) << 8) | d[7];
    ip.fragment = ip.frag_offset != 0 || ip.more_fragments;
    if (ip.fragment) return handle_fragment(s, ip, at);
    handle_l4(s, src, dst, ip.proto, ip.l4, ip.l4_len, ip.l4_wire_len, n + 40, at);
}

#ifdef _WIN32
LPFN_WSARECVMSG wsa_recvmsg(SOCKET sk) {
    static LPFN_WSARECVMSG fn = nullptr;
    if (!fn) {
        GUID guid = WSAID_WSARECVMSG;
        DWORD bytes = 0;
        ::WSAIoctl(sk, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), &fn,
                   sizeof(fn), &bytes, nullptr, nullptr);
    }
    return fn;
}

// one IPv6 datagram: payload, source from the sender address, destination
// from IPV6_PKTINFO. Returns the byte count or <= 0
int recv_v6(SOCKET sk, std::vector<uint8_t>& buf, parse::ip_addr_t& src, parse::ip_addr_t& dst) {
    LPFN_WSARECVMSG fn = wsa_recvmsg(sk);
    if (!fn) return -1;
    sockaddr_in6 from{};
    char control[WSA_CMSG_SPACE(sizeof(IN6_PKTINFO))]{};
    WSABUF data{static_cast<ULONG>(buf.size()), reinterpret_cast<CHAR*>(buf.data())};
    WSAMSG msg{};
    msg.name = reinterpret_cast<LPSOCKADDR>(&from);
    msg.namelen = sizeof(from);
    msg.lpBuffers = &data;
    msg.dwBufferCount = 1;
    msg.Control = {sizeof(control), control};
    DWORD got = 0;
    if (fn(sk, &msg, &got, nullptr, nullptr) != 0) return -1;
    src = parse::make_v6(reinterpret_cast<const uint8_t*>(&from.sin6_addr));
    dst = parse::ip_addr_t{};
    for (WSACMSGHDR* c = WSA_CMSG_FIRSTHDR(&msg); c; c = WSA_CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_PKTINFO) {
            const auto* pi = reinterpret_cast<const IN6_PKTINFO*>(WSA_CMSG_DATA(c));
            dst = parse::make_v6(reinterpret_cast<const uint8_t*>(&pi->ipi6_addr));
        }
    }
    return dst.valid() ? static_cast<int>(got) : -1;
}
#endif

// re-enumerates adapters: refreshes the local address set, opens sockets for
// new interfaces and closes those whose adapter went away. Socket thread only
void refresh_interfaces(state_t& s) {
    std::vector<parse::ip_addr_t> locals;
    auto addrs = enumerate(locals);
    std::vector<sock_t> keep;
    for (auto& sk : s.socks) {
        const bool present = std::any_of(addrs.begin(), addrs.end(), [&](const adapter_addr_t& a) {
            return a.key == sk.key && parse::to_string(a.ip) == sk.info.address;
        });
        if (present) keep.push_back(sk);
        else close_socket(sk);
    }
    std::vector<capture_iface_t> ifaces;
    for (const auto& a : addrs) {
        auto it = std::find_if(keep.begin(), keep.end(), [&](const sock_t& k) { return k.key == a.key; });
        if (it != keep.end()) {
            ifaces.push_back(it->info);
            continue;
        }
        sock_t ns = open_socket(a);
        ifaces.push_back(ns.info);
        if (ns.s != INVALID_SOCKET) keep.push_back(std::move(ns));
    }
    s.socks = std::move(keep);
    std::lock_guard lk(s.mu);
    s.locals = std::move(locals);
    s.locals_at = now_ms();
    s.ifaces = std::move(ifaces);
}

void capture_thread() {
    state_t& s = st();
    std::vector<uint8_t> buf(65536);
    std::vector<WSAPOLLFD> fds;
    while (!s.stop_flag.load()) {
        if (now_ms() - s.locals_at > kIfaceRefreshMs) refresh_interfaces(s);
        fds.clear();
        for (const auto& sk : s.socks) fds.push_back({sk.s, POLLRDNORM, 0});
        if (fds.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            continue;
        }
        const int r = ::WSAPoll(fds.data(), static_cast<ULONG>(fds.size()), 250);
        if (r <= 0) continue;
        for (size_t i = 0; i < fds.size(); ++i) {
            const auto& fd = fds[i];
            if (!(fd.revents & (POLLRDNORM | POLLERR | POLLHUP))) continue;
#ifdef _WIN32
            const bool v6 = s.socks[i].info.family == 6;
#endif
            // drain what is queued on this socket, bounded per wakeup
            for (int burst = 0; burst < 256; ++burst) {
#ifdef _WIN32
                if (v6) {
                    parse::ip_addr_t src, dst;
                    const int n = recv_v6(fd.fd, buf, src, dst);
                    if (n <= 0) break;
                    std::lock_guard lk(s.mu);
                    handle_v6_transport(s, src, dst, buf.data(), static_cast<size_t>(n), now_ms());
                    continue;
                }
                const int n = ::recv(fd.fd, reinterpret_cast<char*>(buf.data()),
                                     static_cast<int>(buf.size()), 0);
                if (n <= 0) break;
                std::lock_guard lk(s.mu);
                handle_datagram(s, buf.data(), static_cast<size_t>(n), now_ms());
#else
                // AF_PACKET hands over the link-layer frame; skip Ethernet
                // (and one 802.1Q tag) to reach the IP datagram
                const ssize_t n = ::recv(fd.fd, buf.data(), buf.size(), 0);
                if (n <= 0) break;
                size_t off = 0;
                if (n >= 14) {
                    const uint16_t ethertype =
                        static_cast<uint16_t>((buf[12] << 8) | buf[13]);
                    if (ethertype == 0x8100 && n >= 18)
                        off = 18;
                    else if (ethertype == 0x0800 || ethertype == 0x86DD)
                        off = 14;
                    else
                        continue;   // ARP and friends are not IP
                } else {
                    continue;
                }
                std::lock_guard lk(s.mu);
                handle_datagram(s, buf.data() + off, static_cast<size_t>(n) - off, now_ms());
#endif
            }
        }
    }
    for (auto& sk : s.socks) close_socket(sk);
    s.socks.clear();
    s.active.store(false);
}

std::string apply_filter(state_t& s, const capture_filter_t& f) {
    std::optional<parse::ip_addr_t> host;
    if (!f.host.empty()) {
        host = parse::parse_ip(f.host);
        if (!host) return "capture filter host must be an IPv4/IPv6 address, got '" + f.host + "'";
    }
    if (f.protocol != 0 && f.protocol != 6 && f.protocol != 17)
        return "capture filter protocol must be 6 (tcp), 17 (udp) or 0";
    std::lock_guard lk(s.mu);
    s.filter = f;
    if (host) s.filter.host = parse::to_string(*host);
    s.filter_host = host;
    return {};
}

} // namespace

bool running() {
    return st().active.load();
}

std::string start(const capture_filter_t& filter, bool* updated) {
    state_t& s = st();
    if (updated) *updated = false;
    if (s.active.load()) {
        auto err = apply_filter(s, filter);
        if (err.empty() && updated) *updated = true;
        return err;
    }
    // the previous run's thread has exited on its own; reclaim it
    if (s.th.joinable()) s.th.join();
    if (auto err = apply_filter(s, filter); !err.empty()) return err;

    if (!s.wsa) {
        WSADATA wsa{};
        if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return "WSAStartup failed";
        s.wsa = true;
    }
    std::vector<parse::ip_addr_t> locals;
    const auto addrs = enumerate(locals);
    std::vector<sock_t> socks;
    std::vector<capture_iface_t> ifaces;
    for (const auto& a : addrs) {
        sock_t sk = open_socket(a);
        ifaces.push_back(sk.info);
        if (sk.s != INVALID_SOCKET) socks.push_back(std::move(sk));
    }
    if (socks.empty()) {
        std::string why = addrs.empty() ? "no active network interfaces" : ifaces.front().error;
        for (size_t i = 1; i < ifaces.size(); ++i)
            if (ifaces[i].error != ifaces.front().error) why += "; " + ifaces[i].error;
        std::lock_guard lk(s.mu);
        s.ifaces = std::move(ifaces);
        return "capture failed on every interface: " + why;
    }
    {
        std::lock_guard lk(s.mu);
        s.locals = std::move(locals);
        s.locals_at = now_ms();
        s.ifaces = std::move(ifaces);
        s.frags.clear();
    }
    s.socks = std::move(socks);
    s.stop_flag.store(false);
    s.active.store(true);
    s.th = std::thread(capture_thread);
    return {};
}

std::string stop() {
    state_t& s = st();
    s.stop_flag.store(true);
    if (s.th.joinable()) s.th.join();
    s.active.store(false);
    if (s.wsa) {
        ::WSACleanup();
        s.wsa = false;
    }
    return {};
}

size_t poll(traffic_store_t& sink, size_t max_packets) {
    state_t& s = st();
    std::deque<packet_record_t> batch;
    {
        std::lock_guard lk(s.mu);
        const size_t n = std::min(max_packets, s.pending.size());
        for (size_t i = 0; i < n; ++i) {
            batch.push_back(std::move(s.pending.front()));
            s.pending.pop_front();
        }
    }
    for (auto& rec : batch) sink.add(std::move(rec));
    return batch.size();
}

std::vector<dns_record_t> dns_queries(const std::string& host) {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    if (host.empty()) return {s.dns.begin(), s.dns.end()};
    const auto want = parse::parse_ip(host);
    const std::string canon = want ? parse::to_string(*want) : host;
    std::vector<dns_record_t> out;
    for (const auto& r : s.dns)
        if (r.client_addr == canon || r.server_addr == canon) out.push_back(r);
    return out;
}

net_stats_t stats() {
    state_t& s = st();
    net_stats_t out;
    out.capture_active = s.active.load();
    std::lock_guard lk(s.mu);
    out.packets_seen = s.packets_seen;
    out.packets_in = s.packets_in;
    out.packets_out = s.packets_out;
    out.bytes_in = s.bytes_in;
    out.bytes_out = s.bytes_out;
    out.filtered_out = s.filtered_out;
    out.parse_errors = s.parse_errors;
    out.non_tcp_udp = s.non_tcp_udp;
    out.fragments = s.fragments;
    out.fragments_reassembled = s.frags.completed();
    out.fragments_dropped = s.frags.dropped();
    out.queue_dropped = s.queue_dropped;
    out.payload_truncated = s.payload_truncated;
    out.dns_logged_total = s.dns_total;
    out.dns_buffered = static_cast<uint32_t>(s.dns.size());
    out.pending = static_cast<uint32_t>(s.pending.size());
    out.filter = s.filter;
    out.interfaces = s.ifaces;
    return out;
}

std::string export_pcap(traffic_store_t& store, const std::string& path,
                        uint32_t max_packets, size_t* exported, bool* truncated,
                        const std::string& format) {
    if (format != "pcap" && format != "pcapng")
        return "format must be pcap or pcapng, got '" + format + "'";
    while (poll(store, 4096) > 0) {}
    const auto page = store.packets_tail(max_packets);
    std::string err;
    const bool ok = format == "pcapng" ? store.write_pcapng(path, page.items, &err)
                                       : store.write_pcap(path, page.items, &err);
    if (!ok) return err.empty() ? format + " write failed" : err;
    if (exported) *exported = page.items.size();
    if (truncated) *truncated = page.truncated;
    return {};
}

namespace testing {

void reset() {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    s.pending.clear();
    s.dns.clear();
    s.frags.clear();
    s.locals.clear();
    s.filter = {};
    s.filter_host.reset();
    s.packets_seen = s.packets_in = s.packets_out = s.bytes_in = s.bytes_out = 0;
    s.filtered_out = s.parse_errors = s.non_tcp_udp = s.fragments = 0;
    s.queue_dropped = s.payload_truncated = s.dns_total = 0;
}

void set_local_addresses(const std::vector<std::string>& addrs) {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    s.locals.clear();
    for (const auto& a : addrs)
        if (auto ip = parse::parse_ip(a)) s.locals.push_back(*ip);
    s.locals_at = now_ms();
}

std::string set_filter(const capture_filter_t& filter) {
    return apply_filter(st(), filter);
}

void inject(const uint8_t* d, size_t n, int64_t at) {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    handle_datagram(s, d, n, at);
}

void inject_v6_transport(const std::string& src, const std::string& dst, const uint8_t* d,
                         size_t n, int64_t at) {
    const auto s6 = parse::parse_ip(src);
    const auto d6 = parse::parse_ip(dst);
    if (!s6 || !d6) return;
    state_t& s = st();
    std::lock_guard lk(s.mu);
    handle_v6_transport(s, *s6, *d6, d, n, at);
}

} // namespace testing

} // namespace capture
} // namespace slop::core::network
