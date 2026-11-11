// src/core/network/net_socket.cpp

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "core/network/net_socket.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <mutex>

#pragma comment(lib, "ws2_32.lib")

namespace slop::core::network::sock {

namespace {

bool fill_sockaddr(const parse::ip_addr_t& ip, uint16_t port, sockaddr_storage& ss, int& len) {
    std::memset(&ss, 0, sizeof(ss));
    if (ip.family == 4) {
        auto* sin = reinterpret_cast<sockaddr_in*>(&ss);
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
        std::memcpy(&sin->sin_addr, ip.b.data(), 4);
        len = sizeof(sockaddr_in);
        return true;
    }
    if (ip.family == 6) {
        auto* sin6 = reinterpret_cast<sockaddr_in6*>(&ss);
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(port);
        std::memcpy(&sin6->sin6_addr, ip.b.data(), 16);
        len = sizeof(sockaddr_in6);
        return true;
    }
    return false;
}

std::string sockaddr_text(const sockaddr_storage& ss, uint16_t* port) {
    if (ss.ss_family == AF_INET) {
        const auto* sin = reinterpret_cast<const sockaddr_in*>(&ss);
        if (port) *port = ntohs(sin->sin_port);
        return parse::to_string(parse::make_v4(reinterpret_cast<const uint8_t*>(&sin->sin_addr)));
    }
    if (ss.ss_family == AF_INET6) {
        const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(&ss);
        if (port) *port = ntohs(sin6->sin6_port);
        return parse::to_string(parse::make_v6(reinterpret_cast<const uint8_t*>(&sin6->sin6_addr)));
    }
    return {};
}

} // namespace

void ensure_wsa() {
    static std::once_flag once;
    std::call_once(once, [] {
        WSADATA d{};
        ::WSAStartup(MAKEWORD(2, 2), &d);   // intentionally never cleaned up
    });
}

std::vector<parse::ip_addr_t> resolve(const std::string& host_in, std::string* error) {
    ensure_wsa();
    std::string host = host_in;
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') host = host.substr(1, host.size() - 2);
    if (auto lit = parse::parse_ip(host)) return {*lit};
    if (!parse::valid_host(host)) {
        if (error) *error = "invalid host name '" + parse::escape_nonprintable(host) + "'";
        return {};
    }
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    const int rc = ::getaddrinfo(host.c_str(), nullptr, &hints, &res);
    if (rc != 0 || !res) {
        if (error) *error = "cannot resolve '" + host + "' (error " + std::to_string(rc) + ")";
        return {};
    }
    std::vector<parse::ip_addr_t> v4, v6;
    for (addrinfo* p = res; p; p = p->ai_next) {
        if (p->ai_family == AF_INET && p->ai_addrlen >= sizeof(sockaddr_in)) {
            const auto* sin = reinterpret_cast<const sockaddr_in*>(p->ai_addr);
            auto a = parse::make_v4(reinterpret_cast<const uint8_t*>(&sin->sin_addr));
            if (std::find(v4.begin(), v4.end(), a) == v4.end()) v4.push_back(a);
        } else if (p->ai_family == AF_INET6 && p->ai_addrlen >= sizeof(sockaddr_in6)) {
            const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(p->ai_addr);
            auto a = parse::make_v6(reinterpret_cast<const uint8_t*>(&sin6->sin6_addr));
            if (std::find(v6.begin(), v6.end(), a) == v6.end()) v6.push_back(a);
        }
    }
    ::freeaddrinfo(res);
    v4.insert(v4.end(), v6.begin(), v6.end());
    if (v4.empty() && error) *error = "'" + host + "' has no addresses";
    return v4;
}

socket_t connect(const parse::ip_addr_t& ip, uint16_t port, int timeout_ms,
                 const std::atomic<bool>* cancel, std::string* error) {
    ensure_wsa();
    sockaddr_storage ss{};
    int len = 0;
    if (!fill_sockaddr(ip, port, ss, len)) {
        if (error) *error = "bad address";
        return kInvalid;
    }
    SOCKET s = ::socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        if (error) *error = "socket() failed (" + std::to_string(::WSAGetLastError()) + ")";
        return kInvalid;
    }
    u_long nb = 1;
    ::ioctlsocket(s, FIONBIO, &nb);
    const std::string where = parse::to_string(ip) + ":" + std::to_string(port);
    if (::connect(s, reinterpret_cast<const sockaddr*>(&ss), len) != 0) {
        const int e = ::WSAGetLastError();
        if (e != WSAEWOULDBLOCK) {
            ::closesocket(s);
            if (error) *error = "connect to " + where + " failed (" + std::to_string(e) + ")";
            return kInvalid;
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        for (;;) {
            if (cancel && cancel->load()) {
                ::closesocket(s);
                if (error) *error = "cancelled";
                return kInvalid;
            }
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  deadline - std::chrono::steady_clock::now()).count();
            if (left <= 0) {
                ::closesocket(s);
                if (error) *error = "connect to " + where + " timed out";
                return kInvalid;
            }
            WSAPOLLFD fd{s, POLLWRNORM, 0};
            const int r = ::WSAPoll(&fd, 1, static_cast<INT>(std::min<long long>(left, 250)));
            if (r < 0) break;
            if (r == 0) continue;
            int soerr = 0;
            int sl = sizeof(soerr);
            ::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &sl);
            if (soerr != 0 || (fd.revents & (POLLERR | POLLHUP))) {
                ::closesocket(s);
                if (error)
                    *error = "connect to " + where + " failed (" +
                             std::to_string(soerr ? soerr : WSAECONNREFUSED) + ")";
                return kInvalid;
            }
            break;
        }
    }
    nb = 0;
    ::ioctlsocket(s, FIONBIO, &nb);
    BOOL nodelay = TRUE;
    ::setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
    return static_cast<socket_t>(s);
}

bool send_all(socket_t s, const uint8_t* d, size_t n) {
    while (n > 0) {
        const int w = ::send(static_cast<SOCKET>(s), reinterpret_cast<const char*>(d),
                             static_cast<int>(std::min<size_t>(n, 1 << 20)), 0);
        if (w <= 0) return false;
        d += w;
        n -= static_cast<size_t>(w);
    }
    return true;
}

void set_timeouts(socket_t s, int rcv_ms, int snd_ms) {
    const DWORD r = static_cast<DWORD>(rcv_ms), w = static_cast<DWORD>(snd_ms);
    ::setsockopt(static_cast<SOCKET>(s), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&r), sizeof(r));
    ::setsockopt(static_cast<SOCKET>(s), SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&w), sizeof(w));
}

bool wait_readable(socket_t s, int timeout_ms, const std::atomic<bool>* cancel) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    for (;;) {
        if (cancel && cancel->load()) return false;
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                              deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) return false;
        WSAPOLLFD fd{static_cast<SOCKET>(s), POLLRDNORM, 0};
        const int r = ::WSAPoll(&fd, 1, static_cast<INT>(std::min<long long>(left, 250)));
        if (r < 0) return true;   // let the caller's recv surface the error
        if (r > 0) return true;
    }
}

void close(socket_t s) {
    if (s != kInvalid) ::closesocket(static_cast<SOCKET>(s));
}

std::string peer_address(socket_t s, uint16_t* port) {
    sockaddr_storage ss{};
    int len = sizeof(ss);
    if (::getpeername(static_cast<SOCKET>(s), reinterpret_cast<sockaddr*>(&ss), &len) != 0) return {};
    return sockaddr_text(ss, port);
}

std::string local_address(socket_t s, uint16_t* port) {
    sockaddr_storage ss{};
    int len = sizeof(ss);
    if (::getsockname(static_cast<SOCKET>(s), reinterpret_cast<sockaddr*>(&ss), &len) != 0) return {};
    return sockaddr_text(ss, port);
}

bool split_authority(const std::string& a, uint16_t default_port, std::string* host,
                     uint16_t* port) {
    std::string h = a, p;
    if (!a.empty() && a.front() == '[') {
        const size_t close = a.find(']');
        if (close == std::string::npos) return false;
        h = a.substr(1, close - 1);
        if (close + 1 < a.size()) {
            if (a[close + 1] != ':') return false;
            p = a.substr(close + 2);
        }
    } else if (std::count(a.begin(), a.end(), ':') == 1) {
        const size_t colon = a.find(':');
        h = a.substr(0, colon);
        p = a.substr(colon + 1);
    }
    uint32_t v = default_port;
    if (!p.empty()) {
        if (p.size() > 5) return false;
        v = 0;
        for (char c : p) {
            if (c < '0' || c > '9') return false;
            v = v * 10 + static_cast<uint32_t>(c - '0');
        }
        if (v == 0 || v > 65535) return false;
    }
    if (h.empty()) return false;
    *host = h;
    *port = static_cast<uint16_t>(v);
    return true;
}

} // namespace slop::core::network::sock
