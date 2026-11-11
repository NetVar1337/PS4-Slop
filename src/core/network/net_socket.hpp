#pragma once

// src/core/network/net_socket.hpp
// small blocking-socket helpers shared by the proxy, replay and the web
// client: resolve once, connect to an already vetted address with a deadline
// and a cancel flag, bounded waits

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "core/network/parsers.hpp"

namespace slop::core::network::sock {

using socket_t = uintptr_t;   // SOCKET
inline constexpr socket_t kInvalid = ~static_cast<uintptr_t>(0);

// WSAStartup once per process
void ensure_wsa();

// all addresses of `host` (literal or DNS name), IPv4 first
std::vector<parse::ip_addr_t> resolve(const std::string& host, std::string* error);

// connects to exactly `ip`:`port`; aborts when `cancel` becomes true
socket_t connect(const parse::ip_addr_t& ip, uint16_t port, int timeout_ms,
                 const std::atomic<bool>* cancel, std::string* error);

bool send_all(socket_t s, const uint8_t* d, size_t n);
void set_timeouts(socket_t s, int rcv_ms, int snd_ms);
// true when readable (or closed/errored), false on timeout or cancel
bool wait_readable(socket_t s, int timeout_ms, const std::atomic<bool>* cancel);
void close(socket_t s);
std::string peer_address(socket_t s, uint16_t* port = nullptr);
std::string local_address(socket_t s, uint16_t* port = nullptr);

// "host:port", "[v6]:port" or "host" (default_port); false on a bad port
bool split_authority(const std::string& authority, uint16_t default_port,
                     std::string* host, uint16_t* port);

} // namespace slop::core::network::sock
