#pragma once

// host-side packet capture front end (raw socket in promiscuous mode via
// SIO_RCVALL) pulling packets into the traffic store; needs administrator
// for RCVALL, degrades with a clear error when unavailable

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/network/traffic_store.hpp"

namespace slop::core::network {

struct dns_record_t {
    uint64_t    timestamp = 0;
    uint32_t    pid = 0;
    uint32_t    query_type = 0;
    std::string domain;
    std::string resolved_addr;
    uint32_t    response_code = 0;
    uint32_t    ttl = 0;
};

struct net_stats_t {
    uint64_t bytes_sent = 0, bytes_received = 0;
    uint64_t packets_sent = 0, packets_received = 0;
    uint32_t active_connections = 0;
    bool     capture_active = false;
    uint32_t total_captured = 0, total_dropped = 0;
    uint32_t total_dns_logged = 0;
};

namespace capture {

// true while the raw-socket capture thread is running
bool running();

// Start host capture. Zero filters = capture everything. filter_pid/port/
// protocol are applied when packets are pulled into the store.
std::string start(uint32_t filter_pid = 0, uint32_t filter_port = 0,
                  uint32_t filter_protocol = 0);

std::string stop();

// Pull newly captured packets into the store. Returns count pulled
size_t poll(traffic_store_t& sink, size_t max_packets = 512);

std::vector<dns_record_t> dns_queries(uint32_t filter_pid = 0);

net_stats_t stats();

// pcap export from the in-memory store, written to `path`
std::string export_pcap(const traffic_store_t& store, const std::string& path,
                        uint32_t max_packets = 4096);

} // namespace capture
} // namespace slop::core::network
