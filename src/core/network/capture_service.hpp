#pragma once

// host-side packet capture: one raw socket per (interface, address family)
// in promiscuous mode via SIO_RCVALL (needs administrator). SIO_RCVALL
// delivers IP datagrams without link-layer framing; IPv4 and IPv6 are both
// captured, fragments are reassembled, and the interface/address set is
// refreshed while running. Raw capture cannot attribute packets to processes,
// so capture filters are host (e.g. the PS4's IP) / port / protocol

#include <cstdint>
#include <string>
#include <vector>

#include "core/network/parsers.hpp"
#include "core/network/traffic_store.hpp"

namespace slop::core::network {

using dns_record_t = parse::dns_record_t;

struct capture_filter_t {
    std::string host;          // IP literal: keep only packets to/from it ("" = all)
    uint16_t    port = 0;      // either side (0 = all)
    uint8_t     protocol = 0;  // 6 | 17 (0 = both)
};

struct capture_iface_t {
    std::string name;          // adapter friendly name
    std::string address;       // bound address
    uint8_t     family = 4;
    bool        active = false;
    std::string error;         // why it is not capturing
};

struct net_stats_t {
    bool     capture_active = false;
    uint64_t packets_seen = 0;           // datagrams read off the sockets
    uint64_t packets_in = 0, packets_out = 0;   // accepted (after filters)
    uint64_t bytes_in = 0, bytes_out = 0;       // IP-layer bytes of accepted packets
    uint64_t filtered_out = 0;           // rejected by the capture filter
    uint64_t parse_errors = 0;           // truncated / malformed / not IP
    uint64_t non_tcp_udp = 0;            // ICMP etc. (not stored)
    uint64_t fragments = 0;
    uint64_t fragments_reassembled = 0;
    uint64_t fragments_dropped = 0;
    uint64_t queue_dropped = 0;          // pending queue overflow before poll()
    uint64_t payload_truncated = 0;      // payload longer than the per-packet cap
    uint64_t dns_logged_total = 0;
    uint32_t dns_buffered = 0;
    uint32_t pending = 0;
    capture_filter_t filter;
    std::vector<capture_iface_t> interfaces;
};

namespace capture {

// payload bytes kept per packet; the wire length is recorded separately
inline constexpr size_t kMaxPayload = 2048;

bool running();

// Starts capture: enumerates interfaces, opens and binds a raw socket per
// interface/family and enables SIO_RCVALL synchronously, so failures are
// reported here. When already running the filter is replaced in place and
// *updated is set. Invalid filters (non-IP host, bad protocol) are errors
std::string start(const capture_filter_t& filter, bool* updated = nullptr);
std::string stop();

// Moves captured packets into the store. Returns the number moved
size_t poll(traffic_store_t& sink, size_t max_packets = 512);

// DNS messages seen (queries and responses), oldest first; `host` limits to
// one client/server address ("" = all)
std::vector<dns_record_t> dns_queries(const std::string& host = {});

net_stats_t stats();

// drains pending packets into the store, then writes the newest
// `max_packets` stored packets as pcap
std::string export_pcap(traffic_store_t& store, const std::string& path,
                        uint32_t max_packets = 4096, size_t* exported = nullptr,
                        bool* truncated = nullptr);

// deterministic hooks: feed datagrams through the exact socket-thread path
namespace testing {
void reset();
void set_local_addresses(const std::vector<std::string>& addrs);
// sets the filter without opening sockets
std::string set_filter(const capture_filter_t& filter);
void inject(const uint8_t* d, size_t n, int64_t now_ms);
// what an IPv6 raw socket delivers: transport bytes plus the addresses
// reported by WSARecvMsg
void inject_v6_transport(const std::string& src, const std::string& dst, const uint8_t* d,
                         size_t n, int64_t now_ms);
} // namespace testing

} // namespace capture
} // namespace slop::core::network
