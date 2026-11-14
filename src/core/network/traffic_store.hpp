#pragma once

// in memory traffic store: bounded packet ring, per-tuple stream reassembly
// under a global byte budget with LRU stream eviction, display filters, and
// pcap export (LINKTYPE_RAW) with synthesized IPv4/IPv6 + TCP/UDP headers

#include <cstdint>
#include <deque>
#include <list>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/network/parsers.hpp"

namespace slop::core::network {

struct packet_record_t {
    uint64_t              id = 0;          // monotonic store id
    int64_t               at_ms = 0;       // wall clock
    uint32_t              protocol = 0;    // 6 TCP / 17 UDP
    uint32_t              direction = 0;   // 0 outbound (local -> remote), 1 inbound
    uint8_t               ip_version = 4;  // 4 | 6
    std::string           local_addr;
    uint16_t              local_port = 0;
    std::string           remote_addr;
    uint16_t              remote_port = 0;
    uint32_t              wire_len = 0;    // payload bytes on the wire (>= payload.size(); 0 = same)
    uint32_t              tcp_seq = 0;
    uint32_t              tcp_ack = 0;
    uint8_t               tcp_flags = 0;
    uint64_t              stream_id = 0;   // assigned by the store
    std::vector<uint8_t>  payload;         // captured payload (may be a prefix of the wire payload)
};

struct stream_summary_t {
    uint64_t    id = 0;
    uint32_t    protocol = 0;
    std::string key;            // "tcp 10.0.0.2:1234<->1.1.1.1:80"
    std::string client_addr;    // first outbound sender, else the lower tuple
    uint16_t    client_port = 0;
    std::string server_addr;
    uint16_t    server_port = 0;
    size_t      bytes = 0;      // reassembled bytes held (both directions)
    size_t      packets = 0;
    bool        truncated = false;   // a direction hit the per-stream cap
    int64_t     first_ms = 0;
    int64_t     last_ms = 0;
};

class traffic_store_t {
public:
    struct limits_t {
        size_t max_packets = 20000;
        size_t max_streams = 4096;
        size_t max_stream_bytes = 64u << 20;      // all streams, both directions
        size_t max_direction_bytes = 1u << 20;    // one direction of one stream
    };

    explicit traffic_store_t(size_t max_packets = 20000);
    explicit traffic_store_t(limits_t limits);

    void clear();
    void add(packet_record_t pkt);                       // assigns id

    // Packets oldest-first with id > from_id, capped
    struct page_t { std::vector<packet_record_t> items; bool truncated = false; };
    page_t packets(uint64_t from_id, size_t limit) const;
    // the newest `limit` packets, oldest-first; truncated when older ones exist
    page_t packets_tail(size_t limit) const;

    // streams, most recently active first
    std::vector<stream_summary_t> streams(size_t limit = SIZE_MAX) const;
    std::optional<stream_summary_t> stream(uint64_t id) const;

    // Reassembled payload slice of one stream: client->server bytes, then
    // server->client bytes (each in arrival order)
    std::optional<std::vector<uint8_t>> stream_bytes(uint64_t id,
                                                     size_t offset, size_t len) const;

    // display filters: predicates ANDed with ';'
    //   port=80 | port==80 | port:80   either side port (strict 0..65535)
    //   host:1.2.3.4 | host:10.0.0.0/8 | host:fe80::1   exact address or CIDR, either side
    //   text:foo                       payload byte substring
    //   proto:tcp|udp|<num>
    //   dir:in|out
    // unknown predicates and malformed values are errors
    class filter_t {
    public:
        bool match(const packet_record_t& p) const;
    private:
        friend class traffic_store_t;
        struct term_t {
            enum class kind_t { port, host, text, proto, dir } kind = kind_t::port;
            uint32_t number = 0;
            parse::cidr_t cidr;
            std::string text;
        };
        std::vector<term_t> terms_;
    };
    static std::optional<filter_t> compile_filter(const std::string& expr,
                                                  std::string* error = nullptr);
    // invalid expressions set *error and return an empty page
    page_t packets_filtered(uint64_t from_id, size_t limit, const std::string& expr,
                            std::string* error = nullptr) const;

    // pcap (LINKTYPE_RAW) export. Unparseable or mixed-family addresses and
    // write failures are errors; the partial file is removed. orig_len carries
    // the wire length when the capture kept only a payload prefix
    bool write_pcap(const std::string& path,
                    const std::vector<packet_record_t>& pkts,
                    std::string* error = nullptr) const;

    // pcapng (LINKTYPE_RAW) export: one EPB per packet, carrying the packet's
    // annotation as an epb_comment when it has one (a stream annotation applies
    // to every packet of that stream)
    bool write_pcapng(const std::string& path,
                      const std::vector<packet_record_t>& pkts,
                      std::string* error = nullptr) const;

    // annotations for pcapng export; false when the id is unknown
    bool annotate_packet(uint64_t id, std::string comment);
    bool annotate_stream(uint64_t id, std::string comment);

    size_t size() const;

    struct stats_t {
        size_t   packets = 0;
        size_t   streams = 0;
        size_t   stream_bytes = 0;          // reassembly bytes currently held
        uint64_t packets_evicted = 0;       // fell off the packet ring
        uint64_t streams_evicted = 0;       // LRU-evicted (count or byte budget)
        uint64_t stream_bytes_dropped = 0;  // payload not kept (per-direction cap)
        uint64_t packets_total = 0;         // ever added
        uint64_t quic_packets = 0;          // UDP/443 packets with a QUIC long header
    };
    stats_t stats() const;
    // streams with activity in [now_ms - window_ms, now_ms]
    size_t active_streams(int64_t now_ms, int64_t window_ms) const;

private:
    struct stream_key_t {
        uint32_t protocol = 0;
        std::string a_addr; uint16_t a_port = 0;
        std::string b_addr; uint16_t b_port = 0;
        bool operator<(const stream_key_t& o) const {
            if (protocol != o.protocol) return protocol < o.protocol;
            if (a_addr != o.a_addr) return a_addr < o.a_addr;
            if (a_port != o.a_port) return a_port < o.a_port;
            if (b_addr != o.b_addr) return b_addr < o.b_addr;
            return b_port < o.b_port;
        }
    };

    struct stream_rec_t {
        stream_key_t key;
        std::vector<uint8_t> c2s;      // client -> server bytes
        std::vector<uint8_t> s2c;
        size_t c2s_packets = 0, s2c_packets = 0;
        int64_t first_ms = 0, last_ms = 0;
        uint64_t id = 0;
        bool has_client = false;
        bool truncated = false;
        std::string client_addr;
        uint16_t    client_port = 0;
        std::string server_addr;
        uint16_t    server_port = 0;
        std::list<stream_rec_t*>::iterator lru;
    };

    limits_t lim_;
    mutable std::mutex mu_;
    std::deque<packet_record_t> pkts_;
    uint64_t next_id_ = 1;

    std::map<stream_key_t, stream_rec_t> streams_;      // node-based: stable addresses
    std::unordered_map<uint64_t, stream_rec_t*> by_id_;
    std::list<stream_rec_t*> lru_;                      // front = most recent
    uint64_t next_stream_id_ = 1;
    size_t   stream_bytes_ = 0;
    uint64_t packets_evicted_ = 0, streams_evicted_ = 0, bytes_dropped_ = 0;
    uint64_t quic_packets_ = 0;
    std::map<uint64_t, std::string> pkt_notes_, stream_notes_;

    void index_stream(packet_record_t& p);
    void evict_streams(const stream_rec_t* keep);
    stream_summary_t summarize(const stream_rec_t& s) const;
};

} // namespace slop::core::network
