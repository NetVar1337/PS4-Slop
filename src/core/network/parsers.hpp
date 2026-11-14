#pragma once

// src/core/network/parsers.hpp
// pure parsers for attacker-controlled bytes: IPv4/IPv6 datagrams from the raw
// capture sockets (+ fragment reassembly), TCP/UDP headers, DNS messages, TLS
// ClientHello SNI, HTTP/1.x message framing, plus address/host helpers shared
// by the capture filter, the proxy allowlist and the web egress guard.
// No sockets and no globals: every routine is bounds-checked against its input
// length and is driven by the deterministic mutation fuzz tests in
// src/tests/test_network.cpp

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace slop::core::network::parse {

// addresses

struct ip_addr_t {
    uint8_t family = 0;                // 4 | 6, 0 = unset
    std::array<uint8_t, 16> b{};       // v4 uses b[0..3]
    bool operator==(const ip_addr_t&) const = default;
    bool valid() const { return family == 4 || family == 6; }
};

// dotted IPv4 or IPv6 literal ("[::1]" brackets and "%scope" accepted)
std::optional<ip_addr_t> parse_ip(std::string_view text);
std::string to_string(const ip_addr_t& a);
ip_addr_t make_v4(const uint8_t* four);
ip_addr_t make_v6(const uint8_t* sixteen);

struct cidr_t {
    ip_addr_t net;
    int prefix = 0;
};
// "10.0.0.0/8", "fe80::/10", or a bare address (full-length prefix)
std::optional<cidr_t> parse_cidr(std::string_view text);
bool cidr_contains(const cidr_t& c, const ip_addr_t& a);

// loopback, unspecified, RFC1918, CGNAT, link-local, ULA, multicast, reserved,
// benchmark nets, and IPv4-mapped / NAT64 / 6to4 embeddings of any of those
bool is_non_public(const ip_addr_t& a);

// DNS hostname (LDH labels 1-63, total <= 253, at least one char) or IP literal
bool valid_host(std::string_view host);
std::string lower(std::string_view s);

// allowlist pattern: exact host (case-insensitive), "*.suffix" (subdomains
// only), IP literal, or CIDR. `addr` is the resolved address when known
bool host_pattern_match(std::string_view pattern, std::string_view host,
                        const ip_addr_t* addr);

// bytes outside 0x20..0x7E become \xHH so strings stay valid UTF-8 / JSON
std::string escape_nonprintable(std::string_view s);

// base64 (standard alphabet, padding optional); nullopt on bad input
std::optional<std::string> base64_decode(std::string_view in);
std::string base64_encode(const uint8_t* d, size_t n);

// IP / L4

enum class status_t : uint8_t {
    ok,
    truncated,      // fewer captured bytes than the headers need
    not_ip,         // version nibble is neither 4 nor 6
    malformed,      // inconsistent lengths / header fields
    unsupported,    // valid IP but not TCP/UDP (or no upper layer)
};
const char* status_name(status_t s);

struct ip_info_t {
    ip_addr_t src, dst;
    uint8_t   proto = 0;           // upper-layer protocol after v6 ext headers
    const uint8_t* l4 = nullptr;
    size_t    l4_len = 0;          // captured bytes, clamped to the declared length
    uint32_t  l4_wire_len = 0;     // l4 length declared by the IP header
    bool      fragment = false;    // part of a fragmented datagram
    uint32_t  frag_id = 0;
    uint32_t  frag_offset = 0;     // bytes
    bool      more_fragments = false;
};

// parses the IP header at offset 0 (SIO_RCVALL delivers IP datagrams, no
// link-layer framing). total_len / payload_len bound everything after it
status_t parse_ip(const uint8_t* d, size_t n, ip_info_t& out);

// skips IPv6 extension headers (hop-by-hop, routing, destination options, AH)
// in a reassembled fragmentable part; updates proto/data/len in place
status_t skip_v6_ext(uint8_t& proto, const uint8_t*& d, size_t& n);

// Windows IPv6 raw sockets (even with SIO_RCVALL) deliver only the bytes
// after the last IPv6 header; source/destination come from the socket API.
// The next-header value is inferred: UDP/TCP/ICMPv6 by checksum over the
// pseudo-header, then UDP by length, an IPv6 fragment header by shape, and
// TCP by a sane data offset (outbound packets may carry offloaded, not yet
// computed checksums). Returns 6, 17, 58, 44 or 0 (unknown)
uint8_t infer_v6_transport(const ip_addr_t& src, const ip_addr_t& dst, const uint8_t* d, size_t n);

struct l4_info_t {
    uint16_t src_port = 0, dst_port = 0;
    const uint8_t* payload = nullptr;
    size_t   payload_len = 0;      // captured payload bytes
    uint32_t payload_wire_len = 0; // payload length on the wire
    uint32_t tcp_seq = 0, tcp_ack = 0;
    uint8_t  tcp_flags = 0;
};

// TCP payload = l4_wire_len - data offset; UDP payload is clamped to udp.len
status_t parse_l4(uint8_t proto, const uint8_t* l4, size_t l4_len,
                  uint32_t l4_wire_len, l4_info_t& out);

// bounded IPv4/IPv6 fragment reassembly; unfinished datagrams expire after
// `timeout_ms` and the oldest are dropped when either cap is exceeded
class reassembler_t {
public:
    struct limits_t {
        size_t  max_datagrams = 64;
        size_t  max_bytes = 4u << 20;
        int64_t timeout_ms = 30000;
    };
    struct datagram_t {
        uint8_t proto = 0;
        std::vector<uint8_t> l4;   // complete fragmentable part
    };

    reassembler_t() = default;
    explicit reassembler_t(limits_t l) : lim_(l) {}

    // feed one fragment (ip.fragment == true). Returns the datagram once every
    // byte of it has arrived
    std::optional<datagram_t> add(const ip_info_t& ip, int64_t now_ms);

    size_t   pending() const { return parts_.size(); }
    size_t   bytes() const { return bytes_; }
    uint64_t dropped() const { return dropped_; }
    uint64_t completed() const { return completed_; }
    void     clear();

private:
    struct key_t {
        uint8_t family = 0, proto = 0;
        std::array<uint8_t, 16> src{}, dst{};
        uint32_t id = 0;
        auto operator<=>(const key_t&) const = default;
    };
    struct part_t {
        std::vector<uint8_t> data;
        std::map<uint32_t, uint32_t> have;   // merged [start, end) ranges
        uint32_t total = 0;                  // 0 until the last fragment arrives
        int64_t  first_ms = 0;
        uint8_t  proto = 0;                  // from the offset-0 fragment (v6)
        bool     have_first = false;
    };

    limits_t lim_{};
    std::map<key_t, part_t> parts_;
    size_t   bytes_ = 0;
    uint64_t dropped_ = 0;
    uint64_t completed_ = 0;

    void expire(int64_t now_ms);
    void drop(std::map<key_t, part_t>::iterator it);
};

// DNS

struct dns_record_t {
    uint64_t    timestamp = 0;
    bool        is_response = false;
    uint32_t    query_type = 0;
    std::string domain;
    std::string resolved_addr;           // first A/AAAA answer
    std::vector<std::string> answers;    // all A/AAAA answers (capped)
    uint32_t    response_code = 0;
    uint32_t    ttl = 0;
    std::string client_addr;             // filled by the capture service
    std::string server_addr;
};

// parses one DNS message (UDP payload). Names are escaped printable ASCII;
// compression pointers must point backwards and are hop-limited
std::optional<dns_record_t> parse_dns(const uint8_t* d, size_t n);

// TLS

// server_name from a TLS ClientHello in the first record of `d`; every length
// field is clamped against both the record and the buffer. Empty when absent
// or not a valid hostname
std::string extract_sni(const uint8_t* d, size_t n);

// QUIC

// long-header packet (RFC 9000 §17.2): version, connection ids and the packet
// type. Short headers carry no version, so they are not identified. nullopt
// when the bytes are not a complete long header
struct quic_info_t {
    uint32_t    version = 0;
    uint8_t     type = 0;          // 0 initial, 1 0-RTT, 2 handshake, 3 retry
    std::string dcid, scid;        // hex, 0..20 bytes each
    bool        has_length = false;
    uint64_t    length = 0;        // declared bytes after the length field
};
std::optional<quic_info_t> parse_quic(const uint8_t* d, size_t n);
const char* quic_type_name(uint8_t type);
const char* quic_version_name(uint32_t version);

// HTTP/1.x

struct http_head_t {
    std::string method, target, version;      // request line
    uint32_t    status = 0;                   // status line (responses)
    std::string reason;
    std::vector<std::pair<std::string, std::string>> headers;   // name lowercased
    // first value of `name` (lowercase), nullptr when absent
    const std::string* get(std::string_view name) const;
};

// parses a head up to and including CRLFCRLF; `response` selects the start line
std::optional<http_head_t> parse_http_head(std::string_view head, bool response);
// offset just past CRLFCRLF in [d, d+n) starting the scan at `from`, or npos
size_t find_head_end(const uint8_t* d, size_t n, size_t from = 0);

// decodes a complete chunked body (chunk extensions and trailers ignored);
// false when the encoding is malformed or incomplete
bool decode_chunked(const uint8_t* d, size_t n, std::vector<uint8_t>& out);

// incremental message framer for one direction of an HTTP/1.x connection;
// reports where each message head ends and each message ends, tracking
// Content-Length / chunked / close-delimited bodies so keep-alive streams
// stay aligned
class http_framer_t {
public:
    struct event_t {
        enum class kind_t { head, end } kind = kind_t::head;
        size_t      at = 0;          // offset in the fed chunk just past the head / message
        bool        interim = false; // 1xx response: the request is still pending
        std::string head;            // raw head incl. CRLFCRLF (head events)
    };

    explicit http_framer_t(bool response) : response_(response) {}

    // the method of the request this response answers (HEAD has no body)
    void expect_response_to(std::string method) { pending_methods_.push_back(std::move(method)); }

    void feed(const uint8_t* d, size_t n, std::vector<event_t>* events = nullptr);
    // signals EOF; a close-delimited body completes here (end event at 0)
    void finish(std::vector<event_t>* events = nullptr);

    bool   broken() const { return state_ == st_t::broken; }
    bool   idle() const { return state_ == st_t::head && head_buf_.empty(); }
    bool   until_close() const { return state_ == st_t::until_close; }
    size_t messages_completed() const { return completed_; }
    const std::string& error() const { return error_; }

private:
    enum class st_t { head, body, chunk_size, chunk_data, chunk_crlf, trailer,
                      until_close, broken };
    bool        response_;
    st_t        state_ = st_t::head;
    std::string head_buf_;
    std::string line_buf_;
    uint64_t    remaining_ = 0;
    size_t      completed_ = 0;
    std::deque<std::string> pending_methods_;
    std::string error_;

    void on_head(size_t at, std::vector<event_t>* events);
    void message_done(size_t at, std::vector<event_t>* events);
    void fail(const char* why);
};

} // namespace slop::core::network::parse
