// src/core/network/traffic_store.cpp

#include "core/network/traffic_store.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace slop::core::network {

namespace {

constexpr uint32_t kProtoTcp = 6;
constexpr uint32_t kProtoUdp = 17;

const char* proto_label(uint32_t p) {
    return p == kProtoTcp ? "tcp" : p == kProtoUdp ? "udp" : "ip";
}

void put16(std::vector<uint8_t>& v, size_t at, uint32_t x) {
    v[at] = static_cast<uint8_t>((x >> 8) & 0xFF);
    v[at + 1] = static_cast<uint8_t>(x & 0xFF);
}

void put32(std::vector<uint8_t>& v, size_t at, uint32_t x) {
    v[at] = static_cast<uint8_t>(x >> 24);
    v[at + 1] = static_cast<uint8_t>((x >> 16) & 0xFF);
    v[at + 2] = static_cast<uint8_t>((x >> 8) & 0xFF);
    v[at + 3] = static_cast<uint8_t>(x & 0xFF);
}

uint16_t ipv4_checksum(const uint8_t* h, size_t n) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < n; i += 2)
        sum += (static_cast<uint32_t>(h[i]) << 8) | h[i + 1];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum & 0xFFFF);
}

bool parse_port(const std::string& s, uint32_t& out) {
    if (s.empty() || s.size() > 5) return false;
    uint32_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + static_cast<uint32_t>(c - '0');
    }
    if (v > 65535) return false;
    out = v;
    return true;
}

} // namespace

traffic_store_t::traffic_store_t(size_t max_packets) {
    lim_.max_packets = max_packets;
}

traffic_store_t::traffic_store_t(limits_t limits) : lim_(limits) {
    // one full stream must always fit the global budget
    lim_.max_stream_bytes = std::max(lim_.max_stream_bytes, 2 * lim_.max_direction_bytes);
    lim_.max_streams = std::max<size_t>(lim_.max_streams, 1);
}

void traffic_store_t::clear() {
    std::lock_guard lk(mu_);
    pkts_.clear();
    streams_.clear();
    by_id_.clear();
    lru_.clear();
    stream_bytes_ = 0;
    next_id_ = 1;
    next_stream_id_ = 1;
    packets_evicted_ = streams_evicted_ = bytes_dropped_ = 0;
    quic_packets_ = 0;
    pkt_notes_.clear();
    stream_notes_.clear();
}

void traffic_store_t::evict_streams(const stream_rec_t* keep) {
    while (!lru_.empty() &&
           (streams_.size() > lim_.max_streams || stream_bytes_ > lim_.max_stream_bytes)) {
        stream_rec_t* victim = lru_.back();
        if (victim == keep) {
            if (lru_.size() == 1) break;
            // keep is never the least recent after a touch; defensive only
            lru_.splice(lru_.begin(), lru_, victim->lru);
            continue;
        }
        stream_bytes_ -= victim->c2s.size() + victim->s2c.size();
        by_id_.erase(victim->id);
        stream_notes_.erase(victim->id);
        lru_.pop_back();
        streams_.erase(victim->key);
        ++streams_evicted_;
    }
}

void traffic_store_t::index_stream(packet_record_t& p) {
    stream_key_t key;
    key.protocol = p.protocol;

    // stable tuple normalization: lower (addr,port) is side a
    const bool local_is_a =
        p.local_addr < p.remote_addr ||
        (p.local_addr == p.remote_addr && p.local_port <= p.remote_port);
    key.a_addr = local_is_a ? p.local_addr : p.remote_addr;
    key.a_port = local_is_a ? p.local_port : p.remote_port;
    key.b_addr = local_is_a ? p.remote_addr : p.local_addr;
    key.b_port = local_is_a ? p.remote_port : p.local_port;

    auto it = streams_.find(key);
    if (it == streams_.end()) {
        it = streams_.emplace(key, stream_rec_t{}).first;
        stream_rec_t& rec = it->second;
        rec.key = key;
        rec.id = next_stream_id_++;
        rec.first_ms = p.at_ms;
        lru_.push_front(&rec);
        rec.lru = lru_.begin();
        by_id_.emplace(rec.id, &rec);
    } else {
        lru_.splice(lru_.begin(), lru_, it->second.lru);
    }
    stream_rec_t& s = it->second;
    p.stream_id = s.id;
    s.last_ms = p.at_ms;
    if (!s.has_client && p.direction == 0) {
        s.has_client  = true;
        s.client_addr = p.local_addr;
        s.client_port = p.local_port;
        s.server_addr = p.remote_addr;
        s.server_port = p.remote_port;
    }
    // the client is the local side of the first outbound packet, so outbound
    // bytes are client->server for the whole stream
    const bool c2s = p.direction == 0;
    auto& buf = c2s ? s.c2s : s.s2c;
    const size_t room = buf.size() < lim_.max_direction_bytes
                            ? lim_.max_direction_bytes - buf.size() : 0;
    const size_t take = std::min(p.payload.size(), room);
    if (take) {
        buf.insert(buf.end(), p.payload.begin(), p.payload.begin() + static_cast<std::ptrdiff_t>(take));
        stream_bytes_ += take;
    }
    if (take < p.payload.size()) {
        s.truncated = true;
        bytes_dropped_ += p.payload.size() - take;
    }
    ++(c2s ? s.c2s_packets : s.s2c_packets);
    evict_streams(&s);
}

void traffic_store_t::add(packet_record_t pkt) {
    std::lock_guard lk(mu_);
    pkt.id = next_id_++;
    if (pkt.protocol == kProtoUdp && (pkt.local_port == 443 || pkt.remote_port == 443) &&
        parse::parse_quic(pkt.payload.data(), pkt.payload.size()))
        ++quic_packets_;
    index_stream(pkt);
    pkts_.push_back(std::move(pkt));
    while (pkts_.size() > lim_.max_packets) {
        pkt_notes_.erase(pkts_.front().id);
        pkts_.pop_front();
        ++packets_evicted_;
    }
}

traffic_store_t::page_t traffic_store_t::packets(uint64_t from_id,
                                                 size_t limit) const {
    std::lock_guard lk(mu_);
    page_t out;
    // ids are contiguous in the ring: jump straight to the first newer id
    size_t start = 0;
    if (!pkts_.empty() && from_id >= pkts_.front().id)
        start = static_cast<size_t>(std::min<uint64_t>(from_id - pkts_.front().id + 1, pkts_.size()));
    for (size_t i = start; i < pkts_.size(); ++i) {
        if (out.items.size() >= limit) { out.truncated = true; break; }
        out.items.push_back(pkts_[i]);
    }
    return out;
}

traffic_store_t::page_t traffic_store_t::packets_tail(size_t limit) const {
    std::lock_guard lk(mu_);
    page_t out;
    const size_t start = pkts_.size() > limit ? pkts_.size() - limit : 0;
    out.truncated = start > 0;
    out.items.assign(pkts_.begin() + static_cast<std::ptrdiff_t>(start), pkts_.end());
    return out;
}

size_t traffic_store_t::size() const {
    std::lock_guard lk(mu_);
    return pkts_.size();
}

stream_summary_t traffic_store_t::summarize(const stream_rec_t& s) const {
    stream_summary_t sum;
    sum.id = s.id;
    sum.protocol = s.key.protocol;
    const bool v6a = s.key.a_addr.find(':') != std::string::npos;
    const bool v6b = s.key.b_addr.find(':') != std::string::npos;
    sum.key = std::string(proto_label(s.key.protocol)) + " " +
              (v6a ? "[" + s.key.a_addr + "]" : s.key.a_addr) + ":" +
              std::to_string(s.key.a_port) + "<->" +
              (v6b ? "[" + s.key.b_addr + "]" : s.key.b_addr) + ":" +
              std::to_string(s.key.b_port);
    sum.client_addr = s.has_client ? s.client_addr : s.key.a_addr;
    sum.client_port = s.has_client ? s.client_port : s.key.a_port;
    sum.server_addr = s.has_client ? s.server_addr : s.key.b_addr;
    sum.server_port = s.has_client ? s.server_port : s.key.b_port;
    sum.bytes = s.c2s.size() + s.s2c.size();
    sum.packets = s.c2s_packets + s.s2c_packets;
    sum.truncated = s.truncated;
    sum.first_ms = s.first_ms;
    sum.last_ms = s.last_ms;
    return sum;
}

std::vector<stream_summary_t> traffic_store_t::streams(size_t limit) const {
    std::lock_guard lk(mu_);
    std::vector<stream_summary_t> out;
    out.reserve(std::min(limit, lru_.size()));
    for (const stream_rec_t* s : lru_) {
        if (out.size() >= limit) break;
        out.push_back(summarize(*s));
    }
    return out;
}

std::optional<stream_summary_t> traffic_store_t::stream(uint64_t id) const {
    std::lock_guard lk(mu_);
    const auto it = by_id_.find(id);
    if (it == by_id_.end()) return std::nullopt;
    return summarize(*it->second);
}

std::optional<std::vector<uint8_t>> traffic_store_t::stream_bytes(
    uint64_t id, size_t offset, size_t len) const {
    std::lock_guard lk(mu_);
    const auto it = by_id_.find(id);
    if (it == by_id_.end()) return std::nullopt;
    const stream_rec_t& s = *it->second;
    const size_t total = s.c2s.size() + s.s2c.size();
    if (offset >= total) return std::vector<uint8_t>{};
    const size_t take = std::min(len, total - offset);
    std::vector<uint8_t> out;
    out.reserve(take);
    if (offset < s.c2s.size()) {
        const size_t first = std::min(take, s.c2s.size() - offset);
        out.insert(out.end(), s.c2s.begin() + static_cast<std::ptrdiff_t>(offset),
                   s.c2s.begin() + static_cast<std::ptrdiff_t>(offset + first));
        offset = 0;
    } else {
        offset -= s.c2s.size();
    }
    const size_t remaining = take - out.size();
    out.insert(out.end(), s.s2c.begin() + static_cast<std::ptrdiff_t>(offset),
               s.s2c.begin() + static_cast<std::ptrdiff_t>(offset + remaining));
    return out;
}

traffic_store_t::stats_t traffic_store_t::stats() const {
    std::lock_guard lk(mu_);
    stats_t s;
    s.packets = pkts_.size();
    s.streams = streams_.size();
    s.stream_bytes = stream_bytes_;
    s.packets_evicted = packets_evicted_;
    s.streams_evicted = streams_evicted_;
    s.stream_bytes_dropped = bytes_dropped_;
    s.packets_total = next_id_ - 1;
    s.quic_packets = quic_packets_;
    return s;
}

size_t traffic_store_t::active_streams(int64_t now_ms, int64_t window_ms) const {
    std::lock_guard lk(mu_);
    size_t n = 0;
    for (const stream_rec_t* s : lru_) {
        if (now_ms - s->last_ms > window_ms) break;   // lru_ is recency ordered
        ++n;
    }
    return n;
}

// filters

bool traffic_store_t::filter_t::match(const packet_record_t& p) const {
    for (const auto& t : terms_) {
        bool pass = false;
        switch (t.kind) {
        case term_t::kind_t::port:
            pass = p.local_port == t.number || p.remote_port == t.number;
            break;
        case term_t::kind_t::host: {
            const auto la = parse::parse_ip(p.local_addr);
            const auto ra = parse::parse_ip(p.remote_addr);
            pass = (la && parse::cidr_contains(t.cidr, *la)) ||
                   (ra && parse::cidr_contains(t.cidr, *ra));
            break;
        }
        case term_t::kind_t::text:
            pass = std::search(p.payload.begin(), p.payload.end(),
                               t.text.begin(), t.text.end()) != p.payload.end();
            break;
        case term_t::kind_t::proto:
            pass = p.protocol == t.number;
            break;
        case term_t::kind_t::dir:
            pass = p.direction == t.number;
            break;
        }
        if (!pass) return false;
    }
    return true;
}

std::optional<traffic_store_t::filter_t> traffic_store_t::compile_filter(
    const std::string& expr, std::string* error) {
    static constexpr char kSyntax[] =
        " (syntax: port=80 | host:1.2.3.4 | host:10.0.0.0/8 | text:foo | proto:tcp|udp|N | "
        "dir:in|out, joined with ';')";
    auto bad = [&](const std::string& why) -> std::optional<filter_t> {
        if (error) *error = "filter: " + why + kSyntax;
        return std::nullopt;
    };
    filter_t f;
    size_t begin = 0;
    while (begin <= expr.size()) {
        size_t end = expr.find(';', begin);
        if (end == std::string::npos) end = expr.size();
        std::string term = expr.substr(begin, end - begin);
        begin = end + 1;
        while (!term.empty() && (term.front() == ' ' || term.front() == '\t')) term.erase(term.begin());
        while (!term.empty() && (term.back() == ' ' || term.back() == '\t')) term.pop_back();
        if (term.empty()) continue;

        // name followed by '=', '==' or ':'
        const size_t sep = term.find_first_of("=:");
        if (sep == std::string::npos) return bad("missing value in '" + term + "'");
        const std::string name = parse::lower(term.substr(0, sep));
        size_t vstart = sep + 1;
        if (term[sep] == '=' && vstart < term.size() && term[vstart] == '=') ++vstart;
        const std::string value = term.substr(vstart);

        filter_t::term_t t;
        if (name == "port") {
            t.kind = filter_t::term_t::kind_t::port;
            if (!parse_port(value, t.number)) return bad("bad port '" + value + "'");
        } else if (name == "host") {
            t.kind = filter_t::term_t::kind_t::host;
            auto c = parse::parse_cidr(value);
            if (!c) return bad("host expects an IP address or CIDR, got '" + value + "'");
            t.cidr = *c;
        } else if (name == "text") {
            t.kind = filter_t::term_t::kind_t::text;
            if (value.empty()) return bad("empty text");
            t.text = value;
        } else if (name == "proto") {
            t.kind = filter_t::term_t::kind_t::proto;
            const std::string v = parse::lower(value);
            if (v == "tcp") t.number = kProtoTcp;
            else if (v == "udp") t.number = kProtoUdp;
            else if (!parse_port(v, t.number) || t.number > 255) return bad("bad proto '" + value + "'");
        } else if (name == "dir") {
            t.kind = filter_t::term_t::kind_t::dir;
            const std::string v = parse::lower(value);
            if (v == "out" || v == "outbound") t.number = 0;
            else if (v == "in" || v == "inbound") t.number = 1;
            else return bad("dir expects in|out");
        } else if (name == "pid") {
            return bad("pid filters are not supported: raw capture cannot attribute packets to "
                       "processes; filter by host:<console ip> instead");
        } else {
            return bad("unknown predicate '" + name + "'");
        }
        f.terms_.push_back(std::move(t));
    }
    return f;
}

traffic_store_t::page_t traffic_store_t::packets_filtered(
    uint64_t from_id, size_t limit, const std::string& expr, std::string* error) const {
    page_t out;
    const auto f = compile_filter(expr, error);
    if (!f) return out;
    std::lock_guard lk(mu_);
    for (const auto& p : pkts_) {
        if (p.id <= from_id) continue;
        if (!f->match(p)) continue;
        if (out.items.size() >= limit) { out.truncated = true; break; }
        out.items.push_back(p);
    }
    return out;
}

// pcap / pcapng

namespace {

// synthesizes the IPv4/IPv6 + TCP/UDP frame a stored packet describes; the
// first `incl_payload` bytes of the captured payload follow it
bool build_frame(const packet_record_t& p, std::vector<uint8_t>& f, size_t& incl_payload,
                 size_t& wire_payload, std::string* error) {
    auto fail = [&](const std::string& why) {
        if (error) *error = why;
        return false;
    };
    const auto la = parse::parse_ip(p.local_addr);
    const auto ra = parse::parse_ip(p.remote_addr);
    if (!la || !ra)
        return fail("packet " + std::to_string(p.id) + ": unparseable address '" +
                    (la ? p.remote_addr : p.local_addr) + "'");
    if (la->family != ra->family)
        return fail("packet " + std::to_string(p.id) + ": mixed IPv4/IPv6 addresses");
    if (p.protocol != kProtoTcp && p.protocol != kProtoUdp)
        return fail("packet " + std::to_string(p.id) + ": protocol " +
                    std::to_string(p.protocol) + " cannot be synthesized");

    const bool out_dir = p.direction == 0;
    const parse::ip_addr_t& src = out_dir ? *la : *ra;
    const parse::ip_addr_t& dst = out_dir ? *ra : *la;
    const uint16_t sport = out_dir ? p.local_port : p.remote_port;
    const uint16_t dport = out_dir ? p.remote_port : p.local_port;
    const bool udp = p.protocol == kProtoUdp;
    const bool v6 = la->family == 6;
    const size_t ip_hdr = v6 ? 40 : 20;
    const size_t l4_hdr = udp ? 8 : 20;
    // the 16-bit IP length fields bound what one record can describe
    const size_t max_payload = 65535 - l4_hdr - (v6 ? 0 : ip_hdr);
    wire_payload = std::min<size_t>(std::max<size_t>(p.wire_len, p.payload.size()), max_payload);
    incl_payload = std::min(p.payload.size(), wire_payload);

    f.assign(ip_hdr + l4_hdr, 0);
    if (v6) {
        f[0] = 0x60;
        put16(f, 4, static_cast<uint32_t>(l4_hdr + wire_payload));
        f[6] = static_cast<uint8_t>(p.protocol);
        f[7] = 64;
        std::memcpy(f.data() + 8, src.b.data(), 16);
        std::memcpy(f.data() + 24, dst.b.data(), 16);
    } else {
        f[0] = 0x45;
        put16(f, 2, static_cast<uint32_t>(ip_hdr + l4_hdr + wire_payload));
        put16(f, 4, static_cast<uint32_t>(p.id & 0xFFFF));
        f[6] = 0x40;                                  // DF
        f[8] = 64;
        f[9] = static_cast<uint8_t>(p.protocol);
        std::memcpy(f.data() + 12, src.b.data(), 4);
        std::memcpy(f.data() + 16, dst.b.data(), 4);
        put16(f, 10, ipv4_checksum(f.data(), 20));
    }
    const size_t l4 = ip_hdr;
    put16(f, l4, sport);
    put16(f, l4 + 2, dport);
    if (udp) {
        put16(f, l4 + 4, static_cast<uint32_t>(8 + wire_payload));
    } else {
        put32(f, l4 + 4, p.tcp_seq);
        put32(f, l4 + 8, p.tcp_ack);
        f[l4 + 12] = 0x50;
        f[l4 + 13] = p.tcp_flags ? p.tcp_flags : 0x18;   // PSH|ACK when unknown
        put16(f, l4 + 14, 0xFFFF);
    }
    return true;
}

void push_u16(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
    v.push_back(static_cast<uint8_t>(x & 0xFF));
}

void push_u32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(static_cast<uint8_t>(x >> 24));
    v.push_back(static_cast<uint8_t>((x >> 16) & 0xFF));
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
    v.push_back(static_cast<uint8_t>(x & 0xFF));
}

void push_u64(std::vector<uint8_t>& v, uint64_t x) {
    push_u32(v, static_cast<uint32_t>(x >> 32));
    push_u32(v, static_cast<uint32_t>(x & 0xFFFFFFFFu));
}

void pad4(std::vector<uint8_t>& v) {
    while (v.size() % 4) v.push_back(0);
}

// pcapng block: type, total length, body, total length again
void append_block(std::vector<uint8_t>& out, uint32_t type, const std::vector<uint8_t>& body) {
    const uint32_t total = static_cast<uint32_t>(12 + body.size());
    push_u32(out, type);
    push_u32(out, total);
    out.insert(out.end(), body.begin(), body.end());
    push_u32(out, total);
}

bool write_file(const std::string& path, const std::vector<uint8_t>& out, std::string* error) {
    std::FILE* fp = std::fopen(path.c_str(), "wb");
    if (!fp) {
        if (error) *error = "cannot open output file '" + path + "'";
        return false;
    }
    const size_t wrote = std::fwrite(out.data(), 1, out.size(), fp);
    const bool flushed = std::fflush(fp) == 0;
    const bool closed = std::fclose(fp) == 0;
    if (wrote != out.size() || !flushed || !closed) {
        std::remove(path.c_str());
        if (error) *error = "write failed for '" + path + "' (disk full or I/O error)";
        return false;
    }
    return true;
}

} // namespace

bool traffic_store_t::write_pcap(const std::string& path,
                                 const std::vector<packet_record_t>& pkts,
                                 std::string* error) const {
    // build every record first so a bad packet never leaves a half file behind
    std::vector<uint8_t> out;
    out.reserve(24 + pkts.size() * 128);
    auto push = [&](const void* p, size_t n) {
        const auto* b = static_cast<const uint8_t*>(p);
        out.insert(out.end(), b, b + n);
    };
    const uint32_t global[6] = {0xa1b2c3d4u, 0x00040002u /* 2.4 */, 0, 0, 65535u, 101u /* RAW */};
    push(global, sizeof(global));

    for (const auto& p : pkts) {
        std::vector<uint8_t> f;
        size_t incl_payload = 0, wire_payload = 0;
        if (!build_frame(p, f, incl_payload, wire_payload, error)) return false;

        const uint32_t rec[4] = {
            static_cast<uint32_t>(p.at_ms / 1000),
            static_cast<uint32_t>((p.at_ms % 1000) * 1000),
            static_cast<uint32_t>(f.size() + incl_payload),
            static_cast<uint32_t>(f.size() + wire_payload),
        };
        push(rec, sizeof(rec));
        push(f.data(), f.size());
        if (incl_payload) push(p.payload.data(), incl_payload);
    }

    return write_file(path, out, error);
}

bool traffic_store_t::write_pcapng(const std::string& path,
                                   const std::vector<packet_record_t>& pkts,
                                   std::string* error) const {
    std::vector<uint8_t> out;
    out.reserve(64 + pkts.size() * 160);

    // section header: little-endian, version 1.0, unknown section length
    std::vector<uint8_t> shb;
    push_u32(shb, 0x1A2B3C4Du);
    push_u16(shb, 1);
    push_u16(shb, 0);
    push_u64(shb, 0xFFFFFFFFFFFFFFFFull);
    append_block(out, 0x0A0D0D0Au, shb);

    // interface description: LINKTYPE_RAW, microsecond timestamps
    std::vector<uint8_t> idb;
    push_u16(idb, 101);
    push_u16(idb, 0);
    push_u32(idb, 65535);
    push_u16(idb, 9);                     // if_tsresol
    push_u16(idb, 1);
    idb.push_back(6);                     // 10^-6 s
    pad4(idb);
    push_u16(idb, 0);                     // opt_endofopt
    push_u16(idb, 0);
    append_block(out, 0x00000001u, idb);

    std::lock_guard lk(mu_);
    for (const auto& p : pkts) {
        std::vector<uint8_t> f;
        size_t incl_payload = 0, wire_payload = 0;
        if (!build_frame(p, f, incl_payload, wire_payload, error)) return false;

        std::vector<uint8_t> body;
        const uint64_t ts = static_cast<uint64_t>(p.at_ms) * 1000;   // microseconds
        push_u32(body, 0);                                           // interface id
        push_u32(body, static_cast<uint32_t>(ts >> 32));
        push_u32(body, static_cast<uint32_t>(ts & 0xFFFFFFFFu));
        push_u32(body, static_cast<uint32_t>(f.size() + incl_payload));
        push_u32(body, static_cast<uint32_t>(f.size() + wire_payload));
        body.insert(body.end(), f.begin(), f.end());
        if (incl_payload)
            body.insert(body.end(), p.payload.begin(),
                        p.payload.begin() + static_cast<std::ptrdiff_t>(incl_payload));
        pad4(body);

        std::string comment;
        if (auto it = pkt_notes_.find(p.id); it != pkt_notes_.end()) comment = it->second;
        else if (auto st = stream_notes_.find(p.stream_id); st != stream_notes_.end())
            comment = st->second;
        if (!comment.empty()) {
            push_u16(body, 1);                                    // epb_comment
            push_u16(body, static_cast<uint32_t>(comment.size()));
            body.insert(body.end(), comment.begin(), comment.end());
            pad4(body);
        }
        push_u16(body, 0);                                        // opt_endofopt
        push_u16(body, 0);
        append_block(out, 0x00000006u, body);
    }
    return write_file(path, out, error);
}

bool traffic_store_t::annotate_packet(uint64_t id, std::string comment) {
    std::lock_guard lk(mu_);
    const auto it = std::lower_bound(pkts_.begin(), pkts_.end(), id,
                                     [](const packet_record_t& p, uint64_t v) { return p.id < v; });
    if (it == pkts_.end() || it->id != id) return false;
    if (comment.empty()) pkt_notes_.erase(id);
    else pkt_notes_[id] = std::move(comment);
    return true;
}

bool traffic_store_t::annotate_stream(uint64_t id, std::string comment) {
    std::lock_guard lk(mu_);
    if (!by_id_.contains(id)) return false;
    if (comment.empty()) stream_notes_.erase(id);
    else stream_notes_[id] = std::move(comment);
    return true;
}

} // namespace slop::core::network
