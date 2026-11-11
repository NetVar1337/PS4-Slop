// src/core/network/parsers.cpp

#include "core/network/parsers.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cctype>
#include <cstring>

namespace slop::core::network::parse {

namespace {

uint16_t be16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint32_t be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
    return s;
}

bool in_v4(const uint8_t* a, uint8_t b0, uint8_t b1, int prefix) {
    const uint32_t v = be32(a);
    const uint32_t net = (static_cast<uint32_t>(b0) << 24) | (static_cast<uint32_t>(b1) << 16);
    const uint32_t mask = prefix == 0 ? 0u : 0xFFFFFFFFu << (32 - prefix);
    return (v & mask) == (net & mask);
}

bool v4_non_public(const uint8_t* a) {
    if (a[0] == 0 || a[0] == 10 || a[0] == 127) return true;
    if (in_v4(a, 100, 64, 10)) return true;              // CGNAT
    if (in_v4(a, 169, 254, 16)) return true;             // link-local
    if (in_v4(a, 172, 16, 12)) return true;
    if (in_v4(a, 192, 168, 16)) return true;
    if (a[0] == 192 && a[1] == 0 && (a[2] == 0 || a[2] == 2)) return true;
    if (in_v4(a, 198, 18, 15)) return true;              // benchmarking
    if (a[0] == 198 && a[1] == 51 && a[2] == 100) return true;
    if (a[0] == 203 && a[1] == 0 && a[2] == 113) return true;
    if (a[0] >= 224) return true;                        // multicast, reserved, broadcast
    return false;
}

bool is_token_char(char c) {
    if (std::isalnum(static_cast<unsigned char>(c))) return true;
    return std::strchr("!#$%&'*+-.^_`|~", c) != nullptr && c != '\0';
}

bool parse_u64_digits(std::string_view s, uint64_t& out) {
    if (s.empty() || s.size() > 15) return false;
    uint64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + static_cast<uint64_t>(c - '0');
    }
    out = v;
    return true;
}

} // namespace

// addresses

ip_addr_t make_v4(const uint8_t* four) {
    ip_addr_t a;
    a.family = 4;
    std::memcpy(a.b.data(), four, 4);
    return a;
}

ip_addr_t make_v6(const uint8_t* sixteen) {
    ip_addr_t a;
    a.family = 6;
    std::memcpy(a.b.data(), sixteen, 16);
    return a;
}

std::optional<ip_addr_t> parse_ip(std::string_view text) {
    text = trim(text);
    if (text.size() >= 2 && text.front() == '[' && text.back() == ']')
        text = text.substr(1, text.size() - 2);
    if (const size_t pct = text.find('%'); pct != std::string_view::npos)
        text = text.substr(0, pct);
    if (text.empty() || text.size() > 45) return std::nullopt;
    const std::string s(text);
    uint8_t buf[16]{};
    if (s.find(':') == std::string::npos) {
        // inet_pton accepts only strict dotted quads
        if (::inet_pton(AF_INET, s.c_str(), buf) == 1) return make_v4(buf);
        return std::nullopt;
    }
    if (::inet_pton(AF_INET6, s.c_str(), buf) == 1) return make_v6(buf);
    return std::nullopt;
}

std::string to_string(const ip_addr_t& a) {
    char buf[INET6_ADDRSTRLEN]{};
    if (a.family == 4)
        return ::inet_ntop(AF_INET, a.b.data(), buf, sizeof(buf)) ? buf : std::string{};
    if (a.family == 6)
        return ::inet_ntop(AF_INET6, a.b.data(), buf, sizeof(buf)) ? buf : std::string{};
    return {};
}

std::optional<cidr_t> parse_cidr(std::string_view text) {
    text = trim(text);
    const size_t slash = text.find('/');
    auto addr = parse_ip(slash == std::string_view::npos ? text : text.substr(0, slash));
    if (!addr) return std::nullopt;
    cidr_t c;
    c.net = *addr;
    const int max = addr->family == 4 ? 32 : 128;
    c.prefix = max;
    if (slash != std::string_view::npos) {
        uint64_t p = 0;
        if (!parse_u64_digits(text.substr(slash + 1), p) || p > static_cast<uint64_t>(max))
            return std::nullopt;
        c.prefix = static_cast<int>(p);
    }
    return c;
}

bool cidr_contains(const cidr_t& c, const ip_addr_t& a) {
    if (c.net.family != a.family || !a.valid()) return false;
    int bits = c.prefix;
    for (size_t i = 0; bits > 0; ++i, bits -= 8) {
        const uint8_t mask = bits >= 8 ? 0xFF : static_cast<uint8_t>(0xFF << (8 - bits));
        if ((c.net.b[i] & mask) != (a.b[i] & mask)) return false;
    }
    return true;
}

bool is_non_public(const ip_addr_t& a) {
    if (a.family == 4) return v4_non_public(a.b.data());
    if (a.family != 6) return true;
    const uint8_t* b = a.b.data();
    bool first12_zero = true;
    for (int i = 0; i < 12; ++i) first12_zero = first12_zero && b[i] == 0;
    if (first12_zero) return true;                        // ::, ::1, v4-compatible
    bool mapped = true;
    for (int i = 0; i < 10; ++i) mapped = mapped && b[i] == 0;
    if (mapped && b[10] == 0xFF && b[11] == 0xFF) return v4_non_public(b + 12);
    if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xFF && b[3] == 0x9B) {   // 64:ff9b::/96 NAT64
        bool zero = true;
        for (int i = 4; i < 12; ++i) zero = zero && b[i] == 0;
        if (zero) return v4_non_public(b + 12);
    }
    if (b[0] == 0x20 && b[1] == 0x02) return v4_non_public(b + 2);        // 6to4
    if ((b[0] & 0xFE) == 0xFC) return true;               // ULA fc00::/7
    if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return true;   // link-local
    if (b[0] == 0xFE && (b[1] & 0xC0) == 0xC0) return true;   // site-local
    if (b[0] == 0xFF) return true;                        // multicast
    if (b[0] == 0x01 && b[1] == 0x00 && b[2] == 0 && b[3] == 0 &&
        b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0) return true;    // 100::/64 discard
    if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8) return true;   // docs
    return false;
}

std::string lower(std::string_view s) {
    std::string out(s);
    for (char& c : out)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

bool valid_host(std::string_view host) {
    if (host.empty() || host.size() > 253) return false;
    if (parse_ip(host)) return true;
    size_t label = 0;
    char prev = '.';
    for (char c : host) {
        if (c == '.') {
            if (label == 0 || prev == '-') return false;
            label = 0;
        } else {
            const bool ok = std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_';
            if (!ok) return false;
            if (label == 0 && c == '-') return false;
            if (++label > 63) return false;
        }
        prev = c;
    }
    return label != 0 && prev != '-';
}

bool host_pattern_match(std::string_view pattern, std::string_view host,
                        const ip_addr_t* addr) {
    const std::string p = lower(trim(pattern));
    std::string_view hv = trim(host);
    if (hv.size() >= 2 && hv.front() == '[' && hv.back() == ']') hv = hv.substr(1, hv.size() - 2);
    const std::string h = lower(hv);
    if (p.empty() || h.empty()) return false;
    if (p.size() > 2 && p[0] == '*' && p[1] == '.') {
        const std::string_view suffix = std::string_view(p).substr(1);   // ".example.com"
        return h.size() > suffix.size() &&
               h.compare(h.size() - suffix.size(), suffix.size(), suffix) == 0;
    }
    if (p.find('/') != std::string::npos || parse_ip(p)) {
        const auto c = parse_cidr(p);
        if (!c) return false;
        if (const auto lit = parse_ip(h); lit && cidr_contains(*c, *lit)) return true;
        return addr && cidr_contains(*c, *addr);
    }
    return h == p;
}

std::string escape_nonprintable(std::string_view s) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(s.size());
    for (char ch : s) {
        const auto c = static_cast<unsigned char>(ch);
        if (c >= 0x20 && c <= 0x7E && c != '\\') {
            out.push_back(ch);
        } else {
            out += "\\x";
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 0xF]);
        }
    }
    return out;
}

std::optional<std::string> base64_decode(std::string_view in) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    in = trim(in);
    while (!in.empty() && in.back() == '=') in.remove_suffix(1);
    if (in.size() % 4 == 1) return std::nullopt;
    std::string out;
    out.reserve(in.size() * 3 / 4);
    uint32_t acc = 0;
    int bits = 0;
    for (char c : in) {
        const int v = val(c);
        if (v < 0) return std::nullopt;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((acc >> bits) & 0xFF));
        }
    }
    return out;
}

std::string base64_encode(const uint8_t* d, size_t n) {
    static constexpr char kAlpha[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((n + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 3 <= n; i += 3) {
        const uint32_t v = (static_cast<uint32_t>(d[i]) << 16) |
                           (static_cast<uint32_t>(d[i + 1]) << 8) | d[i + 2];
        out.push_back(kAlpha[(v >> 18) & 63]);
        out.push_back(kAlpha[(v >> 12) & 63]);
        out.push_back(kAlpha[(v >> 6) & 63]);
        out.push_back(kAlpha[v & 63]);
    }
    if (i < n) {
        uint32_t v = static_cast<uint32_t>(d[i]) << 16;
        if (i + 1 < n) v |= static_cast<uint32_t>(d[i + 1]) << 8;
        out.push_back(kAlpha[(v >> 18) & 63]);
        out.push_back(kAlpha[(v >> 12) & 63]);
        out.push_back(i + 1 < n ? kAlpha[(v >> 6) & 63] : '=');
        out.push_back('=');
    }
    return out;
}

// IP / L4

const char* status_name(status_t s) {
    switch (s) {
        case status_t::ok: return "ok";
        case status_t::truncated: return "truncated";
        case status_t::not_ip: return "not_ip";
        case status_t::malformed: return "malformed";
        case status_t::unsupported: return "unsupported";
    }
    return "unknown";
}

status_t skip_v6_ext(uint8_t& proto, const uint8_t*& d, size_t& n) {
    for (int hops = 0; hops < 8; ++hops) {
        if (proto != 0 && proto != 43 && proto != 60 && proto != 51) return status_t::ok;
        if (n < 8) return status_t::truncated;
        const size_t len = proto == 51 ? (static_cast<size_t>(d[1]) + 2) * 4
                                       : (static_cast<size_t>(d[1]) + 1) * 8;
        if (len > n) return status_t::truncated;
        proto = d[0];
        d += len;
        n -= len;
    }
    return status_t::malformed;
}

status_t parse_ip(const uint8_t* d, size_t n, ip_info_t& out) {
    out = ip_info_t{};
    if (!d || n < 1) return status_t::truncated;
    const uint8_t ver = d[0] >> 4;
    if (ver == 4) {
        if (n < 20) return status_t::truncated;
        const size_t ihl = static_cast<size_t>(d[0] & 0x0F) * 4;
        if (ihl < 20) return status_t::malformed;
        if (n < ihl) return status_t::truncated;
        const size_t total = be16(d + 2);
        if (total < ihl) return status_t::malformed;
        const size_t avail = std::min(n, total);
        const uint16_t ff = be16(d + 6);
        out.src = make_v4(d + 12);
        out.dst = make_v4(d + 16);
        out.proto = d[9];
        out.l4 = d + ihl;
        out.l4_len = avail - ihl;
        out.l4_wire_len = static_cast<uint32_t>(total - ihl);
        out.frag_offset = static_cast<uint32_t>(ff & 0x1FFF) * 8;
        out.more_fragments = (ff & 0x2000) != 0;
        out.fragment = out.frag_offset != 0 || out.more_fragments;
        out.frag_id = be16(d + 4);
        return status_t::ok;
    }
    if (ver == 6) {
        if (n < 40) return status_t::truncated;
        const size_t plen = be16(d + 4);
        if (plen == 0) return status_t::unsupported;      // jumbogram / no payload
        out.src = make_v6(d + 8);
        out.dst = make_v6(d + 24);
        uint8_t proto = d[6];
        const uint8_t* p = d + 40;
        size_t avail = std::min(n, 40 + plen) - 40;
        size_t declared = plen;
        for (int hops = 0; hops < 8; ++hops) {
            if (proto == 44) {                             // fragment header
                if (avail < 8) return status_t::truncated;
                const uint16_t fo = be16(p + 2);
                out.frag_offset = fo & 0xFFF8u;
                out.more_fragments = (fo & 1) != 0;
                out.frag_id = be32(p + 4);
                out.fragment = out.frag_offset != 0 || out.more_fragments;
                proto = p[0];
                p += 8;
                avail -= 8;
                declared -= 8;
                if (out.fragment) break;                   // rest is fragmentable data
                continue;                                  // atomic fragment
            }
            if (proto != 0 && proto != 43 && proto != 60 && proto != 51) break;
            if (avail < 8) return status_t::truncated;
            const size_t len = proto == 51 ? (static_cast<size_t>(p[1]) + 2) * 4
                                           : (static_cast<size_t>(p[1]) + 1) * 8;
            if (len > declared) return status_t::malformed;
            if (len > avail) return status_t::truncated;
            proto = p[0];
            p += len;
            avail -= len;
            declared -= len;
        }
        if (proto == 0 || proto == 43 || proto == 60 || proto == 51 || proto == 44)
            if (!out.fragment) return status_t::malformed;
        if (proto == 59) return status_t::unsupported;    // no next header
        out.proto = proto;
        out.l4 = p;
        out.l4_len = avail;
        out.l4_wire_len = static_cast<uint32_t>(declared);
        return status_t::ok;
    }
    return status_t::not_ip;
}

namespace {

bool v6_checksum_ok(const ip_addr_t& src, const ip_addr_t& dst, uint8_t proto,
                    const uint8_t* d, size_t n) {
    uint64_t sum = 0;
    for (int i = 0; i < 16; i += 2) {
        sum += be16(src.b.data() + i);
        sum += be16(dst.b.data() + i);
    }
    sum += static_cast<uint32_t>(n >> 16) & 0xFFFF;
    sum += static_cast<uint32_t>(n) & 0xFFFF;
    sum += proto;
    size_t i = 0;
    for (; i + 1 < n; i += 2) sum += be16(d + i);
    if (i < n) sum += static_cast<uint32_t>(d[i]) << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return sum == 0xFFFF;
}

} // namespace

uint8_t infer_v6_transport(const ip_addr_t& src, const ip_addr_t& dst, const uint8_t* d, size_t n) {
    if (!d || n < 4 || src.family != 6 || dst.family != 6) return 0;
    const bool udp_len = n >= 8 && be16(d + 4) == n;
    if (udp_len && be16(d + 6) != 0 && v6_checksum_ok(src, dst, 17, d, n)) return 17;
    if (n >= 20 && v6_checksum_ok(src, dst, 6, d, n)) return 6;
    if (v6_checksum_ok(src, dst, 58, d, n)) return 58;
    if (udp_len) return 17;
    if (n >= 8 && d[1] == 0 && (d[0] == 6 || d[0] == 17 || d[0] == 58 || d[0] == 60) &&
        (d[3] & 0x06) == 0)
        return 44;
    if (n >= 20) {
        const size_t doff = static_cast<size_t>(d[12] >> 4) * 4;
        if (doff >= 20 && doff <= n && (d[12] & 0x0E) == 0) return 6;
    }
    return 0;
}

status_t parse_l4(uint8_t proto, const uint8_t* l4, size_t l4_len,
                  uint32_t l4_wire_len, l4_info_t& out) {
    out = l4_info_t{};
    if (l4_len > l4_wire_len) l4_len = l4_wire_len;
    if (proto == 6) {
        if (l4_wire_len < 20) return status_t::malformed;
        if (l4_len < 20) return status_t::truncated;
        const size_t doff = static_cast<size_t>(l4[12] >> 4) * 4;
        if (doff < 20 || doff > l4_wire_len) return status_t::malformed;
        if (doff > l4_len) return status_t::truncated;
        out.src_port = be16(l4);
        out.dst_port = be16(l4 + 2);
        out.tcp_seq = be32(l4 + 4);
        out.tcp_ack = be32(l4 + 8);
        out.tcp_flags = l4[13];
        out.payload = l4 + doff;
        out.payload_len = l4_len - doff;
        out.payload_wire_len = static_cast<uint32_t>(l4_wire_len - doff);
        return status_t::ok;
    }
    if (proto == 17) {
        if (l4_wire_len < 8) return status_t::malformed;
        if (l4_len < 8) return status_t::truncated;
        const uint32_t ulen = be16(l4 + 4);
        if (ulen < 8 || ulen > l4_wire_len) return status_t::malformed;
        out.src_port = be16(l4);
        out.dst_port = be16(l4 + 2);
        out.payload = l4 + 8;
        out.payload_wire_len = ulen - 8;
        out.payload_len = std::min<size_t>(l4_len - 8, out.payload_wire_len);
        return status_t::ok;
    }
    return status_t::unsupported;
}

// reassembly

void reassembler_t::clear() {
    parts_.clear();
    bytes_ = 0;
}

void reassembler_t::drop(std::map<key_t, part_t>::iterator it) {
    bytes_ -= it->second.data.size();
    parts_.erase(it);
    ++dropped_;
}

void reassembler_t::expire(int64_t now_ms) {
    for (auto it = parts_.begin(); it != parts_.end();) {
        auto next = std::next(it);
        if (now_ms - it->second.first_ms > lim_.timeout_ms) drop(it);
        it = next;
    }
}

std::optional<reassembler_t::datagram_t> reassembler_t::add(const ip_info_t& ip,
                                                            int64_t now_ms) {
    if (!ip.fragment || (ip.l4 == nullptr && ip.l4_len != 0)) return std::nullopt;
    expire(now_ms);

    key_t k;
    k.family = ip.src.family;
    k.proto = ip.src.family == 4 ? ip.proto : 0;   // v6 next-header can differ per fragment
    k.src = ip.src.b;
    k.dst = ip.dst.b;
    k.id = ip.frag_id;

    auto it = parts_.find(k);
    const size_t len = ip.l4_len;
    const uint64_t start = ip.frag_offset;
    const uint64_t end = start + len;
    const bool bad = ip.l4_len != ip.l4_wire_len ||        // capture truncated it
                     end > 65535 || (ip.more_fragments && (len == 0 || len % 8 != 0));
    if (bad) {
        if (it != parts_.end()) drop(it);
        else ++dropped_;
        return std::nullopt;
    }
    if (it == parts_.end()) {
        while (parts_.size() >= lim_.max_datagrams && !parts_.empty()) {
            auto oldest = parts_.begin();
            for (auto j = parts_.begin(); j != parts_.end(); ++j)
                if (j->second.first_ms < oldest->second.first_ms) oldest = j;
            drop(oldest);
        }
        part_t p;
        p.first_ms = now_ms;
        it = parts_.emplace(k, std::move(p)).first;
    }
    part_t& p = it->second;
    if (!ip.more_fragments) {
        if ((p.total != 0 && p.total != end) ||
            (!p.have.empty() && std::prev(p.have.end())->second > end)) {
            drop(it);
            return std::nullopt;
        }
        p.total = static_cast<uint32_t>(end);
    } else if (p.total != 0 && end > p.total) {
        drop(it);
        return std::nullopt;
    }
    if (start == 0) {
        p.proto = ip.proto;
        p.have_first = true;
    }
    if (end > p.data.size()) {
        const size_t grow = static_cast<size_t>(end) - p.data.size();
        bytes_ += grow;
        p.data.resize(static_cast<size_t>(end));
        while (bytes_ > lim_.max_bytes) {
            auto victim = parts_.end();
            for (auto j = parts_.begin(); j != parts_.end(); ++j)
                if (j != it && (victim == parts_.end() ||
                                j->second.first_ms < victim->second.first_ms))
                    victim = j;
            if (victim == parts_.end()) {
                drop(it);
                return std::nullopt;
            }
            drop(victim);
        }
    }
    if (len) std::memcpy(p.data.data() + start, ip.l4, len);

    // merge [start, end) into the coverage map
    uint32_t s = static_cast<uint32_t>(start), e = static_cast<uint32_t>(end);
    if (e > s) {
        auto lo = p.have.upper_bound(s);
        if (lo != p.have.begin() && std::prev(lo)->second >= s) --lo;
        while (lo != p.have.end() && lo->first <= e) {
            s = std::min(s, lo->first);
            e = std::max(e, lo->second);
            lo = p.have.erase(lo);
        }
        p.have.emplace(s, e);
    }

    if (p.total != 0 && p.have_first && p.have.size() == 1 &&
        p.have.begin()->first == 0 && p.have.begin()->second == p.total) {
        datagram_t out;
        out.proto = p.proto;
        bytes_ -= p.data.size();
        out.l4 = std::move(p.data);
        out.l4.resize(p.total);
        parts_.erase(it);
        ++completed_;
        return out;
    }
    return std::nullopt;
}

// DNS

std::optional<dns_record_t> parse_dns(const uint8_t* d, size_t n) {
    if (!d || n < 12) return std::nullopt;
    const uint16_t flags = be16(d + 2);
    const uint16_t qd = be16(d + 4);
    const uint16_t an = be16(d + 6);
    if (qd == 0) return std::nullopt;
    if ((flags >> 11) & 0xF) return std::nullopt;          // only standard queries

    auto read_name = [&](size_t& off, std::string& name) -> bool {
        name.clear();
        size_t pos = off;
        size_t resume = 0;
        int jumps = 0;
        size_t wire_len = 0;
        for (;;) {
            if (pos >= n) return false;
            const uint8_t l = d[pos];
            if (l == 0) {
                if (resume == 0) resume = pos + 1;
                break;
            }
            if ((l & 0xC0) == 0xC0) {
                if (pos + 1 >= n) return false;
                const size_t ptr = (static_cast<size_t>(l & 0x3F) << 8) | d[pos + 1];
                if (ptr >= pos || ++jumps > 16) return false;   // backwards only
                if (resume == 0) resume = pos + 2;
                pos = ptr;
                continue;
            }
            if (l & 0xC0) return false;                    // extended label types
            if (pos + 1 + l > n) return false;
            wire_len += 1u + l;
            if (wire_len > 255) return false;
            if (!name.empty()) name += '.';
            name += escape_nonprintable(
                std::string_view(reinterpret_cast<const char*>(d + pos + 1), l));
            pos += 1u + l;
        }
        off = resume;
        return true;
    };

    dns_record_t r;
    r.is_response = (flags >> 15) & 1;
    r.response_code = flags & 0xF;
    size_t off = 12;
    std::string qname;
    for (uint16_t i = 0; i < qd; ++i) {
        std::string name;
        if (!read_name(off, name) || off + 4 > n) return std::nullopt;
        if (i == 0) {
            qname = std::move(name);
            r.query_type = be16(d + off);
        }
        off += 4;
    }
    if (qname.empty()) qname = ".";
    r.domain = std::move(qname);
    if (!r.is_response) return r;

    for (uint16_t i = 0; i < an; ++i) {
        std::string aname;
        if (!read_name(off, aname) || off + 10 > n) break;
        const uint16_t type = be16(d + off);
        const uint32_t ttl = be32(d + off + 4);
        const size_t rdlen = be16(d + off + 8);
        off += 10;
        if (off + rdlen > n) break;
        std::string addr;
        if (type == 1 && rdlen == 4) addr = to_string(make_v4(d + off));
        else if (type == 28 && rdlen == 16) addr = to_string(make_v6(d + off));
        if (!addr.empty()) {
            if (r.answers.empty()) {
                r.resolved_addr = addr;
                r.ttl = ttl;
            }
            if (r.answers.size() < 16) r.answers.push_back(std::move(addr));
        }
        off += rdlen;
    }
    return r;
}

// TLS

std::string extract_sni(const uint8_t* d, size_t n) {
    if (!d || n < 5 || d[0] != 0x16 || d[1] != 0x03) return {};
    const size_t rec_end = std::min(n, 5 + static_cast<size_t>(be16(d + 3)));
    size_t off = 5;
    if (off + 4 > rec_end || d[off] != 0x01) return {};    // ClientHello
    const size_t hs_len = (static_cast<size_t>(d[off + 1]) << 16) |
                          (static_cast<size_t>(d[off + 2]) << 8) | d[off + 3];
    off += 4;
    const size_t end = std::min(rec_end, off + hs_len);
    if (off + 2 + 32 + 1 > end) return {};
    off += 2 + 32;                                         // version + random
    off += 1 + static_cast<size_t>(d[off]);                // session id
    if (off + 2 > end) return {};
    off += 2 + static_cast<size_t>(be16(d + off));         // cipher suites
    if (off + 1 > end) return {};
    off += 1 + static_cast<size_t>(d[off]);                // compression methods
    if (off + 2 > end) return {};
    const size_t ext_end = std::min(end, off + 2 + static_cast<size_t>(be16(d + off)));
    off += 2;
    while (off + 4 <= ext_end) {
        const uint16_t type = be16(d + off);
        const size_t len = be16(d + off + 2);
        off += 4;
        if (off + len > ext_end) return {};
        if (type == 0x0000) {                              // server_name
            if (len < 2) return {};
            const size_t list_end = std::min(off + len, off + 2 + static_cast<size_t>(be16(d + off)));
            size_t p = off + 2;
            while (p + 3 <= list_end) {
                const uint8_t name_type = d[p];
                const size_t name_len = be16(d + p + 1);
                p += 3;
                if (p + name_len > list_end) return {};
                if (name_type == 0) {
                    const std::string_view name(reinterpret_cast<const char*>(d + p), name_len);
                    return valid_host(name) ? lower(name) : std::string{};
                }
                p += name_len;
            }
            return {};
        }
        off += len;
    }
    return {};
}

// HTTP

const std::string* http_head_t::get(std::string_view name) const {
    for (const auto& [k, v] : headers)
        if (k == name) return &v;
    return nullptr;
}

size_t find_head_end(const uint8_t* d, size_t n, size_t from) {
    if (n < 4) return std::string::npos;
    for (size_t i = from; i + 4 <= n; ++i)
        if (d[i] == '\r' && d[i + 1] == '\n' && d[i + 2] == '\r' && d[i + 3] == '\n')
            return i + 4;
    return std::string::npos;
}

std::optional<http_head_t> parse_http_head(std::string_view head, bool response) {
    http_head_t h;
    size_t eol = head.find("\r\n");
    if (eol == std::string_view::npos || eol == 0) return std::nullopt;
    const std::string_view start = head.substr(0, eol);
    for (char c : start)
        if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) > 0x7E)
            return std::nullopt;
    const size_t sp1 = start.find(' ');
    if (sp1 == std::string_view::npos || sp1 == 0) return std::nullopt;
    if (response) {
        h.version = std::string(start.substr(0, sp1));
        if (h.version.rfind("HTTP/", 0) != 0) return std::nullopt;
        const std::string_view rest = start.substr(sp1 + 1);
        const std::string_view code = rest.substr(0, std::min<size_t>(rest.find(' '), rest.size()));
        uint64_t st = 0;
        if (code.size() != 3 || !parse_u64_digits(code, st)) return std::nullopt;
        h.status = static_cast<uint32_t>(st);
        if (rest.size() > 4) h.reason = std::string(rest.substr(4));
    } else {
        const size_t sp2 = start.find(' ', sp1 + 1);
        if (sp2 == std::string_view::npos || sp2 == sp1 + 1) return std::nullopt;
        h.method = std::string(start.substr(0, sp1));
        for (char c : h.method)
            if (!is_token_char(c)) return std::nullopt;
        h.target = std::string(start.substr(sp1 + 1, sp2 - sp1 - 1));
        h.version = std::string(start.substr(sp2 + 1));
        if (h.version.rfind("HTTP/", 0) != 0) return std::nullopt;
    }
    size_t pos = eol + 2;
    while (pos < head.size()) {
        eol = head.find("\r\n", pos);
        if (eol == std::string_view::npos) return std::nullopt;
        if (eol == pos) break;                             // blank line ends the head
        const std::string_view line = head.substr(pos, eol - pos);
        pos = eol + 2;
        if (line.front() == ' ' || line.front() == '\t') return std::nullopt;   // obs-fold
        const size_t colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0) return std::nullopt;
        const std::string_view name = line.substr(0, colon);
        for (char c : name)
            if (!is_token_char(c)) return std::nullopt;
        if (h.headers.size() >= 256) return std::nullopt;
        h.headers.emplace_back(lower(name), std::string(trim(line.substr(colon + 1))));
    }
    return h;
}

bool decode_chunked(const uint8_t* d, size_t n, std::vector<uint8_t>& out) {
    out.clear();
    size_t pos = 0;
    for (;;) {
        size_t eol = pos;
        while (eol + 1 < n && !(d[eol] == '\r' && d[eol + 1] == '\n')) ++eol;
        if (eol + 1 >= n || eol - pos > 1024) return false;
        uint64_t size = 0;
        size_t digits = 0;
        for (size_t i = pos; i < eol && d[i] != ';'; ++i) {
            const char h = static_cast<char>(d[i]);
            int x;
            if (h >= '0' && h <= '9') x = h - '0';
            else if (h >= 'a' && h <= 'f') x = h - 'a' + 10;
            else if (h >= 'A' && h <= 'F') x = h - 'A' + 10;
            else if (h == ' ' || h == '\t') continue;
            else return false;
            if (++digits > 10) return false;
            size = size * 16 + static_cast<uint64_t>(x);
        }
        if (digits == 0) return false;
        pos = eol + 2;
        if (size == 0) {
            // trailers until an empty line
            for (;;) {
                size_t e = pos;
                while (e + 1 < n && !(d[e] == '\r' && d[e + 1] == '\n')) ++e;
                if (e + 1 >= n) return false;
                if (e == pos) return true;
                pos = e + 2;
            }
        }
        if (size > n - pos || n - pos - static_cast<size_t>(size) < 2) return false;
        out.insert(out.end(), d + pos, d + pos + size);
        pos += static_cast<size_t>(size);
        if (d[pos] != '\r' || d[pos + 1] != '\n') return false;
        pos += 2;
    }
}

void http_framer_t::fail(const char* why) {
    state_ = st_t::broken;
    error_ = why;
    head_buf_.clear();
    line_buf_.clear();
}

void http_framer_t::message_done(size_t at, std::vector<event_t>* events) {
    ++completed_;
    state_ = st_t::head;
    if (events) events->push_back({event_t::kind_t::end, at, false, {}});
}

void http_framer_t::on_head(size_t at, std::vector<event_t>* events) {
    auto h = parse_http_head(head_buf_, response_);
    if (!h) return fail("unparseable message head");
    const bool interim = response_ && h->status >= 100 && h->status < 200;
    if (events) events->push_back({event_t::kind_t::head, at, interim, head_buf_});
    head_buf_.clear();

    bool chunked = false;
    std::optional<uint64_t> length;
    for (const auto& [k, v] : h->headers) {
        if (k == "transfer-encoding") {
            const std::string tv = lower(v);
            chunked = tv.size() >= 7 && tv.compare(tv.size() - 7, 7, "chunked") == 0;
            if (!chunked) return fail("unsupported transfer-encoding");
        } else if (k == "content-length") {
            uint64_t cl = 0;
            if (!parse_u64_digits(v, cl)) return fail("bad content-length");
            if (length && *length != cl) return fail("conflicting content-length");
            length = cl;
        }
    }

    auto done = [&] { message_done(at, events); };
    if (!response_) {
        if (h->method == "CONNECT") return fail("tunnel request");
        if (chunked) { state_ = st_t::chunk_size; line_buf_.clear(); return; }
        if (length && *length) { remaining_ = *length; state_ = st_t::body; return; }
        return done();
    }
    std::string method;
    if (h->status >= 100 && h->status < 200) {
        if (h->status == 101) return fail("protocol switch");
        state_ = st_t::head;                               // interim, request still pending
        return;
    }
    if (!pending_methods_.empty()) {
        method = std::move(pending_methods_.front());
        pending_methods_.pop_front();
    }
    if (h->status == 204 || h->status == 304 || method == "HEAD") return done();
    if (chunked) { state_ = st_t::chunk_size; line_buf_.clear(); return; }
    if (length) {
        if (*length == 0) return done();
        remaining_ = *length;
        state_ = st_t::body;
        return;
    }
    state_ = st_t::until_close;
}

void http_framer_t::feed(const uint8_t* d, size_t n, std::vector<event_t>* events) {
    constexpr size_t kMaxHead = 64 * 1024;
    size_t i = 0;
    while (i < n) {
        switch (state_) {
        case st_t::broken:
        case st_t::until_close:
            return;
        case st_t::head: {
            if (head_buf_.empty())
                while (i < n && (d[i] == '\r' || d[i] == '\n')) ++i;   // tolerate stray CRLF
            if (i >= n) return;
            const size_t before = head_buf_.size();
            const size_t scan_from = before >= 3 ? before - 3 : 0;
            const size_t take = std::min(n - i, kMaxHead + 4 - before);
            head_buf_.append(reinterpret_cast<const char*>(d + i), take);
            const size_t end = find_head_end(reinterpret_cast<const uint8_t*>(head_buf_.data()),
                                             head_buf_.size(), scan_from);
            if (end == std::string::npos) {
                if (head_buf_.size() > kMaxHead) return fail("message head too large");
                i += take;
                break;
            }
            i += end - before;
            head_buf_.resize(end);
            on_head(i, events);
            break;
        }
        case st_t::body: {
            const uint64_t take = std::min<uint64_t>(remaining_, n - i);
            remaining_ -= take;
            i += static_cast<size_t>(take);
            if (remaining_ == 0) {
                message_done(i, events);
            }
            break;
        }
        case st_t::chunk_size:
        case st_t::trailer: {
            const char c = static_cast<char>(d[i++]);
            line_buf_.push_back(c);
            if (line_buf_.size() > (state_ == st_t::trailer ? kMaxHead : 1024))
                return fail("chunk line too long");
            if (line_buf_.size() < 2 || line_buf_[line_buf_.size() - 2] != '\r' || c != '\n')
                break;
            const std::string line = line_buf_.substr(0, line_buf_.size() - 2);
            line_buf_.clear();
            if (state_ == st_t::trailer) {
                if (line.empty()) {
                    message_done(i, events);
                }
                break;
            }
            const std::string_view sz = trim(std::string_view(line).substr(0, line.find(';')));
            if (sz.empty() || sz.size() > 10) return fail("bad chunk size");
            uint64_t v = 0;
            for (char h : sz) {
                int x;
                if (h >= '0' && h <= '9') x = h - '0';
                else if (h >= 'a' && h <= 'f') x = h - 'a' + 10;
                else if (h >= 'A' && h <= 'F') x = h - 'A' + 10;
                else return fail("bad chunk size");
                v = v * 16 + static_cast<uint64_t>(x);
            }
            if (v == 0) {
                state_ = st_t::trailer;
            } else {
                remaining_ = v;
                state_ = st_t::chunk_data;
            }
            break;
        }
        case st_t::chunk_data: {
            const uint64_t take = std::min<uint64_t>(remaining_, n - i);
            remaining_ -= take;
            i += static_cast<size_t>(take);
            if (remaining_ == 0) {
                state_ = st_t::chunk_crlf;
                line_buf_.clear();
            }
            break;
        }
        case st_t::chunk_crlf: {
            line_buf_.push_back(static_cast<char>(d[i++]));
            if (line_buf_.size() == 2) {
                if (line_buf_ != "\r\n") return fail("missing chunk terminator");
                line_buf_.clear();
                state_ = st_t::chunk_size;
            }
            break;
        }
        }
    }
}

void http_framer_t::finish(std::vector<event_t>* events) {
    if (state_ == st_t::until_close) message_done(0, events);
}

} // namespace slop::core::network::parse
