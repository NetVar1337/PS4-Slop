// src/core/network/pcap_import.cpp

#include "core/network/pcap_import.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>

#include "core/network/parsers.hpp"

namespace slop::core::network::pcap {

namespace {

constexpr size_t kMaxFileBytes = 512u << 20;   // refuse to load bigger captures
constexpr size_t kMaxRecords = 500000;
constexpr size_t kMaxRecordBytes = 1u << 20;   // one frame / packet block
constexpr size_t kMaxPayload = 65535;

uint16_t rd16(const uint8_t* p, bool le) {
    return le ? static_cast<uint16_t>(p[0] | (p[1] << 8))
              : static_cast<uint16_t>((p[0] << 8) | p[1]);
}

uint32_t rd32(const uint8_t* p, bool le) {
    return le ? (static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
                 (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24))
              : ((static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
                 (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]));
}

// link types we can strip: Ethernet (with one VLAN tag), Linux cooked SLL,
// raw IP and the family-specific raw types
enum class link_t { unsupported, ethernet, sll, raw };

link_t link_kind(uint32_t linktype) {
    switch (linktype) {
        case 1: return link_t::ethernet;
        case 113: return link_t::sll;
        case 12: case 101: case 228: case 229: return link_t::raw;
        default: return link_t::unsupported;
    }
}

// offset of the IP header inside one frame, or npos
size_t ip_offset(const uint8_t* d, size_t n, link_t kind) {
    switch (kind) {
        case link_t::ethernet: {
            if (n < 14) return std::string::npos;
            size_t off = 14;
            uint16_t type = rd16(d + 12, false);
            if (type == 0x8100 || type == 0x88A8) {
                if (n < 18) return std::string::npos;
                type = rd16(d + 16, false);
                off = 18;
            }
            if (type != 0x0800 && type != 0x86DD) return std::string::npos;
            return off;
        }
        case link_t::sll:
            return n < 16 ? std::string::npos : 16;
        case link_t::raw:
            return 0;
        default:
            return std::string::npos;
    }
}

bool frame_to_packet(const uint8_t* d, size_t n, link_t kind, int64_t at_ms,
                     packet_record_t& out) {
    const size_t off = ip_offset(d, n, kind);
    if (off == std::string::npos || off >= n) return false;
    parse::ip_info_t ip;
    if (parse::parse_ip(d + off, n - off, ip) != parse::status_t::ok) return false;
    if (ip.fragment || (ip.proto != 6 && ip.proto != 17)) return false;
    parse::l4_info_t l4;
    if (parse::parse_l4(ip.proto, ip.l4, ip.l4_len, ip.l4_wire_len, l4) !=
        parse::status_t::ok)
        return false;

    out.at_ms = at_ms;
    out.protocol = ip.proto;
    out.direction = 0;
    out.ip_version = ip.src.family;
    out.local_addr = parse::to_string(ip.src);
    out.local_port = l4.src_port;
    out.remote_addr = parse::to_string(ip.dst);
    out.remote_port = l4.dst_port;
    const size_t payload = std::min({l4.payload_len, kMaxPayload, n - off});
    out.payload.assign(l4.payload, l4.payload + payload);
    out.wire_len = std::max<uint32_t>(l4.payload_wire_len,
                                      static_cast<uint32_t>(out.payload.size()));
    out.tcp_seq = l4.tcp_seq;
    out.tcp_ack = l4.tcp_ack;
    out.tcp_flags = l4.tcp_flags;
    return true;
}

struct cursor_t {
    const uint8_t* d = nullptr;
    size_t n = 0;
    size_t pos = 0;
    bool le = true;

    size_t left() const { return n - pos; }
    bool take(size_t k) { return k <= left(); }
};

std::string parse_pcap(cursor_t& c, traffic_store_t& store, import_result_t& out) {
    // magic, version, thiszone, sigfigs, snaplen, linktype
    if (!c.take(24)) return "pcap: truncated global header";
    const uint8_t* h = c.d;
    bool le = true;
    bool nano = false;
    if (h[0] == 0xa1 && h[1] == 0xb2 && h[2] == 0xc3 && h[3] == 0xd4) le = false;
    else if (h[0] == 0xd4 && h[1] == 0xc3 && h[2] == 0xb2 && h[3] == 0xa1) le = true;
    else if (h[0] == 0xa1 && h[1] == 0xb2 && h[2] == 0x3c && h[3] == 0x4d) { le = false; nano = true; }
    else if (h[0] == 0x4d && h[1] == 0x3c && h[2] == 0xb2 && h[3] == 0xa1) { le = true; nano = true; }
    else return "pcap: not a pcap file (bad magic)";
    c.le = le;
    c.pos = 24;
    const uint32_t linktype = rd32(h + 20, le);
    const link_t kind = link_kind(linktype);
    if (kind == link_t::unsupported)
        return "pcap: unsupported link type " + std::to_string(linktype) +
               " (Ethernet, Linux SLL and raw IP only)";

    while (c.left() >= 16) {
        if (out.packets + out.skipped >= kMaxRecords) return "pcap: record cap reached";
        const uint8_t* r = c.d + c.pos;
        const uint32_t ts_sec = rd32(r, le);
        const uint32_t ts_frac = rd32(r + 4, le);
        const uint32_t incl = rd32(r + 8, le);
        const uint32_t orig = rd32(r + 12, le);
        if (incl > kMaxRecordBytes) return "pcap: record length " + std::to_string(incl) + " exceeds the cap";
        if (!c.take(16 + static_cast<size_t>(incl))) return "pcap: truncated record";
        const int64_t at_ms = static_cast<int64_t>(ts_sec) * 1000 +
                              (nano ? ts_frac / 1000000 : ts_frac / 1000);
        packet_record_t p;
        if (frame_to_packet(r + 16, incl, kind, at_ms, p)) {
            store.add(std::move(p));
            ++out.packets;
        } else {
            ++out.skipped;
        }
        if (incl < orig) ++out.truncated;
        c.pos += 16 + static_cast<size_t>(incl);
    }
    if (c.left() != 0) return "pcap: trailing bytes after the last record";
    return {};
}

// one interface of the current section: link type and timestamp resolution
struct iface_t {
    link_t kind = link_t::unsupported;
    uint64_t ticks_per_s = 1000000;   // default: microseconds
};

std::string parse_pcapng(cursor_t& c, traffic_store_t& store, import_result_t& out) {
    std::vector<iface_t> ifaces;
    bool have_section = false;
    if (c.left() < 12) return "pcapng: truncated section header";
    while (c.left() >= 12) {
        const uint8_t* b = c.d + c.pos;
        const bool shb = b[0] == 0x0a && b[1] == 0x0d && b[2] == 0x0d && b[3] == 0x0a;
        if (shb) {
            if (!c.take(28)) return "pcapng: truncated section header";
            const uint8_t* bom = b + 8;
            if (rd32(bom, true) == 0x1A2B3C4D) c.le = true;
            else if (rd32(bom, false) == 0x1A2B3C4D) c.le = false;
            else return "pcapng: bad byte-order magic";
            ifaces.clear();
            have_section = true;
        }
        if (!have_section) return "pcapng: no section header block";
        const uint32_t type = rd32(b, c.le);
        const uint32_t total = rd32(b + 4, c.le);
        if (total < 12 || total % 4 != 0) return "pcapng: invalid block length";
        if (total > kMaxRecordBytes + 4096) return "pcapng: block length " + std::to_string(total) + " exceeds the cap";
        if (!c.take(total)) return "pcapng: truncated block";
        if (rd32(b + total - 4, c.le) != total) return "pcapng: block length mismatch";
        const uint8_t* body = b + 8;
        const size_t body_len = total - 12;

        if (type == 0x00000001u) {                       // interface description
            if (body_len < 8) return "pcapng: truncated interface block";
            iface_t iface;
            iface.kind = link_kind(rd16(body, c.le));
            size_t opt = 8;
            while (opt + 4 <= body_len) {
                const uint16_t code = rd16(body + opt, c.le);
                const uint16_t len = rd16(body + opt + 2, c.le);
                opt += 4;
                if (code == 0) break;
                if (opt + len > body_len) return "pcapng: truncated interface option";
                if (code == 9 && len >= 1) {             // if_tsresol
                    const uint8_t v = body[opt];
                    const uint64_t exp = v & 0x7F;
                    if (exp > 63) return "pcapng: invalid timestamp resolution";
                    const uint64_t base = (v & 0x80) ? 2 : 10;
                    uint64_t ticks = 1;
                    for (uint64_t i = 0; i < exp; ++i) ticks *= base;
                    iface.ticks_per_s = ticks;
                }
                opt += (static_cast<size_t>(len) + 3) & ~size_t{3};
            }
            ifaces.push_back(iface);
        } else if (type == 0x00000006u) {                // enhanced packet
            if (body_len < 20) return "pcapng: truncated packet block";
            const uint32_t iface_id = rd32(body, c.le);
            const uint64_t ts = (static_cast<uint64_t>(rd32(body + 4, c.le)) << 32) |
                                rd32(body + 8, c.le);
            const uint32_t caplen = rd32(body + 12, c.le);
            const uint32_t origlen = rd32(body + 16, c.le);
            if (caplen > kMaxRecordBytes) return "pcapng: packet length exceeds the cap";
            if (20 + static_cast<size_t>(caplen) > body_len) return "pcapng: truncated packet data";
            if (iface_id >= ifaces.size()) return "pcapng: packet for an unknown interface";
            if (out.packets + out.skipped >= kMaxRecords) return "pcapng: record cap reached";
            const iface_t& iface = ifaces[iface_id];
            const int64_t at_ms = static_cast<int64_t>(
                static_cast<double>(ts) * 1000.0 / static_cast<double>(iface.ticks_per_s));
            packet_record_t p;
            if (frame_to_packet(body + 20, caplen, iface.kind, at_ms, p)) {
                store.add(std::move(p));
                ++out.packets;
            } else {
                ++out.skipped;
            }
            if (caplen < origlen) ++out.truncated;
        } else if (type == 0x00000003u) {                // simple packet
            if (body_len < 4) return "pcapng: truncated simple packet block";
            if (ifaces.empty()) return "pcapng: packet before any interface";
            const uint32_t origlen = rd32(body, c.le);
            const size_t caplen = std::min<size_t>(origlen, body_len - 4);
            if (caplen > kMaxRecordBytes) return "pcapng: packet length exceeds the cap";
            if (out.packets + out.skipped >= kMaxRecords) return "pcapng: record cap reached";
            packet_record_t p;
            if (frame_to_packet(body + 4, caplen, ifaces.front().kind, 0, p)) {
                store.add(std::move(p));
                ++out.packets;
            } else {
                ++out.skipped;
            }
            if (caplen < origlen) ++out.truncated;
        }
        c.pos += total;
    }
    if (c.left() != 0) return "pcapng: trailing bytes after the last block";
    return {};
}

} // namespace

std::string import_file(traffic_store_t& store, const std::string& path,
                        import_result_t* out) {
    std::FILE* fp = nullptr;
    if (fopen_s(&fp, path.c_str(), "rb") != 0 || !fp) return "cannot open '" + path + "'";
    std::vector<uint8_t> file;
    {
        if (std::fseek(fp, 0, SEEK_END) != 0) { std::fclose(fp); return "cannot seek '" + path + "'"; }
        const long size = std::ftell(fp);
        if (size < 0) { std::fclose(fp); return "cannot size '" + path + "'"; }
        if (static_cast<size_t>(size) > kMaxFileBytes) {
            std::fclose(fp);
            return "capture is larger than the 512 MiB import cap";
        }
        std::rewind(fp);
        file.resize(static_cast<size_t>(size));
        const size_t got = file.empty() ? 0 : std::fread(file.data(), 1, file.size(), fp);
        std::fclose(fp);
        if (got != file.size()) return "short read from '" + path + "'";
    }

    import_result_t result;
    cursor_t c;
    c.d = file.data();
    c.n = file.size();
    std::string err;
    const bool ng = file.size() >= 4 && file[0] == 0x0a && file[1] == 0x0d &&
                    file[2] == 0x0d && file[3] == 0x0a;
    if (file.empty()) err = "capture is empty";
    else if (ng) {
        result.format = "pcapng";
        err = parse_pcapng(c, store, result);
    } else {
        result.format = "pcap";
        err = parse_pcap(c, store, result);
    }
    if (out) *out = result;
    return err;
}

} // namespace slop::core::network::pcap
