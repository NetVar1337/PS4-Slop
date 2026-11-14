// src/core/analysis/libsig.cpp

#include "core/analysis/libsig.hpp"

#include <nlohmann/json.hpp>
#include <zlib.h>

#include <algorithm>
#include <cstdio>
#include <functional>
#include <vector>

namespace slop::core::analysis {

namespace {

struct compiled_sig_t {
    std::string name;
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;    // 1 = must match
    uint32_t anchor_offset = 0;
};

compiled_sig_t compile(const libsig_t& sig, bool* ok) {
    compiled_sig_t out;
    out.name = sig.name;
    out.anchor_offset = sig.offset;
    *ok = false;

    const std::string& s = sig.pattern;
    auto is_hex = [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
               (c >= 'A' && c <= 'F');
    };
    size_t i = 0;
    while (i < s.size()) {
        if (s[i] == ' ') { ++i; continue; }
        if (s[i] == '?') {
            if (i + 1 >= s.size() || s[i+1] != '?') return out;
            out.bytes.push_back(0);
            out.mask.push_back(0);
            i += 2;
            continue;
        }
        if (!is_hex(s[i]) || i + 1 >= s.size() || !is_hex(s[i+1])) return out;
        out.bytes.push_back(static_cast<uint8_t>(
            std::stoul(s.substr(i, 2), nullptr, 16)));
        // byte mask: 0xFF for a fixed byte, 0 for a ?? wildcard. The matcher
        // ANDs the image byte with this, so 1 would only compare the low bit
        out.mask.push_back(0xFF);
        i += 2;
    }
    *ok = !out.bytes.empty();
    return out;
}

const disasm::function_t* enclosing_function(
    const disasm::function_index_t& fidx, uint64_t va) {
    const auto& fns = fidx.functions();
    // Function list is sorted by VA; binary search for the last start <= va
    auto it = std::upper_bound(
        fns.begin(), fns.end(), va,
        [](uint64_t v, const disasm::function_t& f) { return v < f.va; });
    if (it == fns.begin()) return nullptr;
    --it;
    if (va >= it->va && va < it->va + it->size) return &*it;
    return nullptr;
}

} // namespace

std::vector<libsig_hit_t> libsig_scan(
    const disasm::pe_image_t& pe,
    const std::vector<uint8_t>& file,
    const disasm::function_index_t& fidx,
    const std::vector<libsig_t>& sigs) {
    std::vector<libsig_hit_t> hits;
    if (!pe.ok) return hits;

    std::vector<compiled_sig_t> compiled;
    for (const auto& s : sigs) {
        bool ok = false;
        compiled_sig_t c = compile(s, &ok);
        if (ok) compiled.push_back(std::move(c));
    }
    if (compiled.empty()) return hits;

    for (const auto& sec : pe.sections) {
        if (!sec.is_executable() || sec.raw_size == 0) continue;
        if (static_cast<size_t>(sec.raw_offset) + sec.raw_size > file.size())
            continue;

        const uint8_t* base = file.data() + sec.raw_offset;
        const size_t span = std::min<uint32_t>(sec.raw_size, sec.virtual_size);

        for (const auto& cs : compiled) {
            if (span < cs.bytes.size()) continue;
            for (size_t i = 0; i + cs.bytes.size() <= span; ++i) {
                bool m = true;
                for (size_t b = 0; b < cs.bytes.size(); ++b) {
                    if ((base[i + b] & 0xFF & cs.mask[b]) !=
                        (cs.bytes[b] & cs.mask[b])) {
                        m = false;
                        break;
                    }
                }
                if (!m) continue;

                libsig_hit_t hit;
                hit.sig_name = cs.name;
                const size_t rel =
                    i >= cs.anchor_offset ? i - cs.anchor_offset : 0;
                hit.va = pe.image_base + sec.rva + static_cast<uint32_t>(rel);
                if (auto* fn = enclosing_function(fidx, hit.va))
                    hit.function_va = fn->va;
                hits.push_back(std::move(hit));
                break;   // one hit per signature per section
            }
        }
    }
    return hits;
}

std::optional<std::vector<libsig_t>> parse_sig_set(const std::string& json_text,
                                                   std::string* error) {
    using json = nlohmann::json;
    json j = json::parse(json_text, nullptr, false);
    if (j.is_discarded() || !j.is_array()) {
        if (error) *error = "signature set must be a JSON array";
        return std::nullopt;
    }
    std::vector<libsig_t> out;
    for (const auto& e : j) {
        if (!e.contains("name") || !e.contains("pattern") ||
            !e.at("name").is_string() || !e.at("pattern").is_string()) {
            if (error) *error = "entries need string name + pattern";
            return std::nullopt;
        }
        libsig_t s;
        s.name    = e.at("name").get<std::string>();
        s.pattern = e.at("pattern").get<std::string>();
        if (e.contains("offset")) {
            const auto& o = e.at("offset");
            s.offset = o.is_number_unsigned()
                           ? static_cast<uint32_t>(o.get<uint64_t>())
                           : static_cast<uint32_t>(
                                 std::strtoul(o.get<std::string>().c_str(),
                                              nullptr, 0));
        }
        out.push_back(std::move(s));
    }
    return out;
}

std::optional<flirt_sig_t> parse_flirt_sig(const uint8_t* data, size_t len,
                                           std::string* error) {
    const auto fail = [&](std::string why) -> std::optional<flirt_sig_t> {
        if (error) *error = std::move(why);
        return std::nullopt;
    };
    if (!data || len < 8) return fail("signature file is too small");

    // bounds-checked cursor over the (possibly inflated) pattern stream
    struct reader_t {
        const uint8_t* p = nullptr;
        size_t         n = 0;
        size_t         pos = 0;
        bool ok = true;

        bool need(size_t k) {
            if (!ok || k > n - pos) { ok = false; return false; }
            return true;
        }
        uint8_t u8() {
            if (!need(1)) return 0;
            return p[pos++];
        }
        uint16_t be16() {
            if (!need(2)) return 0;
            const uint16_t v = static_cast<uint16_t>((p[pos] << 8) | p[pos + 1]);
            pos += 2;
            return v;
        }
        uint32_t be32() {
            if (!need(4)) return 0;
            const uint32_t v = (uint32_t{p[pos]} << 24) | (uint32_t{p[pos + 1]} << 16) |
                               (uint32_t{p[pos + 2]} << 8) | uint32_t{p[pos + 3]};
            pos += 4;
            return v;
        }
        uint16_t le16() {
            if (!need(2)) return 0;
            const uint16_t v = static_cast<uint16_t>(p[pos] | (p[pos + 1] << 8));
            pos += 2;
            return v;
        }
        uint32_t le32() {
            if (!need(4)) return 0;
            const uint32_t v = uint32_t{p[pos]} | (uint32_t{p[pos + 1]} << 8) |
                               (uint32_t{p[pos + 2]} << 16) | (uint32_t{p[pos + 3]} << 24);
            pos += 4;
            return v;
        }
        // FLIRT variable-length integers (see flirt_utils read_max_2_bytes /
        // read_multiple_bytes)
        uint32_t max2() {
            const uint8_t b = u8();
            if (!(b & 0x80)) return b;
            return (static_cast<uint32_t>(b & 0x7F) << 8) | u8();
        }
        uint32_t multi() {
            const uint8_t b = u8();
            if (!(b & 0x80)) return b;
            if ((b & 0xC0) != 0xC0) return (static_cast<uint32_t>(b & 0x7F) << 8) | u8();
            if ((b & 0xE0) != 0xE0) {
                const uint32_t hi = (static_cast<uint32_t>(b & 0x3F) << 24) |
                                    (static_cast<uint32_t>(u8()) << 16);
                return hi + be16();
            }
            return be32();
        }
        std::string bytes(size_t k) {
            if (!need(k)) return {};
            std::string s(reinterpret_cast<const char*>(p + pos), k);
            pos += k;
            return s;
        }
    };

    reader_t head{data, len, 0, true};
    if (head.bytes(6) != "IDASGN") return fail("not a FLIRT signature (bad magic)");
    flirt_sig_t out;
    out.version = head.u8();
    if (out.version < 5 || out.version > 10)
        return fail("unsupported FLIRT signature version " + std::to_string(out.version));
    out.arch = head.u8();
    (void)head.le32();                       // file_types
    (void)head.le16();                       // os_types
    (void)head.le16();                       // app_types
    const uint16_t features = head.le16();
    (void)head.le16();                       // old_n_functions
    (void)head.le16();                       // crc16
    out.ctype = head.bytes(12);
    const uint8_t libname_len = head.u8();
    (void)head.le16();                       // ctypes_crc16
    if (out.version >= 6) (void)head.le32(); // nfuncs
    if (out.version >= 8) (void)head.le16(); // pattern_size
    if (out.version >= 10) (void)head.le16();// unknown
    out.library = head.bytes(libname_len);
    if (!head.ok) return fail("truncated FLIRT header");

    // pattern stream: the rest of the file, zlib-deflated when the compressed
    // feature bit is set (v6+ files in the wild)
    std::vector<uint8_t> inflated;
    reader_t r{data + head.pos, len - head.pos, 0, true};
    if (features & 0x10) {
        const size_t in_len = len - head.pos;
        size_t cap = std::max<size_t>(in_len * 8, 4096);
        for (int attempt = 0; attempt < 4; ++attempt) {
            inflated.resize(cap);
            uLongf out_len = static_cast<uLongf>(cap);
            const int rc = uncompress(inflated.data(), &out_len,
                                      data + head.pos, static_cast<uLong>(in_len));
            if (rc == Z_OK) {
                inflated.resize(out_len);
                break;
            }
            if (rc != Z_BUF_ERROR) return fail("FLIRT pattern stream does not inflate");
            cap *= 4;
            if (cap > (64u << 20)) return fail("FLIRT pattern stream is implausibly large");
        }
        if (inflated.empty()) return fail("FLIRT pattern stream does not inflate");
        r = reader_t{inflated.data(), inflated.size(), 0, true};
    }

    size_t nodes = 0;
    size_t modules = 0;

    // pattern bytes -> libsig hex with ?? for variant-mask bits
    const auto pattern_hex = [](const std::vector<int>& pat) {
        std::string s;
        for (int v : pat) {
            if (!s.empty()) s.push_back(' ');
            if (v < 0) { s += "??"; continue; }
            char hex[4];
            std::snprintf(hex, sizeof(hex), "%02X", static_cast<unsigned>(v & 0xFF));
            s += hex;
        }
        return s;
    };

    // parse_modules consumes crc groups and their public function names
    const auto parse_modules = [&](reader_t& rd, const std::vector<int>& pat) -> bool {
        for (;;) {
            (void)rd.u8();                    // crc_len
            (void)rd.be16();                  // crc
            uint8_t flags = 0;
            do {
                (void)(out.version >= 9 ? rd.multi() : rd.max2());   // module length
                std::string first_name;
                do {
                    (void)(out.version >= 9 ? rd.multi() : rd.max2()); // function offset
                    uint8_t next = rd.u8();
                    if (next < 0x20) next = rd.u8();   // local/collision flags
                    std::string name;
                    size_t guard = 0;
                    while (next >= 0x20 && next < 0x80) {
                        name.push_back(static_cast<char>(next));
                        next = rd.u8();
                        if (++guard > 4096) return false;
                    }
                    flags = next;
                    if (first_name.empty()) first_name = std::move(name);
                    if (!rd.ok) return false;
                } while (flags & 0x01);       // more public names
                if (flags & 0x02) {           // tail bytes
                    const size_t count = out.version >= 8 ? rd.u8() : 1;
                    for (size_t i = 0; i < count; ++i) {
                        (void)(out.version >= 9 ? rd.multi() : rd.max2());
                        (void)rd.u8();
                    }
                }
                if (flags & 0x04) {           // referenced functions
                    const size_t count = out.version >= 8 ? rd.u8() : 1;
                    for (size_t i = 0; i < count; ++i) {
                        (void)(out.version >= 9 ? rd.multi() : rd.max2());
                        size_t name_len = rd.u8();
                        if (name_len == 0) name_len = rd.multi();
                        if (name_len > 4096) return false;
                        (void)rd.bytes(name_len);
                    }
                }
                if (!rd.ok) return false;
                if (++modules > 200'000) return false;
                if (!first_name.empty() && !pat.empty()) {
                    libsig_t sig;
                    sig.name    = std::move(first_name);
                    sig.pattern = pattern_hex(pat);
                    out.sigs.push_back(std::move(sig));
                }
            } while (flags & 0x08);         // more modules with the same crc
            if (!(flags & 0x10)) break;     // more crc groups
        }
        return true;
    };

    // parse_tree: node pattern prefix, then children or leaf modules
    std::function<bool(reader_t&, size_t)> parse_tree =
        [&](reader_t& rd, size_t depth) -> bool {
        if (depth > 64 || ++nodes > 100'000) return false;
        const uint8_t length = rd.u8();
        uint64_t variant_mask = 0;
        if (length < 0x10)       variant_mask = rd.max2();
        else if (length <= 0x20) variant_mask = rd.multi();
        else if (length <= 0x40) variant_mask = (uint64_t{rd.multi()} << 32) | rd.multi();
        else return false;
        std::vector<int> pat(static_cast<size_t>(length), -1);
        for (size_t i = 0; i < length; ++i) {
            // bit set = wildcard (big-endian bit order over the mask)
            const bool wildcard = (variant_mask >> (length - i - 1)) & 1;
            if (!wildcard) pat[i] = rd.u8();
        }
        if (!rd.ok) return false;
        const uint32_t node_count = rd.multi();
        if (node_count > 0) {
            for (uint32_t i = 0; i < node_count; ++i)
                if (!parse_tree(rd, depth + 1)) return false;
            return true;
        }
        return parse_modules(rd, pat);
    };

    if (!parse_tree(r, 0) || !r.ok)
        return fail("malformed FLIRT pattern tree (truncated or unsupported)");
    if (out.sigs.empty()) return fail("FLIRT signature file has no module patterns");
    return out;
}

} // namespace slop::core::analysis
