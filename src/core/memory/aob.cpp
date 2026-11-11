// src/core/memory/aob.cpp
// aob scan, a port of the cheat engine nibble wildcard logic with chunked reads

#include "core/memory/aob.hpp"

#include "core/infra/limits.hpp"
#include "core/memory/read_util.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>

namespace slop::core::memory {

// Pattern compile

namespace {

int hex_val(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

} // namespace

bool aob_pattern_t::has_wildcards() const noexcept {
    for (uint8_t m : nibble_mask)
        if (m != 0xFF) return true;
    return false;
}

std::optional<aob_pattern_t> aob_compile(std::string_view text, std::string& err) {
    err.clear();
    aob_pattern_t p;

    // Tokenize on spaces / commas
    std::vector<std::string> tokens;
    std::string cur;
    for (char c : text) {
        if (c == ' ' || c == '\t' || c == ',') {
            if (!cur.empty()) { tokens.push_back(cur); cur.clear(); }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) tokens.push_back(cur);

    if (tokens.empty()) {
        err = "empty pattern";
        return std::nullopt;
    }

    const bool has_wild = text.find('?') != std::string_view::npos ||
                          text.find('*') != std::string_view::npos;

    // Compact hex string ("DEADBEEF") only valid without wildcards
    if (tokens.size() == 1 && !has_wild) {
        std::string t = tokens[0];
        if (t.size() > 2 && (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0))
            t.erase(0, 2);
        const bool all_hex = !t.empty() &&
            t.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos;
        if (t.size() > 2 && t.size() % 2 == 0 && all_hex) {
            for (size_t i = 0; i < t.size(); i += 2) {
                p.bytes.push_back(static_cast<uint8_t>(
                    (hex_val(t[i]) << 4) | hex_val(t[i + 1])));
                p.nibble_mask.push_back(0xFF);
            }
            return p;
        }
    }

    for (std::string t : tokens) {
        if (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0) t.erase(0, 2);
        if (t.empty()) {
            err = "empty token";
            return std::nullopt;
        }
        if (t == "??" || t == "*" || t == "?") {
            p.bytes.push_back(0);
            p.nibble_mask.push_back(0x00);
            continue;
        }
        if (t.size() > 2) {
            err = "bad token '" + t + "'";
            return std::nullopt;
        }
        // Per-nibble parse: '?' or '*' = wildcard nibble
        int hi = -1, lo = -1;
        uint8_t mask = 0;
        if (t[0] == '?' || t[0] == '*') {
            mask &= 0x0F;
        } else {
            hi = hex_val(t[0]);
            if (hi < 0) { err = "bad token '" + t + "'"; return std::nullopt; }
            mask |= 0xF0;
        }
        if (t.size() == 2) {
            if (t[1] == '?' || t[1] == '*') {
                mask &= 0xF0;
            } else {
                lo = hex_val(t[1]);
                if (lo < 0) { err = "bad token '" + t + "'"; return std::nullopt; }
                mask |= 0x0F;
            }
        } else {
            mask = 0x0F; // single nibble token: low nibble only
        }
        p.bytes.push_back(static_cast<uint8_t>(((hi < 0 ? 0 : hi) << 4) |
                                               (lo < 0 ? 0 : lo)));
        p.nibble_mask.push_back(mask);
    }

    if (p.bytes.empty()) {
        err = "empty pattern";
        return std::nullopt;
    }
    return p;
}

bool aob_match(const aob_pattern_t& p, const uint8_t* data, size_t len) noexcept {
    // Anchored: the pattern must match at offset 0
    if (p.size() == 0 || len < p.size()) return false;
    for (size_t i = 0; i < p.size(); ++i) {
        const uint8_t m = p.nibble_mask[i];
        if (m == 0) continue;
        if ((data[i] & m) != (p.bytes[i] & m)) return false;
    }
    return true;
}

bool aob_contains(const aob_pattern_t& p, const uint8_t* data, size_t len) noexcept {
    if (p.size() == 0 || len < p.size()) return false;
    const size_t last = len - p.size();
    for (size_t off = 0; off <= last; ++off)
        if (aob_match(p, data + off, len - off)) return true;
    return false;
}

std::string aob_to_string(const aob_pattern_t& p) {
    std::string out;
    out.reserve(p.size() * 3);
    for (size_t i = 0; i < p.size(); ++i) {
        const uint8_t m = p.nibble_mask[i];
        if (m == 0xFF) {
            char buf[3];
            std::snprintf(buf, sizeof(buf), "%02X", p.bytes[i]);
            out += buf;
        } else if (m == 0xF0) {
            char buf[3];
            std::snprintf(buf, sizeof(buf), "%X?", (p.bytes[i] >> 4) & 0xF);
            out += buf;
        } else if (m == 0x0F) {
            char buf[3];
            std::snprintf(buf, sizeof(buf), "?%X", p.bytes[i] & 0xF);
            out += buf;
        } else {
            out += "??";
        }
        if (i + 1 < p.size()) out += ' ';
    }
    return out;
}

std::string aob_from_bytes(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(len * 3);
    for (size_t i = 0; i < len; ++i) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02X", data[i]);
        out += buf;
        if (i + 1 < len) out += ' ';
    }
    return out;
}

// Region scan

std::vector<uintptr_t> aob_scan(reader_t& r,
                                const std::vector<scan_region_t>& regions,
                                const aob_pattern_t& p,
                                const aob_scan_options_t& opt,
                                const infra::cancel_token_t& tok,
                                aob_stats_t* stats) {
    aob_stats_t local{};
    aob_stats_t& st = stats ? *stats : local;

    std::vector<uintptr_t> matches;
    if (p.size() == 0) return matches;

    const reader_hints_t hints = r.hints();
    const size_t max_results = opt.max_results ? opt.max_results
                                               : infra::limits::max_aob_matches;
    const size_t chunk = opt.chunk_bytes ? opt.chunk_bytes
                       : hints.chunk_bytes ? hints.chunk_bytes
                                           : infra::limits::scan_chunk_bytes;
    const size_t align = std::max<size_t>(opt.alignment ? opt.alignment : 1, 1);

    // Contiguous region pairs (begin/end), honoring alignment start
    std::vector<detail::read_range_t> spans;
    for (const auto& reg : regions) {
        if (reg.size < p.size()) continue;
        const uintptr_t b = (reg.base + align - 1) / align * align;
        const uintptr_t e = reg.base + reg.size;
        if (e <= b || e - b < p.size()) continue;
        spans.push_back({b, static_cast<size_t>(e - b)});
    }

    unsigned nw = opt.threads ? opt.threads
                              : std::thread::hardware_concurrency();
    if (hints.max_workers) nw = std::min(nw, hints.max_workers);
    nw = std::max(1u, std::min(nw, 64u));
    if (!spans.empty()) nw = std::min<unsigned>(nw, static_cast<unsigned>(spans.size()));

    // Chunks carry a pattern-1 overlap tail so matches spanning chunk
    // borders are seen whole; only starts before the chunk limit count
    detail::chunk_walk_t walk;
    walk.chunk      = chunk;
    walk.overlap    = p.size() - 1;
    walk.min_leaf   = 4096;
    walk.read_ahead = hints.read_ahead;

    std::mutex mu;
    std::atomic<size_t> next_span{0};

    auto worker = [&] {
        std::vector<uintptr_t> local_matches;
        uint64_t local_bytes = 0;
        bool     local_trunc = false;

        auto sink = [&](size_t, uintptr_t run_addr, const uint8_t* data, size_t len,
                        uintptr_t limit) -> bool {
            local_bytes += std::min<uint64_t>(len, limit > run_addr ? limit - run_addr : 0);
            if (len < p.size()) return true;
            // first aligned start inside the run
            uintptr_t a = (run_addr + align - 1) / align * align;
            const uintptr_t run_end = run_addr + len - p.size();
            for (; a <= run_end && a < limit; a += align) {
                if (aob_match(p, data + (a - run_addr),
                              len - static_cast<size_t>(a - run_addr))) {
                    if (local_matches.size() >= max_results) {
                        local_trunc = true;
                        return false;
                    }
                    local_matches.push_back(a);
                }
            }
            return true;
        };

        if (nw == 1) {
            // one worker: a single walk so read-ahead streams across spans
            detail::chunked_read(r, spans, walk, tok, sink);
        } else {
            std::vector<detail::read_range_t> one(1);
            while (!tok.cancelled() && !local_trunc) {
                const size_t si = next_span.fetch_add(1, std::memory_order_relaxed);
                if (si >= spans.size()) break;
                one[0] = spans[si];
                detail::chunked_read(r, one, walk, tok, sink);
            }
        }

        std::lock_guard<std::mutex> lk(mu);
        st.bytes_scanned += local_bytes;
        st.truncated = st.truncated || local_trunc;
        for (uintptr_t m : local_matches) {
            if (matches.size() >= max_results) { st.truncated = true; break; }
            matches.push_back(m);
        }
    };

    if (nw == 1) {
        worker();
    } else {
        std::vector<std::thread> pool;
        for (unsigned i = 0; i < nw; ++i) pool.emplace_back(worker);
        for (auto& t : pool) t.join();
    }

    std::sort(matches.begin(), matches.end());
    matches.erase(std::unique(matches.begin(), matches.end()), matches.end());
    st.matches = matches.size();
    st.cancelled = tok.cancelled();
    return matches;
}

} // namespace slop::core::memory
