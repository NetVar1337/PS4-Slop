#include "ps4_nid.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

namespace hype::nid {

namespace {

constexpr char kAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";

constexpr u8 kSuffix[16] = {0x51, 0x8D, 0x64, 0xA6, 0x35, 0xDE, 0xD8, 0xC1,
                            0xE6, 0xB0, 0x39, 0xB1, 0xC3, 0xE5, 0x52, 0x30};

int digit_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '-' || c == '/') return 63;   // '/' from standard-base64 tools
    return -1;
}

// Minimal SHA-1 (FIPS 180-4), enough for short symbol names
class Sha1 {
public:
    void update(const u8* p, size_t n) {
        total_ += n;
        while (n) {
            const size_t take = std::min(n, size_t{64} - fill_);
            std::memcpy(block_ + fill_, p, take);
            fill_ += take;
            p += take;
            n -= take;
            if (fill_ == 64) {
                compress(block_);
                fill_ = 0;
            }
        }
    }
    std::array<u8, 20> finish() {
        const u64 bits = total_ * 8;
        const u8 one = 0x80;
        update(&one, 1);
        const u8 zero = 0;
        while (fill_ != 56) update(&zero, 1);
        u8 len[8];
        for (int i = 0; i < 8; ++i) len[i] = static_cast<u8>(bits >> (56 - 8 * i));
        update(len, 8);
        std::array<u8, 20> out{};
        for (int i = 0; i < 5; ++i)
            for (int b = 0; b < 4; ++b)
                out[i * 4 + b] = static_cast<u8>(h_[i] >> (24 - 8 * b));
        return out;
    }

private:
    static u32 rol(u32 v, int s) { return (v << s) | (v >> (32 - s)); }
    void compress(const u8* blk) {
        u32 w[80];
        for (int i = 0; i < 16; ++i)
            w[i] = (u32{blk[i * 4]} << 24) | (u32{blk[i * 4 + 1]} << 16) |
                   (u32{blk[i * 4 + 2]} << 8) | u32{blk[i * 4 + 3]};
        for (int i = 16; i < 80; ++i) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        u32 a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4];
        for (int i = 0; i < 80; ++i) {
            u32 f, k;
            if (i < 20)      { f = (b & c) | (~b & d);          k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else             { f = b ^ c ^ d;                   k = 0xCA62C1D6; }
            const u32 t = rol(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rol(b, 30); b = a; a = t;
        }
        h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d; h_[4] += e;
    }

    u32 h_[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    u8  block_[64]{};
    size_t fill_ = 0;
    u64 total_ = 0;
};

const char* const kBuiltinNames[] = {
#include "../../data/ps4_nid_names.inc"
};

struct Db {
    std::unordered_map<u64, const char*> builtin;
    std::unordered_map<u64, std::string> overrides;
    bool default_loaded = false;
    std::shared_mutex mu;

    Db() {
        builtin.reserve(std::size(kBuiltinNames));
        for (const char* name : kBuiltinNames) builtin.emplace(hash(name), name);
    }
};

Db& db() {
    static Db instance;
    return instance;
}

// "<nid>#<lib>#<mod>" -> "<nid>"
std::string_view nid_part(std::string_view s) {
    const size_t hashpos = s.find('#');
    return hashpos == std::string_view::npos ? s : s.substr(0, hashpos);
}

size_t parse_override_stream(std::istream& in,
                             std::unordered_map<u64, std::string>& out) {
    size_t added = 0;
    std::string line;
    while (std::getline(in, line)) {
        // trim (handles CRLF files and a UTF-8 BOM on the first line)
        if (line.size() >= 3 && static_cast<u8>(line[0]) == 0xEF &&
            static_cast<u8>(line[1]) == 0xBB && static_cast<u8>(line[2]) == 0xBF)
            line.erase(0, 3);
        auto is_space = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
        size_t b = 0, e = line.size();
        while (b < e && is_space(line[b])) ++b;
        while (e > b && is_space(line[e - 1])) --e;
        if (b == e || line[b] == '#') continue;
        const std::string_view body(line.data() + b, e - b);
        size_t sp = 0;
        while (sp < body.size() && !is_space(body[sp])) ++sp;
        if (sp == body.size()) {
            out[hash(body)] = std::string(body);
            ++added;
            continue;
        }
        const std::string_view first = body.substr(0, sp);
        size_t rest = sp;
        while (rest < body.size() && is_space(body[rest])) ++rest;
        const std::string_view name = body.substr(rest);
        u64 v = 0;
        if (name.empty() || !decode(nid_part(first), v)) continue;
        out[v] = std::string(name);
        ++added;
    }
    return added;
}

void ensure_default_loaded(Db& d) {
    {
        std::shared_lock lk(d.mu);
        if (d.default_loaded) return;
    }
    std::unique_lock lk(d.mu);
    if (d.default_loaded) return;
    d.default_loaded = true;
    const auto path = default_override_path();
    if (path.empty()) return;
    std::ifstream in(path);
    if (in) parse_override_stream(in, d.overrides);
}

} // namespace

u64 hash(std::string_view name) {
    Sha1 sha;
    sha.update(reinterpret_cast<const u8*>(name.data()), name.size());
    sha.update(kSuffix, sizeof(kSuffix));
    const auto digest = sha.finish();
    u64 v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | digest[static_cast<size_t>(i)];
    return v;
}

std::string encode(std::string_view name) {
    const u64 v = hash(name);
    // 64 bits as 11 six-bit digits, the last one carrying 4 bits << 2
    std::string out(11, 'A');
    for (int i = 0; i < 10; ++i)
        out[static_cast<size_t>(i)] = kAlphabet[(v >> (58 - 6 * i)) & 0x3F];
    out[10] = kAlphabet[(v & 0xF) << 2];
    return out;
}

bool decode(std::string_view nid, u64& out) {
    if (nid.size() != 11) return false;
    u64 v = 0;
    for (int i = 0; i < 10; ++i) {
        const int d = digit_value(nid[static_cast<size_t>(i)]);
        if (d < 0) return false;
        v = (v << 6) | static_cast<u64>(d);
    }
    const int last = digit_value(nid[10]);
    if (last < 0 || (last & 3)) return false;
    out = (v << 4) | static_cast<u64>(last >> 2);
    return true;
}

bool decode_id(std::string_view field, u64& out) {
    if (field.empty() || field.size() > 10) return false;
    u64 v = 0;
    for (char c : field) {
        const int d = digit_value(c);
        if (d < 0) return false;
        v = (v << 6) | static_cast<u64>(d);
    }
    out = v;
    return true;
}

std::optional<std::string> lookup(std::string_view nid_or_symbol) {
    u64 v = 0;
    if (!decode(nid_part(nid_or_symbol), v)) return std::nullopt;
    Db& d = db();
    ensure_default_loaded(d);
    std::shared_lock lk(d.mu);
    if (auto it = d.overrides.find(v); it != d.overrides.end()) return it->second;
    if (auto it = d.builtin.find(v); it != d.builtin.end()) return std::string(it->second);
    return std::nullopt;
}

size_t load_overrides(const std::filesystem::path& file) {
    std::ifstream in(file);
    if (!in) return 0;
    std::unordered_map<u64, std::string> parsed;
    const size_t n = parse_override_stream(in, parsed);
    Db& d = db();
    ensure_default_loaded(d);
    std::unique_lock lk(d.mu);
    for (auto& [k, v] : parsed) d.overrides[k] = std::move(v);
    return n;
}

void add_override(std::string_view nid, std::string name) {
    u64 v = 0;
    if (!decode(nid_part(nid), v)) return;
    Db& d = db();
    ensure_default_loaded(d);
    std::unique_lock lk(d.mu);
    d.overrides[v] = std::move(name);
}

void clear_overrides() {
    Db& d = db();
    std::unique_lock lk(d.mu);
    d.overrides.clear();
    d.default_loaded = true;   // an explicit reset never re-reads the user file
}

size_t builtin_count() { return db().builtin.size(); }

std::filesystem::path default_override_path() {
#ifdef _WIN32
    char* buf = nullptr;
    size_t len = 0;
    if (_dupenv_s(&buf, &len, "LOCALAPPDATA") != 0 || !buf) return {};
    std::filesystem::path p = std::filesystem::path(buf) / "reverse-slop" / "nids.txt";
    std::free(buf);
    return p;
#else
    const char* base = std::getenv("XDG_DATA_HOME");
    if (!base || !*base) return {};
    return std::filesystem::path(base) / "reverse-slop" / "nids.txt";
#endif
}

}
