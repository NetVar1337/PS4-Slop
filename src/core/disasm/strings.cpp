// src/core/disasm/strings.cpp

#include "core/disasm/strings.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>

namespace slop::core::disasm {

namespace {

bool ascii_printable(uint8_t c) noexcept {
    return (c >= 0x20 && c <= 0x7E) || c == '\t' || c == '\n' || c == '\r';
}

bool utf16_printable(uint8_t lo, uint8_t hi) noexcept {
    return hi == 0x00 && ascii_printable(lo);
}

} // namespace

std::vector<string_hit_t> extract_strings(const uint8_t* data, size_t len,
                                          uintptr_t va_base,
                                          size_t min_chars,
                                          size_t max_results,
                                          string_stats_t* stats) {
    std::vector<string_hit_t> out;
    string_stats_t local{};
    auto& st = stats ? *stats : local;
    st.scanned = 0;
    st.hits = 0;
    st.truncated = false;

    size_t i = 0;
    while (i < len) {
        ++st.scanned;

        // UTF-16LE candidate: printable, NUL, printable, NUL ..
        if (i + 2 * static_cast<int>(min_chars) <= len &&
            utf16_printable(data[i], data[i + 1])) {
            size_t j = i;
            std::string s;
            s.reserve(64);
            while (j + 1 < len && utf16_printable(data[j], data[j + 1]) && s.size() < 4096) {
                s.push_back(static_cast<char>(data[j]));
                j += 2;
            }
            // Must be terminated by NUL pair and long enough
            if (s.size() >= min_chars && j + 1 < len &&
                data[j] == 0x00 && data[j + 1] == 0x00) {
                string_hit_t h;
                h.va    = va_base + i;
                h.text  = std::move(s);
                h.utf16 = true;
                out.push_back(std::move(h));
                ++st.hits;
                if (out.size() >= max_results) { st.truncated = true; return out; }
                i = j + 2;
                continue;
            }
            // Fall through to ASCII handling for this byte
        }

        // ASCII run
        if (ascii_printable(data[i])) {
            size_t j = i;
            std::string s;
            s.reserve(64);
            while (j < len && ascii_printable(data[j]) && s.size() < 4096) {
                s.push_back(static_cast<char>(data[j]));
                ++j;
            }
            const bool terminated = j < len && data[j] == 0x00;
            if (terminated && s.size() >= min_chars) {
                // Skip pure-whitespace noise
                const bool meaningful = s.find_first_not_of(" \t\r\n") != std::string::npos;
                if (meaningful) {
                    string_hit_t h;
                    h.va   = va_base + i;
                    h.text = std::move(s);
                    out.push_back(std::move(h));
                    ++st.hits;
                    if (out.size() >= max_results) { st.truncated = true; return out; }
                    i = j + 1;
                    continue;
                }
            }
            i = j > i ? j : i + 1;
            continue;
        }

        ++i;
    }

    st.hits = out.size();
    return out;
}

double shannon_entropy(const uint8_t* data, size_t len) {
    if (!data || len == 0) return 0.0;
    double counts[256] = {};
    for (size_t i = 0; i < len; ++i) counts[data[i]] += 1.0;
    double h = 0.0;
    for (double c : counts) {
        if (c == 0.0) continue;
        const double p = c / static_cast<double>(len);
        h -= p * std::log2(p);
    }
    return h;
}

namespace {

// Fraction of bytes that are printable ASCII; NULs and controls drag it down
double printable_ratio(const std::string& s) {
    if (s.empty()) return 0.0;
    size_t ok = 0;
    for (unsigned char c : s)
        if ((c >= 0x20 && c <= 0x7E) || c == '\t' || c == '\n' || c == '\r') ++ok;
    return static_cast<double>(ok) / static_cast<double>(s.size());
}

// A preview is only interesting when it is mostly readable text
bool plausible(const std::string& s) {
    if (s.size() < 6) return false;
    if (printable_ratio(s) < 0.92) return false;
    // reject runs of one repeated character (padding, 0x00 XOR 0x00)
    char first = s[0];
    bool all_same = true;
    for (char c : s)
        if (c != first) { all_same = false; break; }
    return !all_same;
}

double score_of(const std::string& s) {
    // printable ratio dominates; word characters (letters, digits, spaces)
    // separate real text from punctuation soup that XOR keys also produce
    const double ratio = printable_ratio(s);
    const double len_w = std::min<double>(1.0, static_cast<double>(s.size()) / 32.0);
    size_t word = 0;
    for (unsigned char c : s)
        if (std::isalnum(c) || c == ' ' || c == '_' || c == '\t' ||
            c == '\n' || c == '\r')
            ++word;
    const double word_w = s.empty() ? 0.0
                                    : static_cast<double>(word) / static_cast<double>(s.size());
    return ratio * 0.6 + word_w * 0.3 + len_w * 0.1;
}

int b64_value(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

std::string base64_decode(const std::string& in) {
    std::string out;
    int acc = 0, bits = 0;
    for (unsigned char c : in) {
        if (c == '=') break;
        const int v = b64_value(c);
        if (v < 0) return {};
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((acc >> bits) & 0xFF));
        }
    }
    return out;
}

bool looks_base64(const std::string& s) {
    if (s.size() < 8) return false;
    size_t pad = 0;
    for (unsigned char c : s) {
        if (c == '=') { ++pad; continue; }
        if (b64_value(c) < 0) return false;
    }
    return pad <= 2 && s.size() % 4 == 0;
}

} // namespace

std::vector<decode_candidate_t> decode_candidates(const uint8_t* data, size_t len,
                                                  size_t max_candidates) {
    std::vector<decode_candidate_t> out;
    if (!data || len < 6) return out;
    // previews are text: cap the blob so a 1 MiB section cannot stall a call
    const size_t n = std::min<size_t>(len, 512);

    auto consider = [&](std::string scheme, std::string text) {
        if (!plausible(text)) return;
        decode_candidate_t c;
        c.text   = std::move(text);
        c.score  = score_of(c.text);
        c.scheme = std::move(scheme);
        out.push_back(std::move(c));
    };

    // single-byte XOR: the classic string obfuscation, key 0 is the input
    for (int key = 1; key < 256; ++key) {
        std::string s;
        s.reserve(n);
        for (size_t i = 0; i < n; ++i)
            s.push_back(static_cast<char>(data[i] ^ static_cast<uint8_t>(key)));
        consider("xor:0x" + [&] {
            char hex[8];
            std::snprintf(hex, sizeof(hex), "%02X", static_cast<unsigned>(key));
            return std::string(hex);
        }(), std::move(s));
    }

    // ROT13 / ROT47 over the ASCII interpretation of the blob
    std::string ascii(reinterpret_cast<const char*>(data), n);
    {
        std::string s = ascii;
        for (char& c : s) {
            if (c >= 'a' && c <= 'z') c = static_cast<char>('a' + (c - 'a' + 13) % 26);
            else if (c >= 'A' && c <= 'Z') c = static_cast<char>('A' + (c - 'A' + 13) % 26);
        }
        consider("rot13", std::move(s));
    }
    {
        std::string s = ascii;
        for (char& c : s) {
            const int v = static_cast<unsigned char>(c);
            if (v >= 33 && v <= 126)
                c = static_cast<char>(33 + (v - 33 + 47) % 94);
        }
        consider("rot47", std::move(s));
    }

    // base64: decode the printable prefix up to the first NUL
    {
        std::string b64;
        for (size_t i = 0; i < n; ++i) {
            const unsigned char c = data[i];
            if (c == 0) break;
            b64.push_back(static_cast<char>(c));
        }
        if (looks_base64(b64)) {
            std::string decoded = base64_decode(b64);
            // only ASCII payloads are useful as a string preview
            if (!decoded.empty() && printable_ratio(decoded) >= 0.92)
                consider("base64", std::move(decoded));
        }
    }

    // UTF-16LE: printable byte + NUL pairs
    {
        std::string s;
        for (size_t i = 0; i + 1 < n; i += 2) {
            if (data[i + 1] != 0x00) { s.clear(); break; }
            s.push_back(static_cast<char>(data[i]));
        }
        if (!s.empty()) consider("utf16le", std::move(s));
    }

    std::sort(out.begin(), out.end(),
              [](const decode_candidate_t& a, const decode_candidate_t& b) {
                  return a.score > b.score;
              });
    if (out.size() > max_candidates) out.resize(max_candidates);
    return out;
}

} // namespace slop::core::disasm
