#pragma once

// src/core/disasm/strings.hpp
// ASCII + UTF-16LE string extraction over a byte image

#include <cstdint>
#include <string>
#include <vector>

namespace slop::core::disasm {

struct string_hit_t {
    uintptr_t   va    = 0;
    std::string text;
    bool        utf16 = false;
};

struct string_stats_t {
    size_t scanned   = 0;
    size_t hits      = 0;
    bool   truncated = false;
};

// Scan [data, data+len) mapped at va_base. Strings must be NUL-terminated
// and >= min_chars. UTF-16 runs are preferred when they qualify
std::vector<string_hit_t> extract_strings(const uint8_t* data, size_t len,
                                          uintptr_t va_base,
                                          size_t min_chars = 4,
                                          size_t max_results = 200'000,
                                          string_stats_t* stats = nullptr);

// Shannon entropy of a byte run, bits per byte (0..8). Used to pick the
// high-entropy blobs worth a decode preview
double shannon_entropy(const uint8_t* data, size_t len);

// One decoded preview of an obfuscated blob
struct decode_candidate_t {
    std::string scheme;   // "xor:0x5A", "rot13", "rot47", "base64", "utf16le"
    std::string text;
    double      score = 0.0;   // printable ratio * length weight, 0..1
};

// Try single-byte XOR keys, ROT13/ROT47, base64 and UTF-16LE over a blob and
// return the readable candidates, best score first. Pure and bounded: at most
// 256 keys and max_candidates results per blob
std::vector<decode_candidate_t> decode_candidates(const uint8_t* data, size_t len,
                                                  size_t max_candidates = 8);

} // namespace slop::core::disasm
