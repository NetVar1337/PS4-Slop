// src/core/memory/dissect.cpp
#include "core/memory/dissect.hpp"

#include <cmath>
#include <cstdio>
#include <cstring>

namespace slop::core::memory {

namespace {

using nlohmann::json;

std::string hex(uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof(b), "0x%llX", static_cast<unsigned long long>(v));
    return b;
}

bool printable(uint8_t c) { return c >= 0x20 && c < 0x7F; }

// >= 4 printable ASCII chars then NUL (or the buffer end): the text, else ""
std::string ascii_at(const uint8_t* p, size_t n) {
    size_t i = 0;
    while (i < n && printable(p[i])) ++i;
    if (i < 4 || (i < n && p[i] != 0)) return {};
    return std::string(reinterpret_cast<const char*>(p), i);
}

// same for UTF-16LE restricted to ASCII code points
std::string utf16_at(const uint8_t* p, size_t n) {
    std::string s;
    size_t i = 0;
    for (; i + 1 < n && printable(p[i]) && p[i + 1] == 0; i += 2) s.push_back(static_cast<char>(p[i]));
    if (s.size() < 4 || (i + 1 < n && (p[i] | p[i + 1]) != 0)) return {};
    return s;
}

bool plausible_float(double v) {
    return std::isfinite(v) && (v == 0.0 || (std::fabs(v) >= 1e-4 && std::fabs(v) <= 1e7));
}

json describe_target(uint64_t ptr, const dissect_env_t& env) {
    json t = {{"addr", ptr}};
    if (const std::string sym = env.symbolize(ptr); !sym.empty()) t["symbol"] = sym;
    if (env.executable(ptr)) {
        t["kind"] = "code";
        return t;
    }
    uint8_t buf[64] = {};
    const size_t got = env.read(ptr, buf, sizeof(buf));
    uint64_t first = 0;
    if (got >= 8) std::memcpy(&first, buf, 8);
    if (got >= 8 && first != 0 && env.executable(first)) {
        t["kind"] = "function_ptr";   // a pointer to a pointer into code
        return t;
    }
    // an object starts with a vtable: a pointer into data whose first slot is code
    uint64_t slot0 = 0;
    if (got >= 8 && first != 0 && env.readable(first) && env.read(first, &slot0, 8) == 8 &&
        slot0 != 0 && env.executable(slot0)) {
        t["kind"] = "object";
        t["vtable"] = first;
        if (const std::string sym = env.symbolize(first); !sym.empty()) t["vtable_symbol"] = sym;
        return t;
    }
    if (const std::string s = ascii_at(buf, got); !s.empty()) {
        t["kind"] = "char*";
        t["text"] = s;
    } else if (const std::string w = utf16_at(buf, got); !w.empty()) {
        t["kind"] = "wchar_t*";
        t["text"] = w;
    } else {
        t["kind"] = "data";
    }
    return t;
}

} // namespace

json dissect(uint64_t base, const uint8_t* data, size_t len, const dissect_env_t& env) {
    json rows = json::array();
    for (size_t off = 0; off + 8 <= len; off += 8) {
        const uint8_t* p = data + off;
        uint64_t v = 0;
        std::memcpy(&v, p, 8);
        json row = {{"offset", off}, {"addr", base + off}, {"hex", hex(v)}};
        float f[2];
        double d = 0;
        std::memcpy(f, p, 8);
        std::memcpy(&d, p, 8);
        uint32_t lo = 0, hi = 0;
        std::memcpy(&lo, p, 4);
        std::memcpy(&hi, p + 4, 4);

        if (v == 0) {
            row["kind"] = "zero";
        } else if (env.readable(v)) {
            json t = describe_target(v, env);
            row["kind"] = "pointer";
            row["value"] = t.value("symbol", hex(v));
            row["target"] = std::move(t);
        } else if (const std::string s = ascii_at(p, 8); !s.empty()) {
            row["kind"] = "text";
            row["value"] = s;
        } else if (lo != 0 && hi != 0 && plausible_float(f[0]) && plausible_float(f[1]) &&
                   (lo >> 23) != 0 && (hi >> 23) != 0) {
            // before double: a float pair also reads as a plausible double, but a
            // round double has lo == 0 and other doubles fail the float test on lo
            row["kind"] = "float2";
            row["value"] = json::array({f[0], f[1]});
        } else if (plausible_float(d) && (hi >> 20) != 0) {   // exponent bits set, not a small int
            row["kind"] = "double";
            row["value"] = d;
        } else if (hi == 0 || hi == 0xFFFFFFFFu) {
            row["kind"] = "int64";
            row["value"] = static_cast<int64_t>(v);
        } else {
            row["kind"] = "int32x2";
            row["value"] = json::array({static_cast<int32_t>(lo), static_cast<int32_t>(hi)});
        }
        rows.push_back(std::move(row));
    }
    return rows;
}

} // namespace slop::core::memory
