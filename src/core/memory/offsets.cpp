// src/core/memory/offsets.cpp
#include "core/memory/offsets.hpp"

#include <algorithm>
#include <cctype>

#include "core/memory/aob.hpp"
#include "core/util/sha256.hpp"

namespace slop::core::memory {

namespace {

using nlohmann::json;

bool parse_u64(const json& v, uint64_t& out) {
    if (v.is_number_unsigned()) { out = v.get<uint64_t>(); return true; }
    if (v.is_number_integer() && v.get<int64_t>() >= 0) { out = v.get<uint64_t>(); return true; }
    if (!v.is_string()) return false;
    const std::string s = v.get<std::string>();
    if (s.empty()) return false;
    size_t used = 0;
    try { out = std::stoull(s, &used, 0); } catch (...) { return false; }
    return used == s.size();
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

} // namespace

json verify_offsets(const json& m, const offsets_input_t& in) {
    json errors = json::array();
    json checks = json::object();
    const auto out = [&] {
        return json{{"ok", errors.empty()}, {"errors", errors}, {"checks", checks},
                    {"resolved", json::object()}};
    };
    if (!m.is_object()) {
        errors.push_back("manifest must be a JSON object");
        return out();
    }

    // build fingerprint first: nothing below is trusted on a different build
    for (const char* key : {"title_id", "app_ver"}) {
        if (!m.contains(key)) continue;
        const std::string want = m[key].is_string() ? m[key].get<std::string>() : "";
        const std::string& have = std::string(key) == "title_id" ? in.title_id : in.app_ver;
        checks[key] = {{"want", want}, {"have", have}};
        if (have.empty()) errors.push_back(std::string(key) + ": the target does not report one");
        else if (want != have) errors.push_back(std::string(key) + ": manifest " + want + ", target " + have);
    }
    const std::string want_sha = m.value("text_sha256", std::string{});
    if (want_sha.size() != 64) {
        errors.push_back("text_sha256 (64 hex chars) is required");
    } else if (!in.text || in.text_len == 0) {
        errors.push_back("no executable segment to hash");
    } else {
        const std::string have_sha = util::sha256_hex(in.text, in.text_len);
        checks["text_sha256"] = {{"want", lower(want_sha)}, {"have", have_sha}};
        if (have_sha != lower(want_sha)) errors.push_back("text_sha256 mismatch: different build");
    }
    if (!m.contains("offsets") || !m["offsets"].is_array() || m["offsets"].empty())
        errors.push_back("offsets must be a non-empty array");
    if (!errors.empty()) return out();

    json resolved = json::object();
    json entries = json::array();
    for (const auto& e : m["offsets"]) {
        const std::string name = e.is_object() ? e.value("name", std::string{}) : "";
        const auto bad = [&](const std::string& why) {
            errors.push_back((name.empty() ? std::string("<unnamed>") : name) + ": " + why);
        };
        if (name.empty()) { bad("missing name"); continue; }
        if (resolved.contains(name)) { bad("duplicate name"); continue; }
        std::string err;
        const auto pat = e.contains("aob") && e["aob"].is_string()
                             ? aob_compile(e["aob"].get<std::string>(), err)
                             : std::nullopt;
        if (!pat) { bad("anchor aob " + (err.empty() ? "missing" : err)); continue; }
        int64_t delta = 0;
        if (e.contains("aob_offset")) {
            if (!e["aob_offset"].is_number_integer()) { bad("aob_offset must be an integer"); continue; }
            delta = e["aob_offset"].get<int64_t>();
        }

        // the anchor must be unique in the executable segment
        size_t hits = 0;
        uint64_t at = 0;
        for (size_t i = 0; i + pat->size() <= in.text_len && hits < 2; ++i)
            if (aob_match(*pat, in.text + i, in.text_len - i)) { ++hits; at = in.text_base + i; }
        if (hits != 1) { bad(hits == 0 ? "anchor not found" : "anchor is not unique"); continue; }

        const uint64_t addr = at + static_cast<uint64_t>(delta);
        if (e.contains("rva")) {
            uint64_t rva = 0;
            if (!parse_u64(e["rva"], rva)) { bad("rva must be a non-negative number or hex string"); continue; }
            if (in.text_base + rva != addr) {
                bad("anchor resolves to rva " + std::to_string(addr - in.text_base) +
                    ", manifest says " + std::to_string(rva));
                continue;
            }
        }
        resolved[name] = addr;
        entries.push_back({{"name", name}, {"addr", addr}, {"anchor", at}});
    }
    json r = out();
    r["entries"] = entries;
    if (errors.empty()) r["resolved"] = std::move(resolved);   // fail closed
    return r;
}

} // namespace slop::core::memory
