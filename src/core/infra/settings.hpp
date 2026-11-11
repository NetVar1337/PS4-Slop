#pragma once

// src/core/infra/settings.hpp
// persistent engine settings (%LOCALAPPDATA%\reverse-slop\settings.json)
//
// every setter persists immediately through an atomic replace so a crash never
// loses a change and never leaves a half written file behind

#include <cstdint>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace slop::core::infra::settings {

// loads settings_file(); a parseable non-object or unparseable file is backed up
// to settings.json.corrupt-<ms> and replaced by an empty object. generates the
// mcp_token on first run when it is empty
void load();
// atomic write of the current state; returns false when the write failed
bool save();

// tests point the store at a scratch file; load() reads from it afterwards
void set_file_for_testing(std::string path);
const std::string& file();

// raw value or null when absent
nlohmann::json get_json(std::string_view key);

// typed read with a fallback for missing keys and type mismatches
template <class T>
T get(std::string_view key, T def) {
    const nlohmann::json j = get_json(key);
    if (j.is_null()) return def;
    try {
        return j.get<T>();
    } catch (...) {
        return def;
    }
}

// sets (null erases) and persists immediately; false when the write failed
bool set(std::string_view key, nlohmann::json value);

// copy of the whole settings object
nlohmann::json snapshot();

// MCP server
bool        mcp_enabled();
uint16_t    mcp_port();                 // out of range values fall back to 8765
std::string mcp_token();
std::string generate_token();           // 32 random bytes as 64 hex chars

// first run registration into ai clients
bool mcp_onboarded();
void set_mcp_onboarded(bool v);

// MCP audit trail + confirm gate (ps4debug-mcp safety model): every tool call
// is appended as one JSONL line to mcp_audit_path(); when mcp_require_confirm
// is on, mutating console/target actions refuse to run without "confirm": true
bool        mcp_audit_enabled();      // default true
std::string mcp_audit_path();         // default <app_data>\mcp_audit.jsonl, "" disables
bool        mcp_require_confirm();    // default false (opt-in)

} // namespace slop::core::infra::settings
