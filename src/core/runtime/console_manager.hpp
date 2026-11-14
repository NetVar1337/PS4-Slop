#pragma once

// src/core/runtime/console_manager.hpp
// saved console endpoints (multi-console manager): CRUD over the settings
// store, the last active console, and the named watchlist sets a console
// profile restores on a switch

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace slop::core::runtime::consoles {

// what a console carries across a switch; the engine applies it on connect
struct profile_t {
    std::string watchlist;    // named watchlist set restored on switch
    std::string scan_width;   // preferred scan width ("i32", "u32", "f32", ...)
    std::string scan_kind;    // preferred scan kind ("exact", "changed", ...)
};

struct console_t {
    std::string name;
    std::string host;
    uint16_t    port = 744;
    std::string notes;
    uint32_t    default_pid = 0;     // attached right after the switch (0 = none)
    std::string title_filter;        // process-list filter the ui restores
    bool        auto_connect = false;
    profile_t   profile;

    // filled in by the engine on connect/switch from the live payload
    int64_t     last_seen_ms = 0;
    std::string last_fw;
    std::string last_branding;
    std::string last_caps;
};

// wire form (also what consoles_list returns)
nlohmann::json to_json(const console_t& c);

std::vector<console_t> list();
bool find(const std::string& name, console_t& out);

// upsert by name; false + err on an invalid name/host/port or a failed write
bool save(const console_t& c, std::string& err);
bool remove(const std::string& name);

// name of the console last connected/switched to ("" when none)
std::string active();
void        set_active(const std::string& name);

// named watchlist sets: entries are {addr, width, label, freeze}
nlohmann::json watchlist_set(const std::string& name);
bool           save_watchlist_set(const std::string& name, nlohmann::json entries);

} // namespace slop::core::runtime::consoles
