// src/core/infra/mcp_onboard.cpp
// drops the SlopStation mcp entry into every ai client config we know about
// runs once on first boot and skips anything that already has us registered
//
// every client wants a slightly different entry shape:
//  - Claude Code: ~/.claude.json "mcpServers" entry with "type":"http", it
//    reads an entry with a url but no type as stdio and skips it
//  - Claude Desktop: stdio only, remote servers go through the connectors ui
//  - Cursor / Windsurf / OpenCode: bare "url" entries
//  - VS Code: settings.json "mcp.servers" entry with "type":"http"

#include "core/infra/mcp_onboard.hpp"
#include "core/infra/paths.hpp"
#include "core/infra/settings.hpp"

#include <nlohmann/json.hpp>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#else
#include <cstdlib>
#endif

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace slop::core::infra::mcp_onboard {

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

// path helpers

std::string env_or(const char* var, const std::string& fallback) {
#ifdef _WIN32
    char buf[MAX_PATH]{};
    const DWORD n = GetEnvironmentVariableA(var, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return fallback;
    return std::string(buf, n);
#else
    const char* v = std::getenv(var);
    return (v && *v) ? std::string(v) : fallback;
#endif
}

#ifdef _WIN32
std::string localappdata() { return env_or("LOCALAPPDATA", ""); }
std::string appdata()      { return env_or("APPDATA", ""); }
std::string userprofile()  { return env_or("USERPROFILE", ""); }
#else
std::string userprofile()  { return env_or("HOME", ""); }
[[maybe_unused]] std::string localappdata() {
    return env_or("XDG_DATA_HOME", userprofile() + "/.local/share");
}
std::string appdata()      { return env_or("XDG_CONFIG_HOME", userprofile() + "/.config"); }
#endif

// json helpers

// parse result, a file we cant read never gets written back over
enum class read_t { ok, missing, corrupt };

read_t read_json_file(const std::string& path, json& out) {
    std::error_code ec;
    if (!fs::exists(path, ec) || ec) return read_t::missing;
    std::ifstream f(path);
    if (!f.is_open()) return read_t::corrupt;
    try {
        f >> out;
        return read_t::ok;
    } catch (...) {
        return read_t::corrupt;
    }
}

bool write_json_file(const std::string& path, const json& j) {
    return paths::write_file_atomic(path, j.dump(2));
}

// entry builder

constexpr const char* kServerName = "slopstation";
#ifdef _WIN32
constexpr const char* kSep = "\\";
#else
constexpr const char* kSep = "/";
#endif

// Configs reference the env var by default so a rotated token never leaves
// plaintext behind in a dotfile repo; mcp_token_in_configs opts into plaintext
// for clients that cannot expand ${VAR}.
constexpr const char* kTokenEnvRef = "Bearer ${SLOP_MCP_TOKEN}";

std::string auth_header(const std::string& token) {
    return infra::settings::mcp_token_in_configs() && !token.empty()
               ? "Bearer " + token
               : std::string(kTokenEnvRef);
}

// bare url entry, no "transport" key since nobody reads one
json make_mcp_entry(uint16_t port, const std::string& token) {
    json entry;
    entry["url"] = "http://127.0.0.1:" + std::to_string(port) + "/mcp";
    entry["headers"] = json::object({{"Authorization", auth_header(token)}});
    return entry;
}

// Tern keeps every MCP server centrally in one array and always gets the env
// reference: its config is the one users share/sync most
std::string tern_path() { return appdata() + kSep + "tern" + kSep + "settings.json"; }

json make_tern_entry(uint16_t port) {
    return {{"name", kServerName},
            {"transport", "http"},
            {"url", "http://127.0.0.1:" + std::to_string(port) + "/mcp"},
            {"headers", json::object({{"Authorization", kTokenEnvRef}})},
            {"agents", json::array()},
            {"enabled", true}};
}

// per client installers

// Each returns {client_name, installed, path, error}

// shared installer, keeps every other key and bails on a config it cant parse
// true when an existing entry already points at this port with this token
bool entry_current(const json& existing, const json& wanted) {
    if (!existing.is_object()) return false;
    for (const char* k : {"url", "headers", "type"}) {
        const bool has_w = wanted.contains(k);
        const bool has_e = existing.contains(k);
        if (has_w != has_e) return false;
        if (has_w && existing.at(k) != wanted.at(k)) return false;
    }
    return true;
}

// writes or refreshes our entry inside container[servers_key]; keeps every
// other key. a stale entry (old port/token) is rewritten in place, and in
// update_only mode a missing entry is left missing
install_result_t upsert_entry(const char* client, const std::string& path, json& cfg,
                              json& container, const char* servers_key, json entry,
                              bool update_only) {
    if (!container.contains(servers_key) || !container.at(servers_key).is_object()) {
        if (update_only) return {client, false, path, ""};
        container[servers_key] = json::object();
    }
    json& servers = container[servers_key];
    if (servers.contains(kServerName)) {
        json& existing = servers[kServerName];
        if (entry_current(existing, entry)) return {client, false, path, ""};
        // keep user additions (env, disabled flags...) and refresh only what we own
        if (existing.is_object()) {
            existing.erase("headers");
            for (auto& [k, v] : entry.items()) existing[k] = v;
        } else {
            existing = std::move(entry);
        }
    } else {
        if (update_only) return {client, false, path, ""};
        servers[kServerName] = std::move(entry);
    }
    if (!write_json_file(path, cfg))
        return {client, false, path, "write failed"};
    return {client, true, path, ""};
}

// shared installer, keeps every other key and bails on a config it cant parse
install_result_t install_url_entry(const char* client, const std::string& path,
                                   uint16_t port, const std::string& token,
                                   bool with_type, bool update_only) {
    json cfg;
    switch (read_json_file(path, cfg)) {
    case read_t::corrupt:
        return {client, false, path, "config unparseable, left untouched"};
    case read_t::missing:
        if (update_only) return {client, false, path, ""};
        cfg = json::object();
        break;
    default:
        break;
    }
    if (!cfg.is_object())
        return {client, false, path, "config root is not an object, left untouched"};

    json entry = make_mcp_entry(port, token);
    if (with_type) entry["type"] = "http";
    return upsert_entry(client, path, cfg, cfg, "mcpServers", std::move(entry), update_only);
}

// old builds wrote a dead entry into ~/.claude/settings.json, wipe just ours
void remove_legacy_claude_code_settings_entry() {
    const std::string path = userprofile() + kSep + ".claude" + kSep + "settings.json";
    json settings;
    if (read_json_file(path, settings) != read_t::ok) return;
    if (!settings.contains("mcpServers") ||
        !settings.at("mcpServers").is_object() ||
        !settings.at("mcpServers").contains(kServerName))
        return;
    settings["mcpServers"].erase(kServerName);
    if (settings.at("mcpServers").empty()) settings.erase("mcpServers");
    write_json_file(path, settings);
}

install_result_t do_claude_code_global(uint16_t port, const std::string& token, bool update_only) {
    // ~/.claude.json is claude codes state file so only add our key and touch nothing else
    remove_legacy_claude_code_settings_entry();   // old builds wrote there
    return install_url_entry("Claude Code (global)", userprofile() + kSep + ".claude.json",
                             port, token, /*with_type=*/true, update_only);
}

install_result_t do_claude_desktop(uint16_t port, const std::string& token) {
    (void)port;
    (void)token;
    // desktop config only does stdio servers so all we can do here is clean up
    const std::string path = appdata() + kSep + "Claude" + kSep + "claude_desktop_config.json";
    json cfg;
    if (read_json_file(path, cfg) == read_t::ok &&
        cfg.contains("mcpServers") && cfg.at("mcpServers").is_object() &&
        cfg.at("mcpServers").contains(kServerName)) {
        const json& e = cfg.at("mcpServers").at(kServerName);
        if (!e.contains("command")) {   // ours, a url entry a stdio client cant load
            cfg["mcpServers"].erase(kServerName);
            if (cfg.at("mcpServers").empty()) cfg.erase("mcpServers");
            write_json_file(path, cfg);
        }
    }
    return {"Claude Desktop", false, path,
            "desktop config is stdio-only; add remote MCP via the Connectors UI"};
}

install_result_t do_cursor(uint16_t port, const std::string& token, bool update_only) {
    return install_url_entry("Cursor", userprofile() + kSep + ".cursor" + kSep + "mcp.json",
                             port, token, /*with_type=*/false, update_only);
}

install_result_t do_windsurf(uint16_t port, const std::string& token, bool update_only) {
    return install_url_entry("Windsurf",
                             userprofile() + kSep + ".codeium" + kSep + "windsurf" + kSep + "mcp_config.json",
                             port, token, /*with_type=*/false, update_only);
}

install_result_t do_vscode(uint16_t port, const std::string& token, bool update_only) {
    // vs code tucks servers under mcp.servers
    const std::string path = appdata() + kSep + "Code" + kSep + "User" + kSep + "settings.json";

    json settings;
    switch (read_json_file(path, settings)) {
    case read_t::corrupt:
        return {"VS Code", false, path, "config unparseable, left untouched"};
    case read_t::missing:
        if (update_only) return {"VS Code", false, path, ""};
        settings = json::object();
        break;
    default:
        break;
    }
    if (!settings.is_object())
        return {"VS Code", false, path, "config root is not an object, left untouched"};

    // VS Code uses "mcp" -> "servers" -> { name: { ... } }; a non-object "mcp"
    // is the user's business, never overwrite it
    if (!settings.contains("mcp")) {
        if (update_only) return {"VS Code", false, path, ""};
        settings["mcp"] = json::object();
    }
    if (!settings.at("mcp").is_object())
        return {"VS Code", false, path, "\"mcp\" is not an object, left untouched"};

    json entry = make_mcp_entry(port, token);
    entry["type"] = "http";
    return upsert_entry("VS Code", path, settings, settings["mcp"], "servers",
                        std::move(entry), update_only);
}

install_result_t do_opencode(uint16_t port, const std::string& token, bool update_only) {
    // ~/.config/opencode/config.json  (XDG on Linux; %USERPROFILE%\.config on Win)
    return install_url_entry("OpenCode",
                             userprofile() + kSep + ".config" + kSep + "opencode" + kSep + "config.json",
                             port, token, /*with_type=*/false, update_only);
}

// Tern: agents.mcp is an array of flat entries, matched by name. "agents" is
// the user's scope choice, so it is written once and never refreshed.
constexpr const char* kTernOwnedKeys[] = {"name", "transport", "url", "headers", "enabled"};

bool tern_entry_current(const json& existing, const json& wanted) {
    if (!existing.is_object()) return false;
    for (const char* k : kTernOwnedKeys) {
        const bool has_w = wanted.contains(k);
        const bool has_e = existing.contains(k);
        if (has_w != has_e) return false;
        if (has_w && existing.at(k) != wanted.at(k)) return false;
    }
    return true;
}

install_result_t do_tern(uint16_t port, bool update_only) {
    const std::string path = tern_path();
    json cfg;
    switch (read_json_file(path, cfg)) {
    case read_t::missing:
        // only users who already run Tern get an entry; never create %APPDATA%\tern
        return {"Tern", false, path, ""};
    case read_t::corrupt:
        return {"Tern", false, path, "config unparseable, left untouched"};
    default:
        break;
    }
    if (!cfg.is_object())
        return {"Tern", false, path, "config root is not an object, left untouched"};

    // a non-object agents / non-array mcp is the user's business, never overwrite it
    if (!cfg.contains("agents")) {
        if (update_only) return {"Tern", false, path, ""};
        cfg["agents"] = json::object();
    }
    if (!cfg.at("agents").is_object())
        return {"Tern", false, path, "\"agents\" is not an object, left untouched"};
    json& agents = cfg["agents"];
    if (!agents.contains("mcp")) {
        if (update_only) return {"Tern", false, path, ""};
        agents["mcp"] = json::array();
    }
    if (!agents.at("mcp").is_array())
        return {"Tern", false, path, "agents.mcp is not an array, left untouched"};

    json& servers = agents["mcp"];
    json entry = make_tern_entry(port);
    for (auto& e : servers) {
        if (!e.is_object() || e.value("name", std::string{}) != kServerName) continue;
        if (tern_entry_current(e, entry)) return {"Tern", false, path, ""};
        // keep user additions (a scoped agents list, extra keys) and refresh ours
        for (const char* k : kTernOwnedKeys) e[k] = entry.at(k);
        if (!write_json_file(path, cfg)) return {"Tern", false, path, "write failed"};
        return {"Tern", true, path, ""};
    }
    if (update_only) return {"Tern", false, path, ""};
    servers.push_back(std::move(entry));
    if (!write_json_file(path, cfg)) return {"Tern", false, path, "write failed"};
    return {"Tern", true, path, ""};
}

} // namespace

// public api

namespace {

// one bad config must never abort the sweep (or the boot that runs it)
template <class Fn>
install_result_t guarded(const char* client, Fn&& fn) {
    try {
        return fn();
    } catch (const std::exception& e) {
        return {client, false, "", std::string("installer failed: ") + e.what()};
    } catch (...) {
        return {client, false, "", "installer failed"};
    }
}

std::vector<install_result_t> sweep(uint16_t port, const std::string& token, bool update_only) {
    std::vector<install_result_t> results;
    std::vector<std::string> clients = infra::settings::mcp_onboard_clients();
    if (clients.empty()) clients = default_clients();
    results.reserve(clients.size());
    for (const std::string& client : clients) {
        const char* c = client.c_str();
        if (client == "Tern") {
            results.push_back(guarded(c, [&] { return do_tern(port, update_only); }));
        } else if (client == "Claude Code (global)") {
            results.push_back(guarded(c, [&] {
                return do_claude_code_global(port, token, update_only);
            }));
        } else if (client == "Claude Desktop") {
            if (!update_only)
                results.push_back(guarded(c, [&] { return do_claude_desktop(port, token); }));
        } else if (client == "Cursor") {
            results.push_back(guarded(c, [&] { return do_cursor(port, token, update_only); }));
        } else if (client == "Windsurf") {
            results.push_back(guarded(c, [&] { return do_windsurf(port, token, update_only); }));
        } else if (client == "VS Code") {
            results.push_back(guarded(c, [&] { return do_vscode(port, token, update_only); }));
        } else if (client == "OpenCode") {
            results.push_back(guarded(c, [&] { return do_opencode(port, token, update_only); }));
        }
    }
    return results;
}

} // namespace

std::vector<install_result_t> install_all(uint16_t port, const std::string& token) {
    return sweep(port, token, /*update_only=*/false);
}

std::vector<install_result_t> refresh_existing(uint16_t port, const std::string& token) {
    return sweep(port, token, /*update_only=*/true);
}

std::vector<install_result_t> uninstall_all() {
    std::vector<install_result_t> results;

    auto remove_key = [&](const char* client, const std::string& path,
                          const char* servers_key, const char* parent_key = nullptr) {
        json cfg;
        switch (read_json_file(path, cfg)) {
        case read_t::missing:
            results.push_back({client, false, path, "file not found"});
            return;
        case read_t::corrupt:
            results.push_back({client, false, path, "config unparseable, left untouched"});
            return;
        default:
            break;
        }

        json* container = &cfg;
        if (parent_key && cfg.contains(parent_key))
            container = &cfg[parent_key];

        if (!container->contains(servers_key) ||
            !(*container)[servers_key].contains(kServerName)) {
            results.push_back({client, false, path, ""});
            return;
        }

        (*container)[servers_key].erase(kServerName);
        if (write_json_file(path, cfg))
            results.push_back({client, true, path, ""});
        else
            results.push_back({client, false, path, "write failed"});
    };

    remove_key("Claude Code (global)",
               userprofile() + kSep + ".claude.json", "mcpServers");
    // Pre-fix builds wrote into settings.json instead of .claude.json  
    // clean both so uninstall actually removes what install wrote
    remove_key("Claude Code (legacy settings)",
               userprofile() + kSep + ".claude" + kSep + "settings.json", "mcpServers");
    remove_key("Claude Desktop",
               appdata() + kSep + "Claude" + kSep + "claude_desktop_config.json", "mcpServers");
    remove_key("Cursor",
               userprofile() + kSep + ".cursor" + kSep + "mcp.json", "mcpServers");
    remove_key("Windsurf",
               userprofile() + kSep + ".codeium" + kSep + "windsurf" + kSep + "mcp_config.json", "mcpServers");
    remove_key("VS Code",
               appdata() + kSep + "Code" + kSep + "User" + kSep + "settings.json", "servers", "mcp");
    remove_key("OpenCode",
               userprofile() + kSep + ".config" + kSep + "opencode" + kSep + "config.json", "mcpServers");

    // Tern keeps servers in an array, so it needs its own removal
    {
        const std::string path = tern_path();
        json cfg;
        switch (read_json_file(path, cfg)) {
        case read_t::missing:
            results.push_back({"Tern", false, path, "file not found"});
            break;
        case read_t::corrupt:
            results.push_back({"Tern", false, path, "config unparseable, left untouched"});
            break;
        default:
            if (!cfg.is_object() || !cfg.contains("agents") || !cfg.at("agents").is_object() ||
                !cfg.at("agents").contains("mcp") || !cfg.at("agents").at("mcp").is_array()) {
                results.push_back({"Tern", false, path, ""});
                break;
            }
            {
                json& servers = cfg["agents"]["mcp"];
                const size_t before = servers.size();
                servers.erase(std::remove_if(servers.begin(), servers.end(),
                                             [](const json& e) {
                                                 return e.is_object() &&
                                                        e.value("name", std::string{}) ==
                                                            kServerName;
                                             }),
                              servers.end());
                if (servers.size() == before)
                    results.push_back({"Tern", false, path, ""});
                else if (write_json_file(path, cfg))
                    results.push_back({"Tern", true, path, ""});
                else
                    results.push_back({"Tern", false, path, "write failed"});
            }
            break;
        }
    }

    return results;
}

std::vector<std::string> default_clients() {
    std::error_code ec;
    if (fs::exists(tern_path(), ec) && !ec) return {"Tern"};
    return {"Claude Code (global)", "Claude Desktop", "Cursor", "Windsurf", "VS Code", "OpenCode"};
}

std::vector<std::string> plaintext_token_clients() {
    std::vector<std::string> out;

    // a literal bearer is anything that is not the ${SLOP_MCP_TOKEN} reference
    auto literal = [](const json& entry) {
        if (!entry.is_object() || !entry.contains("headers") || !entry.at("headers").is_object())
            return false;
        const json& h = entry.at("headers");
        if (!h.contains("Authorization") || !h.at("Authorization").is_string()) return false;
        return h.at("Authorization").get<std::string>().find("${") == std::string::npos;
    };

    auto check = [&](const char* client, const std::string& path, const char* servers_key,
                     const char* parent_key = nullptr) {
        json cfg;
        if (read_json_file(path, cfg) != read_t::ok || !cfg.is_object()) return;
        const json* container = &cfg;
        if (parent_key) {
            if (!cfg.contains(parent_key) || !cfg.at(parent_key).is_object()) return;
            container = &cfg.at(parent_key);
        }
        if (!container->contains(servers_key) || !(*container)[servers_key].is_object()) return;
        const json& servers = (*container)[servers_key];
        if (servers.contains(kServerName) && literal(servers.at(kServerName)))
            out.push_back(client);
    };

    check("Claude Code (global)", userprofile() + kSep + ".claude.json", "mcpServers");
    check("Cursor", userprofile() + kSep + ".cursor" + kSep + "mcp.json", "mcpServers");
    check("Windsurf", userprofile() + kSep + ".codeium" + kSep + "windsurf" + kSep + "mcp_config.json", "mcpServers");
    check("VS Code", appdata() + kSep + "Code" + kSep + "User" + kSep + "settings.json", "servers", "mcp");
    check("OpenCode", userprofile() + kSep + ".config" + kSep + "opencode" + kSep + "config.json", "mcpServers");

    json tern;
    if (read_json_file(tern_path(), tern) == read_t::ok && tern.is_object() &&
        tern.contains("agents") && tern.at("agents").is_object() &&
        tern.at("agents").contains("mcp") && tern.at("agents").at("mcp").is_array()) {
        for (const auto& e : tern.at("agents").at("mcp"))
            if (e.is_object() && e.value("name", std::string{}) == kServerName && literal(e)) {
                out.push_back("Tern");
                break;
            }
    }
    return out;
}

} // namespace slop::core::infra::mcp_onboard
