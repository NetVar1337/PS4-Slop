#include "core/runtime/console_manager.hpp"

#include "core/infra/settings.hpp"

#include <algorithm>
#include <cctype>
#include <mutex>

namespace slop::core::runtime::consoles {

namespace {

constexpr const char* kListKey   = "target_consoles";
constexpr const char* kActiveKey = "target_consoles_active";
constexpr const char* kSetsKey   = "target_watchlists";

// the settings store guards its own map; this guards the read-modify-write of
// the console list so two saves cannot drop each other
std::mutex g_mu;

bool valid_name(const std::string& n) {
    if (n.empty() || n.size() > 64) return false;
    return std::all_of(n.begin(), n.end(), [](char c) {
        const auto u = static_cast<unsigned char>(c);
        return std::isalnum(u) != 0 || c == '.' || c == '_' || c == '-';
    });
}

bool valid_host(const std::string& h) {
    if (h.empty() || h.size() > 255) return false;
    return std::none_of(h.begin(), h.end(), [](char c) {
        return std::isspace(static_cast<unsigned char>(c)) != 0;
    });
}

// tolerant: a hand-edited entry missing name/host is skipped, never fatal
bool from_json(const nlohmann::json& j, console_t& c) {
    if (!j.is_object()) return false;
    if (!j.contains("name") || !j["name"].is_string()) return false;
    if (!j.contains("host") || !j["host"].is_string()) return false;
    c.name = j["name"].get<std::string>();
    c.host = j["host"].get<std::string>();
    if (!valid_name(c.name) || !valid_host(c.host)) return false;
    const int64_t port = j.value("port", int64_t{744});
    if (port < 1 || port > 65535) return false;
    c.port          = static_cast<uint16_t>(port);
    c.notes         = j.value("notes", std::string{});
    c.default_pid   = static_cast<uint32_t>(std::max<int64_t>(
        j.value("default_pid", int64_t{0}), 0));
    c.title_filter  = j.value("title_filter", std::string{});
    c.auto_connect  = j.value("auto_connect", false);
    c.last_seen_ms  = j.value("last_seen_ms", int64_t{0});
    c.last_fw       = j.value("last_fw", std::string{});
    c.last_branding = j.value("last_branding", std::string{});
    c.last_caps     = j.value("last_caps", std::string{});
    if (j.contains("profile") && j["profile"].is_object()) {
        const auto& p          = j["profile"];
        c.profile.watchlist    = p.value("watchlist", std::string{});
        c.profile.scan_width   = p.value("scan_width", std::string{});
        c.profile.scan_kind    = p.value("scan_kind", std::string{});
    }
    return true;
}

nlohmann::json list_raw() {
    const nlohmann::json arr = infra::settings::get_json(kListKey);
    return arr.is_array() ? arr : nlohmann::json::array();
}

} // namespace

nlohmann::json to_json(const console_t& c) {
    return {{"name", c.name},
            {"host", c.host},
            {"port", c.port},
            {"notes", c.notes},
            {"default_pid", c.default_pid},
            {"title_filter", c.title_filter},
            {"auto_connect", c.auto_connect},
            {"profile", {{"watchlist", c.profile.watchlist},
                         {"scan_width", c.profile.scan_width},
                         {"scan_kind", c.profile.scan_kind}}},
            {"last_seen_ms", c.last_seen_ms},
            {"last_fw", c.last_fw},
            {"last_branding", c.last_branding},
            {"last_caps", c.last_caps}};
}

std::vector<console_t> list() {
    std::lock_guard lk(g_mu);
    std::vector<console_t> out;
    for (const auto& j : list_raw()) {
        console_t c;
        if (from_json(j, c)) out.push_back(std::move(c));
    }
    return out;
}

bool find(const std::string& name, console_t& out) {
    for (const auto& c : list()) {
        if (c.name != name) continue;
        out = c;
        return true;
    }
    return false;
}

bool save(const console_t& c, std::string& err) {
    if (!valid_name(c.name)) {
        err = "name must be 1..64 chars of [A-Za-z0-9._-]";
        return false;
    }
    if (!valid_host(c.host)) {
        err = "host must be a non-empty address without spaces";
        return false;
    }
    if (c.port == 0) {
        err = "port must be 1..65535";
        return false;
    }
    std::lock_guard lk(g_mu);
    nlohmann::json arr = list_raw();
    const nlohmann::json entry = to_json(c);
    bool replaced = false;
    for (auto& j : arr) {
        if (j.is_object() && j.value("name", std::string{}) == c.name) {
            j = entry;
            replaced = true;
            break;
        }
    }
    if (!replaced) arr.push_back(entry);
    if (!infra::settings::set(kListKey, arr)) {
        err = "could not write " + infra::settings::file();
        return false;
    }
    return true;
}

bool remove(const std::string& name) {
    std::lock_guard lk(g_mu);
    nlohmann::json arr  = list_raw();
    const auto before   = arr.size();
    std::string set_name;
    nlohmann::json kept = nlohmann::json::array();
    for (auto& j : arr) {
        console_t c;
        if (from_json(j, c) && c.name == name) {
            set_name = c.profile.watchlist;
            continue;
        }
        kept.push_back(std::move(j));
    }
    if (kept.size() == before) return false;
    if (!infra::settings::set(kListKey, kept)) return false;
    if (active() == name) set_active({});
    // the profile's watchlist set only existed for this console
    nlohmann::json sets = infra::settings::get_json(kSetsKey);
    if (!set_name.empty() && sets.is_object() && sets.erase(set_name) > 0)
        infra::settings::set(kSetsKey, sets);
    return true;
}

std::string active() {
    return infra::settings::get<std::string>(kActiveKey, {});
}

void set_active(const std::string& name) {
    infra::settings::set(kActiveKey, name.empty() ? nlohmann::json() : nlohmann::json(name));
}

nlohmann::json watchlist_set(const std::string& name) {
    if (name.empty()) return nlohmann::json::array();
    const nlohmann::json sets = infra::settings::get_json(kSetsKey);
    if (!sets.is_object() || !sets.contains(name) || !sets[name].is_array())
        return nlohmann::json::array();
    return sets[name];
}

bool save_watchlist_set(const std::string& name, nlohmann::json entries) {
    if (name.empty() || !entries.is_array()) return false;
    std::lock_guard lk(g_mu);
    nlohmann::json sets = infra::settings::get_json(kSetsKey);
    if (!sets.is_object()) sets = nlohmann::json::object();
    sets[name] = std::move(entries);
    return infra::settings::set(kSetsKey, sets);
}

} // namespace slop::core::runtime::consoles
