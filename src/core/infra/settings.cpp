#include "core/infra/settings.hpp"
#include "core/infra/paths.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>

#pragma comment(lib, "bcrypt.lib")

namespace slop::core::infra::settings {

namespace {

constexpr uint16_t kDefaultPort = 8765;

std::mutex      g_mu;
nlohmann::json  g_data = nlohmann::json::object();
std::string     g_file;          // empty = paths::settings_file()

const std::string& path_locked() {
    return g_file.empty() ? paths::settings_file() : g_file;
}

bool save_locked() {
    const std::string& p = path_locked();
    if (p.empty()) return false;
    return paths::write_file_atomic(p, g_data.dump(2));
}

// keep the unreadable original around so a hand edit with a typo is recoverable
void backup_corrupt_locked(const std::string& p) {
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
    std::error_code ec;
    std::filesystem::copy_file(p, p + ".corrupt-" + std::to_string(ms),
                               std::filesystem::copy_options::overwrite_existing, ec);
}

} // namespace

std::string generate_token() {
    unsigned char buf[32]{};
    if (!BCRYPT_SUCCESS(::BCryptGenRandom(nullptr, buf, sizeof(buf),
                                          BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        return {};
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(sizeof(buf) * 2);
    for (unsigned char b : buf) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0xF]);
    }
    return out;
}

void load() {
    std::lock_guard lk(g_mu);
    const std::string& p = path_locked();
    g_data = nlohmann::json::object();
    bool dirty = false;

    std::ifstream f(p, std::ios::binary);
    if (f.is_open()) {
        std::stringstream ss;
        ss << f.rdbuf();
        f.close();
        nlohmann::json parsed = nlohmann::json::parse(ss.str(), nullptr, false);
        if (!parsed.is_discarded() && parsed.is_object()) {
            g_data = std::move(parsed);
        } else {
            backup_corrupt_locked(p);
            dirty = true;
        }
    }

    // first run (or a wiped token) gets a fresh bearer token so the server is never open by default
    const auto tok = g_data.find("mcp_token");
    if (tok == g_data.end() || !tok->is_string() || tok->get_ref<const std::string&>().empty()) {
        const std::string t = generate_token();
        if (!t.empty()) {
            g_data["mcp_token"] = t;
            dirty = true;
        }
    }
    if (dirty) save_locked();
}

bool save() {
    std::lock_guard lk(g_mu);
    return save_locked();
}

void set_file_for_testing(std::string path) {
    std::lock_guard lk(g_mu);
    g_file = std::move(path);
    g_data = nlohmann::json::object();
}

const std::string& file() {
    std::lock_guard lk(g_mu);
    return path_locked();
}

nlohmann::json get_json(std::string_view key) {
    std::lock_guard lk(g_mu);
    const auto it = g_data.find(key);
    return it == g_data.end() ? nlohmann::json() : *it;
}

bool set(std::string_view key, nlohmann::json value) {
    std::lock_guard lk(g_mu);
    if (value.is_null())
        g_data.erase(std::string(key));
    else
        g_data[std::string(key)] = std::move(value);
    return save_locked();
}

nlohmann::json snapshot() {
    std::lock_guard lk(g_mu);
    return g_data;
}

bool mcp_enabled() { return get<bool>("mcp_enabled", true); }

uint16_t mcp_port() {
    const int64_t p = get<int64_t>("mcp_port", kDefaultPort);
    if (p < 1 || p > 65535) return kDefaultPort;
    return static_cast<uint16_t>(p);
}

std::string mcp_token() { return get<std::string>("mcp_token", {}); }

bool mcp_onboarded() { return get<bool>("mcp_onboarded", false); }

void set_mcp_onboarded(bool v) { set("mcp_onboarded", v); }

std::vector<std::string> mcp_onboard_clients() {
    return get<std::vector<std::string>>("mcp_onboard_clients", {});
}

bool mcp_token_in_configs() { return get<bool>("mcp_token_in_configs", false); }

bool mcp_audit_enabled() { return get<bool>("mcp_audit_enabled", true); }

std::string mcp_audit_path() {
    const std::string p = get<std::string>("mcp_audit_path", {});
    if (!p.empty()) return p;
    const std::string& ad = paths::app_data();
    if (ad.empty()) return {};
    return ad + "\\mcp_audit.jsonl";
}

bool mcp_require_confirm() { return get<bool>("mcp_require_confirm", false); }

} // namespace slop::core::infra::settings
