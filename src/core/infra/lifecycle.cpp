// src/core/infra/lifecycle.cpp

#include "core/infra/lifecycle.hpp"

#include <windows.h>
#include <dpapi.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <thread>
#include <vector>

#include "core/disasm/binary_state.hpp"
#include "core/infra/app_control.hpp"
#include "core/infra/clock.hpp"
#include "core/infra/event_bus.hpp"
#include "core/infra/jobs.hpp"
#include "core/infra/mcp_onboard.hpp"
#include "core/infra/paths.hpp"
#include "core/infra/settings.hpp"
#include "core/infra/text_format.hpp"
#include "core/infra/work_queue.hpp"
#include "core/mcp/mcp_server.hpp"
#include "core/memory/watch_service.hpp"
#include "core/process/target_service.hpp"
#include "core/runtime/backend_registry.hpp"

#pragma comment(lib, "crypt32.lib")

namespace slop::core::infra::lifecycle {

namespace {

using json = nlohmann::json;
namespace bus = event_bus;

// Auto-reconnect a dropped console on a worker thread: reconnect() opens a TCP
// socket and can block for seconds, so it must not run on the 10 ms tick.
std::thread       g_auto_thread;
std::atomic<bool> g_auto_stop{false};

struct state_t {
    std::mutex        mu;
    config_t          cfg;
    boot_result_t     result;
    std::atomic<int>  stage{0};
    std::atomic<bool> started{false};
    std::atomic<bool> torn_down{false};
    int64_t           last_tick_ms = 0;
};

state_t& st() {
    static state_t s;
    return s;
}

std::string endpoint_file() {
    const std::string& dir = paths::app_data();
    if (dir.empty()) return {};
    return dir + "\\engine.json";
}

// the token never lands on disk in the clear: DPAPI (current user) blob as hex
std::string protect(const std::string& plain) {
    if (plain.empty()) return {};
    DATA_BLOB in{static_cast<DWORD>(plain.size()),
                 reinterpret_cast<BYTE*>(const_cast<char*>(plain.data()))};
    DATA_BLOB out{};
    if (!::CryptProtectData(&in, L"reverse-slop engine token", nullptr, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &out))
        return {};
    std::string hex = fmt::format_hex_packed({out.pbData, out.cbData});
    ::LocalFree(out.pbData);
    return hex;
}

std::string unprotect(const std::string& hex) {
    std::vector<uint8_t> blob;
    std::string err;
    if (hex.empty() || !fmt::parse_hex(hex, blob, err)) return {};
    DATA_BLOB in{static_cast<DWORD>(blob.size()), blob.data()};
    DATA_BLOB out{};
    if (!::CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                              CRYPTPROTECT_UI_FORBIDDEN, &out))
        return {};
    std::string plain(reinterpret_cast<const char*>(out.pbData), out.cbData);
    ::SecureZeroMemory(out.pbData, out.cbData);
    ::LocalFree(out.pbData);
    return plain;
}

std::wstring image_path_of(HANDLE process) {
    wchar_t buf[MAX_PATH * 2]{};
    DWORD n = static_cast<DWORD>(std::size(buf));
    if (!::QueryFullProcessImageNameW(process, 0, buf, &n)) return {};
    return std::wstring(buf, n);
}

std::string utf8(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                                        nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), n,
                          nullptr, nullptr);
    return out;
}

std::wstring wide(const std::string& s) {
    if (s.empty()) return {};
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                                        nullptr, 0);
    std::wstring out(static_cast<size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

void write_endpoint(uint16_t p, const std::string& token) {
    const std::string path = endpoint_file();
    if (path.empty()) return;
    const json doc{{"pid", static_cast<uint32_t>(::GetCurrentProcessId())},
                   {"port", p},
                   {"exe", utf8(image_path_of(::GetCurrentProcess()))},
                   {"token_dpapi", protect(token)}};
    paths::write_file_atomic(path, doc.dump(2));
}

void remove_endpoint() {
    endpoint_t existing;
    // only delete the file if it is still ours
    if (read_endpoint(existing) && existing.pid != ::GetCurrentProcessId())
        return;
    const std::string path = endpoint_file();
    if (path.empty()) return;
    std::error_code ec;
    std::filesystem::remove(path, ec);
}

void set_stage(stage_t s) {
    st().stage.store(static_cast<int>(s), std::memory_order_release);
    bus::publish("boot.stage",
                 json{{"stage", static_cast<int>(s)},
                      {"total", kStageCount},
                      {"label", stage_label(s)},
                      {"done", s == stage_t::done}});
}

void start_mcp() {
    state_t& s = st();
    if (!settings::mcp_enabled()) return;

    bool onboard = false, insecure_dev = false;
    {
        std::lock_guard lk(s.mu);
        onboard      = s.cfg.mcp_onboarding;
        insecure_dev = s.cfg.insecure_dev;
    }

    mcp::server_config_t cfg;
    cfg.port  = settings::mcp_port();
    cfg.token = settings::mcp_token();
    cfg.insecure_dev = insecure_dev;
    if (const char* env_port = std::getenv("SLOP_MCP_PORT")) {
        const int p = std::atoi(env_port);
        if (p > 0 && p < 65536) cfg.port = static_cast<uint16_t>(p);
    }
    // a spawner (tauri supervisor, test harness) brings its own per-launch token
    // so the persisted one never has to travel over stdout
    if (const char* env_tok = std::getenv("SLOP_MCP_TOKEN"); env_tok && *env_tok)
        cfg.extra_tokens.emplace_back(env_tok);
    if (cfg.token.empty() && cfg.extra_tokens.empty()) {
        // Fail closed. An empty token used to mean "no auth" (the server
        // accepted any local process); generate and persist one instead, and
        // refuse to start rather than expose an open endpoint if that fails.
        const std::string tok = settings::generate_token();
        if (tok.empty() || !settings::set("mcp_token", tok)) {
            bus::output("mcp_token is empty and could not be generated; refusing to start "
                        "an unauthenticated MCP server");
            return;
        }
        cfg.token = tok;
        bus::output("mcp_token was empty; generated a new bearer token");
    }

    // port taken means fall back to an ephemeral one and skip onboarding so clients stay pointed at the owner
    bool ephemeral = false;
    if (!mcp::start(cfg)) {
        const uint16_t wanted = cfg.port;
        cfg.port  = 0;
        ephemeral = mcp::start(cfg);
        if (!ephemeral) {
            bus::output("mcp server failed to bind port " + std::to_string(wanted));
            return;
        }
        bus::output("mcp port " + std::to_string(wanted) +
                    " busy, bound ephemeral port " + std::to_string(mcp::port()));
    }
    {
        std::lock_guard lk(s.mu);
        s.result.mcp_ok   = true;
        s.result.mcp_port = mcp::port();
    }
    bus::output("mcp server ready: http://127.0.0.1:" +
                std::to_string(mcp::port()) + "/mcp");
    write_endpoint(mcp::port(), cfg.token);

    if (!onboard || ephemeral) return;

    // first run registers everywhere; later runs only refresh entries we already
    // wrote so a changed port or rotated token never leaves a client stale
    const bool first = !settings::mcp_onboarded();
    const auto results = first ? mcp_onboard::install_all(mcp::port(), cfg.token)
                               : mcp_onboard::refresh_existing(mcp::port(), cfg.token);
    for (const auto& r : results) {
        if (r.installed)
            bus::output(std::string(first ? "mcp registered: " : "mcp entry refreshed: ") +
                        r.client + " -> " + r.path);
        else if (!r.error.empty())
            bus::output("mcp onboard skip (" + r.client + "): " + r.error);
    }
    if (first) {
        settings::set_mcp_onboarded(true);
        bus::output(settings::mcp_token_in_configs()
                        ? "note: client configs now hold the mcp bearer token; do not sync "
                          "them to public dotfile repos"
                        : "note: client configs reference ${SLOP_MCP_TOKEN}; set that user "
                          "env var to the token shown in Settings");
    }
}

} // namespace

const char* stage_label(stage_t s) noexcept {
    switch (s) {
    case stage_t::runtime_pool:     return "runtime pool & job queue";
    case stage_t::process_services: return "process / target services";
    case stage_t::settings:         return "settings & session store";
    case stage_t::mcp_server:       return "mcp server";
    case stage_t::frontend:         return "interface";
    case stage_t::done:             return "ready";
    }
    return "?";
}

const char* stage_status(stage_t row) noexcept {
    const int cur = st().stage.load(std::memory_order_acquire);
    const int idx = static_cast<int>(row);
    if (idx < cur) return "ok";
    if (idx == cur) return "run";
    return "wait";
}

stage_t stage() noexcept {
    return static_cast<stage_t>(st().stage.load(std::memory_order_acquire));
}

bool booted() noexcept { return stage() == stage_t::done; }

boot_result_t result() {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    return s.result;
}

void begin(config_t cfg) {
    state_t& s = st();
    if (s.started.exchange(true)) return;
    {
        std::lock_guard lk(s.mu);
        s.cfg = std::move(cfg);
    }

    // init paths first or settings save renames onto nothing and drops temp files everywhere
    paths::init();

    pool::start();
    set_stage(stage_t::process_services);

    process::target_init();
    runtime::registry_init();
    set_stage(stage_t::settings);
}

stage_t advance() {
    state_t& s = st();

    if (stage() == stage_t::settings) {
        // probe before load creates the file or every run looks like the first
        const bool fresh = !std::filesystem::exists(paths::settings_file());
        settings::load();
        {
            std::lock_guard lk(s.mu);
            s.result.first_run = fresh;
        }
        set_stage(stage_t::mcp_server);
    }

    if (stage() == stage_t::mcp_server) {
        start_mcp();
        set_stage(stage_t::frontend);
    }

    if (stage() == stage_t::frontend) {
        bus::output("memory suite ready (scanner / aob / pointer scan / snapshots)");
        bus::output("disasm suite ready (zydis / functions / xrefs / strings / pe)");
        bus::output("analysis suites ready (emulation+taint / packer / signatures / decompiler)");
        bus::output("recon ready (rtti / vtables / danger imports / libsig / symbols)");
        bus::output("network ready (raw-socket capture / proxy / pcap), persistence + scripting live");
        bus::output("ps4 toolkit ready: connect a console with target ps4_auto, then debugger ps4_* / guide get ps4_setup.");
        set_stage(stage_t::done);
    }

    return stage();
}

void tick() {
    state_t& s = st();

    process::target_tick();
    jobs::reap();
    memory::watch::tick();

    // A dropped console comes back on its own with exponential backoff; the
    // session, breakpoints and slots are restored by reconnect(). Opt out with
    // ps4_auto_reconnect=false. disconnect() clears "lost", so an intentional
    // disconnect is never undone.
    if (!g_auto_thread.joinable() &&
        settings::get<bool>("ps4_auto_reconnect", true) &&
        runtime::registry_ps4_lost()) {
        g_auto_stop.store(false);
        g_auto_thread = std::thread([] {
            int backoff_ms = 1000;
            while (!g_auto_stop.load() && runtime::registry_ps4_lost()) {
                std::string err;
                if (runtime::registry_ps4_reconnect(err)) break;
                for (int waited = 0; waited < backoff_ms && !g_auto_stop.load(); waited += 100)
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                backoff_ms = (std::min)(backoff_ms * 2, 30000);
            }
        });
    }
    if (g_auto_thread.joinable() && !runtime::registry_ps4_lost()) {
        g_auto_stop.store(true);
        g_auto_thread.join();
    }

    // mirror state at 10hz for the stream since polling over a socket isnt free anymore
    const int64_t now = steady_ms();
    if (now - s.last_tick_ms < 100) return;
    s.last_tick_ms = now;

    json target{{"attached", false}};
    if (auto sess = process::active_session(); sess && sess->valid()) {
        target["attached"] = true;
        target["pid"]      = sess->pid();
        target["name"]     = sess->name();
    }
    bus::publish_changed("target.changed", target);

    bus::publish_changed("backend.changed",
                         json{{"badge", runtime::active_badge()},
                              {"ps4", runtime::registry_ps4_active()}});

    const auto hs = disasm::binary_state::hype_status();
    bus::publish_changed("hype.progress",
                         json{{"has_image", hs.has_image},
                              {"image", hs.image},
                              {"present", hs.engine_present},
                              {"ready", hs.ready},
                              {"running", hs.running},
                              {"progress", hs.progress},
                              {"error", hs.engine_error}});
}

void shutdown() {
    state_t& s = st();
    if (s.torn_down.exchange(true)) return;

    g_auto_stop.store(true);
    if (g_auto_thread.joinable()) g_auto_thread.join();

    remove_endpoint();
    mcp::stop();
    jobs::shutdown(1000);
    pool::stop(1000);
    memory::watch::shutdown();
    process::target_shutdown();
    settings::save();

    bus::shutdown();
}

const std::string& endpoint_path() {
    static const std::string path = [] {
        paths::init();
        return endpoint_file();
    }();
    return path;
}

void refresh_endpoint() {
    // only the booted engine owns engine.json; a bare mcp::start (tests) never writes it
    if (!st().started.load() || st().torn_down.load() || !mcp::running()) return;
    write_endpoint(mcp::port(), settings::mcp_token());
}

bool read_endpoint(endpoint_t& out) {
    const std::string path = endpoint_file();
    if (path.empty()) return false;

    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    json doc = json::parse(f, nullptr, false);
    if (doc.is_discarded() || !doc.is_object()) return false;

    endpoint_t ep;
    ep.pid   = doc.value("pid", uint32_t{0});
    ep.port  = doc.value("port", uint16_t{0});
    ep.token = unprotect(doc.value("token_dpapi", std::string{}));
    const std::string exe = doc.value("exe", std::string{});
    if (ep.pid == 0 || ep.port == 0) return false;

    // a crash leaves the file behind, treat a dead pid as no endpoint
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ep.pid);
    if (h == nullptr) return false;
    DWORD exit_code = 0;
    const bool alive = ::GetExitCodeProcess(h, &exit_code) && exit_code == STILL_ACTIVE;
    // pid reuse: the live process must still be the image that wrote the file
    const std::wstring image = alive ? image_path_of(h) : std::wstring{};
    ::CloseHandle(h);
    if (!alive) return false;
    if (exe.empty() || image.empty() ||
        ::CompareStringOrdinal(image.c_str(), -1, wide(exe).c_str(), -1, TRUE) != CSTR_EQUAL)
        return false;

    out = std::move(ep);
    return true;
}

} // namespace slop::core::infra::lifecycle

