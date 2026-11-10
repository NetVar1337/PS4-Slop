// src/core/infra/lifecycle.cpp

#include "core/infra/lifecycle.hpp"

#include <windows.h>

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
#include "core/infra/work_queue.hpp"
#include "core/mcp/mcp_server.hpp"
#include "core/memory/watch_service.hpp"
#include "core/process/target_service.hpp"
#include "core/runtime/backend_registry.hpp"

namespace slop::core::infra::lifecycle {

namespace {

using json = nlohmann::json;
namespace bus = event_bus;

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

void write_endpoint(uint16_t p, const std::string& token) {
    const std::string path = endpoint_file();
    if (path.empty()) return;
    const json doc{{"pid", static_cast<uint32_t>(::GetCurrentProcessId())},
                   {"port", p},
                   {"token", token}};
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (f) f << doc.dump(2);
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

    mcp::server_config_t cfg;
    cfg.port  = settings::mcp_port();
    cfg.token = settings::mcp_token();
    if (const char* env_port = std::getenv("SLOP_MCP_PORT")) {
        const int p = std::atoi(env_port);
        if (p > 0 && p < 65536) cfg.port = static_cast<uint16_t>(p);
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

    bool onboard = false;
    {
        std::lock_guard lk(s.mu);
        onboard = s.cfg.mcp_onboarding;
    }
    if (!onboard || ephemeral || settings::mcp_onboarded()) return;

    for (const auto& r : mcp_onboard::install_all(mcp::port(), cfg.token)) {
        if (r.installed)
            bus::output("mcp registered: " + r.client + " -> " + r.path);
        else if (!r.error.empty())
            bus::output("mcp onboard skip (" + r.client + "): " + r.error);
    }
    settings::set_mcp_onboarded(true);
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
    ep.token = doc.value("token", std::string{});
    if (ep.pid == 0 || ep.port == 0) return false;

    // a crash leaves the file behind, treat a dead pid as no endpoint
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ep.pid);
    if (h == nullptr) return false;
    DWORD exit_code = 0;
    const bool alive = ::GetExitCodeProcess(h, &exit_code) && exit_code == STILL_ACTIVE;
    ::CloseHandle(h);
    if (!alive) return false;

    out = std::move(ep);
    return true;
}

} // namespace slop::core::infra::lifecycle

