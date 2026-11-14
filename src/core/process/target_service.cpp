#include "core/process/target_service.hpp"

#include "core/infra/clock.hpp"
#include "core/runtime/backend_ps4.hpp"
#include "core/runtime/backend_registry.hpp"

#include <algorithm>
#include <atomic>
#include <mutex>

namespace slop::core::process {

namespace {

// the session is mutated from mcp workers and read from the ui, every
// access takes the lock and hands out a copy. Holders of a copy keep the
// session (and its backend handle) alive; it closes when the last one drops
std::mutex g_session_mu;
std::shared_ptr<runtime::session_t> g_session;

// heartbeat bookkeeping; the misses counter is reset from attach paths too
std::atomic<int64_t>  g_hb_interval_ms{1000};
std::atomic<int64_t>  g_last_hb_ms{0};
std::atomic<uint32_t> g_misses{0};
const runtime::session_t* g_hb_session = nullptr;   // target_tick thread only

// sessions never survive a backend/console swap: the registry calls this
// before it replaces the connection
const bool g_swap_hook_installed = [] {
    runtime::registry_set_before_swap([] { target_detach(); });
    return true;
}();

} // namespace

void target_init() {
    // make sure the swap hook is in place even if static init dropped it
    (void)g_swap_hook_installed;
    runtime::registry_set_before_swap([] { target_detach(); });
}

void target_shutdown() {
    target_detach();
}

bool target_attach(uint32_t pid) {
    std::shared_ptr<runtime::session_t> old;
    {
        std::lock_guard lk(g_session_mu);
        old = std::move(g_session);
    }
    old.reset();   // closes now unless an in-flight call still holds it

    auto s = std::make_shared<runtime::session_t>();
    if (!s->open(pid)) return false;
    std::lock_guard lk(g_session_mu);
    g_session = std::move(s);
    g_misses = 0;
    return true;
}

void target_detach() {
    std::shared_ptr<runtime::session_t> old;
    {
        std::lock_guard lk(g_session_mu);
        old = std::move(g_session);
    }
    // dropping our reference closes the session once in-flight users
    // (a running scan, an async enumeration job) release theirs
}

std::shared_ptr<runtime::session_t> active_session() {
    std::lock_guard lk(g_session_mu);
    return g_session;
}

bool target_connect_ps4(const std::string& host, uint16_t port, uint32_t pid,
                        std::string& err) {
    // the registry detaches the current session before swapping (hook)
    if (!runtime::registry_connect_ps4(host, port, err)) return false;
    if (pid == 0) return true;
    if (!target_attach(pid)) {
        err = "connected to " + host + ":" + std::to_string(port) +
              " but attach to pid " + std::to_string(pid) + " failed";
        target_detach();
        runtime::registry_disconnect_ps4();
        return false;
    }
    return true;
}

void target_disconnect_ps4() {
    target_detach();
    runtime::registry_disconnect_ps4();
}

bool target_reconnect_ps4(std::string& err, runtime::backend_ps4_t::reconnect_report_t* report) {
    // the session (and its handle) stays: the backend keeps handles valid
    // across a reconnect to the same console
    if (!runtime::registry_ps4_reconnect(err, report)) return false;
    g_misses = 0;
    return true;
}

bool target_connect_ps5(const std::string& host, uint16_t port, uint32_t pid,
                        std::string& err) {
    // the registry detaches the current session before swapping (hook)
    if (!runtime::registry_connect_ps5(host, port, err)) return false;
    if (pid == 0) return true;
    if (!target_attach(pid)) {
        err = "connected to " + host + ":" + std::to_string(port) +
              " but attach to pid " + std::to_string(pid) + " failed";
        target_detach();
        runtime::registry_disconnect_ps5();
        return false;
    }
    return true;
}

void target_disconnect_ps5() {
    target_detach();
    runtime::registry_disconnect_ps5();
}

bool target_reconnect_ps5(std::string& err, runtime::backend_ps5_t::reconnect_report_t* report) {
    if (!runtime::registry_ps5_reconnect(err, report)) return false;
    g_misses = 0;
    return true;
}

void target_tick() {
    // Heartbeat: drop the session if the target died. Work on a local copy,
    // the session may be replaced concurrently by an MCP attach
    std::shared_ptr<runtime::session_t> s;
    {
        std::lock_guard lk(g_session_mu);
        s = g_session;
    }
    if (!s || !s->backend()) { g_misses = 0; g_hb_session = nullptr; return; }
    if (s.get() != g_hb_session) { g_hb_session = s.get(); g_misses = 0; }

    // a process enumeration per frame is too chatty (a console roundtrip, a
    // toolhelp snapshot locally); once a second is plenty
    const int64_t now = infra::steady_ms();
    if (now - g_last_hb_ms.load() < g_hb_interval_ms.load()) return;
    g_last_hb_ms = now;

    runtime::backend_t& b = *s->backend();
    if (b.kind() == runtime::backend_kind_t::ps4) {
        auto* p = static_cast<runtime::backend_ps4_t*>(&b);
        // a dropped connection is not a dead process: keep the session for
        // target.ps4_reconnect. While a debug session is attached the event
        // channel already reports the process going away (SIGKILL / channel
        // close) and a stopped debuggee must not be second-guessed
        if (!p->connected() || p->ps4_debug_attached()) { g_misses = 0; return; }
    }
    if (b.kind() == runtime::backend_kind_t::ps5) {
        auto* p = static_cast<runtime::backend_ps5_t*>(&b);
        // same contract as the PS4 branch: keep the session across a dropped
        // connection (target.ps5_reconnect) and never second-guess a debuggee
        // the payload is holding
        if (!p->connected() || p->ps5_debug_attached()) { g_misses = 0; return; }
    }

    auto procs = b.enum_processes();
    if (!procs.ok) return;   // a failed enumeration says nothing about the pid
    const uint32_t pid = s->pid();
    const bool alive = std::any_of(procs.items.begin(), procs.items.end(),
                                   [pid](const runtime::process_info_t& p) { return p.pid == pid; });
    if (alive) { g_misses = 0; return; }
    // one missing entry can be a transient payload hiccup or a game in a
    // loading transition; require several consecutive misses
    if (++g_misses < kHeartbeatMissesToDetach) return;
    g_misses = 0;
    std::shared_ptr<runtime::session_t> dead;
    {
        std::lock_guard lk(g_session_mu);
        if (g_session == s) dead = std::move(g_session);
    }
}

void target_set_heartbeat_interval_ms(int64_t ms) {
    g_hb_interval_ms = ms < 0 ? 0 : ms;
    g_last_hb_ms = 0;
}

} // namespace slop::core::process
