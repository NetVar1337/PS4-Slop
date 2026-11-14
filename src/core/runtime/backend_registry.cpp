#include "core/runtime/backend_registry.hpp"
#include "core/runtime/backend_usermode.hpp"
#include "core/runtime/backend_ps4.hpp"

#include <atomic>
#include <mutex>

namespace slop::core::runtime {

namespace {

backend_usermode_t       g_user{};
backend_ps4_t            g_ps4{};
backend_ps5_t            g_ps5{};
std::atomic<backend_t*>  g_active{nullptr};
std::atomic<bool>        g_ps4_connected{false};
std::atomic<bool>        g_ps5_connected{false};
std::mutex               g_swap_mu;   // serializes connect/disconnect/reconnect

std::function<void()>& before_swap_hook() {
    static std::function<void()> fn;
    return fn;
}

void run_before_swap() {
    if (auto& fn = before_swap_hook()) fn();
}

} // namespace

void registry_init() {
    g_active.store(&g_user);
}

backend_t& active() {
    backend_t* b = g_active.load();
    return b ? *b : static_cast<backend_t&>(g_user);
}

backend_kind_t active_kind() noexcept {
    return active().kind();
}

const char* active_badge() noexcept {
    return active().badge();
}

void registry_set_before_swap(std::function<void()> fn) {
    std::lock_guard lk(g_swap_mu);
    before_swap_hook() = std::move(fn);
}

bool registry_connect_ps4(const std::string& host, uint16_t port, std::string& err) {
    std::lock_guard lk(g_swap_mu);
    if (g_ps4_connected && g_ps4.connected() &&
        g_ps4.endpoint() == host + ":" + std::to_string(port))
        return true;
    // sessions opened on the previous backend/console go first
    run_before_swap();
    // one console at a time: a selected PS5 goes
    if (g_ps5_connected) {
        g_ps5.disconnect();
        g_ps5_connected = false;
    }
    if (!g_ps4.connect(host, port, err)) {
        g_ps4_connected = false;
        g_active.store(&g_user);
        return false;
    }
    g_ps4_connected = true;
    g_active.store(&g_ps4);
    return true;
}

void registry_disconnect_ps4() {
    std::lock_guard lk(g_swap_mu);
    if (!g_ps4_connected) return;
    run_before_swap();
    g_ps4.disconnect();
    g_ps4_connected = false;
    g_active.store(&g_user);
}

bool registry_ps4_reconnect(std::string& err, backend_ps4_t::reconnect_report_t* report) {
    std::lock_guard lk(g_swap_mu);
    if (!g_ps4_connected) {
        err = "no console selected (use target.ps4_connect)";
        return false;
    }
    return g_ps4.reconnect(err, report);
}

bool registry_ps4_active() noexcept {
    return g_ps4_connected && g_ps4.connected();
}

bool registry_ps4_selected() noexcept {
    return g_ps4_connected;
}

bool registry_ps4_lost() noexcept {
    return g_ps4_connected && !g_ps4.connected();
}

std::string registry_ps4_endpoint() {
    if (!g_ps4_connected) return {};
    std::string ep = g_ps4.endpoint();
    return ep.empty() ? g_ps4.last_endpoint() : ep;
}

std::string registry_ps4_branding() {
    return g_ps4_connected ? g_ps4.branding() : std::string{};
}

backend_ps4_t* registry_ps4() noexcept {
    return g_ps4_connected ? &g_ps4 : nullptr;
}

// ---------------------------------------------------------------------------
// remote PS5 (ps5debug-NG)

bool registry_connect_ps5(const std::string& host, uint16_t port, std::string& err) {
    std::lock_guard lk(g_swap_mu);
    if (g_ps5_connected && g_ps5.connected() &&
        g_ps5.endpoint() == host + ":" + std::to_string(port))
        return true;
    // sessions opened on the previous backend/console go first
    run_before_swap();
    // one console at a time: a selected PS4 goes
    if (g_ps4_connected) {
        g_ps4.disconnect();
        g_ps4_connected = false;
    }
    if (!g_ps5.connect(host, port, err)) {
        g_ps5_connected = false;
        g_active.store(&g_user);
        return false;
    }
    g_ps5_connected = true;
    g_active.store(&g_ps5);
    return true;
}

void registry_disconnect_ps5() {
    std::lock_guard lk(g_swap_mu);
    if (!g_ps5_connected) return;
    run_before_swap();
    g_ps5.disconnect();
    g_ps5_connected = false;
    g_active.store(&g_user);
}

bool registry_ps5_reconnect(std::string& err, backend_ps5_t::reconnect_report_t* report) {
    std::lock_guard lk(g_swap_mu);
    if (!g_ps5_connected) {
        err = "no console selected (use target.ps5_connect)";
        return false;
    }
    return g_ps5.reconnect(err, report);
}

bool registry_ps5_active() noexcept {
    return g_ps5_connected && g_ps5.connected();
}

bool registry_ps5_selected() noexcept {
    return g_ps5_connected;
}

bool registry_ps5_lost() noexcept {
    return g_ps5_connected && !g_ps5.connected();
}

std::string registry_ps5_endpoint() {
    if (!g_ps5_connected) return {};
    std::string ep = g_ps5.endpoint();
    return ep.empty() ? g_ps5.last_endpoint() : ep;
}

std::string registry_ps5_branding() {
    return g_ps5_connected ? g_ps5.branding() : std::string{};
}

backend_ps5_t* registry_ps5() noexcept {
    return g_ps5_connected ? &g_ps5 : nullptr;
}

} // namespace slop::core::runtime
