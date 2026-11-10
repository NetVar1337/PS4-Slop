#include "core/runtime/backend_registry.hpp"
#include "core/runtime/backend_usermode.hpp"
#include "core/runtime/backend_ps4.hpp"

namespace slop::core::runtime {

namespace {

backend_usermode_t g_user{};
backend_ps4_t      g_ps4{};
backend_t*         g_active = nullptr;

bool               g_initialized = false;
bool               g_ps4_connected = false;

} // namespace

void registry_init() {
    g_active = &g_user;
    g_initialized = true;
}

backend_t& active() {
    return g_active ? *g_active : static_cast<backend_t&>(g_user);
}

backend_kind_t active_kind() noexcept {
    return active().kind();
}

const char* active_badge() noexcept {
    return active().badge();
}

bool registry_connect_ps4(const std::string& host, uint16_t port, std::string& err) {
    if (g_ps4_connected && g_ps4.endpoint() == host + ":" + std::to_string(port))
        return true;
    if (g_ps4_connected) registry_disconnect_ps4();
    if (!g_ps4.connect(host, port, err)) {
        g_ps4_connected = false;
        return false;
    }
    g_ps4_connected = true;
    g_active = &g_ps4;
    return true;
}

void registry_disconnect_ps4() {
    if (!g_ps4_connected) return;
    g_ps4.disconnect();
    g_ps4_connected = false;
    g_active = static_cast<backend_t*>(&g_user);
}

bool registry_ps4_active() noexcept {
    return g_ps4_connected && g_ps4.connected();
}

std::string registry_ps4_endpoint() {
    return g_ps4_connected ? g_ps4.endpoint() : std::string{};
}

std::string registry_ps4_branding() {
    return g_ps4_connected ? g_ps4.branding() : std::string{};
}

} // namespace slop::core::runtime
