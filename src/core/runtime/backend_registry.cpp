#include "core/runtime/backend_registry.hpp"
#include "core/runtime/backend_usermode.hpp"
#include "core/runtime/backend_kernel.hpp"
#include "core/runtime/backend_ps4.hpp"

namespace slop::core::runtime {

namespace {

backend_usermode_t g_user{};
backend_kernel_t   g_kernel{};
backend_ps4_t      g_ps4{};
backend_t*         g_active = nullptr;

backend_pref_t     g_pref = backend_pref_t::auto_detect;
bool               g_initialized = false;
bool               g_ps4_connected = false;

void apply_preference() {
    // a live ps4 connection wins over the local backends until disconnected
    if (g_ps4_connected) {
        g_active = &g_ps4;
        return;
    }
    switch (g_pref) {
    case backend_pref_t::force_user:
        g_kernel.disconnect();
        g_active = &g_user;
        break;

    case backend_pref_t::force_kernel:
        g_active = g_kernel.connect() ? static_cast<backend_t*>(&g_kernel)
                                      : static_cast<backend_t*>(&g_user);
        break;

    case backend_pref_t::auto_detect:
    default:
        // Probe the driver; fall back silently
        if (!g_kernel.connect()) g_kernel.disconnect();
        g_active = g_kernel.connect() ? static_cast<backend_t*>(&g_kernel)
                                      : static_cast<backend_t*>(&g_user);
        break;
    }
}

} // namespace

void registry_init() {
    apply_preference();
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

bool set_backend_preference(backend_pref_t pref) {
    // switching the local backend drops a remote console connection
    if (g_ps4_connected) registry_disconnect_ps4();
    g_pref = pref;
    if (g_initialized) apply_preference();
    return active_kind() == backend_kind_t::kernel;
}

backend_pref_t current_preference() noexcept {
    return g_pref;
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
    g_active = &g_ps4;   // apply_preference() would pick the same, skip the driver probe
    return true;
}

void registry_disconnect_ps4() {
    if (!g_ps4_connected) return;
    g_ps4.disconnect();
    g_ps4_connected = false;
    if (g_initialized) apply_preference();
    else g_active = static_cast<backend_t*>(&g_user);
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
