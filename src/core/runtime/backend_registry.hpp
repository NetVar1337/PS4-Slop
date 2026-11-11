#pragma once

// src/core/runtime/backend_registry.hpp
// the backend registry: a live PS4 connection is the active backend;
// the local user-mode backend remains as the internal test lab

#include <cstdint>
#include <functional>
#include <string>

#include "core/runtime/backend.hpp"
#include "core/runtime/backend_ps4.hpp"

namespace slop::core::runtime {

void             registry_init();
backend_t&       active();
backend_kind_t   active_kind() noexcept;
const char*      active_badge() noexcept;

// called before the active backend changes or the console connection is
// replaced, so whoever owns attached sessions (the target service) can drop
// them first; a session must never outlive the connection it was opened on
void registry_set_before_swap(std::function<void()> fn);

// remote PS4 (ps4debug-NG) backend control. While connected the ps4 backend
// is the active one and attach/detach/memory go over the wire to the console
bool        registry_connect_ps4(const std::string& host, uint16_t port, std::string& err);
void        registry_disconnect_ps4();
// re-open the last console after a dropped connection (handshake, auth,
// debug re-attach, slot re-arm); sessions on it stay valid
bool        registry_ps4_reconnect(std::string& err,
                                   backend_ps4_t::reconnect_report_t* report = nullptr);
bool        registry_ps4_active() noexcept;   // selected and the socket is alive
bool        registry_ps4_selected() noexcept; // selected, maybe with a dropped socket
bool        registry_ps4_lost() noexcept;     // selected but the connection dropped
std::string registry_ps4_endpoint();   // "host:port" or ""
std::string registry_ps4_branding();   // server branding string or ""
backend_ps4_t* registry_ps4() noexcept;  // the console backend while selected, else null

} // namespace slop::core::runtime
