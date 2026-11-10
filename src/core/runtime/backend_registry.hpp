#pragma once

// src/core/runtime/backend_registry.hpp
// the backend registry picks the kernel path when the driver is around
// and hot swaps live so the badge is honest

#include <cstdint>
#include <string>

#include "core/runtime/backend.hpp"

namespace slop::core::runtime {

enum class backend_pref_t : uint8_t { auto_detect, force_user, force_kernel };

void             registry_init();
backend_t&       active();
backend_kind_t   active_kind() noexcept;
const char*      active_badge() noexcept;

// live switch, returns true when a kernel backend is active
bool             set_backend_preference(backend_pref_t pref);
backend_pref_t   current_preference() noexcept;

// remote PS4 (ps4debug-NG) backend control. While connected the ps4 backend
// is the active one and attach/detach/memory go over the wire to the console
bool        registry_connect_ps4(const std::string& host, uint16_t port, std::string& err);
void        registry_disconnect_ps4();
bool        registry_ps4_active() noexcept;
std::string registry_ps4_endpoint();   // "host:port" or ""
std::string registry_ps4_branding();   // server branding string or ""

} // namespace slop::core::runtime
