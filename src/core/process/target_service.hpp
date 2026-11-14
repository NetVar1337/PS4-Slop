#pragma once

// src/core/process/target_service.hpp
// Central target lifecycle, attach, detach, session management

#include <cstdint>
#include <memory>
#include <string>

#include "core/runtime/backend.hpp"
#include "core/runtime/backend_ps4.hpp"
#include "core/runtime/backend_ps5.hpp"
#include "core/runtime/session.hpp"

namespace slop::core::process {

// consecutive heartbeat misses (pid absent from a successful enumeration)
// before the session is dropped
constexpr uint32_t kHeartbeatMissesToDetach = 3;

// Initialise the target service (call once at startup)
void target_init();

// Shut down, detaches active session if any
void target_shutdown();

// Attach to a process by PID. Returns true on success
bool target_attach(uint32_t pid);

// Detach from the current target. The session closes once every in-flight
// holder of active_session() has released it
void target_detach();

// Connect to a PS4 running the ps4debug-NG payload and optionally attach to
// pid (pid == 0 connects without attaching). Any current session is detached
// first. On failure err says why and the local backend is active
bool target_connect_ps4(const std::string& host, uint16_t port, uint32_t pid,
                        std::string& err);

// Drop the remote console connection (and any session on it), back to local
void target_disconnect_ps4();

// Re-open the selected console after a dropped connection; the current
// session survives (see backend_ps4_t::reconnect)
bool target_reconnect_ps4(std::string& err,
                          runtime::backend_ps4_t::reconnect_report_t* report = nullptr);

// Connect to a PS5 running the ps5debug-NG payload and optionally attach to
// pid (pid == 0 connects without attaching). Any current session is detached
// first. On failure err says why and the local backend is active
bool target_connect_ps5(const std::string& host, uint16_t port, uint32_t pid,
                        std::string& err);

// Drop the remote PS5 connection (and any session on it), back to local
void target_disconnect_ps5();

// Re-open the selected PS5 after a dropped connection; the current session
// survives (see backend_ps5_t::reconnect)
bool target_reconnect_ps5(std::string& err,
                          runtime::backend_ps5_t::reconnect_report_t* report = nullptr);

// Returns the active session, or nullptr if none
std::shared_ptr<runtime::session_t> active_session();

// Per-frame tick, drives deferred operations, heartbeat checks
void target_tick();

// heartbeat period (default 1000 ms); tests shorten it
void target_set_heartbeat_interval_ms(int64_t ms);

} // namespace slop::core::process
