#pragma once

// src/core/process/target_service.hpp
// Central target lifecycle, attach, detach, session management

#include <cstdint>
#include <memory>
#include <string>

#include "core/runtime/backend.hpp"
#include "core/runtime/session.hpp"

namespace slop::core::process {

// Initialise the target service (call once at startup)
void target_init();

// Shut down, detaches active session if any
void target_shutdown();

// Attach to a process by PID. Returns true on success
bool target_attach(uint32_t pid);

// Detach from the current target
void target_detach();

// Connect to a PS4 running the ps4debug-NG payload and optionally attach to
// pid (pid == 0 connects without attaching). On failure err says why and the
// previous backend stays active
bool target_connect_ps4(const std::string& host, uint16_t port, uint32_t pid,
                        std::string& err);

// Drop the remote console connection (and any session on it), back to local
void target_disconnect_ps4();

// Returns the active session, or nullptr if none
std::shared_ptr<runtime::session_t> active_session();

// Per-frame tick, drives deferred operations, heartbeat checks
void target_tick();

} // namespace slop::core::process
