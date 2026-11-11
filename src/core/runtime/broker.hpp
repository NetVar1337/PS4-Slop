#pragma once

// src/core/runtime/broker.hpp
// The broker: one console connection, many clients. The UI, the MCP tools and
// the GDB-RSP bridge all drive the same backend_ps4_t, so every
// console-reaching operation takes broker_gate() and clients serialize
// instead of interleaving on the wire or racing debug state (continue/wait,
// breakpoint slots, the current thread)

#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace slop::core::runtime {

// recursive: the Lua script tool re-enters the tool layer from its bindings
std::recursive_mutex& broker_gate();

// named clients sharing the console (mcp, gdb:2331, ...) for status reports
void broker_client_attach(const std::string& name);
void broker_client_detach(const std::string& name);
// {name, attached_since_epoch_ms} pairs, in attach order
std::vector<std::pair<std::string, int64_t>> broker_clients();

} // namespace slop::core::runtime
