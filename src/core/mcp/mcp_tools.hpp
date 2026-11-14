#pragma once

// one tool per domain with an action param, all serialized through one mutex

#include <nlohmann/json.hpp>
#include <string>

#include "core/infra/cancel.hpp"

namespace slop::core::mcp {

// fills out the tools/list entries
void list_tools(nlohmann::json& out);

// runs a tool call, sets is_error on failure and never throws.
// allow_app is the UI channel (/api) only: `app` carries settings/token/shutdown
// and must stay unreachable from the agent-facing MCP endpoint.
nlohmann::json call_tool(const std::string& name, const nlohmann::json& args,
                         bool& is_error, infra::cancel_token_t cancel = {},
                         bool allow_app = false);

// drop tool state on shutdown
void shutdown_tools();

// identity of the client whose tool call runs on this thread: an MCP
// Mcp-Session-Id, "ui" for /api, "" when unknown. Set by the server around
// each call; used for breakpoint slot ownership.
void set_client_id(std::string id);
std::string client_id();

// session snapshot for the agent, rides the initialize result
nlohmann::json session_state();

} // namespace slop::core::mcp
