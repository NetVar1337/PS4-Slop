#pragma once

// one tool per domain with an action param, all serialized through one mutex

#include <nlohmann/json.hpp>
#include <string>

#include "core/infra/cancel.hpp"

namespace slop::core::mcp {

// fills out the tools/list entries
void list_tools(nlohmann::json& out);

// true when the action writes to the target, the host or the shared session;
// drives the confirm gate and the readOnlyHint annotation
bool action_mutating(const std::string& tool, const std::string& action);

// notifications/progress for one tools/call: the session whose GET /mcp stream
// receives them and the client's _meta.progressToken
struct progress_ctx_t {
    std::string   session;
    nlohmann::json token;
};

// runs a tool call, sets is_error on failure and never throws.
// allow_app is the UI channel (/api) only: `app` carries settings/token/shutdown
// and must stay unreachable from the agent-facing MCP endpoint.
// progress != nullptr emits notifications/progress while the call runs.
nlohmann::json call_tool(const std::string& name, const nlohmann::json& args,
                         bool& is_error, infra::cancel_token_t cancel = {},
                         bool allow_app = false, const progress_ctx_t* progress = nullptr);

// drop tool state on shutdown
void shutdown_tools();

// identity of the client whose tool call runs on this thread: an MCP
// Mcp-Session-Id, "ui" for /api, "" when unknown. Set by the server around
// each call; used for breakpoint slot ownership.
void set_client_id(std::string id);
std::string client_id();

// session snapshot for the agent, rides the initialize result
nlohmann::json session_state();

// MCP resources: live state plus the guide playbooks
nlohmann::json list_resources();
nlohmann::json read_resource(const std::string& uri);   // null when unknown

// MCP prompts: the guide playbooks as prompt templates
nlohmann::json list_prompts();
nlohmann::json get_prompt(const std::string& name);     // null when unknown

} // namespace slop::core::mcp
