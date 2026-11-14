#pragma once

// src/core/infra/mcp_onboard.hpp
// first boot registration into the ai clients we know about
// claude desktop is stdio only so it just gets reported as unsupported

#include <cstdint>
#include <string>
#include <vector>

namespace slop::core::infra::mcp_onboard {

struct install_result_t {
    std::string client;     // which client we touched
    bool        installed;  // true when we actually wrote
    std::string path;       // the file we touched
    std::string error;      // empty when all good
};

// runs the whole sweep, one result per client; an existing entry with a stale
// url/token is rewritten in place (user added keys are kept). The client list
// comes from mcp_onboard_clients, or default_clients() when that is unset
std::vector<install_result_t> install_all(uint16_t port, const std::string& token);

// only refreshes entries we already wrote (port/token changed), never adds new ones
std::vector<install_result_t> refresh_existing(uint16_t port, const std::string& token);

// removes everything we wrote, for an uninstall button
std::vector<install_result_t> uninstall_all();

// auto policy: Tern alone when its settings.json exists (it keeps every other
// MCP server centrally), else every client we know about
std::vector<std::string> default_clients();

// clients whose config still carries a literal bearer token instead of the
// ${SLOP_MCP_TOKEN} reference (audit item 72, shown as a warning in Settings)
std::vector<std::string> plaintext_token_clients();

} // namespace slop::core::infra::mcp_onboard
