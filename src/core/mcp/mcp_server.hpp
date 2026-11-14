#pragma once

// src/core/mcp/mcp_server.hpp
// the localhost mcp server, jsonrpc over http plus sse streams
// loopback only and it runs on its own threads, never the shared work queue
//
// every route goes through one guard: Host must be a loopback name on our
// port (dns rebinding), a browser Origin must be on the allowlist (tauri +
// vite dev) and gets CORS headers back, OPTIONS preflights answer 204

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace slop::core::mcp {

struct server_config_t {
    uint16_t    port  = 8765;
    std::string token;                        // primary bearer (settings mcp_token); empty = no auth
    std::vector<std::string> extra_tokens;    // also accepted, e.g. the supervisor's per-launch token
    bool        insecure_dev = false;         // --insecure-dev only: accept tokenless loopback requests
    size_t      worker_threads = 48;          // http workers; sse streams are capped well below this
    size_t      max_streams    = 64;          // concurrent GET /mcp + GET /events streams
};

// starts the server, false if the port would not bind
bool start(const server_config_t& cfg);

// stop and join all the server threads
void stop();

// for the boot log and tests
bool running();
uint16_t port();

// engine version string (the root VERSION file)
const char* server_version() noexcept;

// live token management (app.rotate_token / engine handover)
void set_primary_token(std::string token);
void add_extra_token(std::string token);

// true while serving a request that authenticated with the primary token
bool request_used_primary_token();

// single use ticket for GET /events?ticket=..., valid for 60 s
std::string issue_events_ticket();

// RFC 6455 Sec-WebSocket-Accept for a client key, exposed for the handshake test
std::string ws_accept_key(std::string_view key);

// guard predicates, exposed for tests
bool host_allowed(std::string_view host, uint16_t port);
bool origin_allowed(std::string_view origin);

// active sse streams right now
size_t active_streams();

// ---- per-tool rate limiting (agent transport only; /api is exempt) ----
// token bucket per tool, configured by the mcp_rate_limits setting
// ({tool: {rate, burst}}, rate = tokens per second); heavy tools ship defaults
struct rate_limit_t {
    bool    allowed        = true;
    int64_t retry_after_ms = 0;   // 0 when allowed
    double  rate           = 0;   // tokens per second
    double  burst          = 0;
};
rate_limit_t rate_limit_take(const std::string& tool);

// ---- server -> client notifications on the GET /mcp stream ----
// session "" (or the legacy session) reaches a stream opened without
// Mcp-Session-Id; used for notifications/progress
void push_notification(const std::string& session, const nlohmann::json& msg);

} // namespace slop::core::mcp
