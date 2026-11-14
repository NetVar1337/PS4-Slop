// src/core/mcp/mcp_server.cpp
// the mcp server, jsonrpc over http with sse streams on the side
// tool calls are serialized in call_tool (see mcp_tools.cpp)

#include "core/mcp/mcp_server.hpp"
#include "core/mcp/mcp_tools.hpp"

#include "core/infra/clock.hpp"
#include "core/infra/event_bus.hpp"
#include "core/infra/settings.hpp"
#include "core/runtime/broker.hpp"

#include <httplib.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cmath>
#include <condition_variable>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace slop::core::mcp {

namespace {

using json = nlohmann::json;

std::unique_ptr<httplib::Server> g_srv;
std::unique_ptr<std::thread>     g_thread;
std::atomic<bool>                g_running{false};
std::atomic<uint16_t>            g_port{0};
std::atomic<size_t>              g_streams{0};
size_t                           g_max_streams = 16;
std::mutex                       g_active_mu;
std::map<std::string, std::shared_ptr<infra::cancel_source_t>> g_active;

// bearer tokens, rotated live
std::mutex               g_tok_mu;
std::string              g_primary_token;
std::vector<std::string> g_extra_tokens;

// server issued Mcp-Session-Id values, oldest evicted past the cap
constexpr size_t                kMaxSessions = 1024;
std::mutex                      g_sess_mu;
std::unordered_set<std::string> g_sessions;
std::deque<std::string>         g_session_order;

// single use /events tickets -> expiry (steady ms)
constexpr int64_t kTicketTtlMs = 60'000;
constexpr size_t  kMaxTickets  = 256;
std::mutex                               g_ticket_mu;
std::unordered_map<std::string, int64_t> g_tickets;

thread_local bool t_used_primary = false;

// tells tools which client is calling (breakpoint slot ownership)
struct client_scope_t {
    std::string prev;
    explicit client_scope_t(std::string id) : prev(client_id()) {
        set_client_id(std::move(id));
    }
    ~client_scope_t() { set_client_id(std::move(prev)); }
    client_scope_t(const client_scope_t&) = delete;
    client_scope_t& operator=(const client_scope_t&) = delete;
};

// server -> client notifications, queued per session until its GET /mcp stream
// drains them; a client that stops reading must never grow this without bound
constexpr size_t kMaxNotifyQueue = 64;
struct notify_hub_t {
    std::mutex                                            mu;
    std::condition_variable                               cv;
    std::unordered_map<std::string, std::deque<std::string>> queues;
};
notify_hub_t g_notify;

// per-tool token buckets (mcp_rate_limits setting); /api never consults these
struct bucket_t {
    double  tokens  = 0;
    int64_t last_ms = 0;
    bool    init    = false;
};
std::mutex                           g_rl_mu;
std::unordered_map<std::string, bucket_t> g_buckets;

constexpr const char* kLatestProtocol = "2025-06-18";
constexpr const char* kSupportedProtocols[] = {"2025-06-18", "2025-03-26", "2024-11-05"};
constexpr const char* kServerName      = "slopstation";
#ifdef SLOP_VERSION_STRING
constexpr const char* kServerVersion   = SLOP_VERSION_STRING;   // root VERSION file
#else
constexpr const char* kServerVersion   = "0.0.0-dev";
#endif
constexpr const char* kLegacySession   = "<legacy>";
constexpr int64_t     kStopJoinBudgetMs = 4000;

// the little intro agents get when they connect so they know how to drive us
constexpr const char* kInstructions =
    "Windows reverse-engineering workbench. One tool per domain, each "
    "dispatched by an 'action' enum; read a tool's description before first "
    "use. Core model: ONE shared session, the UI and every tool see the same "
    "attached target and the same loaded binary (see 'state' in this "
    "response). Open every session with target.status and disasm.loaded. "
    "Static flow: disasm.load(path) -> poll disasm.loaded until "
    "image.hype.ready=true -> functions/xrefs/strings -> decomp.function. "
    "Live flow on a PS4: target.ps4_connect {host} (or the one-call "
    "target.ps4_auto {host}) -> memory.scan / debugger ps4_* over the wire. "
    "Live flow on a PS5: target.ps5_connect {host} (or target.ps5_auto "
    "{host}) -> memory.* / target.modules / debugger ps5_* over ps5debug-NG. "
    "Actions fail fast with structured errors when a precondition is missing "
    "(console connected, image.ready, image.hype.ready), re-check state "
    "rather than retrying. "
    "Annotations (disasm.symbol_set, notes, types) persist per binary hash "
    "and are shared with the UI.";

json rpc_error(int code, const std::string& message, const json& id) {
    return {{"jsonrpc", "2.0"}, {"error", {{"code", code}, {"message", message}}}, {"id", id}};
}

json rpc_result(const json& result, const json& id) {
    return {{"jsonrpc", "2.0"}, {"result", result}, {"id", id}};
}

void send_json(httplib::Response& res, int status, const json& body) {
    res.status = status;
    res.set_content(body.dump(-1, ' ', false, json::error_handler_t::replace),
                    "application/json");
}

// a rate-limited tools/call answers 429 with Retry-After; the body stays a
// JSON-RPC error so the client can read the code and the exact retry delay
void send_rpc(httplib::Response& res, const json& resp) {
    if (resp.is_object() && resp.contains("error") && resp.at("error").is_object() &&
        resp.at("error").value("code", 0) == -32002) {
        const json& err = resp.at("error");
        if (err.contains("data") && err.at("data").is_object() &&
            err.at("data").contains("retry_after_ms")) {
            const int64_t ms = err.at("data").at("retry_after_ms").get<int64_t>();
            res.set_header("Retry-After", std::to_string((ms + 999) / 1000));
        }
        send_json(res, 429, resp);
        return;
    }
    send_json(res, 200, resp);
}

// length is not secret (tokens are fixed width), the content is
bool ct_equal(std::string_view a, std::string_view b) {
    const size_t n = std::max(a.size(), b.size());
    unsigned diff = static_cast<unsigned>(a.size() ^ b.size());
    for (size_t i = 0; i < n; ++i) {
        const unsigned ca = i < a.size() ? static_cast<unsigned char>(a[i]) : 0u;
        const unsigned cb = i < b.size() ? static_cast<unsigned char>(b[i]) : 0u;
        diff |= ca ^ cb;
    }
    return diff == 0;
}

std::string lower(std::string_view s) {
    std::string out(s);
    for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

enum class auth_t { open, primary, extra, denied };

auth_t check_token(std::string_view presented) {
    std::lock_guard lk(g_tok_mu);
    if (g_primary_token.empty() && g_extra_tokens.empty()) return auth_t::open;
    bool primary = false, extra = false;
    // compare against every token so timing does not reveal which one matched
    if (!g_primary_token.empty()) primary = ct_equal(presented, g_primary_token);
    for (const auto& t : g_extra_tokens)
        extra = ct_equal(presented, t) || extra;
    if (primary) return auth_t::primary;
    if (extra) return auth_t::extra;
    return auth_t::denied;
}

auth_t authorize(const httplib::Request& req) {
    const std::string auth = req.get_header_value("Authorization");
    std::string_view presented;
    if (auth.size() > 7 && lower(std::string_view(auth).substr(0, 7)) == "bearer ")
        presented = std::string_view(auth).substr(7);
    return check_token(presented);
}

// sets the per-request primary flag; false = already answered 401
bool require_auth(const httplib::Request& req, httplib::Response& res, bool rpc_shape) {
    const auth_t a = authorize(req);
    if (a == auth_t::denied) {
        res.set_header("WWW-Authenticate", "Bearer");
        if (rpc_shape)
            send_json(res, 401, rpc_error(-32001, "unauthorized: missing or invalid bearer token",
                                          nullptr));
        else
            send_json(res, 401, {{"ok", false}, {"error", "unauthorized"}});
        return false;
    }
    t_used_primary = (a == auth_t::primary);
    return true;
}

std::string random_hex() { return infra::settings::generate_token(); }

std::string new_session() {
    std::string id = random_hex();
    std::lock_guard lk(g_sess_mu);
    g_sessions.insert(id);
    g_session_order.push_back(id);
    while (g_session_order.size() > kMaxSessions) {
        g_sessions.erase(g_session_order.front());
        g_session_order.pop_front();
    }
    return id;
}

bool session_known(const std::string& id) {
    std::lock_guard lk(g_sess_mu);
    return g_sessions.contains(id);
}

void drop_session(const std::string& id) {
    std::lock_guard lk(g_sess_mu);
    g_sessions.erase(id);
    g_session_order.erase(std::remove(g_session_order.begin(), g_session_order.end(), id),
                          g_session_order.end());
}

bool consume_ticket(const std::string& t) {
    if (t.empty()) return false;
    std::lock_guard lk(g_ticket_mu);
    auto it = g_tickets.find(t);
    if (it == g_tickets.end()) return false;
    const bool live = it->second > infra::steady_ms();
    g_tickets.erase(it);
    return live;
}

std::optional<std::string> request_key(const std::string& session, const json& id) {
    if (id.is_string())
        return session + std::string("\0s:", 3) + id.get<std::string>();
    if (id.is_number_unsigned())
        return session + std::string("\0u:", 3) + std::to_string(id.get<uint64_t>());
    if (id.is_number_integer())
        return session + std::string("\0i:", 3) + std::to_string(id.get<int64_t>());
    return std::nullopt;
}

void cancel_active(const std::string& session, const json& id) {
    const auto key = request_key(session, id);
    if (!key) return;
    std::shared_ptr<infra::cancel_source_t> source;
    {
        std::lock_guard lk(g_active_mu);
        auto it = g_active.find(*key);
        if (it != g_active.end()) source = it->second;
    }
    if (source) source->request();
}

std::string negotiate_protocol(const json& params) {
    if (params.is_object() && params.contains("protocolVersion") &&
        params.at("protocolVersion").is_string()) {
        const auto& want = params.at("protocolVersion").get_ref<const std::string&>();
        for (const char* v : kSupportedProtocols)
            if (want == v) return want;
    }
    return kLatestProtocol;
}

// returns null for notifications (no id): they never get a reply, known or not
json handle_request(const json& req, const std::string& session) {
    if (!req.is_object())
        return rpc_error(-32600, "invalid request: expected an object", nullptr);
    const bool notification = !req.contains("id");
    const json id = notification ? json(nullptr) : req.at("id");
    if (!req.contains("method") || !req.at("method").is_string())
        return notification ? json() : rpc_error(-32600, "invalid request: missing method", id);

    const std::string method = req.at("method").get<std::string>();
    const json params = req.contains("params") ? req.at("params") : json::object();

    if (method == "notifications/cancelled") {
        if (params.is_object() && params.contains("requestId"))
            cancel_active(session, params.at("requestId"));
        return json();
    }
    if (notification) return json();   // initialized, progress, roots/list_changed, unknown...

    if (method == "initialize") {
        return rpc_result({
            {"protocolVersion", negotiate_protocol(params)},
            {"capabilities", {{"tools", {{"listChanged", false}}},
                              {"resources", {{"listChanged", false}, {"subscribe", false}}},
                              {"prompts", {{"listChanged", false}}}}},
            {"serverInfo", {{"name", kServerName}, {"version", kServerVersion}}},
            {"instructions", kInstructions},
            // tell the agent what we already have going so it doesnt start blind
            {"state", session_state()}
        }, id);
    }

    if (method == "ping") {
        return rpc_result(json::object(), id);
    }

    if (method == "tools/list") {
        json tools = json::array();
        list_tools(tools);
        return rpc_result({{"tools", tools}}, id);
    }

    // state + guide playbooks as resources, playbooks as prompts
    if (method == "resources/list") {
        return rpc_result({{"resources", list_resources()}}, id);
    }

    if (method == "resources/read") {
        if (!params.is_object() || !params.contains("uri") || !params.at("uri").is_string())
            return rpc_error(-32602, "resources/read: missing uri", id);
        const std::string uri = params.at("uri").get<std::string>();
        json out = read_resource(uri);
        if (out.is_null()) return rpc_error(-32602, "unknown resource uri: " + uri, id);
        return rpc_result(std::move(out), id);
    }

    if (method == "prompts/list") {
        return rpc_result({{"prompts", list_prompts()}}, id);
    }

    if (method == "prompts/get") {
        if (!params.is_object() || !params.contains("name") || !params.at("name").is_string())
            return rpc_error(-32602, "prompts/get: missing name", id);
        const std::string name = params.at("name").get<std::string>();
        json out = get_prompt(name);
        if (out.is_null()) return rpc_error(-32602, "unknown prompt: " + name, id);
        return rpc_result(std::move(out), id);
    }

    if (method == "tools/call") {
        if (!params.is_object() || !params.contains("name") || !params.at("name").is_string())
            return rpc_error(-32602, "tools/call: missing tool name", id);
        const std::string name = params.at("name").get<std::string>();
        // `app` is UI plumbing (settings, token rotation, shutdown) and is not
        // in tools/list; keep it off the agent-facing transport entirely.
        if (name == "app")
            return rpc_error(-32601, "tool not found: app (UI-only)", id);
        // token bucket per tool; the UI channel (/api) never comes through here
        if (const rate_limit_t rl = rate_limit_take(name); !rl.allowed) {
            json err = rpc_error(-32002,
                                 "rate limit exceeded for tool '" + name + "' (" +
                                     std::to_string(static_cast<int>(rl.rate)) + "/s, burst " +
                                     std::to_string(static_cast<int>(rl.burst)) +
                                     "); retry after " + std::to_string(rl.retry_after_ms) +
                                     " ms",
                                 id);
            err["error"]["data"] = {{"tool", name},
                                    {"rate", rl.rate},
                                    {"burst", rl.burst},
                                    {"retry_after_ms", rl.retry_after_ms}};
            return err;
        }
        const json args = params.contains("arguments") ? params.at("arguments") : json::object();

        // _meta.progressToken turns on notifications/progress for this call
        progress_ctx_t progress;
        progress.session = session;
        if (params.contains("_meta") && params.at("_meta").is_object() &&
            params.at("_meta").contains("progressToken"))
            progress.token = params.at("_meta").at("progressToken");

        bool is_error = false;
        auto source = std::make_shared<infra::cancel_source_t>();
        const auto key = request_key(session, id);
        if (key) {
            std::lock_guard lk(g_active_mu);
            if (g_active.contains(*key))
                return rpc_error(-32600, "duplicate active request id", id);
            g_active[*key] = source;
        }
        struct registration_guard_t {
            std::optional<std::string> key;
            std::shared_ptr<infra::cancel_source_t> source;
            ~registration_guard_t() {
                if (!key) return;
                std::lock_guard lk(g_active_mu);
                auto it = g_active.find(*key);
                if (it != g_active.end() && it->second == source) g_active.erase(it);
            }
        } registration{key, source};
        client_scope_t client(session);
        json payload = call_tool(name, args, is_error, source->token(), /*allow_app=*/false,
                                 progress.token.is_null() ? nullptr : &progress);
        // memory reads can hand back junk bytes so swap bad utf8 instead of 500ing
        std::string text = payload.dump(2, ' ', true, json::error_handler_t::replace);
        // structuredContent matches each tool's outputSchema (an object); the text
        // block stays for clients that predate structured results
        json structured = payload.is_object() ? std::move(payload)
                                              : json{{"value", std::move(payload)}};
        return rpc_result({
            {"content", json::array({{{"type", "text"}, {"text", std::move(text)}}})},
            {"structuredContent", std::move(structured)},
            {"isError", is_error}
        }, id);
    }

    return rpc_error(-32601, "method not found: " + method, id);
}

bool is_initialize(const json& r) {
    return r.is_object() && r.contains("id") && r.value("method", std::string{}) == "initialize";
}

// /api is the same tools but raw json for the ui so it only parses once
// also keeps front end only actions out of the agent facing tools list
json handle_api(const json& req, infra::cancel_token_t cancel) {
    if (!req.is_object())
        return {{"ok", false}, {"error", "api: request must be an object"}};
    if (!req.contains("tool") || !req.at("tool").is_string())
        return {{"ok", false}, {"error", "api: missing tool"}};
    if (!req.contains("action") || !req.at("action").is_string())
        return {{"ok", false}, {"error", "api: missing action"}};

    const std::string tool = req.at("tool").get<std::string>();
    json args = req.contains("params") && req.at("params").is_object()
                    ? req.at("params")
                    : json::object();
    args["action"] = req.at("action");

    bool is_error = false;
    // /api is the UI channel and is the only caller allowed to reach `app`
    client_scope_t client("ui");
    json payload = call_tool(tool, args, is_error, cancel, /*allow_app=*/true);
    json out{{"ok", !is_error}, {"data", std::move(payload)}};
    if (req.contains("id")) out["id"] = req.at("id");
    return out;
}

// a stream slot, released when the content provider is torn down
struct stream_slot_t {
    bool ok = false;
    stream_slot_t() {
        size_t cur = g_streams.load();
        while (cur < g_max_streams) {
            if (g_streams.compare_exchange_weak(cur, cur + 1)) {
                ok = true;
                return;
            }
        }
    }
};

void release_stream(bool) { g_streams.fetch_sub(1); }

bool claim_stream(httplib::Response& res) {
    stream_slot_t slot;
    if (slot.ok) return true;
    res.set_header("Retry-After", "5");
    send_json(res, 503, {{"ok", false}, {"error", "too many open event streams"}});
    return false;
}

// ---- per-tool rate limits ----
// defaults for the tools that can pin a core or a console for minutes; a
// settings entry {tool: {rate, burst}} overrides or adds one
struct rate_default_t {
    const char* tool;
    double      rate;    // tokens per second
    double      burst;
};
constexpr rate_default_t kRateDefaults[] = {
    {"memory", 50.0, 100.0},   // scans/rescans are the hot loop of a CE-style session
    {"emulate", 20.0, 40.0},
    {"xray", 30.0, 60.0},
    {"analyze", 10.0, 20.0},   // whole-binary Hyperion runs
    {"devirt", 20.0, 40.0},
    {"script", 20.0, 40.0},
};

bool rate_config(const std::string& tool, double& rate, double& burst) {
    const json limits = infra::settings::get_json("mcp_rate_limits");
    if (limits.is_object() && limits.contains(tool)) {
        const json& lim = limits.at(tool);
        if (lim.is_object() && lim.contains("rate") && lim.contains("burst") &&
            lim.at("rate").is_number() && lim.at("burst").is_number()) {
            rate  = lim.at("rate").get<double>();
            burst = lim.at("burst").get<double>();
            return rate > 0.0 && burst >= 1.0;
        }
        return false;   // malformed entry: no limit rather than a wrong one
    }
    for (const auto& d : kRateDefaults) {
        if (tool == d.tool) {
            rate  = d.rate;
            burst = d.burst;
            return true;
        }
    }
    return false;
}

} // namespace

rate_limit_t rate_limit_take(const std::string& tool) {
    rate_limit_t out;
    double rate = 0.0, burst = 0.0;
    if (!rate_config(tool, rate, burst)) return out;
    out.rate  = rate;
    out.burst = burst;
    const int64_t now = infra::steady_ms();
    std::lock_guard lk(g_rl_mu);
    bucket_t& b = g_buckets[tool];
    if (!b.init) {
        b.tokens  = burst;
        b.last_ms = now;
        b.init    = true;
    }
    const double elapsed = static_cast<double>(now - b.last_ms) / 1000.0;
    b.tokens  = std::min(burst, b.tokens + elapsed * rate);
    b.last_ms = now;
    if (b.tokens >= 1.0) {
        b.tokens -= 1.0;
        return out;
    }
    out.allowed        = false;
    out.retry_after_ms = static_cast<int64_t>(std::ceil((1.0 - b.tokens) / rate * 1000.0));
    if (out.retry_after_ms < 1) out.retry_after_ms = 1;
    return out;
}

void push_notification(const std::string& session, const nlohmann::json& msg) {
    std::string frame = "event: message\ndata: ";
    frame += msg.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    frame += "\n\n";
    std::lock_guard lk(g_notify.mu);
    auto& q = g_notify.queues[session];
    q.push_back(std::move(frame));
    while (q.size() > kMaxNotifyQueue) q.pop_front();
    g_notify.cv.notify_all();
}

bool host_allowed(std::string_view host, uint16_t port) {
    if (host.empty()) return true;   // http/1.0 or a raw socket client, not a browser
    std::string h = lower(host);
    std::string port_part;
    if (!h.empty() && h.front() == '[') {
        const size_t close = h.find(']');
        if (close == std::string::npos) return false;
        if (close + 1 < h.size()) {
            if (h[close + 1] != ':') return false;
            port_part = h.substr(close + 2);
        }
        h = h.substr(0, close + 1);
    } else if (const size_t colon = h.rfind(':'); colon != std::string::npos) {
        port_part = h.substr(colon + 1);
        h = h.substr(0, colon);
    }
    if (h != "127.0.0.1" && h != "localhost" && h != "[::1]") return false;
    if (port_part.empty()) return true;
    if (port_part.size() > 5 ||
        !std::all_of(port_part.begin(), port_part.end(),
                     [](char c) { return c >= '0' && c <= '9'; }))
        return false;
    return std::stoul(port_part) == port;
}

bool origin_allowed(std::string_view origin) {
    static constexpr std::string_view kAllowed[] = {
        "http://tauri.localhost",  "https://tauri.localhost",
        "tauri://localhost",       "http://localhost:1420",
        "http://127.0.0.1:1420",
    };
    for (std::string_view a : kAllowed)
        if (origin == a) return true;
    return false;
}

// dns rebinding + foreign origin rejection. Returns false and fills res with a
// 403 when the request must not reach a handler.
//
// Callers with a request body must run this from inside the handler, not from
// the pre-routing hook: httplib invokes that hook before it reads the body, so
// answering there closes the connection with the body still unread and the
// client sees a reset instead of the 403.
bool guard_request(const httplib::Request& req, httplib::Response& res) {
    if (!host_allowed(req.get_header_value("Host"), g_port.load())) {
        res.set_header("Connection", "close");
        send_json(res, 403, {{"ok", false}, {"error", "host not allowed"}});
        return false;
    }
    const std::string origin = req.get_header_value("Origin");
    if (!origin.empty() && !origin_allowed(origin)) {
        res.set_header("Connection", "close");
        send_json(res, 403, {{"ok", false}, {"error", "origin not allowed"}});
        return false;
    }
    return true;
}

bool request_used_primary_token() { return t_used_primary; }

void set_primary_token(std::string token) {
    std::lock_guard lk(g_tok_mu);
    g_primary_token = std::move(token);
}

void add_extra_token(std::string token) {
    if (token.empty()) return;
    std::lock_guard lk(g_tok_mu);
    if (std::find(g_extra_tokens.begin(), g_extra_tokens.end(), token) == g_extra_tokens.end())
        g_extra_tokens.push_back(std::move(token));
}

std::string issue_events_ticket() {
    std::string t = random_hex();
    const int64_t now = infra::steady_ms();
    std::lock_guard lk(g_ticket_mu);
    for (auto it = g_tickets.begin(); it != g_tickets.end();) {
        if (it->second <= now) it = g_tickets.erase(it);
        else ++it;
    }
    if (g_tickets.size() >= kMaxTickets) {
        auto oldest = std::min_element(g_tickets.begin(), g_tickets.end(),
                                       [](const auto& a, const auto& b) { return a.second < b.second; });
        g_tickets.erase(oldest);
    }
    g_tickets[t] = now + kTicketTtlMs;
    return t;
}

size_t active_streams() { return g_streams.load(); }

namespace {

// POST /api/v1 (and the deprecated /api alias): raw json for the ui
void serve_api(const httplib::Request& req, httplib::Response& res, bool deprecated) {
    if (!guard_request(req, res)) return;
    if (!require_auth(req, res, /*rpc_shape=*/false)) return;
    if (deprecated) {
        // old path still answers, but clients must move to /api/v1
        res.set_header("Deprecation", "true");
        res.set_header("Link", "</api/v1>; rel=\"successor-version\"");
    }
    json body = json::parse(req.body, nullptr, false);
    if (body.is_discarded()) {
        send_json(res, 400, {{"ok", false}, {"error", "parse error"}});
        return;
    }

    // let the ui batch a bunch of calls so opening a view is one round trip
    auto source = std::make_shared<infra::cancel_source_t>();
    json out;
    if (body.is_array()) {
        out = json::array();
        for (const auto& r : body)
            out.push_back(handle_api(r, source->token()));
    } else {
        out = handle_api(body, source->token());
    }
    send_json(res, 200, out);
}

// GET /api/v1/events (and the deprecated /events alias)
void serve_events(const httplib::Request& req, httplib::Response& res, bool deprecated) {
    if (!guard_request(req, res)) return;
    // eventsource cant send headers, so the ui trades its bearer for a single
    // use ticket (app.events_ticket) and passes that instead of the token
    if (!consume_ticket(req.get_param_value("ticket")) &&
        !require_auth(req, res, /*rpc_shape=*/false))
        return;
    if (!claim_stream(res)) return;
    if (deprecated) {
        res.set_header("Deprecation", "true");
        res.set_header("Link", "</api/v1/events>; rel=\"successor-version\"");
    }

    res.set_header("Cache-Control", "no-cache");
    res.set_header("X-Accel-Buffering", "no");

    auto sub = infra::event_bus::subscribe();
    // cursor for the client so a reconnect can pull the output it missed
    const uint64_t revision = infra::event_bus::output_revision();

    res.set_content_provider(
        "text/event-stream",
        [sub, revision](size_t offset, httplib::DataSink& sink) -> bool {
            if (offset == 0) {
                const std::string hello =
                    "event: hello\ndata: " +
                    json({{"output_revision", revision}}).dump() + "\n\n";
                return sink.write(hello.data(), hello.size());
            }
            if (!g_running.load()) return false;
            std::string batch;
            if (!sub->wait(batch, 1000)) return false;   // bus closed
            if (batch.empty()) {
                if (!g_running.load()) return false;
                static constexpr char kPing[] = ": keepalive\n\n";
                return sink.write(kPing, sizeof(kPing) - 1);
            }
            return sink.write(batch.data(), batch.size());
        },
        release_stream);
}

// OpenAPI 3.1 descriptor for /api/v1, generated from the same tool schemas
// tools/list serves so the two can never drift
json openapi_doc() {
    json tools = json::array();
    list_tools(tools);
    json schemas = json::object();
    json names   = json::array();
    for (const auto& t : tools) {
        const std::string n = t.at("name").get<std::string>();
        names.push_back(n);
        schemas[n] = t.at("inputSchema");
    }

    json api_call;
    api_call["type"] = "object";
    api_call["properties"] = {
        {"tool", {{"type", "string"}, {"enum", names}}},
        {"action", {{"type", "string"}, {"description", "one action from the tool's enum"}}},
        {"params", {{"type", "object"}, {"description", "tool arguments, see the tool schema"}}},
        {"id", {{"description", "echoed back on the response envelope"}}}};
    api_call["required"] = json::array({"tool", "action"});
    schemas["ApiCall"]   = std::move(api_call);

    json media;
    media["schema"] = {{"$ref", "#/components/schemas/ApiCall"}};
    json content;
    content["application/json"] = std::move(media);
    json request_body;
    request_body["required"] = true;
    request_body["content"]  = std::move(content);

    json responses;
    responses["200"] = {{"description", "{ok, data, id?}"}};
    responses["400"] = {{"description", "{ok:false, error}"}};
    responses["401"] = {{"description", "unauthorized"}};

    json post;
    post["summary"]     = "Run one tool action";
    post["requestBody"] = std::move(request_body);
    post["responses"]   = std::move(responses);

    json path;
    path["post"] = std::move(post);

    json paths;
    paths["/api/v1"] = std::move(path);

    json doc;
    doc["openapi"] = "3.1.0";
    doc["info"]    = {{"title", "SlopStation engine API"},
                      {"version", kServerVersion},
                      {"description", "One POST /api/v1 runs one tool action; batch with a JSON "
                                      "array. The same tool schemas drive /mcp."}};
    doc["servers"]     = json::array({{{"url", "http://127.0.0.1:" + std::to_string(g_port.load())}}});
    doc["paths"]       = std::move(paths);
    doc["components"]  = {{"schemas", std::move(schemas)}};
    doc["x-mcp-tools"] = std::move(tools);
    return doc;
}

} // namespace

bool start(const server_config_t& cfg) {
    if (g_running) return true;

    {
        std::lock_guard lk(g_tok_mu);
        g_primary_token = cfg.token;
        g_extra_tokens.clear();
        for (const auto& t : cfg.extra_tokens)
            if (!t.empty()) g_extra_tokens.push_back(t);
    }
    g_max_streams = std::max<size_t>(1, cfg.max_streams);
    auto srv = std::make_unique<httplib::Server>();
    // httplib's default SO_REUSEADDR lets a second process bind the same
    // 127.0.0.1 port on Windows and silently take half the connections
    srv->set_socket_options([](socket_t s) {
        BOOL excl = TRUE;
        ::setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&excl), sizeof(excl));
    });

    // long lived sse streams each pin a worker, so the pool is sized well past the stream cap
    const size_t workers = std::max(cfg.worker_threads, g_max_streams + 8);
    srv->new_task_queue = [workers] { return new httplib::ThreadPool(workers); };

    // cap the body so a wild client cant eat all the ram
    srv->set_payload_max_length(32ull << 20);
    srv->set_read_timeout(std::chrono::seconds(30));
    srv->set_write_timeout(std::chrono::seconds(30));

    srv->set_exception_handler([](const httplib::Request&, httplib::Response& res, std::exception_ptr ep) {
        std::string msg = "internal error";
        try { if (ep) std::rethrow_exception(ep); }
        catch (const std::exception& e) { msg = e.what(); }
        catch (...) {}
        send_json(res, 500, rpc_error(-32603, msg, nullptr));
    });

    // cors for the webview, plus the preflight answer. The host/origin guard
    // itself lives in guard_request() and is called from each handler: this
    // hook runs before httplib reads the request body, so rejecting a POST here
    // would close the connection with the body unread.
    srv->set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        const std::string origin = req.get_header_value("Origin");
        if (!origin.empty() && origin_allowed(origin)) {
            res.set_header("Access-Control-Allow-Origin", origin);
            res.set_header("Vary", "Origin");
            res.set_header("Access-Control-Allow-Headers",
                           "Authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version");
            res.set_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
            res.set_header("Access-Control-Expose-Headers", "Mcp-Session-Id");
            res.set_header("Access-Control-Max-Age", "600");
        }
        if (req.method == "OPTIONS") {
            // a preflight never carries a body, so it is safe to reject here
            if (!guard_request(req, res)) return httplib::Server::HandlerResponse::Handled;
            res.status = 204;
            return httplib::Server::HandlerResponse::Handled;
        }
        t_used_primary = false;
        return httplib::Server::HandlerResponse::Unhandled;
    });

    srv->Get("/health", [](const httplib::Request& req, httplib::Response& res) {
        if (!guard_request(req, res)) return;
        send_json(res, 200, {{"ok", true}, {"server", kServerName}, {"version", kServerVersion}});
    });

    srv->Post("/mcp", [](const httplib::Request& req, httplib::Response& res) {
        if (!guard_request(req, res)) return;
        if (!require_auth(req, res, /*rpc_shape=*/true)) return;
        json req_json = json::parse(req.body, nullptr, false);
        if (req_json.is_discarded()) {
            send_json(res, 400, rpc_error(-32700, "parse error", nullptr));
            return;
        }
        if (req_json.is_array() && req_json.empty()) {
            send_json(res, 400, rpc_error(-32600, "invalid request: empty batch", nullptr));
            return;
        }

        // sessions are server issued on initialize; an unknown id means the
        // client must re-initialize (engine restarted or session deleted)
        std::string session = kLegacySession;
        const std::string presented = req.get_header_value("Mcp-Session-Id");
        if (!presented.empty()) {
            if (!session_known(presented)) {
                send_json(res, 404, rpc_error(-32001, "unknown Mcp-Session-Id; re-initialize",
                                              nullptr));
                return;
            }
            session = presented;
        }
        const bool init = req_json.is_array()
                              ? std::any_of(req_json.begin(), req_json.end(), is_initialize)
                              : is_initialize(req_json);
        if (init) {
            session = new_session();
            res.set_header("Mcp-Session-Id", session);
        }

        // jsonrpc allows whole batches in one post
        if (req_json.is_array()) {
            json out = json::array();
            for (const auto& r : req_json) {
                json resp = handle_request(r, session);
                if (!resp.is_null()) out.push_back(std::move(resp));
            }
            // nothing but notifications means we say nothing back
            if (out.empty()) {
                res.status = 202;
                return;
            }
            send_json(res, 200, out);
            return;
        }

        json resp = handle_request(req_json, session);
        if (resp.is_null()) {
            res.status = 202;   // accepted notification, nothing to answer
            return;
        }
        send_rpc(res, resp);
    });

    srv->Delete("/mcp", [](const httplib::Request& req, httplib::Response& res) {
        if (!guard_request(req, res)) return;
        if (!require_auth(req, res, /*rpc_shape=*/true)) return;
        const std::string sid = req.get_header_value("Mcp-Session-Id");
        if (sid.empty() || !session_known(sid)) {
            send_json(res, 404, rpc_error(-32001, "unknown Mcp-Session-Id", nullptr));
            return;
        }
        drop_session(sid);
        res.status = 204;
    });

    srv->Post("/api/v1", [](const httplib::Request& req, httplib::Response& res) {
        serve_api(req, res, /*deprecated=*/false);
    });

    // deprecated alias: same body plus the Deprecation header
    srv->Post("/api", [](const httplib::Request& req, httplib::Response& res) {
        serve_api(req, res, /*deprecated=*/true);
    });

    srv->Get("/api/v1/openapi.json", [](const httplib::Request& req, httplib::Response& res) {
        if (!guard_request(req, res)) return;
        if (!require_auth(req, res, /*rpc_shape=*/false)) return;
        send_json(res, 200, openapi_doc());
    });

    srv->Get("/mcp", [](const httplib::Request& req, httplib::Response& res) {
        if (!guard_request(req, res)) return;
        // gate the stream too or it leaks to anyone when a token is set
        if (!require_auth(req, res, /*rpc_shape=*/true)) return;
        if (!claim_stream(res)) return;
        // server -> client notifications (notifications/progress) for this session
        const std::string presented = req.get_header_value("Mcp-Session-Id");
        struct stream_guard_t {
            std::string key;
            ~stream_guard_t() {
                std::lock_guard lk(g_notify.mu);
                g_notify.queues.erase(key);
            }
        };
        auto guard = std::make_shared<stream_guard_t>(
            stream_guard_t{presented.empty() ? std::string(kLegacySession) : presented});
        res.set_header("Cache-Control", "no-cache");
        // keepalive pings run on this worker thread, never the shared work queue
        res.set_content_provider(
            "text/event-stream",
            [guard](size_t offset, httplib::DataSink& sink) -> bool {
                if (offset == 0) {
                    return sink.write("event: endpoint\ndata: /mcp\n\n", 28);
                }
                // poll in small chunks so shutdown and a gone client free the worker quickly
                for (int i = 0; i < 150 && g_running.load(); ++i) {
                    if (sink.is_writable && !sink.is_writable()) return false;
                    std::unique_lock lk(g_notify.mu);
                    const bool woke = g_notify.cv.wait_for(
                        lk, std::chrono::milliseconds(100), [&] {
                            return !g_notify.queues[guard->key].empty() || !g_running.load();
                        });
                    if (!woke) continue;
                    auto& q = g_notify.queues[guard->key];
                    if (q.empty()) continue;
                    std::string batch;
                    while (!q.empty()) {
                        batch += q.front();
                        q.pop_front();
                    }
                    lk.unlock();
                    return sink.write(batch.data(), batch.size());
                }
                if (!g_running.load()) return false;
                return sink.write(": keepalive\n\n", 13);
            },
            release_stream);
    });

    // event stream for the ui, way better than polling every bit of state 60 times a second
    srv->Get("/api/v1/events", [](const httplib::Request& req, httplib::Response& res) {
        serve_events(req, res, /*deprecated=*/false);
    });

    srv->Get("/events", [](const httplib::Request& req, httplib::Response& res) {
        serve_events(req, res, /*deprecated=*/true);
    });

    if (cfg.port == 0) {
        const int actual = srv->bind_to_any_port("127.0.0.1");
        if (actual <= 0) return false;
        g_port = static_cast<uint16_t>(actual);
    } else {
        if (!srv->bind_to_port("127.0.0.1", cfg.port)) return false;
        g_port = cfg.port;
    }
    g_srv = std::move(srv);
    g_running = true;
    g_thread = std::make_unique<std::thread>([] {
        g_srv->listen_after_bind();
    });
    g_srv->wait_until_ready();
    if (!g_srv->is_running()) {
        g_running = false;
        if (g_thread->joinable()) g_thread->join();
        g_thread.reset();
        g_srv.reset();
        g_port = 0;
        return false;
    }
    runtime::broker_client_attach("mcp");
    return true;
}

void stop() {
    if (!g_running.exchange(false)) return;
    runtime::broker_client_detach("mcp");
    // nudge the parked event streams so the join below is instant
    infra::event_bus::publish("server.stopping", nlohmann::json::object());
    std::vector<std::shared_ptr<infra::cancel_source_t>> active;
    {
        std::lock_guard lk(g_active_mu);
        for (const auto& [key, source] : g_active) {
            (void)key;
            active.push_back(source);
        }
    }
    for (const auto& source : active) source->request();
    // wake the parked GET /mcp streams so their workers free up
    {
        std::lock_guard lk(g_notify.mu);
        g_notify.queues.clear();
    }
    g_notify.cv.notify_all();
    if (g_srv) g_srv->stop();
    // the listener join waits for every worker, and a tool that ignores its cancel
    // token would wedge shutdown here; join on a helper with a deadline and, if it
    // runs over, let the helper finish the join and free the server later
    if (g_thread) {
        auto joined = std::make_shared<std::atomic<bool>>(false);
        std::thread* listener = g_thread.release();
        httplib::Server* srv = g_srv.release();
        std::thread joiner([listener, srv, joined] {
            if (listener->joinable()) listener->join();
            delete listener;
            delete srv;
            joined->store(true);
        });
        const int64_t deadline = infra::steady_ms() + kStopJoinBudgetMs;
        while (!joined->load() && infra::steady_ms() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        if (joined->load()) {
            joiner.join();
        } else {
            joiner.detach();
            infra::event_bus::output("mcp server stop: a request is still running, "
                                     "finishing teardown in the background");
        }
    }
    g_srv.reset();
    g_port = 0;
    {
        std::lock_guard lk(g_active_mu);
        g_active.clear();
    }
    {
        std::lock_guard lk(g_sess_mu);
        g_sessions.clear();
        g_session_order.clear();
    }
    {
        std::lock_guard lk(g_ticket_mu);
        g_tickets.clear();
    }
    shutdown_tools();
}

bool running() { return g_running; }
uint16_t port() { return g_port; }

const char* server_version() noexcept { return kServerVersion; }

} // namespace slop::core::mcp
