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

constexpr const char* kLatestProtocol = "2025-06-18";
constexpr const char* kSupportedProtocols[] = {"2025-06-18", "2025-03-26", "2024-11-05"};
constexpr const char* kServerName      = "reverse-slop";
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
            {"capabilities", {{"tools", {{"listChanged", false}}}}},
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

    if (method == "tools/call") {
        if (!params.is_object() || !params.contains("name") || !params.at("name").is_string())
            return rpc_error(-32602, "tools/call: missing tool name", id);
        const std::string name = params.at("name").get<std::string>();
        // `app` is UI plumbing (settings, token rotation, shutdown) and is not
        // in tools/list; keep it off the agent-facing transport entirely.
        if (name == "app")
            return rpc_error(-32601, "tool not found: app (UI-only)", id);
        const json args = params.contains("arguments") ? params.at("arguments") : json::object();

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
        json payload = call_tool(name, args, is_error, source->token());
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

} // namespace

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
        send_json(res, 200, resp);
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

    srv->Post("/api", [](const httplib::Request& req, httplib::Response& res) {
        if (!guard_request(req, res)) return;
        if (!require_auth(req, res, /*rpc_shape=*/false)) return;
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
    });

    srv->Get("/mcp", [](const httplib::Request& req, httplib::Response& res) {
        if (!guard_request(req, res)) return;
        // gate the stream too or it leaks to anyone when a token is set
        if (!require_auth(req, res, /*rpc_shape=*/true)) return;
        if (!claim_stream(res)) return;
        res.set_header("Cache-Control", "no-cache");
        // keepalive pings run on this worker thread, never the shared work queue
        res.set_content_provider(
            "text/event-stream",
            [](size_t offset, httplib::DataSink& sink) -> bool {
                if (offset == 0) {
                    return sink.write("event: endpoint\ndata: /mcp\n\n", 28);
                }
                // poll in small chunks so shutdown and a gone client free the worker quickly
                for (int i = 0; i < 150 && g_running.load(); ++i) {
                    if (sink.is_writable && !sink.is_writable()) return false;
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                if (!g_running.load()) return false;
                return sink.write(": keepalive\n\n", 13);
            },
            release_stream);
    });

    // event stream for the ui, way better than polling every bit of state 60 times a second
    srv->Get("/events", [](const httplib::Request& req, httplib::Response& res) {
        if (!guard_request(req, res)) return;
        // eventsource cant send headers, so the ui trades its bearer for a single
        // use ticket (app.events_ticket) and passes that instead of the token
        if (!consume_ticket(req.get_param_value("ticket")) &&
            !require_auth(req, res, /*rpc_shape=*/false))
            return;
        if (!claim_stream(res)) return;

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

} // namespace slop::core::mcp
