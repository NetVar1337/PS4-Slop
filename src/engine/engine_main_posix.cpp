// src/engine/engine_main_posix.cpp
// headless host for the core on POSIX: same boot, same MCP surface, no window.
// prints SLOP_ENGINE_READY <port> [<token>] on stdout when listening and exits
// clean on SIGINT/SIGTERM so a driver never gets stranded.
//
// --stdio: MCP over stdin/stdout for stdio-only clients. Each stdin line is
// POSTed to the engine's own /mcp with a per-process token; each reply is one
// stdout line, everything else goes to stderr.

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <random>
#include <string>
#include <thread>

#include "core/infra/app_control.hpp"
#include "core/infra/event_bus.hpp"
#include "core/infra/lifecycle.hpp"
#include "core/infra/settings.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <unistd.h>

namespace {

namespace lifecycle = slop::core::infra::lifecycle;
namespace control   = slop::core::infra::app_control;
namespace bus       = slop::core::infra::event_bus;

struct options_t {
    bool     mcp_onboarding = true;
    bool     quiet          = false;
    uint32_t parent_pid     = 0;
    bool     stdio          = false;
    uint16_t port           = 0;
};

FILE* g_rpc_out = nullptr;

void on_signal(int) {
    control::request_quit("console signal");
}

std::string env_token() {
    const char* t = std::getenv("SLOP_MCP_TOKEN");
    return (t && *t) ? std::string(t) : std::string{};
}

void emit(const char* line) {
    std::fputs(line, stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
}

// keep the real stdout for JSON-RPC only and point fd 1 at stderr, so printf,
// spdlog and emit() can never corrupt the protocol stream
void claim_stdout_for_rpc() {
    std::fflush(stdout);
    const int rpc_fd = ::dup(1);
    ::dup2(2, 1);
    g_rpc_out = ::fdopen(rpc_fd, "wb");
}

std::string random_token() {
    std::random_device rd;
    std::string t;
    for (int i = 0; i < 4; ++i) {
        char b[9];
        std::snprintf(b, sizeof(b), "%08x", rd());
        t += b;
    }
    return t;
}

void run_stdio_bridge(uint16_t port, const std::string& token) {
    httplib::Client cli("127.0.0.1", port);
    cli.set_connection_timeout(std::chrono::seconds(5));
    cli.set_read_timeout(std::chrono::minutes(30));
    std::string session, line;
    while (std::getline(std::cin, line)) {
        if (line.find_first_not_of(" \t\r") == std::string::npos) continue;
        httplib::Headers h{{"Authorization", "Bearer " + token}};
        if (!session.empty()) h.emplace("Mcp-Session-Id", session);
        auto res = cli.Post("/mcp", h, line, "application/json");
        nlohmann::json reply;
        if (res) {
            if (res->has_header("Mcp-Session-Id")) session = res->get_header_value("Mcp-Session-Id");
            if (res->status == 202 || res->body.empty()) continue;
            reply = nlohmann::json::parse(res->body, nullptr, false);
        }
        if (!res || reply.is_discarded()) {
            const auto req = nlohmann::json::parse(line, nullptr, false);
            if (!req.is_object() || !req.contains("id")) continue;
            reply = {{"jsonrpc", "2.0"}, {"id", req["id"]},
                     {"error", {{"code", -32603}, {"message", "engine unreachable"}}}};
        }
        const std::string out = reply.dump() + "\n";
        std::fwrite(out.data(), 1, out.size(), g_rpc_out);
        std::fflush(g_rpc_out);
    }
}

options_t parse_args(int argc, char** argv) {
    options_t o;
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (std::strcmp(a, "--no-onboard") == 0)  o.mcp_onboarding = false;
        else if (std::strcmp(a, "--quiet") == 0)  o.quiet = true;
        else if (std::strcmp(a, "--port") == 0 && i + 1 < argc) {
            const unsigned long p = std::strtoul(argv[++i], nullptr, 10);
            if (p > 0 && p < 65536) o.port = static_cast<uint16_t>(p);
        }
        else if (std::strcmp(a, "--parent-pid") == 0 && i + 1 < argc)
            o.parent_pid = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        else if (std::strcmp(a, "--stdio") == 0) {
            o.stdio = true;
            o.mcp_onboarding = false;
        }
    }
    return o;
}

// SIGKILL-proof parent watch: /proc/<pid> disappearing is the only signal we
// get when the front end is killed hard
bool parent_alive(uint32_t pid) {
    if (pid == 0) return true;
    return ::kill(static_cast<pid_t>(pid), 0) == 0;
}

} // namespace

int main(int argc, char** argv) {
    const options_t opts = parse_args(argc, argv);
    if (opts.stdio) {
        claim_stdout_for_rpc();
        if (env_token().empty()) ::setenv("SLOP_MCP_TOKEN", random_token().c_str(), 1);
    }

    const std::string own_token = env_token();
    lifecycle::endpoint_t live;
    if (lifecycle::read_endpoint(live) && lifecycle::endpoint_serving(live)) {
        if (own_token.empty()) {
            emit(("SLOP_ENGINE_READY " + std::to_string(live.port) + " " + live.token).c_str());
        } else {
            httplib::Client cli("127.0.0.1", live.port);
            cli.set_connection_timeout(std::chrono::seconds(2));
            cli.set_read_timeout(std::chrono::seconds(5));
            httplib::Headers h;
            if (!live.token.empty()) h.emplace("Authorization", "Bearer " + live.token);
            const nlohmann::json body = {{"tool", "app"},
                                         {"action", "register_token"},
                                         {"params", {{"token", own_token}}}};
            auto res = cli.Post("/api", h, body.dump(), "application/json");
            const auto reply = res ? nlohmann::json::parse(res->body, nullptr, false)
                                   : nlohmann::json();
            if (!res || res->status != 200 || !reply.is_object() || !reply.value("ok", false)) {
                emit("SLOP_ENGINE_FAILED running engine refused the spawner token");
                return 1;
            }
            emit(("SLOP_ENGINE_READY " + std::to_string(live.port)).c_str());
        }
        emit(("SLOP_ENGINE_EXISTING " + std::to_string(live.pid)).c_str());
        if (opts.stdio) run_stdio_bridge(live.port, own_token);
        return 0;
    }
    if (lifecycle::drop_stale_endpoint())
        std::fprintf(stderr, "stale engine registration dropped (endpoint did not answer)\n");

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);

    lifecycle::config_t cfg;
    cfg.mcp_onboarding = opts.mcp_onboarding;
    cfg.mcp_port       = opts.port;
    lifecycle::begin(std::move(cfg));

    uint64_t mirrored = 0;
    const auto drain_output = [&] {
        if (opts.quiet) return;
        for (const auto& l : bus::output_since(mirrored)) {
            std::fprintf(stderr, "%s\n", l.text.c_str());
            mirrored = l.seq;
        }
        std::fflush(stderr);
    };

    bool announced = false;
    std::thread bridge;
    while (!control::quit_requested()) {
        lifecycle::advance();
        lifecycle::tick();
        drain_output();

        if (!announced) {
            const auto boot = lifecycle::result();
            if (boot.mcp_ok) {
                const lifecycle::endpoint_t self{static_cast<uint32_t>(::getpid()),
                                                 boot.mcp_port,
                                                 slop::core::infra::settings::mcp_token()};
                announced = true;
                if (!lifecycle::endpoint_serving(self, 3000)) {
                    emit("SLOP_ENGINE_FAILED mcp endpoint did not answer after boot");
                    control::request_quit("mcp endpoint probe failed");
                } else {
                    if (own_token.empty())
                        emit(("SLOP_ENGINE_READY " + std::to_string(boot.mcp_port) + " " +
                              slop::core::infra::settings::mcp_token())
                                 .c_str());
                    else
                        emit(("SLOP_ENGINE_READY " + std::to_string(boot.mcp_port)).c_str());
                    if (opts.stdio)
                        bridge = std::thread([port = boot.mcp_port, own_token] {
                            run_stdio_bridge(static_cast<uint16_t>(port), own_token);
                            control::request_quit("stdin closed");
                        });
                }
            } else if (lifecycle::booted()) {
                emit("SLOP_ENGINE_FAILED mcp server did not bind");
                announced = true;
                control::request_quit("mcp bind failure");
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        if (!parent_alive(opts.parent_pid)) control::request_quit("front end exited");
    }

    drain_output();
    lifecycle::shutdown();
    drain_output();
    if (bridge.joinable()) bridge.detach();
    return 0;
}
