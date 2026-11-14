// src/engine/engine_main.cpp
// headless host for the core, same boot and same mcp surface minus the window
// prints SLOP_ENGINE_READY <port> on stdout when listening and exits clean
// on ctrl c or shutdown so the driver never gets stranded
//
// token handshake: a spawner that sets SLOP_MCP_TOKEN brings its own bearer,
// the engine accepts it and the READY line carries no token. without it the
// legacy "SLOP_ENGINE_READY <port> <token>" form is printed
// if something is already listening we hand over that endpoint and leave; with
// SLOP_MCP_TOKEN set the spawner's token is registered with the running engine
//
// --stdio: MCP over stdin/stdout for stdio-only clients (Claude Desktop). Each
// stdin line is POSTed to the engine's own /mcp (or the running engine's) with
// a per-process token; each reply is one stdout line. Everything else that
// would reach stdout (handshake, logs) is moved to stderr.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <io.h>
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

namespace {

namespace lifecycle = slop::core::infra::lifecycle;
namespace control   = slop::core::infra::app_control;
namespace bus       = slop::core::infra::event_bus;

struct options_t {
    bool     mcp_onboarding = true;
    bool     quiet          = false;   // quiet the mirrored output
    uint32_t parent_pid     = 0;       // watch this pid and exit when it dies
    bool     stdio          = false;   // MCP over stdin/stdout
};

FILE* g_rpc_out = nullptr;   // the real stdout in --stdio mode, nullptr otherwise

BOOL WINAPI ctrl_handler(DWORD type) {
    switch (type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        control::request_quit("console signal");
        // close event gives us about 5 seconds, the main loop sees the flag and tears down
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));
        return TRUE;
    default:
        return FALSE;
    }
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

// keep the real stdout for JSON-RPC only and point fd 1 / STD_OUTPUT_HANDLE at
// stderr, so printf, spdlog and emit() can never corrupt the protocol stream
void claim_stdout_for_rpc() {
    std::fflush(stdout);
    const int rpc_fd = _dup(1);
    _dup2(2, 1);
    ::SetStdHandle(STD_OUTPUT_HANDLE, ::GetStdHandle(STD_ERROR_HANDLE));
    g_rpc_out = _fdopen(rpc_fd, "wb");
}

std::string random_token() {
    std::random_device rd;   // MSVC: rand_s, a CSPRNG
    std::string t;
    for (int i = 0; i < 4; ++i) {
        char b[9];
        std::snprintf(b, sizeof(b), "%08x", rd());
        t += b;
    }
    return t;
}

// one JSON-RPC message per stdin line -> POST /mcp -> one reply line (none
// for notifications); returns when stdin closes
void run_stdio_bridge(uint16_t port, const std::string& token) {
    httplib::Client cli("127.0.0.1", port);
    cli.set_connection_timeout(std::chrono::seconds(5));
    cli.set_read_timeout(std::chrono::minutes(30));   // long tool calls (scans, analysis)
    std::string session, line;
    while (std::getline(std::cin, line)) {
        if (line.find_first_not_of(" \t\r") == std::string::npos) continue;
        httplib::Headers h{{"Authorization", "Bearer " + token}};
        if (!session.empty()) h.emplace("Mcp-Session-Id", session);
        auto res = cli.Post("/mcp", h, line, "application/json");
        nlohmann::json reply;
        if (res) {
            if (res->has_header("Mcp-Session-Id")) session = res->get_header_value("Mcp-Session-Id");
            if (res->status == 202 || res->body.empty()) continue;   // notification
            reply = nlohmann::json::parse(res->body, nullptr, false);
        }
        if (!res || reply.is_discarded()) {
            const auto req = nlohmann::json::parse(line, nullptr, false);
            if (!req.is_object() || !req.contains("id")) continue;   // nobody to answer
            reply = {{"jsonrpc", "2.0"}, {"id", req["id"]},
                     {"error", {{"code", -32603}, {"message", "engine unreachable"}}}};
        }
        const std::string out = reply.dump() + "\n";   // dump() never emits a raw newline
        std::fwrite(out.data(), 1, out.size(), g_rpc_out);
        std::fflush(g_rpc_out);
    }
}

options_t parse_args(int argc, char** argv) {
    options_t o;
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (std::strcmp(a, "--no-onboard") == 0)  o.mcp_onboarding = false;
        else if (std::strcmp(a, "--quiet") == 0)       o.quiet = true;
        else if (std::strcmp(a, "--port") == 0 && i + 1 < argc)
            ::_putenv_s("SLOP_MCP_PORT", argv[++i]); // CRT getenv() does not see SetEnvironmentVariable
        else if (std::strcmp(a, "--parent-pid") == 0 && i + 1 < argc)
            o.parent_pid = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        else if (std::strcmp(a, "--stdio") == 0) {
            o.stdio = true;
            o.mcp_onboarding = false;   // the stdio client already has its own config entry
        }
        // accepted and ignored, this binary is always headless
    }
    return o;
}

} // namespace

int main(int argc, char** argv) {
    const options_t opts = parse_args(argc, argv);
    if (opts.stdio) {
        claim_stdout_for_rpc();
        if (env_token().empty()) ::_putenv_s("SLOP_MCP_TOKEN", random_token().c_str());
    }

    // already served, hand the caller that endpoint and get out of the way
    const std::string own_token = env_token();
    if (lifecycle::endpoint_t live; lifecycle::read_endpoint(live)) {
        if (own_token.empty()) {
            emit(("SLOP_ENGINE_READY " + std::to_string(live.port) + " " + live.token).c_str());
        } else {
            // teach the running engine the spawner's token instead of leaking ours
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

    ::SetConsoleCtrlHandler(ctrl_handler, TRUE);

    // exit when the parent ui dies, the job object is just the backstop
    HANDLE parent = nullptr;
    if (opts.parent_pid != 0) {
        parent = ::OpenProcess(SYNCHRONIZE, FALSE, opts.parent_pid);
        if (parent == nullptr)
            std::fprintf(stderr, "parent pid %lu not open-able; watch disabled\n",
                         static_cast<unsigned long>(opts.parent_pid));
    }

    lifecycle::config_t cfg;
    cfg.mcp_onboarding = opts.mcp_onboarding;
    lifecycle::begin(std::move(cfg));

    // mirror the boot story to stderr so it never collides with the stdout handshake
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
                if (own_token.empty())
                    emit(("SLOP_ENGINE_READY " + std::to_string(boot.mcp_port) + " " +
                          slop::core::infra::settings::mcp_token())
                             .c_str());
                else
                    emit(("SLOP_ENGINE_READY " + std::to_string(boot.mcp_port)).c_str());
                announced = true;
                if (opts.stdio)
                    bridge = std::thread([port = boot.mcp_port, own_token] {
                        run_stdio_bridge(static_cast<uint16_t>(port), own_token);
                        control::request_quit("stdin closed");
                    });
            } else if (lifecycle::booted()) {
                emit("SLOP_ENGINE_FAILED mcp server did not bind");
                announced = true;
                control::request_quit("mcp bind failure");
            }
        }

        // nothing here is frame paced, 10ms keeps shutdown snappy without spinning a core
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        if (parent != nullptr && ::WaitForSingleObject(parent, 0) == WAIT_OBJECT_0)
            control::request_quit("front end exited");
    }

    if (parent != nullptr) ::CloseHandle(parent);

    drain_output();
    lifecycle::shutdown();
    drain_output();   // teardown story lands here
    // a quit from elsewhere leaves the bridge blocked on stdin; nothing left to flush
    if (bridge.joinable()) bridge.detach();
    return 0;
}

