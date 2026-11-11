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

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
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
};

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

options_t parse_args(int argc, char** argv) {
    options_t o;
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (std::strcmp(a, "--no-onboard") == 0)  o.mcp_onboarding = false;
        else if (std::strcmp(a, "--quiet") == 0)       o.quiet = true;
        else if (std::strcmp(a, "--port") == 0 && i + 1 < argc)
            ::SetEnvironmentVariableA("SLOP_MCP_PORT", argv[++i]);
        else if (std::strcmp(a, "--parent-pid") == 0 && i + 1 < argc)
            o.parent_pid = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        // accepted and ignored, this binary is always headless
    }
    return o;
}

} // namespace

int main(int argc, char** argv) {
    const options_t opts = parse_args(argc, argv);

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
    return 0;
}

