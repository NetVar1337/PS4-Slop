#pragma once

// src/core/infra/lifecycle.hpp
// the boot and shutdown state machine, any shell can drive it

#include <cstdint>
#include <string>

namespace slop::core::infra::lifecycle {

enum class stage_t : int {
    runtime_pool = 0,
    process_services,
    settings,
    mcp_server,
    // not interface because windows.h defines it as a macro and it wrecks the enum
    frontend,
    done,
};

inline constexpr int kStageCount = static_cast<int>(stage_t::done);

// label for the splash
const char* stage_label(stage_t s) noexcept;

// ok, run or wait for a row
const char* stage_status(stage_t row) noexcept;

struct config_t {
    // register the mcp endpoint into ai clients on first run
    bool mcp_onboarding = true;
};

struct boot_result_t {
    bool        mcp_ok           = false;
    uint16_t    mcp_port         = 0;
    bool        first_run        = false;   // no prior settings on disk
};

// starts the sequence
void begin(config_t cfg);

// call once per loop, done means booted
stage_t advance();

stage_t stage() noexcept;
bool    booted() noexcept;

// copy by value, another thread writes these
boot_result_t result();

// the per loop tick, heartbeat, job reaping, watchlist, change events
void tick();

// teardown in the old order, safe to call twice
void shutdown();

// endpoint advertisement
// the running instance writes pid, port, its image path and the DPAPI (current
// user) protected token to engine.json so a front end / second engine can find it

struct endpoint_t {
    uint32_t    pid  = 0;
    uint16_t    port = 0;
    std::string token;   // decrypted; empty when the blob is missing or not ours
};

const std::string& endpoint_path();

// false when the file is missing, the pid is dead or now runs another image
bool read_endpoint(endpoint_t& out);

// rewrites engine.json with the current port and settings token (token rotation)
void refresh_endpoint();

} // namespace slop::core::infra::lifecycle
