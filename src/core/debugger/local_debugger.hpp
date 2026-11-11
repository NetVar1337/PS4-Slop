#pragma once

// src/core/debugger/local_debugger.hpp
// Win32 debugger for the user-mode backend (the internal test lab): one
// debuggee at a time, software int3 breakpoints with transparent step-over,
// DR0-DR3 hardware watchpoints on every thread, single-step. It mirrors the
// console debugger's stop semantics (a stop freezes the process until
// resume()/step()), so the composite flows run unchanged on both.

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "core/debugger/debug_target.hpp"

namespace slop::core::debugger {

class local_debugger_t final : public debug_target_t {
public:
    local_debugger_t();
    ~local_debugger_t() override;   // detaches, the debuggee keeps running

    local_debugger_t(const local_debugger_t&) = delete;
    local_debugger_t& operator=(const local_debugger_t&) = delete;

    // DebugActiveProcess on a dedicated debug thread; returns once the
    // attach break-in has been consumed and the process runs again
    bool     attach(uint32_t pid, std::string& err);
    // remove every breakpoint/watchpoint, release a held stop, stop debugging
    void     detach();
    uint32_t pid() const noexcept;
    bool     stopped() const noexcept;   // a stop event is holding the process

    static constexpr uint32_t kMaxBreakpoints = 30;
    static constexpr uint32_t kMaxWatchpoints = 4;
    struct slot_t {
        uint32_t index = 0;
        uint64_t addr  = 0;
        uint32_t len   = 0;
        uint32_t type  = 0;
    };
    std::vector<slot_t> breakpoints() const;
    std::vector<slot_t> watchpoints() const;

    // debug_target_t
    const char* kind() const noexcept override { return "user"; }
    bool attached() const override;
    runtime::io_result_t bp_arm(uint64_t addr, uint32_t& index, bool& reused) override;
    runtime::io_result_t bp_disarm(uint64_t addr) override;
    runtime::io_result_t wp_arm(uint64_t addr, uint32_t len, uint32_t type,
                                uint32_t& index, bool& reused) override;
    runtime::io_result_t wp_disarm(uint64_t addr) override;
    runtime::io_result_t resume() override;
    runtime::io_result_t step(uint32_t tid) override;
    bool wait_event(stop_event_t& out, int timeout_ms) override;
    bool read(uint64_t addr, void* dst, size_t len) override;

private:
    struct impl_t;
    std::unique_ptr<impl_t> m_;
};

} // namespace slop::core::debugger
