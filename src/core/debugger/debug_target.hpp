#pragma once

// src/core/debugger/debug_target.hpp
// The small surface the composite debugger flows (run-until, find-writer,
// call tracing, step tracing) need, implemented by the PS4 console debugger
// (ps4debug-NG over the wire) and by the local Win32 debugger. Semantics
// follow the console: a stop event freezes the debuggee until resume() or
// step(); breakpoints are software, watchpoints are the DR0-DR3 slots.

#include <cstddef>
#include <cstdint>
#include <string>

#include "core/runtime/backend.hpp"

namespace slop::core::debugger {

// watchpoint types (same values as ps4::kWp*)
constexpr uint32_t kWatchExec      = 0;
constexpr uint32_t kWatchWrite     = 1;
constexpr uint32_t kWatchReadWrite = 3;

struct stop_event_t {
    uint32_t    tid = 0;            // lwpid on the console, thread id locally
    int         signal = 0;         // 5 (SIGTRAP) for breakpoint/step/watch stops
    uint64_t    status = 0;         // raw wait4 status (PS4) / exception code (local)
    std::string reason;             // breakpoint | single_step | watchpoint | exception | signal | exit
    std::string thread;             // thread name when known
    runtime::thread_context_t ctx{};
    uint64_t    dr[16]{};           // debug registers at the stop when known (dr[6] = DR6)
};

class debug_target_t {
public:
    virtual ~debug_target_t() = default;

    virtual const char* kind() const noexcept = 0;   // "ps4" | "user"
    virtual bool attached() const = 0;

    // true while a stop event is holding the debuggee (run_until/trace_* must
    // only resume() from this state; a running target needs no resume)
    virtual bool stopped() const = 0;

    // arm a software breakpoint at addr; reuses the slot already armed there
    // (reused = true) so callers know whether they own the slot
    virtual runtime::io_result_t bp_arm(uint64_t addr, uint32_t& index, bool& reused) = 0;
    virtual runtime::io_result_t bp_disarm(uint64_t addr) = 0;
    // arm a hardware watchpoint (len 1/2/4/8, type kWatch*)
    virtual runtime::io_result_t wp_arm(uint64_t addr, uint32_t len, uint32_t type,
                                        uint32_t& index, bool& reused) = 0;
    virtual runtime::io_result_t wp_disarm(uint64_t addr) = 0;

    // let the stopped debuggee run / single-step one thread (0 = the thread
    // of the last stop)
    virtual runtime::io_result_t resume() = 0;
    virtual runtime::io_result_t step(uint32_t tid) = 0;

    // next stop event, false on timeout
    virtual bool wait_event(stop_event_t& out, int timeout_ms) = 0;

    // debuggee memory as the program sees it (software breakpoints hidden)
    virtual bool read(uint64_t addr, void* dst, size_t len) = 0;
};

} // namespace slop::core::debugger
