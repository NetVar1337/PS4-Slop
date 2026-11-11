#pragma once

// src/core/debugger/composite.hpp
// One-call debugger workflows over any debug_target_t (PS4 console or the
// local Win32 debugger): run until an address, find the writer of an address,
// log every call to a function, and single-step trace a thread.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "core/debugger/debug_target.hpp"

namespace slop::core::debugger {

struct frame_rec_t {
    uint64_t ret_addr  = 0;
    uint64_t frame_ptr = 0;
};

// rbp chain from a stop context; frame 0 is rip itself
std::vector<frame_rec_t> rbp_frames(debug_target_t& t, const runtime::thread_context_t& ctx,
                                    size_t depth);

// does a breakpoint stop belong to addr? (rip at the breakpoint, or one past
// the int3 on payloads that report the trap address)
bool stop_at(const stop_event_t& ev, uint64_t addr);

struct until_result_t {
    bool         ok = false;        // false = could not even arm/resume (see error)
    std::string  error;
    bool         halted = false;    // stopped at addr before the timeout
    stop_event_t ev;
    uint32_t     index = 0;         // breakpoint slot used
    bool         reused = false;    // addr was already armed (slot left armed)
    uint32_t     skipped = 0;       // other stops resumed past while waiting
};
// arm a one-shot breakpoint at addr (unless one is already there), resume,
// wait for the stop at addr (other stops are resumed past), disarm
until_result_t run_until(debug_target_t& t, uint64_t addr, int timeout_ms);

struct find_write_result_t {
    bool         ok = false;
    std::string  error;
    bool         halted = false;
    stop_event_t ev;
    uint32_t     index = 0;         // watchpoint slot used
    bool         reused = false;
    std::vector<frame_rec_t> frames;
};
// write watchpoint on [addr, addr+len), resume, wait, callstack of the writer
find_write_result_t find_write(debug_target_t& t, uint64_t addr, uint32_t len,
                               int timeout_ms, size_t depth);

struct trace_calls_result_t {
    bool         ok = false;
    std::string  error;
    std::vector<stop_event_t> hits;
    std::string  stop_reason;       // count_reached | timeout | continue_failed
    uint32_t     index = 0;
    bool         reused = false;
    uint32_t     skipped = 0;
};
// breakpoint at addr, then resume+wait count times recording every hit (the
// debuggee stays stopped at the last hit)
trace_calls_result_t trace_calls(debug_target_t& t, uint64_t addr, size_t count, int timeout_ms);

struct step_rec_t {
    uint32_t tid = 0;
    uint64_t rip = 0;
    uint8_t  bytes[16]{};
    size_t   nbytes = 0;            // bytes read at rip (0 = unreadable)
};
struct trace_steps_result_t {
    bool         ok = false;
    std::string  error;
    std::vector<step_rec_t> steps;
    std::string  stop_reason;       // count_reached | timeout | step_failed
};
// single-step tid count times recording rip and the code bytes there
trace_steps_result_t trace_steps(debug_target_t& t, uint32_t tid, size_t count, int timeout_ms);

} // namespace slop::core::debugger
