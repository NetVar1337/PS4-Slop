// src/core/debugger/composite.cpp

#include "core/debugger/composite.hpp"

#include "core/infra/clock.hpp"
#include "core/runtime/ps4_protocol.hpp"

#include <algorithm>

namespace slop::core::debugger {

namespace {

namespace infra = slop::core::infra;

std::string io_text(const char* what, const runtime::io_result_t& io) {
    return std::string(what) + ": " + runtime::ps4::io_error_str(io.error);
}

int remaining_ms(int64_t deadline) {
    const int64_t left = deadline - infra::steady_ms();
    return left <= 0 ? 0 : static_cast<int>(left);
}

} // namespace

std::vector<frame_rec_t> rbp_frames(debug_target_t& t, const runtime::thread_context_t& ctx,
                                    size_t depth) {
    std::vector<frame_rec_t> out;
    if (depth == 0) return out;
    out.push_back({ctx.rip, ctx.rbp});
    uint64_t rbp = ctx.rbp;
    for (size_t i = 1; i < depth && rbp != 0; ++i) {
        uint64_t pair[2] = {0, 0};   // saved rbp, return address
        if (!t.read(rbp, pair, sizeof(pair))) break;
        out.push_back({pair[1], rbp});
        if (pair[0] == 0 || pair[0] <= rbp) break;   // 0 = top; the chain must ascend
        rbp = pair[0];
    }
    return out;
}

bool stop_at(const stop_event_t& ev, uint64_t addr) {
    return ev.ctx.rip == addr || ev.ctx.rip == addr + 1;
}

until_result_t run_until(debug_target_t& t, uint64_t addr, int timeout_ms) {
    until_result_t r;
    if (!t.attached()) { r.error = "no debug session"; return r; }
    auto io = t.bp_arm(addr, r.index, r.reused);
    if (!io.ok) { r.error = io_text("cannot arm breakpoint", io); return r; }
    const int64_t deadline = infra::steady_ms() + std::max(timeout_ms, 0);
    // resume only a debuggee that is actually held: a running target needs no
    // resume, and resuming after the bp stop already landed would consume the
    // very stop we are waiting for (the event would still look like a hit)
    if (t.stopped()) {
        io = t.resume();
        if (!io.ok) {
            if (!r.reused) t.bp_disarm(addr);
            r.error = io_text("resume failed", io);
            return r;
        }
    }
    r.ok = true;
    for (;;) {
        stop_event_t ev;
        if (!t.wait_event(ev, remaining_ms(deadline))) break;
        if (stop_at(ev, addr)) { r.halted = true; r.ev = ev; break; }
        if (ev.reason == "exit") { r.ev = ev; break; }
        // a stop that is not ours (another breakpoint, a step, a signal):
        // let the debuggee go on toward addr
        ++r.skipped;
        if (!t.resume().ok) break;
    }
    if (!r.reused) t.bp_disarm(addr);
    return r;
}

find_write_result_t find_write(debug_target_t& t, uint64_t addr, uint32_t len,
                               int timeout_ms, size_t depth) {
    find_write_result_t r;
    if (!t.attached()) { r.error = "no debug session"; return r; }
    if (len != 1 && len != 2 && len != 4 && len != 8) { r.error = "len must be 1, 2, 4 or 8"; return r; }
    auto io = t.wp_arm(addr, len, kWatchWrite, r.index, r.reused);
    if (!io.ok) { r.error = io_text("cannot arm watchpoint", io); return r; }
    if (t.stopped()) {
        io = t.resume();
        if (!io.ok) {
            if (!r.reused) t.wp_disarm(addr);
            r.error = io_text("resume failed", io);
            return r;
        }
    }
    r.ok = true;
    stop_event_t ev;
    if (t.wait_event(ev, std::max(timeout_ms, 0)) && ev.reason != "exit") {
        r.halted = true;
        r.ev = ev;
        r.frames = rbp_frames(t, ev.ctx, depth);
    }
    if (!r.reused) t.wp_disarm(addr);
    return r;
}

trace_calls_result_t trace_calls(debug_target_t& t, uint64_t addr, size_t count, int timeout_ms) {
    trace_calls_result_t r;
    if (!t.attached()) { r.error = "no debug session"; return r; }
    auto io = t.bp_arm(addr, r.index, r.reused);
    if (!io.ok) { r.error = io_text("cannot arm breakpoint", io); return r; }
    r.ok = true;
    r.stop_reason = "count_reached";
    // the first wait needs a resume only when the debuggee is held; after any
    // consumed stop it is held again
    bool need_resume = t.stopped();
    while (r.hits.size() < count) {
        if (need_resume && !t.resume().ok) { r.stop_reason = "continue_failed"; break; }
        need_resume = true;
        // the per-hit timeout covers foreign stops resumed past on the way
        const int64_t deadline = infra::steady_ms() + std::max(timeout_ms, 0);
        bool got = false;
        for (;;) {
            stop_event_t ev;
            if (!t.wait_event(ev, remaining_ms(deadline))) break;
            if (ev.reason == "exit") { r.stop_reason = "process_exited"; break; }
            if (stop_at(ev, addr)) { r.hits.push_back(ev); got = true; break; }
            ++r.skipped;
            if (!t.resume().ok) { r.stop_reason = "continue_failed"; break; }
        }
        if (!got) {
            if (r.stop_reason == "count_reached") r.stop_reason = "timeout";
            break;
        }
    }
    if (!r.reused) t.bp_disarm(addr);
    return r;
}

trace_steps_result_t trace_steps(debug_target_t& t, uint32_t tid, size_t count, int timeout_ms) {
    trace_steps_result_t r;
    if (!t.attached()) { r.error = "no debug session"; return r; }
    r.ok = true;
    r.stop_reason = "count_reached";
    for (size_t i = 0; i < count; ++i) {
        if (!t.step(tid).ok) { r.stop_reason = "step_failed"; break; }
        stop_event_t ev;
        if (!t.wait_event(ev, std::max(timeout_ms, 0))) { r.stop_reason = "timeout"; break; }
        if (ev.reason == "exit") { r.stop_reason = "process_exited"; break; }
        step_rec_t s;
        s.tid = ev.tid;
        s.rip = ev.ctx.rip;
        if (t.read(s.rip, s.bytes, sizeof(s.bytes))) s.nbytes = sizeof(s.bytes);
        r.steps.push_back(s);
        if (tid == 0) tid = ev.tid;   // keep stepping the thread that stopped
    }
    return r;
}

} // namespace slop::core::debugger
