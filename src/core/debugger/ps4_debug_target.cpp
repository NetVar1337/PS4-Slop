// src/core/debugger/ps4_debug_target.cpp

#include "core/debugger/ps4_debug_target.hpp"

#include "core/runtime/ps4_protocol.hpp"

#include <cstring>

namespace slop::core::debugger {

stop_event_t ps4_debug_target_t::from_ps4(const runtime::ps4_event_t& e) {
    stop_event_t s;
    s.tid    = e.lwpid;
    s.signal = e.signal;
    s.status = e.status;
    s.thread = e.thread_name;
    s.ctx    = e.ctx;
    std::memcpy(s.dr, e.dr, sizeof(s.dr));
    switch (e.signal) {
    case 5:  s.reason = "breakpoint"; break;   // SIGTRAP: bp, step or DR trap
    case 9:  s.reason = "exit";       break;   // SIGKILL tears the session down
    default: s.reason = "signal";     break;
    }
    // DR6 bits 0-3 name the hardware slot that fired, BS (bit 14) a step
    if (e.signal == 5) {
        if (e.dr[6] & (1ull << 14)) s.reason = "single_step";
        else if (e.dr[6] & 0xF)     s.reason = "watchpoint";
    }
    return s;
}

runtime::io_result_t ps4_debug_target_t::bp_arm(uint64_t addr, uint32_t& index, bool& reused) {
    return p_.ps4_bp_arm(addr, runtime::backend_ps4_t::kAutoSlot, index, &reused);
}

runtime::io_result_t ps4_debug_target_t::bp_disarm(uint64_t addr) {
    return p_.ps4_bp_disarm_addr(addr);
}

runtime::io_result_t ps4_debug_target_t::wp_arm(uint64_t addr, uint32_t len, uint32_t type,
                                                uint32_t& index, bool& reused) {
    return p_.ps4_wp_arm(addr, len, type, runtime::backend_ps4_t::kAutoSlot, index, &reused);
}

runtime::io_result_t ps4_debug_target_t::wp_disarm(uint64_t addr) {
    return p_.ps4_wp_disarm_addr(addr);
}

runtime::io_result_t ps4_debug_target_t::resume() {
    return p_.ps4_continue(runtime::ps4::kStopResume);
}

runtime::io_result_t ps4_debug_target_t::step(uint32_t tid) {
    return p_.ps4_step(tid);
}

bool ps4_debug_target_t::wait_event(stop_event_t& out, int timeout_ms) {
    runtime::ps4_event_t e{};
    if (!p_.ps4_wait_event(e, timeout_ms)) return false;
    out = from_ps4(e);
    return true;
}

bool ps4_debug_target_t::read(uint64_t addr, void* dst, size_t len) {
    if (!s_ || !s_->valid()) return false;
    const auto io = s_->read(static_cast<uintptr_t>(addr), dst, len);
    return io.ok && io.bytes == len;
}

} // namespace slop::core::debugger
