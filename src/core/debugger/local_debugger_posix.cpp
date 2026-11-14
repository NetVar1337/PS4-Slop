// src/core/debugger/local_debugger_posix.cpp
// The local debugger is the Win32 debug API (DebugActiveProcess, EXCEPTION
// records, DR0-DR3). Nothing here pretends to debug: attach() reports that the
// platform has no local debugger, so the composite flows stay on the console
// backends. A ptrace implementation is the natural follow-up.

#include "core/debugger/local_debugger.hpp"

namespace slop::core::debugger {

namespace {

constexpr const char* kUnsupported =
    "the local debugger is a Win32 debug-API feature; use a console backend on this platform";

runtime::io_result_t unsupported() {
    runtime::io_result_t r;
    r.error = 1;
    return r;
}

} // namespace

struct local_debugger_t::impl_t {};

local_debugger_t::local_debugger_t() : m_(std::make_unique<impl_t>()) {}
local_debugger_t::~local_debugger_t() = default;

bool local_debugger_t::attach(uint32_t, std::string& err) {
    err = kUnsupported;
    return false;
}

void local_debugger_t::detach() {}

uint32_t local_debugger_t::pid() const noexcept { return 0; }

bool local_debugger_t::stopped() const noexcept { return false; }

bool local_debugger_t::last_stop_context(uint32_t, runtime::thread_context_t&) const {
    return false;
}

std::vector<local_debugger_t::slot_t> local_debugger_t::breakpoints() const { return {}; }

std::vector<local_debugger_t::slot_t> local_debugger_t::watchpoints() const { return {}; }

bool local_debugger_t::attached() const { return false; }

runtime::io_result_t local_debugger_t::bp_arm(uint64_t, uint32_t&, bool&) {
    return unsupported();
}

runtime::io_result_t local_debugger_t::bp_disarm(uint64_t) { return unsupported(); }

runtime::io_result_t local_debugger_t::wp_arm(uint64_t, uint32_t, uint32_t, uint32_t&, bool&) {
    return unsupported();
}

runtime::io_result_t local_debugger_t::wp_disarm(uint64_t) { return unsupported(); }

runtime::io_result_t local_debugger_t::resume() { return unsupported(); }

runtime::io_result_t local_debugger_t::step(uint32_t) { return unsupported(); }

bool local_debugger_t::wait_event(stop_event_t&, int) { return false; }

bool local_debugger_t::read(uint64_t, void*, size_t) { return false; }

} // namespace slop::core::debugger
