#pragma once

// src/core/debugger/ps4_debug_target.hpp
// debug_target_t over the ps4debug-NG console debugger

#include <memory>

#include "core/debugger/debug_target.hpp"
#include "core/runtime/backend_ps4.hpp"
#include "core/runtime/session.hpp"

namespace slop::core::debugger {

class ps4_debug_target_t final : public debug_target_t {
public:
    // session (optional) serves memory reads for callstacks/step bytes
    ps4_debug_target_t(runtime::backend_ps4_t& p, std::shared_ptr<runtime::session_t> s)
        : p_(p), s_(std::move(s)) {}

    const char* kind() const noexcept override { return "ps4"; }
    bool attached() const override { return p_.ps4_debug_attached(); }
    bool stopped() const noexcept override { return p_.ps4_debug_held(); }

    runtime::io_result_t bp_arm(uint64_t addr, uint32_t& index, bool& reused) override;
    runtime::io_result_t bp_disarm(uint64_t addr) override;
    runtime::io_result_t wp_arm(uint64_t addr, uint32_t len, uint32_t type,
                                uint32_t& index, bool& reused) override;
    runtime::io_result_t wp_disarm(uint64_t addr) override;
    runtime::io_result_t resume() override;
    runtime::io_result_t step(uint32_t tid) override;
    bool wait_event(stop_event_t& out, int timeout_ms) override;
    bool read(uint64_t addr, void* dst, size_t len) override;

    // the console event as a generic stop
    static stop_event_t from_ps4(const runtime::ps4_event_t& e);

private:
    runtime::backend_ps4_t& p_;
    std::shared_ptr<runtime::session_t> s_;
};

} // namespace slop::core::debugger
