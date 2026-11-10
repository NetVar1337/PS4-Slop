// src/tests/test_process_tables.cpp
// Tests for core/process job-based tables: process list, threads, modules,
// handles, va_to_module, and the session epoch clock

#include "harness.hpp"

#include "core/infra/jobs.hpp"
#include "core/process/handle_table.hpp"
#include "core/process/module_table.hpp"
#include "core/process/process_list.hpp"
#include "core/process/target_service.hpp"
#include "core/process/thread_table.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/session.hpp"

#include <windows.h>

#include <chrono>
#include <thread>

namespace {

bool wait_job(uint64_t id) {
    for (int i = 0; i < 500 && slop::core::infra::jobs::alive(id); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    const bool alive = slop::core::infra::jobs::alive(id);
    slop::core::infra::jobs::reap();
    return !alive;
}

} // namespace

TEST_CASE(session_epoch_uses_steady_clock) {
    slop::core::runtime::session_t s;
    REQUIRE(s.epoch_ms() == 0);
    REQUIRE(s.open(GetCurrentProcessId()));
    REQUIRE(s.epoch_ms() > 0);
    s.close();
    REQUIRE(s.epoch_ms() == 0);
}

TEST_CASE(process_list_refresh_publishes_snapshot) {
    using namespace slop::core;
    if (runtime::active_kind() != runtime::backend_kind_t::user_mode) {
        std::printf("  [skip] process list test requires user-mode backend\n");
        return;
    }
    // earlier suites may have left the job system shut down
    infra::jobs::reset();

    const uint64_t id = process::refresh_processes(true);
    REQUIRE(id != 0);
    REQUIRE(wait_job(id));

    const auto snap = process::cached_processes();
    REQUIRE(snap != nullptr);
    REQUIRE(snap->sampled_ms > 0);
    REQUIRE_FALSE(snap->items.empty());
    bool found_self = false;
    for (const auto& p : snap->items)
        if (p.pid == GetCurrentProcessId()) found_self = true;
    REQUIRE(found_self);
}

TEST_CASE(tables_refresh_against_attached_target) {
    using namespace slop::core;
    if (runtime::active_kind() != runtime::backend_kind_t::user_mode) {
        std::printf("  [skip] table test requires user-mode backend\n");
        return;
    }
    infra::jobs::reset();
    REQUIRE(process::target_attach(GetCurrentProcessId()));

    const uint64_t jm = process::refresh_modules();
    const uint64_t jt = process::refresh_threads();
    const uint64_t jh = process::refresh_handles();
    REQUIRE(jm != 0);
    REQUIRE(jt != 0);
    REQUIRE(jh != 0);
    REQUIRE(wait_job(jm));
    REQUIRE(wait_job(jt));
    REQUIRE(wait_job(jh));

    const auto mods = process::cached_modules();
    REQUIRE(mods != nullptr);
    REQUIRE_FALSE(mods->items.empty());
    REQUIRE(mods->sampled_ms > 0);

    const auto thrs = process::cached_threads();
    REQUIRE(thrs != nullptr);
    REQUIRE_FALSE(thrs->items.empty());

    const auto hnds = process::cached_handles();
    REQUIRE(hnds != nullptr);
    REQUIRE(hnds->sampled_ms > 0);

    // va_to_module resolves module bases and middles, rejects holes
    const auto& m0 = mods->items.front();
    const auto* hit = process::va_to_module(m0.base);
    REQUIRE(hit != nullptr);
    REQUIRE_EQ(hit->base, m0.base);
    REQUIRE(process::va_to_module(m0.base + m0.size / 2) != nullptr);
    REQUIRE(process::va_to_module(0x1) == nullptr);

    process::target_detach();

    // without a target the refreshes are rejected
    REQUIRE(process::refresh_threads() == 0);
    REQUIRE(process::refresh_modules() == 0);
    REQUIRE(process::refresh_handles() == 0);
}
