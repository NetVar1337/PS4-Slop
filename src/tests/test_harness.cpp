// src/tests/test_harness.cpp
// Self-tests for harness.hpp: area naming, area selection and the per-test
// watchdog (a child slop_tests run whose only test hangs must die with 124).

#include "harness.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <string>

namespace {

struct child_result_t {
    int exit_code = -1;
    std::string output;
};

// Runs this test binary again with extra environment, capturing stdout.
child_result_t run_self(const char* filter, const char* area, const char* victim) {
    char exe[MAX_PATH] = {};
    ::GetModuleFileNameA(nullptr, exe, MAX_PATH);

    // the child inherits the environment; restore ours afterwards
    const auto set = [](const char* key, const char* value) { ::_putenv_s(key, value ? value : ""); };
    std::string old_filter, old_area;
    if (const char* v = std::getenv("SLOP_TEST_FILTER")) old_filter = v;
    if (const char* v = std::getenv("SLOP_TEST_AREA")) old_area = v;
    set("SLOP_TEST_FILTER", filter);
    set("SLOP_TEST_AREA", area);
    set("SLOP_TEST_HARNESS_VICTIM", victim);

    child_result_t r;
    // cmd /c strips one outer pair of quotes, keep the exe path quoted inside
    const std::string cmd = "\"\"" + std::string(exe) + "\" 2>&1\"";
    if (FILE* pipe = ::_popen(cmd.c_str(), "r")) {
        char buf[512];
        while (std::fgets(buf, static_cast<int>(sizeof buf), pipe)) r.output += buf;
        r.exit_code = ::_pclose(pipe);
    }

    set("SLOP_TEST_FILTER", old_filter.c_str());
    set("SLOP_TEST_AREA", old_area.c_str());
    set("SLOP_TEST_HARNESS_VICTIM", nullptr);
    return r;
}

} // namespace

// Only does something inside the child spawned below: blocks far past its
// 1 s deadline so the watchdog has to end the process.
TEST_CASE_TIMEOUT(harness_watchdog_victim, 1) {
    const char* victim = std::getenv("SLOP_TEST_HARNESS_VICTIM");
    if (!victim || std::string(victim) != "1") return;
    ::Sleep(60'000);
}

TEST_CASE(harness_area_of_strips_prefix_and_extension) {
    REQUIRE_STR_EQ(slop_test::area_of("C:\\repo\\src\\tests\\test_network.cpp"), "network");
    REQUIRE_STR_EQ(slop_test::area_of("/repo/src/tests/test_disasm_accuracy.cpp"), "disasm_accuracy");
    REQUIRE_STR_EQ(slop_test::area_of("test_harness.cpp"), "harness");
    REQUIRE_STR_EQ(slop_test::area_of("bench.cpp"), "bench");
}

TEST_CASE(harness_area_selection_is_exact_and_listable) {
    CHECK(slop_test::area_selected("network", nullptr));
    CHECK(slop_test::area_selected("network", ""));
    CHECK(slop_test::area_selected("network", "memory,network"));
    CHECK(slop_test::area_selected("disasm", "disasm"));
    CHECK(!slop_test::area_selected("disasm", "disasm_accuracy"));
    CHECK(!slop_test::area_selected("disasm_accuracy", "disasm"));
}

TEST_CASE(harness_registers_this_file_as_area_harness) {
    bool found = false;
    for (const auto& tc : slop_test::registry())
        if (std::string(tc.name) == "harness_watchdog_victim") found = tc.area == "harness" && tc.timeout_sec == 1;
    CHECK(found);
}

TEST_CASE(harness_watchdog_kills_hung_test) {
    const auto r = run_self("harness_watchdog_victim", "harness", "1");
    CHECK(r.exit_code == 124);
    CHECK(r.output.find("[TIMEOUT] harness_watchdog_victim") != std::string::npos);
}

TEST_CASE(harness_unmatched_area_fails_the_run) {
    const auto r = run_self(nullptr, "no_such_area", nullptr);
    CHECK(r.exit_code == 2);
    CHECK(r.output.find("no test matched") != std::string::npos);
}
