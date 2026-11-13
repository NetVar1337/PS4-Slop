#pragma once

// src/tests/harness.hpp
// Minimal test harness, no external deps. Reports pass/fail per test case.
//
// Selection (environment):
//   SLOP_TEST_AREA    comma-separated areas; a test's area is its source file
//                     name minus "test_" and the extension (test_network.cpp ->
//                     "network"). CTest registers one entry per area.
//   SLOP_TEST_FILTER  substring of the test case name.
//   SLOP_TEST_EXCLUDE comma-separated substrings to skip (used by the ASan
//                     lane to run the mcp area without the Unicorn cases).
// Watchdog:
//   every test runs under a deadline (TEST_CASE: SLOP_TEST_TIMEOUT_SEC, default
//   300 s; TEST_CASE_TIMEOUT(name, seconds) overrides it per test). A test that
//   overruns is reported as [TIMEOUT] and the process exits with code 124, so a
//   hung socket or deadlock fails the run instead of wedging it. ASan builds
//   scale every deadline by 4.

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <functional>
#include <stdexcept>

namespace slop_test {

struct test_case_t {
    const char* name;
    std::function<void()> fn;
    std::string area;
    unsigned timeout_sec = 0;   // 0: SLOP_TEST_TIMEOUT_SEC / default
};

inline std::vector<test_case_t>& registry() {
    static std::vector<test_case_t> r;
    return r;
}

inline int g_failures = 0;
inline int g_assertions = 0;
inline const char* g_current_test = nullptr;

// "C:\\src\\tests\\test_network.cpp" -> "network"
inline std::string area_of(std::string_view file) {
    const size_t slash = file.find_last_of("/\\");
    if (slash != std::string_view::npos) file.remove_prefix(slash + 1);
    if (const size_t dot = file.rfind('.'); dot != std::string_view::npos) file = file.substr(0, dot);
    if (file.substr(0, 5) == "test_") file.remove_prefix(5);
    return std::string(file);
}

struct registrar_t {
    registrar_t(const char* name, std::function<void()> fn, const char* file = "",
                unsigned timeout_sec = 0) {
        registry().push_back({name, std::move(fn), area_of(file), timeout_sec});
    }
};

#define TEST_CASE(name) \
    static void test_##name(); \
    static slop_test::registrar_t reg_##name(#name, test_##name, __FILE__); \
    static void test_##name()

// Same as TEST_CASE with an explicit watchdog deadline in seconds.
#define TEST_CASE_TIMEOUT(name, seconds) \
    static void test_##name(); \
    static slop_test::registrar_t reg_##name(#name, test_##name, __FILE__, (seconds)); \
    static void test_##name()

#define CHECK(expr) do { \
    ++slop_test::g_assertions; \
    if (!(expr)) { \
        std::printf("  FAIL: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        ++slop_test::g_failures; \
    } \
} while(0)

#define REQUIRE(expr) do { \
    ++slop_test::g_assertions; \
    if (!(expr)) { \
        std::printf("  FAIL: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        ++slop_test::g_failures; \
        throw std::runtime_error("fatal test prerequisite failed"); \
    } \
} while(0)

#define REQUIRE_EQ(a, b) do { \
    ++slop_test::g_assertions; \
    if ((a) != (b)) { \
        std::printf("  FAIL: %s:%d: %s != %s\n", __FILE__, __LINE__, #a, #b); \
        ++slop_test::g_failures; \
    } \
} while(0)

#define REQUIRE_STR_EQ(a, b) do { \
    ++slop_test::g_assertions; \
    if (std::string(a) != std::string(b)) { \
        std::printf("  FAIL: %s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, \
            std::string(a).c_str(), std::string(b).c_str()); \
        ++slop_test::g_failures; \
    } \
} while(0)

#define REQUIRE_GE(a, b) do { \
    ++slop_test::g_assertions; \
    if (!((a) >= (b))) { \
        std::printf("  FAIL: %s:%d: %s < %s\n", __FILE__, __LINE__, #a, #b); \
        ++slop_test::g_failures; \
    } \
} while(0)

#define REQUIRE_LE(a, b) do { \
    ++slop_test::g_assertions; \
    if (!((a) <= (b))) { \
        std::printf("  FAIL: %s:%d: %s > %s\n", __FILE__, __LINE__, #a, #b); \
        ++slop_test::g_failures; \
    } \
} while(0)

#define REQUIRE_LT(a, b) do { \
    ++slop_test::g_assertions; \
    if (!((a) < (b))) { \
        std::printf("  FAIL: %s:%d: %s >= %s\n", __FILE__, __LINE__, #a, #b); \
        ++slop_test::g_failures; \
    } \
} while(0)

#define REQUIRE_NE(a, b) do { \
    ++slop_test::g_assertions; \
    if (!((a) != (b))) { \
        std::printf("  FAIL: %s:%d: %s == %s\n", __FILE__, __LINE__, #a, #b); \
        ++slop_test::g_failures; \
    } \
} while(0)

#define REQUIRE_FALSE(expr) do { \
    ++slop_test::g_assertions; \
    if ((expr)) { \
        std::printf("  FAIL: %s:%d: expected false: %s\n", __FILE__, __LINE__, #expr); \
        ++slop_test::g_failures; \
    } \
} while(0)

#define REQUIRE_GT(a, b) do { \
    ++slop_test::g_assertions; \
    if (!((a) > (b))) { \
        std::printf("  FAIL: %s:%d: %s <= %s\n", __FILE__, __LINE__, #a, #b); \
        ++slop_test::g_failures; \
    } \
} while(0)

// Per-test deadline. One background thread waits on the armed deadline; on
// expiry it reports the test and terminates the process (a hung test cannot be
// cancelled safely in-process, and later tests would share its broken state).
class watchdog_t {
public:
    watchdog_t() : thread_([this] { loop(); }) {}
    ~watchdog_t() {
        {
            std::lock_guard<std::mutex> lk(mu_);
            stop_ = true;
        }
        cv_.notify_all();
        thread_.join();
    }
    watchdog_t(const watchdog_t&) = delete;
    watchdog_t& operator=(const watchdog_t&) = delete;

    void arm(const char* name, unsigned seconds) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            name_ = name;
            seconds_ = seconds;
            deadline_ = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
            armed_ = true;
        }
        cv_.notify_all();
    }
    void disarm() {
        {
            std::lock_guard<std::mutex> lk(mu_);
            armed_ = false;
        }
        cv_.notify_all();
    }

private:
    void loop() {
        std::unique_lock<std::mutex> lk(mu_);
        while (!stop_) {
            if (!armed_) {
                cv_.wait(lk);
                continue;
            }
            if (cv_.wait_until(lk, deadline_) == std::cv_status::timeout && armed_ && !stop_ &&
                std::chrono::steady_clock::now() >= deadline_) {
                std::printf("  FAIL: %s exceeded its %u s watchdog deadline\n[TIMEOUT] %s\n",
                            name_ ? name_ : "?", seconds_, name_ ? name_ : "?");
                std::fflush(stdout);
                std::_Exit(124);
            }
        }
    }

    std::mutex mu_;
    std::condition_variable cv_;
    const char* name_ = nullptr;
    unsigned seconds_ = 0;
    std::chrono::steady_clock::time_point deadline_{};
    bool armed_ = false;
    bool stop_ = false;
    std::thread thread_;   // last: starts after every member above is constructed
};

inline unsigned default_timeout_sec() {
    unsigned sec = 300;
    if (const char* v = std::getenv("SLOP_TEST_TIMEOUT_SEC"); v && *v) {
        const unsigned long parsed = std::strtoul(v, nullptr, 10);
        if (parsed > 0) sec = static_cast<unsigned>(parsed);
    }
    return sec;
}

inline bool area_selected(const std::string& area, const char* areas) {
    if (!areas || !*areas) return true;
    std::string_view list(areas);
    while (!list.empty()) {
        const size_t comma = list.find(',');
        const std::string_view item = list.substr(0, comma);
        if (item == area) return true;
        if (comma == std::string_view::npos) break;
        list.remove_prefix(comma + 1);
    }
    return false;
}

inline bool matches_list(const char* name, const char* list) {
    if (!list || !*list) return false;
    std::string_view l(list);
    size_t pos = 0;
    while (pos <= l.size()) {
        const size_t comma = l.find(',', pos);
        const size_t end = comma == std::string_view::npos ? l.size() : comma;
        if (end > pos) {
            const std::string needle(l.substr(pos, end - pos));
            if (std::strstr(name, needle.c_str()) != nullptr) return true;
        }
        if (comma == std::string_view::npos) break;
        pos = comma + 1;
    }
    return false;
}

inline int run_all() {
    int passed = 0, failed = 0, selected = 0;
    const char* filter = std::getenv("SLOP_TEST_FILTER");
    const char* exclude = std::getenv("SLOP_TEST_EXCLUDE");
    const char* areas = std::getenv("SLOP_TEST_AREA");
    const unsigned fallback_timeout = default_timeout_sec();
#if defined(SLOP_ASAN)
    constexpr unsigned timeout_scale = 4;
#else
    constexpr unsigned timeout_scale = 1;
#endif
    watchdog_t watchdog;
    for (auto& tc : registry()) {
        if (filter && *filter && std::strstr(tc.name, filter) == nullptr) continue;
        if (matches_list(tc.name, exclude)) continue;
        if (!area_selected(tc.area, areas)) continue;
        ++selected;
        g_current_test = tc.name;
        int before = g_failures;
        std::printf("[RUN ] %s\n", tc.name);
        watchdog.arm(tc.name, (tc.timeout_sec ? tc.timeout_sec : fallback_timeout) * timeout_scale);
        try {
            tc.fn();
        } catch (const std::exception& e) {
            std::printf("  FAIL: %s threw: %s\n", tc.name, e.what());
            ++g_failures;
        } catch (...) {
            std::printf("  FAIL: %s threw unknown exception\n", tc.name);
            ++g_failures;
        }
        watchdog.disarm();
        if (g_failures == before) {
            std::printf("[PASS] %s\n", tc.name);
            ++passed;
        } else {
            std::printf("[FAIL] %s\n", tc.name);
            ++failed;
        }
    }
    std::printf("\n=== %d passed, %d failed, %d assertions ===\n",
        passed, failed, g_assertions);
    if (selected == 0 && ((filter && *filter) || (areas && *areas))) {
        // a CTest area or filter that matches nothing is a registration bug,
        // never a silent pass
        std::printf("no test matched SLOP_TEST_AREA='%s' SLOP_TEST_FILTER='%s'\n",
                    areas ? areas : "", filter ? filter : "");
        return 2;
    }
    return failed > 0 ? 1 : 0;
}

} // namespace slop_test
