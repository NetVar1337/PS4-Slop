// src/tests/test_infra.cpp
// Tests for core/infra: cancel, published, pool, jobs, diag, text_format

#include "harness.hpp"

#include "core/infra/cancel.hpp"
#include "core/infra/published.hpp"
#include "core/infra/work_queue.hpp"
#include "core/infra/jobs.hpp"
#include "core/infra/diag.hpp"
#include "core/infra/text_format.hpp"
#include "core/infra/clock.hpp"
#include "core/infra/limits.hpp"
#include "core/infra/capability.hpp"
#include "core/infra/deferred.hpp"
#include "core/infra/mcp_onboard.hpp"
#include "core/infra/paths.hpp"
#include "core/infra/settings.hpp"
#include "core/util/fs_tools.hpp"

#include <windows.h>

#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <future>
#include <sstream>
#include <string>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

// === cancel ===

TEST_CASE(cancel_token_default_not_cancelled) {
    slop::core::infra::cancel_token_t tok;
    REQUIRE(!tok.cancelled());
}

TEST_CASE(cancel_source_request) {
    slop::core::infra::cancel_source_t src;
    auto tok = src.token();
    REQUIRE(!tok.cancelled());
    src.request();
    REQUIRE(tok.cancelled());
    REQUIRE(src.requested());
}

TEST_CASE(cancel_multiple_tokens_share_flag) {
    slop::core::infra::cancel_source_t src;
    auto t1 = src.token();
    auto t2 = src.token();
    src.request();
    REQUIRE(t1.cancelled());
    REQUIRE(t2.cancelled());
}

// === published ===

TEST_CASE(published_default_non_null) {
    slop::core::infra::published_t<int> pub;
    auto val = pub.get();
    REQUIRE(val != nullptr);
    REQUIRE_EQ(*val, 0);
}

TEST_CASE(published_publish_updates_value) {
    slop::core::infra::published_t<int> pub;
    pub.publish(std::make_shared<const int>(42));
    REQUIRE_EQ(*pub.get(), 42);
    REQUIRE_EQ(pub.revision(), 1u);
}

TEST_CASE(published_revision_increments) {
    slop::core::infra::published_t<int> pub;
    pub.publish(std::make_shared<const int>(1));
    pub.publish(std::make_shared<const int>(2));
    pub.publish(std::make_shared<const int>(3));
    REQUIRE_EQ(pub.revision(), 3u);
    REQUIRE_EQ(*pub.get(), 3);
}

// === capability ===

TEST_CASE(command_state_ok) {
    auto cs = slop::core::infra::command_state_t::ok();
    REQUIRE(cs.enabled);
    REQUIRE(cs.disabled_reason == nullptr);
    REQUIRE(static_cast<bool>(cs));
}

TEST_CASE(command_state_no) {
    auto cs = slop::core::infra::command_state_t::no("not attached");
    REQUIRE(!cs.enabled);
    REQUIRE_STR_EQ(cs.disabled_reason, "not attached");
    REQUIRE(!static_cast<bool>(cs));
}

// === text_format ===

TEST_CASE(format_hex_basic) {
    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
    auto s = slop::core::infra::fmt::format_hex(data);
    REQUIRE_STR_EQ(s, "DE AD BE EF");
}

TEST_CASE(format_as_c_array) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    auto s = slop::core::infra::fmt::format_as(data, slop::core::infra::fmt::copy_dialect_t::c_array);
    REQUIRE_STR_EQ(s, "{ 0x01, 0x02, 0x03 }");
}

TEST_CASE(format_as_python_bytes) {
    std::vector<uint8_t> data = {0xCA, 0xFE};
    auto s = slop::core::infra::fmt::format_as(data, slop::core::infra::fmt::copy_dialect_t::python_bytes);
    REQUIRE_STR_EQ(s, "b'\\xCA\\xFE'");
}

TEST_CASE(format_as_rust_array) {
    std::vector<uint8_t> data = {0xAA, 0xBB};
    auto s = slop::core::infra::fmt::format_as(data, slop::core::infra::fmt::copy_dialect_t::rust_array);
    REQUIRE_STR_EQ(s, "[0xAA, 0xBB]");
}

TEST_CASE(parse_hex_spaced) {
    std::vector<uint8_t> out;
    std::string err;
    REQUIRE(slop::core::infra::fmt::parse_hex("DE AD BE EF", out, err));
    REQUIRE_EQ(out.size(), 4u);
    REQUIRE_EQ(out[0], 0xDE);
    REQUIRE_EQ(out[3], 0xEF);
}

TEST_CASE(parse_hex_compact) {
    std::vector<uint8_t> out;
    std::string err;
    REQUIRE(slop::core::infra::fmt::parse_hex("DEADBEEF", out, err));
    REQUIRE_EQ(out.size(), 4u);
}

TEST_CASE(parse_hex_0x_prefix) {
    std::vector<uint8_t> out;
    std::string err;
    REQUIRE(slop::core::infra::fmt::parse_hex("0xDE, 0xAD", out, err));
    REQUIRE_EQ(out.size(), 2u);
    REQUIRE_EQ(out[0], 0xDE);
    REQUIRE_EQ(out[1], 0xAD);
}

TEST_CASE(parse_hex_odd_digits_fails) {
    std::vector<uint8_t> out;
    std::string err;
    REQUIRE(!slop::core::infra::fmt::parse_hex("DEA", out, err));
    REQUIRE(err.find("odd") != std::string::npos);
}

TEST_CASE(parse_hex_invalid_char_fails) {
    std::vector<uint8_t> out;
    std::string err;
    REQUIRE(!slop::core::infra::fmt::parse_hex("DXAD", out, err));
    REQUIRE(err.find("invalid") != std::string::npos);
}

TEST_CASE(format_address_64bit) {
    auto s = slop::core::infra::fmt::format_address(0x7FF6ABCD1234, 8);
    REQUIRE_STR_EQ(s, "0x00007FF6ABCD1234");
}

TEST_CASE(format_address_32bit) {
    auto s = slop::core::infra::fmt::format_address(0x00401000, 4);
    REQUIRE_STR_EQ(s, "0x00401000");
}

TEST_CASE(format_bytes_units) {
    REQUIRE(slop::core::infra::fmt::format_bytes(512).find("B") != std::string::npos);
    REQUIRE(slop::core::infra::fmt::format_bytes(2048).find("KiB") != std::string::npos);
    REQUIRE(slop::core::infra::fmt::format_bytes(2u << 20).find("MiB") != std::string::npos);
    REQUIRE(slop::core::infra::fmt::format_bytes(2ull << 30).find("GiB") != std::string::npos);
}

// === diag ===

TEST_CASE(diag_log_and_snapshot) {
    slop::core::infra::diag::init();
    slop::core::infra::diag::info("test", "hello world");
    slop::core::infra::diag::warn("test", "warning msg");
    auto snap = slop::core::infra::diag::snapshot(0);
    REQUIRE_EQ(snap.entries.size(), 2u);
    REQUIRE_STR_EQ(snap.entries[0].tag, "test");
    REQUIRE_STR_EQ(snap.entries[0].message, "hello world");
    REQUIRE_EQ(snap.entries[0].level, slop::core::infra::diag::level_t::info);
    REQUIRE_EQ(snap.entries[1].level, slop::core::infra::diag::level_t::warn);
    REQUIRE_EQ(snap.revision, 2u);
    slop::core::infra::diag::shutdown();
}

TEST_CASE(diag_snapshot_since_revision) {
    slop::core::infra::diag::init();
    slop::core::infra::diag::info("a", "one");
    slop::core::infra::diag::info("b", "two");
    slop::core::infra::diag::info("c", "three");
    auto snap = slop::core::infra::diag::snapshot(1);
    // revision 1 means "give me entries after revision 1" = entries 2 and 3
    REQUIRE_EQ(snap.entries.size(), 2u);
    REQUIRE_STR_EQ(snap.entries[0].message, "two");
    slop::core::infra::diag::shutdown();
}

// === clock ===

TEST_CASE(clock_steady_ms_positive) {
    auto ms = slop::core::infra::steady_ms();
    REQUIRE(ms > 0);
}

TEST_CASE(clock_wall_ms_reasonable) {
    auto ms = slop::core::infra::wall_ms();
    // Should be after 2020-01-01 in epoch ms
    REQUIRE(ms > 1577836800000LL);
}

// === pool ===

TEST_CASE(pool_submit_and_complete) {
    slop::core::infra::pool::start(2);
    std::atomic<int> counter{0};
    for (int i = 0; i < 100; ++i) {
        slop::core::infra::pool::submit([&] { counter.fetch_add(1); });
    }
    // Wait for completion
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    auto stats = slop::core::infra::pool::snapshot();
    REQUIRE_EQ(counter.load(), 100);
    REQUIRE(stats.completed >= 100u);
    slop::core::infra::pool::stop(1000);
}

TEST_CASE(pool_parallel_for_basic) {
    slop::core::infra::pool::start(4);
    std::vector<std::atomic<int>> results(50);
    for (auto& a : results) a.store(0);

    slop::core::infra::cancel_source_t src;
    slop::core::infra::pool::parallel_for(50, src.token(),
        [&](size_t idx, uint32_t /*slot*/) {
            results[idx].store(static_cast<int>(idx * 2));
        });

    for (size_t i = 0; i < 50; ++i) {
        REQUIRE_EQ(results[i].load(), static_cast<int>(i * 2));
    }
    slop::core::infra::pool::stop(1000);
}

TEST_CASE(pool_parallel_for_cancel) {
    slop::core::infra::pool::start(4);
    std::atomic<int> count{0};
    slop::core::infra::cancel_source_t src;

    // Cancel after a short delay
    std::thread canceller([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        src.request();
    });

    slop::core::infra::pool::parallel_for(1000000, src.token(),
        [&](size_t /*idx*/, uint32_t /*slot*/) {
            count.fetch_add(1);
            std::this_thread::sleep_for(std::chrono::microseconds(1));
        });

    canceller.join();
    // Should have been cancelled before completing all 1M items
    REQUIRE(count.load() < 1000000);
    slop::core::infra::pool::stop(1000);
}

// === jobs ===

TEST_CASE(jobs_submit_and_complete) {
    slop::core::infra::pool::start(2);
    std::atomic<bool> ran{false};

    auto id = slop::core::infra::jobs::submit({
        .label = "test job",
        .owner = "test",
        .body = [&](slop::core::infra::job_context_t& ctx) {
            (void)ctx;
            ran.store(true);
        }
    });
    REQUIRE(id != 0);

    // Wait for it to finish
    for (int i = 0; i < 100 && slop::core::infra::jobs::alive(id); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    REQUIRE(!slop::core::infra::jobs::alive(id));
    REQUIRE(ran.load());

    slop::core::infra::jobs::reap();
    auto snap = slop::core::infra::jobs::snapshot();
    REQUIRE(snap != nullptr);
    REQUIRE(!snap->empty());
    REQUIRE_EQ((*snap)[0].state, slop::core::infra::job_state_t::succeeded);

    slop::core::infra::jobs::shutdown(1000);
    slop::core::infra::pool::stop(1000);
}

TEST_CASE(jobs_cancel) {
    slop::core::infra::jobs::reset();
    slop::core::infra::pool::start(2);

    auto id = slop::core::infra::jobs::submit({
        .label = "cancellable",
        .owner = "test",
        .cancellable = true,
        .body = [](slop::core::infra::job_context_t& ctx) {
            while (!ctx.cancelled()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        }
    });
    REQUIRE(id != 0);

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    REQUIRE(slop::core::infra::jobs::cancel(id));

    for (int i = 0; i < 100 && slop::core::infra::jobs::alive(id); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    REQUIRE(!slop::core::infra::jobs::alive(id));

    slop::core::infra::jobs::reap();
    auto snap = slop::core::infra::jobs::snapshot();
    bool found_cancelled = false;
    for (auto& j : *snap) {
        if (j.id == id && j.state == slop::core::infra::job_state_t::cancelled)
            found_cancelled = true;
    }
    REQUIRE(found_cancelled);

    slop::core::infra::jobs::shutdown(1000);
    slop::core::infra::pool::stop(1000);
}

TEST_CASE(jobs_progress_reporting) {
    slop::core::infra::jobs::reset();
    slop::core::infra::pool::start(2);

    auto id = slop::core::infra::jobs::submit({
        .label = "progress test",
        .owner = "test",
        .body = [](slop::core::infra::job_context_t& ctx) {
            ctx.set_stage("step 1");
            ctx.set_progress(0.5f);
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            ctx.set_stage("step 2");
            ctx.set_progress(1.0f);
        }
    });

    for (int i = 0; i < 100 && slop::core::infra::jobs::alive(id); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    slop::core::infra::jobs::reap();
    auto snap = slop::core::infra::jobs::snapshot();
    bool found = false;
    for (auto& j : *snap) {
        if (j.id == id) {
            found = true;
            REQUIRE_EQ(j.state, slop::core::infra::job_state_t::succeeded);
        }
    }
    REQUIRE(found);

    slop::core::infra::jobs::shutdown(1000);
    slop::core::infra::pool::stop(1000);
}

// === settings / atomic writes / onboarding (never the real profile) ===

namespace {

namespace fs = std::filesystem;
using njson = nlohmann::json;

// unique scratch dir under %TEMP%, removed on scope exit
struct scratch_dir_t {
    fs::path dir;
    scratch_dir_t() {
        dir = fs::temp_directory_path() /
              ("slop_infra_" + std::to_string(::GetCurrentProcessId()) + "_" +
               std::to_string(slop::core::infra::steady_ms()) + "_" +
               std::to_string(reinterpret_cast<uintptr_t>(this) & 0xFFFF));
        fs::create_directories(dir);
    }
    ~scratch_dir_t() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
    std::string str(const char* leaf = nullptr) const {
        return leaf ? (dir / leaf).string() : dir.string();
    }
};

std::string slurp(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

void spit(const fs::path& p, const std::string& text) {
    fs::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f << text;
}

// points USERPROFILE / APPDATA at a scratch dir for the onboarder, restores on exit
struct env_sandbox_t {
    std::string old_profile, old_appdata;
    bool had_profile = false, had_appdata = false;
    explicit env_sandbox_t(const std::string& root) {
        char buf[32768];
        DWORD n = ::GetEnvironmentVariableA("USERPROFILE", buf, sizeof(buf));
        had_profile = n > 0 && n < sizeof(buf);
        if (had_profile) old_profile.assign(buf, n);
        n = ::GetEnvironmentVariableA("APPDATA", buf, sizeof(buf));
        had_appdata = n > 0 && n < sizeof(buf);
        if (had_appdata) old_appdata.assign(buf, n);
        ::SetEnvironmentVariableA("USERPROFILE", (root + "\\profile").c_str());
        ::SetEnvironmentVariableA("APPDATA", (root + "\\appdata").c_str());
    }
    ~env_sandbox_t() {
        ::SetEnvironmentVariableA("USERPROFILE", had_profile ? old_profile.c_str() : nullptr);
        ::SetEnvironmentVariableA("APPDATA", had_appdata ? old_appdata.c_str() : nullptr);
    }
};

} // namespace

TEST_CASE(infra_atomic_write_replaces_existing) {
    namespace paths = slop::core::infra::paths;
    scratch_dir_t tmp;
    const std::string file = tmp.str("sub\\cfg.json");
    REQUIRE(paths::write_file_atomic(file, "first"));
    REQUIRE_STR_EQ(slurp(file).c_str(), "first");
    REQUIRE(paths::write_file_atomic(file, "second, longer"));
    REQUIRE_STR_EQ(slurp(file).c_str(), "second, longer");
    REQUIRE(!fs::exists(file + ".tmp"));
    // a destination that cannot be replaced (a directory) leaves it untouched
    fs::create_directories(tmp.dir / "isdir");
    REQUIRE(!paths::write_file_atomic(tmp.str("isdir"), "x"));
    REQUIRE(fs::is_directory(tmp.dir / "isdir"));
}

TEST_CASE(infra_settings_first_run_generates_token_and_persists) {
    namespace settings = slop::core::infra::settings;
    scratch_dir_t tmp;
    settings::set_file_for_testing(tmp.str("settings.json"));
    settings::load();
    const std::string tok = settings::mcp_token();
    REQUIRE_EQ(tok.size(), 64u);
    REQUIRE(tok.find_first_not_of("0123456789abcdef") == std::string::npos);
    // persisted right away, not only at shutdown
    const njson disk = njson::parse(slurp(tmp.dir / "settings.json"));
    REQUIRE_STR_EQ(disk.at("mcp_token").get<std::string>().c_str(), tok.c_str());
    // a reload keeps the same token
    settings::load();
    REQUIRE_STR_EQ(settings::mcp_token().c_str(), tok.c_str());
    REQUIRE_NE(settings::generate_token(), tok);
    settings::set_file_for_testing({});
}

TEST_CASE(infra_settings_typed_accessors_and_immediate_save) {
    namespace settings = slop::core::infra::settings;
    scratch_dir_t tmp;
    settings::set_file_for_testing(tmp.str("settings.json"));
    settings::load();
    REQUIRE(!settings::get<bool>("script_unsafe", false));
    REQUIRE(settings::set("script_unsafe", true));
    REQUIRE(settings::get<bool>("script_unsafe", false));
    REQUIRE(settings::set("web_allowlist", njson::array({"example.com"})));
    const auto list = settings::get<std::vector<std::string>>("web_allowlist", {});
    REQUIRE_EQ(list.size(), 1u);
    // type mismatch falls back to the default instead of throwing
    REQUIRE_EQ(settings::get<int>("web_allowlist", 7), 7);
    REQUIRE(njson::parse(slurp(tmp.dir / "settings.json")).at("script_unsafe").get<bool>());
    // null erases
    REQUIRE(settings::set("script_unsafe", nullptr));
    REQUIRE(settings::get_json("script_unsafe").is_null());
    // out of range ports never truncate
    settings::set("mcp_port", 70000);
    REQUIRE_EQ(settings::mcp_port(), 8765);
    settings::set("mcp_port", 9001);
    REQUIRE_EQ(settings::mcp_port(), 9001);
    settings::set_file_for_testing({});
}

TEST_CASE(infra_settings_corrupt_or_non_object_file_is_backed_up) {
    namespace settings = slop::core::infra::settings;
    scratch_dir_t tmp;
    const fs::path file = tmp.dir / "settings.json";
    spit(file, "[1, 2, 3]");
    settings::set_file_for_testing(file.string());
    settings::load();
    REQUIRE(settings::snapshot().is_object());
    REQUIRE_EQ(settings::mcp_token().size(), 64u);
    bool backup = false;
    for (const auto& e : fs::directory_iterator(tmp.dir))
        if (e.path().filename().string().rfind("settings.json.corrupt-", 0) == 0) {
            backup = true;
            REQUIRE_STR_EQ(slurp(e.path()).c_str(), "[1, 2, 3]");
        }
    REQUIRE(backup);
    spit(file, "{not json");
    settings::load();
    REQUIRE(settings::snapshot().is_object());
    settings::set_file_for_testing({});
}

TEST_CASE(infra_onboard_survives_non_object_mcp_and_refreshes_stale_entries) {
    namespace onboard = slop::core::infra::mcp_onboard;
    scratch_dir_t tmp;
    env_sandbox_t env(tmp.str());
    const fs::path vscode = tmp.dir / "appdata" / "Code" / "User" / "settings.json";
    const fs::path cursor = tmp.dir / "profile" / ".cursor" / "mcp.json";
    spit(vscode, R"({"mcp": true, "editor.fontSize": 14})");
    spit(cursor, R"({"mcpServers":{"slopstation":{"url":"http://127.0.0.1:1111/mcp","env":{"K":"V"}},"other":{"url":"x"}}})");

    const auto results = onboard::install_all(8765, "tok-new");
    bool vscode_err = false;
    for (const auto& r : results)
        if (r.client == "VS Code") vscode_err = !r.error.empty() && !r.installed;
    REQUIRE(vscode_err);
    // the user's non-object value is left exactly as it was
    REQUIRE(njson::parse(slurp(vscode)).at("mcp") == true);

    // stale port/token rewritten in place, user keys and other servers kept
    const njson c = njson::parse(slurp(cursor));
    const njson& ours = c.at("mcpServers").at("slopstation");
    REQUIRE_STR_EQ(ours.at("url").get<std::string>().c_str(), "http://127.0.0.1:8765/mcp");
    REQUIRE_STR_EQ(ours.at("headers").at("Authorization").get<std::string>().c_str(),
                   "Bearer tok-new");
    REQUIRE(ours.at("env").at("K") == "V");
    REQUIRE(c.at("mcpServers").contains("other"));

    // refresh never creates entries for clients we never registered with
    const fs::path windsurf = tmp.dir / "profile" / ".codeium" / "windsurf" / "mcp_config.json";
    REQUIRE(fs::exists(windsurf));   // install_all registered it
    fs::remove(windsurf);
    onboard::refresh_existing(9000, "tok-2");
    REQUIRE(!fs::exists(windsurf));
    REQUIRE_STR_EQ(njson::parse(slurp(cursor)).at("mcpServers").at("slopstation")
                       .at("url").get<std::string>().c_str(),
                   "http://127.0.0.1:9000/mcp");
}

// === concurrency regressions ===

TEST_CASE(infra_jobs_reap_never_joins_under_the_registry_lock) {
    namespace jobs = slop::core::infra::jobs;
    jobs::reset();
    std::atomic<uint64_t> my_id{0};
    std::atomic<bool> body_done{false};
    const uint64_t id = jobs::submit({
        .label = "fails then keeps calling into jobs",
        .owner = "test",
        .body = [&](slop::core::infra::job_context_t& ctx) {
            ctx.fail("early failure");
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            (void)jobs::alive(my_id.load());   // takes the registry lock
            body_done = true;
        }});
    REQUIRE_NE(id, 0u);
    my_id = id;
    auto fut = std::async(std::launch::async, [&] {
        for (int i = 0; i < 200 && !body_done.load(); ++i) {
            jobs::reap();
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        jobs::reap();
    });
    REQUIRE(fut.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
    REQUIRE(body_done.load());
    jobs::shutdown(1000);
}

TEST_CASE(infra_jobs_shutdown_deadline_bounds_the_whole_sweep) {
    namespace jobs = slop::core::infra::jobs;
    jobs::reset();
    for (int i = 0; i < 3; ++i)
        jobs::submit({.label = "ignores cancel", .owner = "test",
                      .body = [](slop::core::infra::job_context_t&) {
                          std::this_thread::sleep_for(std::chrono::milliseconds(1500));
                      }});
    const int64_t t0 = slop::core::infra::steady_ms();
    jobs::shutdown(200);
    REQUIRE_LT(slop::core::infra::steady_ms() - t0, 1000);
    jobs::reset();
}

TEST_CASE(infra_pool_stop_is_bounded_and_drops_queued_work) {
    namespace pool = slop::core::infra::pool;
    pool::start(1);
    std::atomic<int> ran{0};
    pool::submit([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        ran.fetch_add(1);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    pool::submit([&] { ran.fetch_add(100); });   // queued behind the busy worker
    const int64_t t0 = slop::core::infra::steady_ms();
    pool::stop(200);
    REQUIRE_LT(slop::core::infra::steady_ms() - t0, 1000);
    // a fresh pool works while the straggler finishes on its own
    pool::start(2);
    std::atomic<int> fresh{0};
    for (int i = 0; i < 8; ++i) pool::submit([&] { fresh.fetch_add(1); });
    for (int i = 0; i < 200 && fresh.load() < 8; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    REQUIRE_EQ(fresh.load(), 8);
    std::this_thread::sleep_for(std::chrono::milliseconds(1700));
    REQUIRE_EQ(ran.load(), 1);   // the queued task was dropped at stop
    pool::stop(1000);
}

TEST_CASE(infra_deferred_executor_runs_outside_the_lock) {
    auto& dm = slop::core::infra::deferred_manager_t::get();
    dm.clear();
    static bool bound = false;
    if (!bound) {
        bound = dm.bind_executor("test_reentrant", [](const std::string& params, std::string* out) {
            // re-entering the manager from an executor used to deadlock
            auto& m = slop::core::infra::deferred_manager_t::get();
            *out = std::to_string(m.list().size()) + ":" + params;
            m.submit("never_bound", "{}");
            return true;
        });
    }
    const uint64_t id = dm.submit("test_reentrant", "p");
    auto fut = std::async(std::launch::async, [&] { return dm.execute_pending("test_reentrant"); });
    REQUIRE(fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    REQUIRE_EQ(fut.get(), 1u);
    const auto a = dm.get(id);
    REQUIRE(a.has_value());
    REQUIRE_STR_EQ(a->status.c_str(), "done");
    REQUIRE_STR_EQ(a->result_json.c_str(), "1:p");
    dm.clear();
}

// === fs tools ===

TEST_CASE(infra_fs_read_file_pages_and_reports_size) {
    namespace util = slop::core::util;
    scratch_dir_t tmp;
    const std::string file = tmp.str("data.bin");
    spit(file, "0123456789");
    std::vector<uint8_t> out;
    uint64_t total = 0;
    REQUIRE(util::read_file(file, 4, &out, 3, &total));
    REQUIRE_EQ(total, 10u);
    REQUIRE_EQ(std::string(out.begin(), out.end()), std::string("456"));
    REQUIRE(util::read_file(file, 10, &out, 3, &total));
    REQUIRE(out.empty());
    REQUIRE(!util::read_file(tmp.str("missing.bin"), 0, &out, 3, &total));
}

TEST_CASE(infra_fs_walks_skip_junctions_and_honor_cancel) {
    namespace util = slop::core::util;
    scratch_dir_t tmp;
    spit(tmp.dir / "real" / "needle_file.txt", "has needle inside\n");
    // a junction back to the root would loop (and double every hit) if followed
    const std::string cmd = "cmd /c mklink /J \"" + tmp.str("real\\loop") + "\" \"" +
                            tmp.str() + "\" >NUL 2>&1";
    const bool junction = std::system(cmd.c_str()) == 0 && fs::exists(tmp.dir / "real" / "loop");
    const auto found = util::search_files(tmp.str(), "needle_file", 100);
    REQUIRE_EQ(found.size(), 1u);
    const auto hits = util::grep_in_files(tmp.str(), "needle", ".txt", 100);
    REQUIRE_EQ(hits.size(), 1u);
    if (junction) {
        bool flagged = false;
        for (const auto& e : util::list_directory(tmp.str("real")))
            if (e.name == "loop") flagged = e.reparse;
        REQUIRE(flagged);
        ::RemoveDirectoryW((tmp.dir / "real" / "loop").wstring().c_str());
    }
    slop::core::infra::cancel_source_t src;
    src.request();
    REQUIRE(util::search_files(tmp.str(), "needle_file", 100, src.token()).empty());
    REQUIRE(util::grep_in_files(tmp.str(), "needle", "", 100, src.token()).empty());
}

TEST_CASE(infra_format_hex_packed) {
    const uint8_t b[] = {0xDE, 0xAD, 0x00, 0x0F};
    REQUIRE_STR_EQ(slop::core::infra::fmt::format_hex_packed(b).c_str(), "dead000f");
    REQUIRE_STR_EQ(slop::core::infra::fmt::format_hex_packed(b, true).c_str(), "DEAD000F");
}
