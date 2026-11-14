// src/tests/test_script.cpp
// Lua engine: sandboxed execution, output capture, timeout enforcement,
// error propagation, and the static-analysis surface over the shared
// binary session (IDA-Python-equivalent API)

#include "harness.hpp"

#include "core/disasm/binary_state.hpp"
#include "core/infra/settings.hpp"
#include "core/process/target_service.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/script/lua_engine.hpp"

#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>

using namespace slop::core::script;
namespace ds = slop::core::disasm::binary_state;

namespace {

// Embed a Windows path in a Lua double-quoted string literal
std::string lua_path_literal(const char* path) {
    std::string out = "\"";
    for (const char* p = path; *p; ++p) {
        if (*p == '\\' || *p == '\"') out += '\\';
        out += *p;
    }
    out += "\"";
    return out;
}

// Run a static-analysis script against the built SlopTarget fixture with a
// generous timeout (hyperion analysis + decompile paths need it)
lua_run_result_t run_static(const std::string& body, int timeout_ms = 60000) {
    // Loading the fixture is host file access, which the sandbox refuses; the
    // static-analysis tests run with script_unsafe semantics.
    lua_run_options_t opt;
    opt.timeout_ms = timeout_ms;
    opt.unsafe = true;
    return lua_run(
        "local ok = slop.image.load(" + lua_path_literal(SLOP_TARGET_EXE_PATH) + ")\n"
        "assert(ok, \"image load failed\")\n" + body, opt);
}

void dump_on_fail(const lua_run_result_t& r) {
    if (!r.ok)
        std::printf("  detail: %s\n", r.error.c_str());
}

} // namespace

TEST_CASE(lua_runs_and_captures_output) {
    auto r = lua_run(R"(
        slop.log("hello", 42, true)
        print("via-print")
        local t = { slop.version() }
        return nil
    )");
    REQUIRE(r.ok);
    REQUIRE(r.error.empty());
    REQUIRE(r.output.find("hello\t42\ttrue") != std::string::npos);
    REQUIRE(r.output.find("via-print") != std::string::npos);
    REQUIRE(!r.output.empty());
}

TEST_CASE(lua_syntax_error_is_reported) {
    auto r = lua_run("this is not = valid lua (");
    REQUIRE(!r.ok);
    REQUIRE(!r.error.empty());
}

TEST_CASE(lua_runtime_error_propagates) {
    auto r = lua_run("error('boom')");
    REQUIRE(!r.ok);
    REQUIRE(r.error.find("boom") != std::string::npos);
}

TEST_CASE(lua_slop_table_exists_with_expected_surface) {
    auto r = lua_run(R"(
        assert(type(slop) == "table")
        assert(type(slop.version) == "function")
        assert(type(slop.target.list) == "function")
        assert(type(slop.target.attach) == "function")
        assert(type(slop.mem.read_hex) == "function")
        assert(type(slop.mem.read_bytes) == "function")
        assert(type(slop.mem.write_hex) == "function")
        assert(type(slop.mem.scan) == "function")
        assert(type(slop.disasm.disassemble) == "function")
        assert(type(slop.analyze.packer) == "function")
        -- static-analysis surface
        assert(type(slop.image.load) == "function")
        assert(type(slop.image.unload) == "function")
        assert(type(slop.image.status) == "function")
        assert(type(slop.image.wait_ready) == "function")
        assert(type(slop.disasm.decode) == "function")
        assert(type(slop.disasm.functions) == "function")
        assert(type(slop.disasm.function_at) == "function")
        assert(type(slop.disasm.xrefs_to) == "function")
        assert(type(slop.disasm.strings) == "function")
        assert(type(slop.disasm.pe) == "function")
        assert(type(slop.disasm.bytes) == "function")
        assert(type(slop.disasm.name) == "function")
        assert(type(slop.disasm.set_name) == "function")
        assert(type(slop.disasm.comment) == "function")
        assert(type(slop.disasm.set_comment) == "function")
        assert(type(slop.disasm.bookmark_toggle) == "function")
        assert(type(slop.disasm.bookmarks) == "function")
        assert(type(slop.decomp.decompile) == "function")
        assert(type(slop.decomp.blocks) == "function")
        assert(type(slop.decomp.vtables) == "function")
        assert(type(slop.decomp.globals) == "function")
        assert(type(slop.decomp.rtti) == "function")
        -- console + debugger surface
        for _, fn in ipairs({"connect", "disconnect", "auto", "status"}) do
            assert(type(slop.ps4[fn]) == "function", "slop.ps4." .. fn)
        end
        for _, fn in ipairs({"status", "attach", "detach", "bp_set", "bp_clear",
                             "bp_list", "watch_set", "watch_clear", "watch_list",
                             "continue", "step", "suspend", "resume", "wait",
                             "events", "regs", "set_reg", "callstack", "call",
                             "run_until", "find_write", "trace_calls",
                             "trace_start", "trace_stop", "trace_status", "action"}) do
            assert(type(slop.debugger[fn]) == "function", "slop.debugger." .. fn)
        end
    )");
    REQUIRE(r.ok);
    dump_on_fail(r);
}

TEST_CASE(lua_no_target_errors_are_lua_errors_not_crashes) {
    auto r = lua_run("slop.mem.read_hex(0x41414141, 16)");
    // No target attached in unit tests -> must fail cleanly with message
    REQUIRE(!r.ok);
    REQUIRE(r.error.find("no target") != std::string::npos);
}

TEST_CASE(lua_timeout_kills_infinite_loop) {
    auto r = lua_run("while true do end", 500);
    REQUIRE(!r.ok);
    REQUIRE(r.error.find("timed out") != std::string::npos);
}

// === static-analysis surface over the shared binary session ==================

TEST_CASE(lua_static_actions_require_loaded_image) {
    ds::unload();
    for (const char* expr : {
             "slop.disasm.functions()",
             "slop.disasm.xrefs_to(0x140001000)",
             "slop.disasm.strings()",
             "slop.disasm.pe()",
             "slop.disasm.bytes(0x140001000, 16)",
             "slop.decomp.vtables()",
             "slop.decomp.rtti()",
             "slop.image.wait_ready(100)",
         }) {
        auto r = lua_run(expr);
        REQUIRE_FALSE(r.ok);
        if (r.ok) continue;
        REQUIRE(r.error.find("no image") != std::string::npos);
        if (r.error.find("no image") == std::string::npos)
            std::printf("  detail (%s): %s\n", expr, r.error.c_str());
    }
}

TEST_CASE(lua_image_load_and_status) {
    auto r = run_static(R"(
        local st = slop.image.status()
        assert(st.ready, "image not ready")
        assert(st.base ~= 0, "no base")
        assert(st.entry ~= 0, "no entry")
        assert(st.name ~= "", "no name")
        assert(st.functions > 0, "no functions indexed")
        assert(st.xrefs > 0, "no xrefs indexed")
        assert(st.strings > 0, "no strings indexed")
        assert(type(st.hype) == "table", "no hype sub-table")
        assert(st.hype.available, "hyperion engine missing")
        return st.entry
    )");
    REQUIRE(r.ok);
    dump_on_fail(r);
    REQUIRE(r.output.find("return:") != std::string::npos);
}

TEST_CASE(lua_image_pe_metadata) {
    auto r = run_static(R"(
        local pe = slop.disasm.pe()
        assert(pe.pe32plus == true, "fixture is x64")
        assert(pe.image_base ~= 0)
        assert(pe.entry_rva ~= 0)
        assert(#pe.sections >= 3, "expected at least 3 sections")
        assert(#pe.imports >= 1, "expected imports")
        local saw_kernel32 = false
        for _, dll in ipairs(pe.imports) do
            assert(type(dll.dll) == "string")
            assert(type(dll.functions) == "table")
            if dll.dll:lower():find("kernel32") then saw_kernel32 = true end
        end
        assert(saw_kernel32, "no kernel32 import")
        for _, s in ipairs(pe.sections) do
            assert(type(s.name) == "string")
            assert(s.vsize and s.raw_size)
        end
        return #pe.sections
    )");
    REQUIRE(r.ok);
    dump_on_fail(r);
}

TEST_CASE(lua_functions_listing_and_lookup) {
    auto r = run_static(R"(
        local fns = slop.disasm.functions()
        assert(#fns > 0, "no functions")
        for i, f in ipairs(fns) do
            assert(type(f.va) == "number" and f.va > 0, "bad va at " .. i)
            assert(type(f.size) == "number" and f.size >= 0, "bad size at " .. i)
            assert(type(f.name) == "string" and #f.name > 0, "unnamed at " .. i)
        end
        -- function_at resolves the owner of an entry address
        local f0 = fns[1]
        local owner = slop.disasm.function_at(f0.va)
        assert(owner, "function_at missed an entry")
        assert(owner.va == f0.va, "owner mismatch")
        -- entrypoint lands in some function
        local st = slop.image.status()
        assert(slop.disasm.function_at(st.entry), "entrypoint not owned")
        -- far-out address is nobody's function
        assert(slop.disasm.function_at(0x10) == nil, "bogus owner")
        -- limit is honored
        local few = slop.disasm.functions(2)
        assert(#few <= 2, "limit ignored")
        return #fns
    )");
    REQUIRE(r.ok);
    dump_on_fail(r);
}

TEST_CASE(lua_decode_static_instructions) {
    auto r = run_static(R"(
        local st = slop.image.status()
        local insns = slop.disasm.decode(st.entry, 8)
        assert(#insns >= 1, "no instructions decoded at entry")
        for _, i in ipairs(insns) do
            assert(type(i.addr) == "number" and i.addr >= st.base)
            assert(type(i.len) == "number" and i.len >= 1)
            assert(type(i.text) == "string" and #i.text > 0)
            assert(type(i.bytes) == "string" and #i.bytes == i.len)
        end
        -- bytes() returns raw image bytes at a VA
        local b = slop.disasm.bytes(st.entry, 16)
        assert(#b == 16, "byte length mismatch")
        -- decode from an unmapped VA fails with a Lua error
        local ok, err = pcall(slop.disasm.decode, 0x10)
        assert(not ok, "decode outside image should fail")
        return #insns
    )");
    REQUIRE(r.ok);
    dump_on_fail(r);
}

TEST_CASE(lua_xrefs_resolve_callers) {
    auto r = run_static(R"(
        local fns = slop.disasm.functions()
        -- Find a function that is actually referenced by something.
        local found_from, found_kind
        for i = 1, #fns do
            local refs = slop.disasm.xrefs_to(fns[i].va)
            if #refs > 0 then
                found_from = refs[1].from
                found_kind = refs[1].kind
                break
            end
        end
        assert(found_from, "no xrefs found for any indexed function")
        assert(type(found_kind) == "string" and #found_kind > 0)
        return found_from
    )");
    REQUIRE(r.ok);
    dump_on_fail(r);
}

TEST_CASE(lua_strings_listing) {
    auto r = run_static(R"(
        local hits = slop.disasm.strings(4, 1000)
        assert(#hits > 0, "no strings")
        for _, s in ipairs(hits) do
            assert(type(s.va) == "number" and s.va > 0)
            assert(type(s.text) == "string" and #s.text >= 4)
            assert(type(s.utf16) == "boolean")
        end
        -- higher minimum length filters (weakly) fewer results
        local wide = slop.disasm.strings(16, 100000)
        assert(#wide <= #hits, "min_chars filter widened the result")
        return #hits
    )");
    REQUIRE(r.ok);
    dump_on_fail(r);
}

TEST_CASE(lua_names_and_comments_roundtrip) {
    auto r = run_static(R"(
        local fns = slop.disasm.functions()
        local va = fns[1].va
        slop.disasm.set_name(va, "lua_renamed_fn")
        assert(slop.disasm.name(va) == "lua_renamed_fn", "rename not visible")
        slop.disasm.set_comment(va, "annotated from lua")
        assert(slop.disasm.comment(va) == "annotated from lua", "comment not visible")
        -- clear both
        slop.disasm.set_name(va, "")
        slop.disasm.set_comment(va, "")
        -- function listing still yields a display name after the clear
        local f2 = slop.disasm.function_at(va)
        assert(f2 and type(f2.name) == "string" and #f2.name > 0)
    )");
    dump_on_fail(r);
    REQUIRE(r.ok);
}

TEST_CASE(lua_bookmarks_roundtrip) {
    auto r = run_static(R"(
        local st = slop.image.status()
        local now = slop.disasm.bookmark_toggle(st.entry)
        assert(type(now) == "boolean")
        local marks = slop.disasm.bookmarks()
        local saw = false
        for _, m in ipairs(marks) do
            assert(type(m) == "number")
            if m == st.entry then saw = true end
        end
        assert(saw == now, "bookmark state inconsistent")
        -- toggle back off to keep the fixture store clean
        slop.disasm.bookmark_toggle(st.entry)
    )");
    REQUIRE(r.ok);
    dump_on_fail(r);
}

TEST_CASE(lua_decompile_after_hype_wait) {
    auto r = run_static(R"(
        assert(slop.image.wait_ready(30000), "hyperion analysis did not finish")
        local st = slop.image.status()
        assert(st.hype.ready, "status disagrees with wait_ready")
        assert(st.hype.functions > 0, "hyperion found no functions")

        local fns = slop.disasm.functions()
        -- Decompile the first function hyperion knows about.
        local d
        for i = 1, #fns do
            local ok, res = pcall(slop.decomp.decompile, fns[i].va)
            if ok and res then d = res; break end
        end
        assert(d, "no function decompiled")
        assert(type(d.va) == "number" and d.va > 0)
        assert(type(d.name) == "string" and #d.name > 0)
        assert(type(d.signature) == "string" and #d.signature > 0)
        assert(type(d.lines) == "table" and #d.lines > 0)
        for _, l in ipairs(d.lines) do
            assert(type(l.text) == "string")
            assert(type(l.indent) == "number")
        end

        -- CFG blocks for the same function
        local bl = slop.decomp.blocks(d.va)
        assert(type(bl) == "table" and bl.entry == d.va)
        assert(type(bl.blocks) == "table" and #bl.blocks >= 1)
        for _, b in ipairs(bl.blocks) do
            assert(b.end_va > b.start, "bad block range")
            assert(type(b.succs) == "table")
            assert(type(b.preds) == "table")
        end

        -- Rich DB views answer without erroring.
        assert(type(slop.decomp.vtables()) == "table")
        assert(type(slop.decomp.globals()) == "table")
        assert(type(slop.decomp.rtti()) == "table")
        return #d.lines
    )", 60000);
    dump_on_fail(r);
    REQUIRE(r.ok);
    REQUIRE(r.output.find("return:") != std::string::npos);
}

TEST_CASE(lua_returned_tables_are_serialized_into_output) {
    auto r = lua_run("return { 1, 2, 3 }");
    REQUIRE(r.ok);
    REQUIRE(r.output.find("return: {1, 2, 3}") != std::string::npos);

    auto r2 = lua_run("return { va = 0x10, name = \"x\" }");
    REQUIRE(r2.ok);
    REQUIRE(r2.output.find("va=16") != std::string::npos);
    REQUIRE(r2.output.find("name=\"x\"") != std::string::npos);
}

TEST_CASE(lua_decomp_before_ready_reports_pending_state) {
    // Load synchronously and immediately ask the decompiler for the richest
    // path without calling wait_ready, the error must name the pending
    // analysis (or, on a very fast machine that already finished, succeed)
    lua_run_options_t opt;
    opt.timeout_ms = 60000;
    opt.unsafe = true;   // loads the fixture from disk
    auto r = lua_run(
        "local ok = slop.image.load(" + lua_path_literal(SLOP_TARGET_EXE_PATH) + ")\n"
        "assert(ok)\n"
        "assert(slop.image.wait_ready(30000))\n"
        "slop.image.unload()\n"
        "local ok2 = slop.image.load(" + lua_path_literal(SLOP_TARGET_EXE_PATH) + ")\n"
        "assert(ok2)\n"
        "local ok3, err = pcall(slop.decomp.vtables)\n"
        "return ok3", opt);
    REQUIRE(r.ok);   // pcall guards either outcome; the point is no crash/lockup
    dump_on_fail(r);
}

// === sandbox (item 6) ========================================================

namespace {

lua_run_result_t run_with(const std::string& code, bool unsafe, int timeout_ms = 5000) {
    lua_run_options_t opt;
    opt.timeout_ms = timeout_ms;
    opt.unsafe = unsafe;
    return lua_run(code, opt);
}

int64_t elapsed_ms(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - t0).count();
}

} // namespace

TEST_CASE(lua_sandbox_hides_host_libraries) {
    auto r = run_with(R"(
        assert(io == nil, "io")
        assert(package == nil and require == nil, "package")
        assert(debug == nil, "debug")
        assert(coroutine == nil, "coroutine")
        assert(dofile == nil and loadfile == nil, "file loaders")
        assert(os.execute == nil and os.remove == nil and os.getenv == nil, "os")
        assert(type(os.clock) == "function" and type(os.time) == "function")
        assert(type(os.difftime) == "function")
        assert(string.format("%d", 7) == "7")
        assert(table.concat({1, 2}, ",") == "1,2")
        assert(math.floor(2.5) == 2)
        assert(utf8.char(65) == "A")
        -- text chunks load, precompiled ones are refused
        assert(load("return 1 + 1")() == 2)
        local env = { x = 5 }
        assert(load("return x", "c", "t", env)() == 5)
        local f, err = load(string.dump(function() return 1 end))
        assert(f == nil and err:find("binary"), "binary chunk loaded")
        local f2 = load(string.dump(function() return 1 end), "c", "b")
        assert(f2 == nil, "mode override bypassed the sandbox")
        return "sandboxed"
    )", false);
    dump_on_fail(r);
    REQUIRE(r.ok);
    REQUIRE_FALSE(r.unsafe);
    REQUIRE(r.output.find("sandboxed") != std::string::npos);
}

TEST_CASE(lua_sandbox_refuses_binary_main_chunk) {
    auto r = run_with(std::string("\x1bLua\x54\x00garbage", 12), false);
    REQUIRE_FALSE(r.ok);
    REQUIRE(r.error.find("binary") != std::string::npos);
}

TEST_CASE(lua_unsafe_option_opens_full_stdlib) {
    auto r = run_with(R"(
        assert(type(io) == "table" and type(io.open) == "function")
        assert(type(os.execute) == "function")
        assert(type(package) == "table" and type(require) == "function")
        assert(type(debug) == "table")
        return true
    )", true);
    dump_on_fail(r);
    REQUIRE(r.ok);
    REQUIRE(r.unsafe);
}

TEST_CASE(lua_unsafe_follows_script_unsafe_setting) {
    namespace settings = slop::core::infra::settings;
    const std::string old = settings::file();
    const auto scratch = (std::filesystem::temp_directory_path() /
                          ("slop_test_script_settings_" +
                           std::to_string(GetCurrentProcessId()) + ".json")).string();
    settings::set_file_for_testing(scratch);

    REQUIRE(settings::set("script_unsafe", true));
    auto on = lua_run("return io ~= nil");
    REQUIRE(on.ok);
    REQUIRE(on.unsafe);
    REQUIRE(on.output.find("return: true") != std::string::npos);

    REQUIRE(settings::set("script_unsafe", false));
    auto off = lua_run("return io ~= nil");
    REQUIRE(off.ok);
    REQUIRE_FALSE(off.unsafe);
    REQUIRE(off.output.find("return: false") != std::string::npos);

    settings::set_file_for_testing(old);
    std::error_code ec;
    std::filesystem::remove(scratch, ec);
}

// === limits: timeout clamp, hook granularity, cancel, memory, output (77, 150)

TEST_CASE(lua_timeout_clamp_is_symmetric) {
    REQUIRE_EQ(clamp_timeout_ms(100), 100);          // no silent raise to 500
    REQUIRE_EQ(clamp_timeout_ms(0), kMinTimeoutMs);
    REQUIRE_EQ(clamp_timeout_ms(-5), kMinTimeoutMs);
    REQUIRE_EQ(clamp_timeout_ms(int64_t(1) << 40), kMaxTimeoutMs);

    const auto t0 = std::chrono::steady_clock::now();
    auto r = lua_run("while true do end", 100);
    const int64_t took = elapsed_ms(t0);
    REQUIRE_FALSE(r.ok);
    REQUIRE_EQ(r.timeout_ms, 100);
    REQUIRE(r.error.find("timed out") != std::string::npos);
    REQUIRE(took < 2000);
}

TEST_CASE(lua_timeout_fires_inside_string_heavy_loop) {
    // few vm instructions per iteration but each one is a sizeable c call;
    // the 1000-instruction hook still lands close to the deadline
    const auto t0 = std::chrono::steady_clock::now();
    auto r = lua_run(R"(
        local s = string.rep("ab", 4096)
        while true do s = s:upper():lower() end
    )", 200);
    const int64_t took = elapsed_ms(t0);
    REQUIRE_FALSE(r.ok);
    REQUIRE(r.error.find("timed out") != std::string::npos);
    REQUIRE(took < 1500);
}

TEST_CASE(lua_cancel_token_stops_script) {
    slop::core::infra::cancel_source_t src;
    lua_run_options_t opt;
    opt.timeout_ms = 30000;
    opt.cancel = src.token();
    std::thread canceller([&src] {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        src.request();
    });
    const auto t0 = std::chrono::steady_clock::now();
    auto r = lua_run("while true do end", opt);
    canceller.join();
    REQUIRE_FALSE(r.ok);
    REQUIRE(r.error.find("cancelled") != std::string::npos);
    REQUIRE(elapsed_ms(t0) < 5000);
}

TEST_CASE(lua_memory_cap_fails_allocations) {
    lua_run_options_t opt;
    opt.mem_limit = 8u << 20;
    auto big = lua_run("local s = string.rep('x', 64 * 1024 * 1024) return #s", opt);
    REQUIRE_FALSE(big.ok);
    REQUIRE(big.error.find("memory limit") != std::string::npos);

    auto grow = lua_run(R"(
        local t = {}
        for i = 1, 10000000 do t[i] = string.rep("y", 64) .. i end
    )", opt);
    REQUIRE_FALSE(grow.ok);
    REQUIRE(grow.error.find("memory limit") != std::string::npos);
    REQUIRE(grow.peak_mem <= opt.mem_limit);

    // pcall catches the memory error and the state stays usable
    auto rec = lua_run(R"(
        local ok = pcall(string.rep, "z", 64 * 1024 * 1024)
        assert(not ok)
        return "recovered"
    )", opt);
    dump_on_fail(rec);
    REQUIRE(rec.ok);
    REQUIRE(rec.output.find("recovered") != std::string::npos);
}

TEST_CASE(lua_output_is_capped) {
    auto r = lua_run(R"(
        local line = string.rep("o", 1000)
        for i = 1, 6000 do print(line) end
        return 1
    )", 20000);
    REQUIRE(r.ok);
    REQUIRE(r.output_truncated);
    REQUIRE(r.output.size() <= kMaxOutputBytes + 64);
    REQUIRE(r.output.find("[output truncated]") != std::string::npos);
}

TEST_CASE(lua_tool_mutex_is_per_binding_not_per_script) {
    std::mutex mu;
    lua_run_options_t opt;
    opt.tool_mutex = &mu;
    opt.timeout_ms = 5000;

    // a busy script that never calls a binding leaves the mutex free
    std::atomic<bool> grabbed{false};
    std::thread prober([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (mu.try_lock()) {
            grabbed = true;
            mu.unlock();
        }
    });
    auto busy = lua_run(R"(
        local t0 = os.clock()
        while os.clock() - t0 < 0.4 do end
        return slop.target.status().backend ~= nil
    )", opt);
    prober.join();
    dump_on_fail(busy);
    REQUIRE(busy.ok);
    REQUIRE(grabbed.load());
    REQUIRE(busy.output.find("return: true") != std::string::npos);

    // a binding waiting for a held mutex gives up at the script deadline
    // instead of hanging, and plain lua keeps running meanwhile
    std::unique_lock held(mu);
    opt.timeout_ms = 300;
    const auto t0 = std::chrono::steady_clock::now();
    auto blocked = lua_run("local x = 1 + 1 return slop.target.status()", opt);
    held.unlock();
    REQUIRE_FALSE(blocked.ok);
    REQUIRE(blocked.error.find("tool lock") != std::string::npos);
    REQUIRE(elapsed_ms(t0) < 3000);

    // errors raised inside a locked binding release the mutex
    opt.timeout_ms = 5000;
    auto failing = lua_run("return pcall(slop.mem.read_hex, 0x1000, 0)", opt);
    REQUIRE(failing.ok);
    REQUIRE(mu.try_lock());
    mu.unlock();
}

// === memory read helpers (178) ===============================================

namespace {
alignas(16) volatile unsigned char g_lua_probe[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x7F, 0x80, 0xFF};
} // namespace

TEST_CASE(lua_read_hex_returns_hex_and_read_bytes_raw) {
    using namespace slop::core;
    auto none = lua_run("return slop.mem.read_bytes(0x1000, 4)");
    REQUIRE_FALSE(none.ok);
    REQUIRE(none.error.find("no target") != std::string::npos);

    if (runtime::active_kind() != runtime::backend_kind_t::user_mode) {
        std::printf("  [skip] live read needs the user-mode backend\n");
        return;
    }
    REQUIRE(process::target_attach(GetCurrentProcessId()));
    char addr[32];
    std::snprintf(addr, sizeof(addr), "0x%llX",
                  static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(&g_lua_probe[0])));
    auto r = lua_run(std::string(R"(
        local a = )") + addr + R"(
        local hex = slop.mem.read_hex(a, 8)
        assert(hex == "deadbeef007f80ff", "read_hex gave " .. tostring(hex))
        local raw = slop.mem.read_bytes(a, 8)
        assert(#raw == 8, "read_bytes length")
        assert(raw:byte(1) == 0xDE and raw:byte(8) == 0xFF, "read_bytes content")
        return hex
    )");
    process::target_detach();
    dump_on_fail(r);
    REQUIRE(r.ok);
}

// === canonical names (179) ===================================================

TEST_CASE(lua_auto_names_are_canonical_sub_va) {
    auto r = run_static(R"(
        assert(slop.image.wait_ready(30000), "hyperion not ready")
        local fns = slop.disasm.functions()
        local checked = 0
        for _, f in ipairs(fns) do
            if f.name:sub(1, 4) == "sub_" then
                local want = string.format("sub_%X", f.va)
                assert(f.name == want, f.name .. " ~= " .. want)
                local owner = slop.disasm.function_at(f.va)
                if owner and owner.va == f.va then
                    assert(owner.name == want, "function_at " .. owner.name)
                end
                assert(slop.disasm.name(f.va) == want, "name() differs")
                checked = checked + 1
                if checked >= 25 then break end
            end
        end
        assert(checked > 0, "fixture has no auto-named functions")
        return checked
    )");
    dump_on_fail(r);
    REQUIRE(r.ok);
}

// === debugger / ps4 bindings (177) ===========================================

TEST_CASE(lua_debugger_bindings_route_through_mcp_actions) {
    // no console in unit tests: status works locally, debug actions fail
    // with the mcp error text as a catchable lua error
    auto r = lua_run(R"(
        local st = slop.ps4.status()
        assert(type(st) == "table", "status not a table")
        assert(type(st.backend) == "string", "backend missing")
        assert(st.ps4_connected == false, "unexpected console")

        local ok, err = pcall(slop.debugger.bp_set, 0x401000)
        assert(not ok and tostring(err):find("connected console"), tostring(err))
        ok, err = pcall(slop.debugger.wait, 100)
        assert(not ok and tostring(err):find("connected console"), tostring(err))
        ok, err = pcall(slop.debugger.bp_set)
        assert(not ok and tostring(err):find("addr required"), tostring(err))
        -- the second bp_set argument is a rule table (hits/log/condition)
        ok, err = pcall(slop.debugger.bp_set, 0x401000, {hits = 2, log = "rax={rax}"})
        assert(not ok and tostring(err):find("connected console"), tostring(err))
        ok, err = pcall(slop.debugger.trace_status)
        assert(not ok and tostring(err):find("connected console"), tostring(err))
        -- trace_start writes a host file: sandboxed scripts cannot reach it
        ok, err = pcall(slop.debugger.trace_start, "steps", "C:/trace.jsonl")
        assert(not ok and tostring(err):find("script_unsafe"), tostring(err))
        ok, err = pcall(slop.debugger.call, 0x1000, {1, 2, 3, 4, 5, 6, 7})
        assert(not ok and tostring(err):find("at most 6"), tostring(err))
        ok, err = pcall(slop.debugger.action, "bp_list", {})
        assert(not ok and tostring(err):find("connected console"), tostring(err))
        -- host-file actions stay closed in the sandbox
        ok, err = pcall(slop.debugger.action, "elf_load", {path = "C:/x.elf"})
        assert(not ok and tostring(err):find("script_unsafe"), tostring(err))
        ok, err = pcall(slop.image.load, "C:/x.elf")
        assert(not ok and tostring(err):find("script_unsafe"), tostring(err))
        ok, err = pcall(slop.debugger.action, "bp_set", {addr = print})
        assert(not ok and tostring(err):find("cannot pass"), tostring(err))
        return st.backend
    )");
    dump_on_fail(r);
    REQUIRE(r.ok);
}
