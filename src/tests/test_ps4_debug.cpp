// src/tests/test_ps4_debug.cpp
// PS4 (ps4debug-NG) tests against the fake payload in ps4_fixture.hpp:
// debug control and events, remote calls, MCP debugger flows and power actions, native scan, console-side tooling.

#include "ps4_fixture.hpp"

TEST_CASE(ps4_debug_control_and_events) {
    server_guard_t g;
    backend_ps4_t b;
    std::string err;
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));

    // explicit debug attach (starts the 755 listener, connects the fake back)
    REQUIRE(b.ps4_debug_attach(kFakePid, err));
    std::fprintf(stderr, "after attach: att=%d pid=%u", (int)b.ps4_debug_attached(), b.ps4_debug_pid());
    if (!err.empty()) std::printf("  attach err: %s\n", err.c_str());
    CHECK(b.ps4_debug_attached());
    CHECK(b.ps4_debug_pid() == kFakePid);

    // software breakpoint + hardware watchpoint land on the fake console
    auto io = b.ps4_set_breakpoint(0, true, 0x400500);
    REQUIRE(io.ok);
    CHECK(g.srv.bps[0].enabled);
    CHECK(g.srv.bps[0].address == 0x400500);
    io = b.ps4_set_watchpoint(1, true, 8, ps4::kWpRdWr, 0x7FFF00001000);
    REQUIRE(io.ok);
    CHECK(g.srv.wps[1].enabled);
    CHECK(g.srv.wps[1].length == 8);
    CHECK(g.srv.wps[1].breaktype == ps4::kWpRdWr);
    CHECK(g.srv.wps[1].address == 0x7FFF00001000);

    // continue into the breakpoint -> SIGTRAP event on port 755
    io = b.ps4_continue(ps4::kStopResume);
    REQUIRE(io.ok);
    CHECK(g.srv.last_continue_stop == 0);
    slop::core::runtime::ps4_event_t ev{};
    REQUIRE(b.ps4_wait_event(ev, 3000));
    CHECK(ev.lwpid == 101);
    CHECK(ev.signal == 5);                 // SIGTRAP
    CHECK(ev.ctx.rip == 0x400500);         // stopped at the breakpoint
    REQUIRE_STR_EQ(ev.thread_name, "main");
    CHECK(ev.dr[0] == 0xD000);
    CHECK(b.ps4_pending_events() == 0);

    // single-step all threads -> event with the advanced rip
    io = b.ps4_step(0);
    REQUIRE(io.ok);
    REQUIRE(b.ps4_wait_event(ev, 3000));
    CHECK(ev.lwpid == 101);
    CHECK(ev.ctx.rip == 0x400124);

    // single-step one thread
    io = b.ps4_step(102);
    REQUIRE(io.ok);
    REQUIRE(b.ps4_wait_event(ev, 3000));
    CHECK(ev.lwpid == 102);

    // register read/write through the debug session
    slop::core::runtime::thread_context_t ctx{};
    REQUIRE(b.get_thread_context(101, ctx).ok);
    ctx.rax = 0x777;
    REQUIRE(b.set_thread_context(101, ctx).ok);
    slop::core::runtime::thread_context_t ctx2{};
    REQUIRE(b.get_thread_context(101, ctx2).ok);
    CHECK(ctx2.rax == 0x777);

    // thread suspend/resume + process signal
    REQUIRE(b.ps4_suspend_thread(101).ok);
    REQUIRE(b.ps4_resume_thread(101).ok);
    CHECK(g.srv.last_suspend == 101);
    CHECK(g.srv.last_resume == 101);
    REQUIRE(b.ps4_process_stop(kFakePid, ps4::kStopStop).ok);
    CHECK(g.srv.last_proc_stop_pid == kFakePid);
    CHECK(g.srv.last_proc_stop_state == 1);

    // debug registers
    uint64_t dr[16]{};
    REQUIRE(b.ps4_get_dbregs(101, dr).ok);
    CHECK(dr[0] == 0xD000);
    CHECK(dr[15] == 0xD00F);

    // drain with nothing queued
    CHECK(b.ps4_drain_events(64, true).empty());
    // wait with nothing arriving times out
    CHECK(!b.ps4_wait_event(ev, 200));

    // clear breakpoint + watchpoint
    REQUIRE(b.ps4_set_breakpoint(0, false, 0x400500).ok);
    CHECK(!g.srv.bps[0].enabled);
    REQUIRE(b.ps4_set_watchpoint(1, false, 8, ps4::kWpRdWr, 0).ok);
    CHECK(!g.srv.wps[1].enabled);

    REQUIRE(b.ps4_debug_detach());
    CHECK(!b.ps4_debug_attached());
    b.disconnect();
}

TEST_CASE(ps4_remote_call) {
    server_guard_t g;
    backend_ps4_t b;
    std::string err;
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));

    uint64_t stub = 0;
    REQUIRE(b.ps4_install(kFakePid, stub).ok);
    CHECK(stub == 0x700000);
    // second install rides the client-side cache, not the wire
    REQUIRE(b.ps4_install(kFakePid, stub).ok);
    CHECK(g.srv.intall_count == 1);

    uint64_t args[6] = {41, 2, 3, 4, 5, 6};
    uint64_t rax = 0;
    REQUIRE(b.ps4_call(kFakePid, stub, 0x400800, args, rax).ok);
    CHECK(rax == 42);   // fake target returns rdi + 1
    CHECK(g.srv.last_call.pid == kFakePid);
    CHECK(g.srv.last_call.rpcstub == 0x700000);
    CHECK(g.srv.last_call.rip == 0x400800);
    CHECK(g.srv.last_call.rdi == 41);
    CHECK(g.srv.last_call.rsi == 2);
    CHECK(g.srv.last_call.rdx == 3);
    CHECK(g.srv.last_call.rcx == 4);
    CHECK(g.srv.last_call.r8 == 5);
    CHECK(g.srv.last_call.r9 == 6);

    b.disconnect();
}

TEST_CASE(ps4_mcp_debugger_flow) {
    server_guard_t g;
    ps4_disconnect_guard_t guard;

    std::string err;
    REQUIRE(slop::core::process::target_connect_ps4("127.0.0.1", g.srv.port, kFakePid, err));
    auto s = slop::core::process::active_session();
    REQUIRE(s && s->valid());

    // seed an rbp frame chain at the default rbp 0x7FFF00007FF0 (caller frames
    // live at higher addresses, the chain must ascend):
    //   [0x7FFF00007FF0] = 0x7FFF00008100   [0x7FFF00007FF8] = ret 0x400111
    //   [0x7FFF00008100] = 0                [0x7FFF00008108] = ret 0x400222
    {
        uint64_t v = 0x7FFF00008100ull;
        REQUIRE(s->write(0x7FFF00007FF0, &v, sizeof(v)).ok);
        v = 0x400111;
        REQUIRE(s->write(0x7FFF00007FF8, &v, sizeof(v)).ok);
        v = 0;
        REQUIRE(s->write(0x7FFF00008100, &v, sizeof(v)).ok);
        v = 0x400222;
        REQUIRE(s->write(0x7FFF00008108, &v, sizeof(v)).ok);
    }

    auto dbg = [](const json& args, bool& is_err) {
        return slop::core::mcp::call_tool("debugger", args, is_err);
    };
    bool e = false;

    // ps4_attach through the debugger tool
    json r = dbg({{"action", "ps4_attach"}, {"pid", kFakePid}}, e);
    CHECK(!e);
    if (e) std::printf("  ps4_attach error: %s\n", r.dump().c_str());
    CHECK(r.value("attached", false) == true);
    CHECK(r.value("pid", 0) == kFakePid);

    // status
    r = dbg({{"action", "ps4_status"}}, e);
    CHECK(!e);
    CHECK(r.value("attached", false) == true);
    CHECK(r.value("backend", "") == "PS4");

    // arm a breakpoint (index auto-allocated) and a watchpoint
    r = dbg({{"action", "ps4_bp_set"}, {"addr", 0x400500}}, e);
    CHECK(!e);
    if (e) std::printf("  ps4_bp_set error: %s\n", r.dump().c_str());
    CHECK(r.value("set", false) == true);
    CHECK(r.value("index", 999) == 0);
    r = dbg({{"action", "ps4_watch_set"}, {"addr", 0x7FFF00001000}, {"len", 8}, {"type", 3}}, e);
    CHECK(!e);
    CHECK(r.value("set", false) == true);
    CHECK(r.value("index", 999) == 0);

    // continue into the breakpoint, then wait for the stop event
    r = dbg({{"action", "ps4_continue"}, {"stop", 0}}, e);
    CHECK(!e);
    CHECK(r.value("continued", false) == true);
    r = dbg({{"action", "ps4_wait"}, {"timeout_ms", 3000}}, e);
    CHECK(!e);
    if (e) std::printf("  ps4_wait error: %s\n", r.dump().c_str());
    CHECK(r.value("halted", false) == true);
    CHECK(r.value("signal", 0) == 5);
    CHECK(r.value("lwpid", 0) == 101);
    CHECK(r.value("rip", 0) == 0x400500);

    // regs + set_reg
    r = dbg({{"action", "ps4_regs"}, {"lwpid", 101}}, e);
    CHECK(!e);
    CHECK(r.value("rax", 0) == 0x2A);
    r = dbg({{"action", "ps4_set_reg"}, {"lwpid", 101}, {"name", "rax"}, {"value", 0x999}}, e);
    CHECK(!e);
    CHECK(r.value("set", false) == true);
    r = dbg({{"action", "ps4_regs"}, {"lwpid", 101}}, e);
    CHECK(!e);
    CHECK(r.value("rax", 0) == 0x999);

    // callstack walks the seeded rbp chain over live memory reads
    r = dbg({{"action", "ps4_callstack"}, {"lwpid", 101}, {"depth", 8}}, e);
    CHECK(!e);
    if (e) std::printf("  ps4_callstack error: %s\n", r.dump().c_str());
    CHECK(r.value("count", 0) == 3);
    REQUIRE(r["frames"].size() == 3);
    CHECK(r["frames"][0].value("ret_addr", 0) == 0x400123);
    CHECK(r["frames"][1].value("ret_addr", 0) == 0x400111);
    CHECK(r["frames"][2].value("ret_addr", 0) == 0x400222);

    // remote function call in the console process
    r = dbg({{"action", "ps4_call"}, {"addr", 0x400800}, {"args", json::array({41, 0, 0, 0, 0, 0})}}, e);
    CHECK(!e);
    if (e) std::printf("  ps4_call error: %s\n", r.dump().c_str());
    CHECK(r.value("called", false) == true);
    CHECK(r.value("rax", 0) == 42);
    CHECK(r.value("rpcstub", 0) == 0x700000);

    // step the thread and catch the step event
    r = dbg({{"action", "ps4_step"}, {"lwpid", 101}}, e);
    CHECK(!e);
    r = dbg({{"action", "ps4_wait"}, {"timeout_ms", 3000}}, e);
    CHECK(!e);
    CHECK(r.value("halted", false) == true);
    CHECK(r.value("rip", 0) == 0x400124);

    // drain the event queue
    r = dbg({{"action", "ps4_events"}, {"max", 16}, {"clear", true}}, e);
    CHECK(!e);
    CHECK(r.value("count", 999) == 0);

    // dbregs
    r = dbg({{"action", "ps4_dbregs"}, {"lwpid", 101}}, e);
    CHECK(!e);
    CHECK(r["dr"].size() == 16);
    CHECK(r["dr"][0].get<uint64_t>() == 0xD000);

    // clear bp + watchpoint, then detach
    r = dbg({{"action", "ps4_bp_clear"}, {"addr", 0x400500}}, e);
    CHECK(!e);
    CHECK(r.value("cleared", false) == true);
    r = dbg({{"action", "ps4_watch_clear"}, {"index", 0}}, e);
    CHECK(!e);
    CHECK(r.value("cleared", false) == true);
    r = dbg({{"action", "ps4_detach"}}, e);
    CHECK(!e);
    CHECK(r.value("attached", true) == false);
}

TEST_CASE(guide_smoke_before_ps4) {
    bool e = false;
    json l = slop::core::mcp::call_tool("guide", {{"action", "list"}}, e);
    CHECK(!e);
    CHECK(l.value("count", 0) >= 10);
    json g = slop::core::mcp::call_tool("guide", {{"action", "get"}, {"topic", "ps4_setup"}}, e);
    CHECK(!e);
    REQUIRE(g.contains("steps") && g["steps"].is_array() && !g["steps"].empty());
    CHECK(g["steps"][0].value("tool", "") == "target");
}

TEST_CASE(ps4_power_actions_ps4_auto_and_guide) {
    server_guard_t g;
    ps4_disconnect_guard_t guard;

    std::string err;
    REQUIRE(slop::core::process::target_connect_ps4("127.0.0.1", g.srv.port, kFakePid, err));
    auto s = slop::core::process::active_session();
    REQUIRE(s && s->valid());

    auto dbg = [](const json& args, bool& is_err) {
        return slop::core::mcp::call_tool("debugger", args, is_err);
    };
    bool e = false;

    // debug attach
    json r = dbg({{"action", "ps4_attach"}, {"pid", kFakePid}}, e);
    CHECK(!e);
    CHECK(r.value("attached", false) == true);

    // ps4_until: one-call run-until, bp auto-armed and auto-cleared
    r = dbg({{"action", "ps4_bp_list"}}, e);
    CHECK(!e);
    CHECK(r.value("count", 999) == 0);
    r = dbg({{"action", "ps4_until"}, {"addr", 0x400700}, {"timeout_ms", 3000}}, e);
    CHECK(!e);
    if (e) std::printf("  ps4_until error: %s\n", r.dump().c_str());
    CHECK(r.value("halted", false) == true);
    CHECK(r.value("rip", 0) == 0x400700);
    CHECK(r.value("signal", 0) == 5);
    r = dbg({{"action", "ps4_bp_list"}}, e);   // one-shot bp cleared afterwards
    CHECK(!e);
    CHECK(r.value("count", 999) == 0);

    // ps4_trace_calls: 3 hits, each carrying the arg registers
    r = dbg({{"action", "ps4_trace_calls"}, {"addr", 0x400600}, {"count", 3}, {"timeout_ms", 2000}}, e);
    CHECK(!e);
    if (e) std::printf("  ps4_trace_calls error: %s\n", r.dump().c_str());
    CHECK(r.value("hits_count", -1) == 3);
    REQUIRE_STR_EQ(r.value("stop_reason", ""), "count_reached");
    REQUIRE(r.contains("hits") && r["hits"].size() == 3);
    for (const auto& h : r["hits"]) {
        CHECK(h.value("rip", 0) == 0x400600);
        CHECK(h.contains("rdi") && h.contains("r9"));
    }
    r = dbg({{"action", "ps4_bp_list"}}, e);   // trace_calls cleared its bp
    CHECK(!e);
    CHECK(r.value("count", 999) == 0);

    // ps4_find_write: watchpoint -> event -> callstack, watchpoint auto-cleared
    r = dbg({{"action", "ps4_find_write"}, {"addr", 0x7FFF00001000}, {"len", 8}, {"timeout_ms", 3000}}, e);
    CHECK(!e);
    if (e) std::printf("  ps4_find_write error: %s\n", r.dump().c_str());
    CHECK(r.value("halted", false) == true);
    CHECK(r.contains("callstack") && r["callstack"].is_array());
    CHECK(r["callstack"].size() >= 1);
    CHECK(r.contains("writer_rip"));
    r = dbg({{"action", "ps4_watch_list"}}, e);
    CHECK(!e);
    CHECK(r.value("count", 999) == 0);

    // ps4_trace_steps: rip advances by one per step
    r = dbg({{"action", "ps4_trace_steps"}, {"lwpid", 101}, {"count", 4}, {"timeout_ms", 2000}}, e);
    CHECK(!e);
    if (e) std::printf("  ps4_trace_steps error: %s\n", r.dump().c_str());
    CHECK(r.value("steps_count", -1) == 4);
    REQUIRE(r.contains("steps") && r["steps"].size() == 4);
    for (size_t i = 1; i < 4; ++i)
        CHECK(r["steps"][i].value("rip", 0) == r["steps"][i - 1].value("rip", 0) + 1);

    // ps4_auto: already connected; picks the /app0/ game process (1234), not 42
    {
        bool e2 = false;
        json a = slop::core::mcp::call_tool(
            "target",
            {{"action", "ps4_auto"}, {"host", "127.0.0.1"}, {"port", g.srv.port}},
            e2);
        CHECK(!e2);
        if (e2) std::printf("  ps4_auto error: %s\n", a.dump().c_str());
        CHECK(a.value("connected", false) == true);
        CHECK(a.value("pid", 0) == kFakePid);
        CHECK(a.value("debug_attached", false) == true);
        CHECK(a.value("module_count", 0) == 2);   // 3 maps, but the anonymous stack map is skipped
        REQUIRE(a.contains("modules") && a["modules"].size() == 2);
        CHECK(a["modules"][0].value("name", "") == "eboot.bin");
        CHECK(a["modules"][0].value("base", 0) == 0x400000);
        CHECK(a.value("thread_count", 0) == 2);
        CHECK(a.value("region_count", 0) == 6);   // 6 raw vm maps; modules coalesce to 2
        REQUIRE(a.contains("candidates"));
        bool saw_game = false, saw_system = false;
        for (const auto& c : a["candidates"]) {
            if (c.value("pid", 0) == kFakePid) {
                saw_game = true;
                CHECK(c.value("game", false) == true);
            }
            if (c.value("pid", 0) == 42) {
                saw_system = true;
                CHECK(c.value("game", false) == false);
            }
        }
        CHECK(saw_game);
        CHECK(saw_system);
    }

    // guide tool: list + get
    {
        bool e2 = false;
        json l = slop::core::mcp::call_tool("guide", {{"action", "list"}}, e2);
        CHECK(!e2);
        CHECK(l.value("count", 0) >= 10);
        json gt = slop::core::mcp::call_tool(
            "guide", {{"action", "get"}, {"topic", "ps4_setup"}}, e2);
        CHECK(!e2);
        REQUIRE(gt.contains("steps") && gt["steps"].is_array() && !gt["steps"].empty());
        CHECK(gt["steps"][0].value("tool", "") == "target");
        CHECK(gt["steps"][0].contains("params"));
        bool e3 = false;
        json bad = slop::core::mcp::call_tool(
            "guide", {{"action", "get"}, {"topic", "nope"}}, e3);
        CHECK(e3);
    }

    // ps4_detach at the end
    r = dbg({{"action", "ps4_detach"}}, e);
    CHECK(!e);
}

TEST_CASE(ps4_auth_and_native_scan) {
    server_guard_t g;
    backend_ps4_t b;
    std::string err;
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));   // auto-auth runs on connect
    CHECK(b.ps4_authed());
    CHECK(g.srv.auth_attempts >= 1);
    CHECK(g.srv.auth_ok);

    auto h = b.attach(kFakePid);
    REQUIRE(h.valid());

    const auto put32 = [&](uint64_t a, uint32_t v) {
        g.srv.mem_write(a, reinterpret_cast<const uint8_t*>(&v), 4);
    };
    put32(0x401000, 1000);
    put32(0x401008, 2000);
    put32(0x401010, 1000);

    std::vector<uint8_t> val(4);
    const uint32_t want = 1000;
    std::memcpy(val.data(), &want, 4);
    std::vector<backend_ps4_t::ps4_scan_hit_t> hits;
    auto io = b.ps4_scan_first(kFakePid, 0x401000, 0x20, ps4::kValU32, ps4::kCmpExact, 0, val, hits);
    REQUIRE(io.ok);
    CHECK(hits.size() == 2u);

    put32(0x401000, 555);   // change one of the hits
    std::vector<backend_ps4_t::ps4_scan_hit_t> hits2;
    auto io2 = b.ps4_scan_next(kFakePid, 0x401000, ps4::kValU32, ps4::kCmpChanged, hits, {}, hits2);
    REQUIRE(io2.ok);
    CHECK(hits2.size() == 1u);
    CHECK(hits2[0].addr == 0x401000ull);

    // AOB with wildcards
    const uint8_t code[] = {0xE8, 0x03, 0x00, 0x00, 0x00, 0x90};
    g.srv.mem_write(0x401020, code, sizeof(code));
    std::vector<uint8_t> pat = {0xE8, 0x03}, msk = {1, 1};
    uint64_t hit = 0;
    auto io3 = b.ps4_scan_aob(kFakePid, 0x401000, 0x40, pat, msk, 1, 0, hit);
    REQUIRE(io3.ok);
    CHECK(hit == 0x401010ull);   // 1000 = E8 03 00 00 matches there first

    // legacy whole-memory scan
    std::vector<uint64_t> addrs;
    auto io4 = b.ps4_scan_all(kFakePid, ps4::kValU32, ps4::kCmpExact, val, addrs);
    REQUIRE(io4.ok);
    CHECK(std::find(addrs.begin(), addrs.end(), 0x401010ull) != addrs.end());
    CHECK(std::find(addrs.begin(), addrs.end(), 0x401000ull) == addrs.end());  // now 555

    b.detach(h);
    b.disconnect();
}

TEST_CASE(ps4_mcp_console_side_tooling) {
    server_guard_t g;
    ps4_disconnect_guard_t guard;
    std::string err;
    REQUIRE(slop::core::runtime::registry_connect_ps4("127.0.0.1", g.srv.port, err));
    REQUIRE(slop::core::process::target_connect_ps4("127.0.0.1", g.srv.port, kFakePid, err));
    auto dbg = [&](const json& a, bool& is_err) {
        return slop::core::mcp::call_tool("debugger", a, is_err);
    };

    // native scan through MCP
    {
        bool e = false;
        const uint32_t want = 1000;
        g.srv.mem_write(0x401000, reinterpret_cast<const uint8_t*>(&want), 4);
        json r = dbg({{"action", "ps4_scan"}, {"addr", 0x401000}, {"len", 0x20},
                      {"value_type", "u32"}, {"compare", "exact"}, {"value", 1000}}, e);
        CHECK(!e);
        if (e) std::printf("  ps4_scan error: %s\n", r.dump().c_str());
        CHECK(r.value("count", 0) == 1u);
        json st = dbg({{"action", "ps4_scan_state"}}, e);
        CHECK(!e);
        CHECK(st.value("count", 0) == 1u);
        json rs = dbg({{"action", "ps4_rescan"}, {"compare", "unchanged"}}, e);
        CHECK(!e);
        CHECK(rs.value("count", 0) == 1u);
        json clr = dbg({{"action", "ps4_scan_reset"}}, e);
        CHECK(!e);
        json st2 = dbg({{"action", "ps4_scan_state"}}, e);
        CHECK(!e);
        CHECK(st2.value("used", true) == false);
    }
    // aob through MCP (?? wildcards)
    {
        bool e = false;
        const uint8_t code[] = {0x48, 0x8B, 0x05, 0x11, 0x22, 0x33, 0x44};
        g.srv.mem_write(0x401040, code, sizeof(code));
        json r = dbg({{"action", "ps4_scan_aob"}, {"addr", 0x401000}, {"len", 0x100},
                      {"pattern", "48 8b 05 ?? ?? ?? ??"}}, e);
        CHECK(!e);
        if (e) std::printf("  ps4_scan_aob error: %s\n", r.dump().c_str());
        CHECK(r.value("found", false) == true);
        CHECK(r.value("addr", 0) == 0x401040ull);
    }
    // on-device disasm + xrefs
    {
        bool e = false;
        json r = dbg({{"action", "ps4_disasm"}, {"addr", 0x400000}, {"len", 16}, {"max", 8}}, e);
        CHECK(!e);
        if (e) std::printf("  ps4_disasm error: %s\n", r.dump().c_str());
        CHECK(r.value("count", 0) == 2u);
        CHECK(r["instructions"][0].value("rip_rel_target", 0) == 0x400100ull);
        json x = dbg({{"action", "ps4_xrefs"}, {"addr", 0x400000}, {"len", 64}}, e);
        CHECK(!e);
        CHECK(x.value("count", 0) == 1u);
        json xt = dbg({{"action", "ps4_xrefs_to"}, {"addr", 0x400000}, {"len", 64},
                       {"target", 0x400100}}, e);
        CHECK(!e);
        CHECK(xt.value("count", 0) == 1u);
    }
    // server-side stack walk over a fake frame chain
    {
        const uint64_t saved_rbp = 0x7FFF00007FF0ull, ret = 0x400123ull;
        const uint64_t zero = 0;
        g.srv.mem_write(0x7FFF00008000, reinterpret_cast<const uint8_t*>(&saved_rbp), 8);
        g.srv.mem_write(0x7FFF00008008, reinterpret_cast<const uint8_t*>(&ret), 8);
        g.srv.mem_write(0x7FFF00007FF0, reinterpret_cast<const uint8_t*>(&zero), 8);
        bool e = false;
        json r = dbg({{"action", "ps4_stack"}, {"rbp", 0x7FFF00008000ull},
                      {"rsp", 0x7FFF00007FF0ull}, {"depth", 4}}, e);
        CHECK(!e);
        if (e) std::printf("  ps4_stack error: %s\n", r.dump().c_str());
        CHECK(r.value("count", 0) == 1u);
        CHECK(r["frames"][0].value("ret_addr", 0) == 0x400123ull);
    }
    // on-device assemble
    {
        bool e = false;
        json r = dbg({{"action", "ps4_assemble"}, {"asm", "int3"}}, e);
        CHECK(!e);
        if (e) std::printf("  ps4_assemble error: %s\n", r.dump().c_str());
        CHECK(r.value("bytes_hex", "") == "cc");
        json bad = dbg({{"action", "ps4_assemble"}, {"asm", "zzz"}}, e);
        CHECK(e);   // assembler error surfaces as a tool error carrying the message
    }
    // elf rpc + load
    {
        bool e = false;
        const char* path = "ps4_test_payload.elf";
        {
            std::ofstream f(path, std::ios::binary | std::ios::trunc);
            const uint8_t hdr[8] = {0x7F, 'E', 'L', 'F', 2, 1, 1, 0};
            f.write(reinterpret_cast<const char*>(hdr), sizeof(hdr));
            const uint8_t pad[56] = {};
            f.write(reinterpret_cast<const char*>(pad), sizeof(pad));
        }
        json r = dbg({{"action", "ps4_elf_rpc"}, {"path", path}}, e);
        CHECK(!e);
        if (e) std::printf("  elf_rpc err: %s\n", r.dump().c_str());
        CHECK(r.value("entry", 0) == 0x400500ull);
        json l = dbg({{"action", "ps4_elf_load"}, {"path", path}}, e);
        CHECK(!e);
        CHECK(l.value("executed", false) == true);
        std::remove(path);
    }
    // notify / print / foreground app
    {
        bool e = false;
        json r = dbg({{"action", "ps4_notify"}, {"msg", "hello from reverse-slap"}}, e);
        CHECK(!e);
        CHECK(r.value("notified", false) == true);
        CHECK(g.srv.last_notify.find("hello from reverse-slap") != std::string::npos);
        CHECK(g.srv.last_notify_type == 222u);
        json p = dbg({{"action", "ps4_print"}, {"msg", "klog line"}}, e);
        CHECK(!e);
        CHECK(g.srv.last_print == "klog line");
        json a = dbg({{"action", "ps4_app"}}, e);
        CHECK(!e);
        CHECK(a.value("pid", 0) == kFakePid);
        REQUIRE_STR_EQ(a.value("titleid", ""), "CUSA12345_00");
    }
    // dump a module over the wire through the target tool
    {
        bool e = false;
        const uint8_t marker[16] = {0x7F, 'E', 'L', 'F', 2, 1, 1, 0, 0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4};
        g.srv.mem_write(0x400000, marker, sizeof(marker));
        const char* out = "ps4_dump_test.bin";
        json r = slop::core::mcp::call_tool("target",
            {{"action", "ps4_dump_module"}, {"name", "eboot.bin"}, {"path", out}}, e);
        CHECK(!e);
        if (e) std::printf("  ps4_dump_module err: %s\n", r.dump().c_str());
        CHECK(r.value("dumped", false) == true);
        // all three segments (text, relro, data) of the coalesced module,
        // not just the first map entry
        CHECK(r.value("bytes_written", 0) == 0x100000ull);
        CHECK(r.value("segment_count", 0) == 3u);
        CHECK(r.value("format", std::string{}) == "raw");
        std::ifstream f(out, std::ios::binary);
        REQUIRE(f.good());
        std::vector<uint8_t> head(16);
        f.read(reinterpret_cast<char*>(head.data()), static_cast<std::streamsize>(head.size()));
        CHECK(std::memcmp(head.data(), marker, 16) == 0);
        f.close();
        std::remove(out);
    }
    // fpregs / fsgs need a debug session
    {
        bool e = false;
        json a = dbg({{"action", "ps4_attach"}, {"pid", kFakePid}}, e);
        CHECK(!e);
        json fr = dbg({{"action", "ps4_fpregs"}, {"lwpid", 101}}, e);
        CHECK(!e);
        CHECK(fr.value("size", 0) == 832u);
        CHECK(fr.value("hex", std::string{}).size() == 832u * 2u);
        json sf = dbg({{"action", "ps4_set_fsgs"}, {"lwpid", 101},
                       {"fs_base", 0x7FFF0000}, {"gs_base", 0x2000}}, e);
        CHECK(!e);
        CHECK(g.srv.last_fsgs_fs == 0x7FFF0000ull);
        CHECK(g.srv.last_fsgs_gs == 0x2000ull);
        json fg = dbg({{"action", "ps4_fsgs"}, {"lwpid", 101}}, e);
        CHECK(!e);
        CHECK(fg.value("fs_base", 0) == 0x7FFF0000ull);
        CHECK(fg.value("gs_base", 0) == 0x1000ull);
        json d = dbg({{"action", "ps4_detach"}}, e);
        CHECK(!e);
    }
}
