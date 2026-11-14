// src/tests/test_ps5.cpp
// PS5 (ps5debug-NG) tests against the fake payload in ps5_fixture.hpp:
// handshake, memory, maps/modules, the debug session, connection loss and
// reconnect, protocol errors and the MCP target/debugger surfaces.

#include "ps5_fixture.hpp"

namespace rt = slop::core::runtime;

TEST_CASE(ps5_backend_handshake_and_enums) {
    server_guard_t g;
    backend_ps5_t b;
    std::string err;
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));
    if (!err.empty()) std::printf("  connect err: %s\n", err.c_str());
    CHECK(b.connected());
    CHECK(b.ping());
    CHECK(b.kind() == backend_kind_t::ps5);
    REQUIRE_STR_EQ(b.badge(), "PS5");
    CHECK(b.branding().find("ps5debug-NG") != std::string::npos);
    CHECK(b.server_version() == "1.3");
    CHECK(b.server_caps() == "1.1");
    CHECK(b.fw_version() == 900);
    CHECK(b.fw_string() == "9.00");
    CHECK(b.platform_id() == ps5::kPlatformPs5);
    CHECK(b.endpoint() == "127.0.0.1:" + std::to_string(g.srv.port));
    CHECK(b.last_endpoint() == b.endpoint());
    CHECK(!b.lost());
    CHECK(b.drop_count() == 0);

    auto procs = b.enum_processes();
    REQUIRE(procs.ok);
    CHECK(procs.items.size() == 2u);
    bool found = false;
    for (const auto& p : procs.items) {
        if (p.pid == kFakePid) {
            found = true;
            REQUIRE_STR_EQ(p.name, "eboot.bin");
            CHECK(p.arch == rt::arch_t::x64);
            CHECK(p.elevation == rt::elevation_t::system);
        }
    }
    CHECK(found);

    auto h = b.attach(kFakePid);
    REQUIRE(h.valid());
    CHECK(!b.attach(9999).valid());

    auto regions = b.enum_regions(h);
    REQUIRE(regions.ok);
    CHECK(regions.items.size() == 6u);
    bool saw_eboot = false;
    for (const auto& r : regions.items) {
        if (r.base == 0x400000) {
            saw_eboot = true;
            CHECK(r.size == 0x80000);
            CHECK(r.protect == 0x20);   // PAGE_EXECUTE_READ
        }
    }
    CHECK(saw_eboot);

    // one record per module: the three eboot segments coalesce
    auto mods = b.enum_modules(h);
    REQUIRE(mods.ok);
    int eboot_records = 0;
    for (const auto& m : mods.items) {
        if (m.name == "eboot.bin") {
            ++eboot_records;
            CHECK(m.base == 0x400000);
            CHECK(m.size == 0x100000);
            REQUIRE_STR_EQ(m.path, "/app0/eboot.bin");
        }
    }
    CHECK(eboot_records == 1);
    CHECK(mods.items.size() == 2u);   // eboot + libSceLibcInternal
    auto segs = b.ps5_modules(h);
    REQUIRE(segs.ok);
    REQUIRE(!segs.items.empty());
    CHECK(segs.items[0].name == "eboot.bin");
    REQUIRE(segs.items[0].segments.size() == 3u);
    CHECK(segs.items[0].segments[1].start == 0x480000);

    rt::process_info_t pi;
    REQUIRE(b.handle_info(h, pi));
    REQUIRE_STR_EQ(pi.path, "/app0/eboot.bin");
    CHECK(pi.arch == rt::arch_t::x64);
    CHECK(b.query_arch(h) == rt::arch_t::x64);
    CHECK(b.query_elevation() == rt::elevation_t::system);

    // the payload has no handle table: an empty, successful enumeration
    auto handles = b.enum_handles(kFakePid);
    CHECK(handles.ok);
    CHECK(handles.items.empty());

    b.detach(h);
    CHECK(!h.valid());
    b.disconnect();
    CHECK(!b.connected());
    CHECK(!b.lost());
}

TEST_CASE(ps5_backend_memory_rw_protect_alloc) {
    server_guard_t g;
    backend_ps5_t b;
    std::string err;
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));
    auto h = b.attach(kFakePid);
    REQUIRE(h.valid());

    std::vector<uint8_t> pattern(64);
    for (size_t i = 0; i < pattern.size(); ++i) pattern[i] = static_cast<uint8_t>(0xA0 + i);
    auto w = b.write_memory(h, 0x400100, pattern.data(), pattern.size());
    REQUIRE(w.ok);
    CHECK(w.bytes == pattern.size());
    std::vector<uint8_t> back(pattern.size(), 0);
    auto r = b.read_memory(h, 0x400100, back.data(), back.size());
    REQUIRE(r.ok);
    CHECK(std::memcmp(back.data(), pattern.data(), pattern.size()) == 0);
    for (size_t i = 0; i < pattern.size(); ++i)
        CHECK(g.srv.mem_byte(0x400100 + i) == pattern[i]);

    // a 128 KiB transfer crosses the payload's 64 KiB chunking
    std::vector<uint8_t> big(0x20000);
    for (size_t i = 0; i < big.size(); ++i) big[i] = static_cast<uint8_t>(i * 7 + 1);
    REQUIRE(b.write_memory(h, 0x400000, big.data(), big.size()).ok);
    std::vector<uint8_t> bigback(big.size(), 0);
    REQUIRE(b.read_memory(h, 0x400000, bigback.data(), bigback.size()).ok);
    CHECK(std::memcmp(bigback.data(), big.data(), big.size()) == 0);

    // unmapped read fails client-side (the payload would zero-fill)
    std::vector<uint8_t> junk(16, 0);
    auto bad = b.read_memory(h, 0xDEAD0000, junk.data(), junk.size());
    CHECK(!bad.ok);
    CHECK(bad.error == ps5::kErrUnmapped);

    // protect translates PAGE_EXECUTE_READWRITE -> VM_PROT_ALL and reports old
    uint32_t old = 0;
    auto pr = b.protect_memory(h, 0x500000, 0x1000, 0x40, &old);
    REQUIRE(pr.ok);
    CHECK(old == 0x20);
    CHECK(g.srv.last_protect == ps5::kVmProtAll);

    uintptr_t alloc_addr = 0;
    auto al = b.allocate_memory(h, 0, 0x2000, 0x04, &alloc_addr);
    REQUIRE(al.ok);
    CHECK(alloc_addr == 0x600000);
    uintptr_t hinted = 0;
    REQUIRE(b.allocate_memory(h, 0x700000, 0x1000, 0, &hinted).ok);
    CHECK(hinted == 0x700000);
    CHECK(g.srv.last_alloc_hint == 0x700000);
    CHECK(b.free_memory(h, 0x600000).ok);
    // a range outside every map cannot be freed
    CHECK(b.free_memory(h, 0x12340000).error == ps5::kErrUnmapped);

    b.detach(h);
    b.disconnect();
}

TEST_CASE(ps5_backend_debug_session) {
    server_guard_t g;
    const uint16_t evport = free_tcp_port();
    REQUIRE(evport != 0);
    g.srv.event_port = evport;

    backend_ps5_t b;
    b.set_event_port(evport);
    std::string err;
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));
    auto h = b.attach(kFakePid);
    REQUIRE(h.valid());

    std::string derr;
    REQUIRE(b.ps5_debug_attach(kFakePid, derr));
    if (!derr.empty()) std::printf("  attach err: %s\n", derr.c_str());
    CHECK(b.ps5_debug_attached());
    CHECK(b.ps5_debug_pid() == kFakePid);

    auto thr = b.enum_threads(kFakePid);
    REQUIRE(thr.ok);
    CHECK(thr.items.size() == 2u);
    CHECK(thr.items[0].tid == 101);
    CHECK(thr.items[1].tid == 102);
    CHECK(thr.items[0].owner_pid == kFakePid);
    CHECK(thr.items[0].priority == 80);
    CHECK(thr.items[0].name == "main");

    rt::thread_context_t ctx{};
    auto gr = b.get_thread_context(101, ctx);
    REQUIRE(gr.ok);
    CHECK(ctx.rip == 0x400123);
    CHECK(ctx.rsp == 0x7FFF00008000ull);
    CHECK(ctx.rax == 0x2A);
    CHECK(ctx.flags == 0x202);

    ctx.rip = 0x400999;
    ctx.rax = 0x1234;
    REQUIRE(b.set_thread_context(101, ctx).ok);
    rt::thread_context_t ctx2{};
    REQUIRE(b.get_thread_context(101, ctx2).ok);
    CHECK(ctx2.rip == 0x400999);
    CHECK(ctx2.rax == 0x1234);

    uint32_t index = 0;
    bool reused = false;
    REQUIRE(b.ps5_bp_arm(0x400200, backend_ps5_t::kAutoSlot, index, &reused).ok);
    CHECK(index == 0);
    CHECK(!reused);
    // arming the same address again reuses the slot
    uint32_t again = 0;
    REQUIRE(b.ps5_bp_arm(0x400200, backend_ps5_t::kAutoSlot, again, &reused).ok);
    CHECK(again == 0);
    CHECK(reused);
    CHECK(g.srv.bps[0].enabled);
    CHECK(g.srv.bps[0].address == 0x400200);
    auto slots = b.ps5_breakpoints();
    REQUIRE(slots.size() == 1u);
    CHECK(slots[0].armed);

    uint32_t wp_index = 0;
    REQUIRE(b.ps5_wp_arm(0x500000, 8, ps5::kWpWrite, backend_ps5_t::kAutoSlot,
                         wp_index, nullptr).ok);
    CHECK(wp_index == 0);
    CHECK(g.srv.wps[0].enabled);
    CHECK(g.srv.wps[0].breaktype == ps5::kWpWrite);
    // the payload wants the DR7 length field, not the byte count (8 bytes -> 2)
    CHECK(g.srv.wps[0].length == ps5::wp_dr7_length(8));

    // an out-of-range slot index is rejected client-side before the wire
    auto bad_bp = b.ps5_set_breakpoint(ps5::kMaxSwBreakpoints, true, 0x400000);
    CHECK(!bad_bp.ok);
    CHECK(bad_bp.error == ps5::kErrBadArg);

    REQUIRE(b.ps5_continue(ps5::kStopResume).ok);
    CHECK(g.srv.last_continue_stop == ps5::kStopResume);
    REQUIRE(b.ps5_step(0).ok);
    CHECK(g.srv.step_calls == 1);
    REQUIRE(b.ps5_step(102).ok);
    CHECK(g.srv.step_thread_calls == 1);
    REQUIRE(b.ps5_suspend_thread(102).ok);
    CHECK(g.srv.last_suspend == 102);
    REQUIRE(b.ps5_resume_thread(102).ok);
    CHECK(g.srv.last_resume == 102);

    // the attach opened the port-755 channel; push one stop packet through it
    REQUIRE(wait_until([&] { return g.srv.send_event(101, 0x057F, "main", 0x400123); }, 3000));
    REQUIRE(wait_until([&] { return b.ps5_pending_events() > 0; }, 3000));
    rt::ps5_event_t ev{};
    REQUIRE(b.ps5_wait_event(ev, 1000));
    CHECK(ev.lwpid == 101);
    CHECK(ev.signal == 5);   // SIGTRAP from the wait4 status
    CHECK(ev.ctx.rip == 0x400123);
    CHECK(std::string(ev.thread_name) == "main");
    CHECK(ev.dr[1] == 0x1001);
    CHECK(b.ps5_events_received() >= 1u);

    REQUIRE(b.ps5_bp_disarm_addr(0x400200).ok);
    CHECK(!g.srv.bps[0].enabled);
    CHECK(b.ps5_breakpoints().empty());
    CHECK(b.ps5_bp_disarm(0).error == ps5::kErrNotArmed);

    CHECK(b.ps5_debug_detach());
    CHECK(!b.ps5_debug_attached());
    CHECK(g.srv.detach_count >= 1);
    // regs need a session
    CHECK(b.get_thread_context(101, ctx).error == ps5::kErrNotAttached);

    b.detach(h);
    b.disconnect();
}

TEST_CASE(ps5_connection_loss_and_reconnect) {
    server_guard_t g;
    const uint16_t evport = free_tcp_port();
    REQUIRE(evport != 0);
    g.srv.event_port = evport;

    backend_ps5_t b;
    b.set_event_port(evport);
    std::string err;
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));
    auto h = b.attach(kFakePid);
    REQUIRE(h.valid());
    std::string derr;
    REQUIRE(b.ps5_debug_attach(kFakePid, derr));
    uint32_t index = 0;
    REQUIRE(b.ps5_bp_arm(0x400200, backend_ps5_t::kAutoSlot, index, nullptr).ok);

    // the payload cuts the connection right after the read's status word
    g.srv.chaos.close_cmd = ps5::CMD_PROC_READ;
    g.srv.chaos.close_after = 4;
    std::vector<uint8_t> buf(16, 0);
    auto r = b.read_memory(h, 0x400000, buf.data(), buf.size());
    CHECK(!r.ok);
    CHECK(r.error == ps5::kErrRecvFailed);
    CHECK(!b.connected());
    CHECK(b.lost());
    CHECK(!b.lost_reason().empty());
    CHECK(b.drop_count() == 1);
    // the handle survives, but the connection is gone
    CHECK(b.read_memory(h, 0x400000, buf.data(), buf.size()).error == ps5::kErrNotConnected);

    // reconnect: handshake again, re-attach the debuggee, re-arm the slot
    backend_ps5_t::reconnect_report_t rep;
    REQUIRE(b.reconnect(err, &rep));
    if (!err.empty()) std::printf("  reconnect err: %s\n", err.c_str());
    CHECK(b.connected());
    CHECK(!b.lost());
    CHECK(rep.handshake_ok);
    CHECK(rep.debug_pid == kFakePid);
    CHECK(rep.debug_restored);
    CHECK(rep.bp_rearmed == 1u);
    CHECK(rep.bp_failed == 0u);
    CHECK(b.ps5_debug_attached());
    CHECK(g.srv.bps[0].enabled);
    CHECK(g.srv.bps[0].address == 0x400200);

    // the session handle still reads
    REQUIRE(b.read_memory(h, 0x400000, buf.data(), buf.size()).ok);

    b.detach(h);
    b.disconnect();
}

TEST_CASE(ps5_protocol_errors) {
    server_guard_t g;
    backend_ps5_t b;
    std::string err;
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));

    // a word that is not a status at all means the stream desynced
    g.srv.chaos.garbage_cmd = ps5::CMD_PROC_LIST;
    auto procs = b.enum_processes();
    CHECK(!procs.ok);
    CHECK(procs.error == ps5::kErrProtocol);
    CHECK(!b.connected());
    CHECK(b.lost());

    // a silent payload hits the idle deadline and drops the connection
    REQUIRE(b.reconnect(err, nullptr));
    CHECK(b.connected());
    b.set_timeouts(300, 1500);
    g.srv.chaos.stall_cmd = ps5::CMD_PROC_LIST;
    procs = b.enum_processes();
    CHECK(!procs.ok);
    CHECK(procs.error == ps5::kErrTimeout);
    CHECK(!b.connected());

    // a connection cut in the middle of a write's data phase: the payload
    // acks, then the socket dies before the terminal status
    REQUIRE(b.reconnect(err, nullptr));
    CHECK(b.connected());
    b.set_timeouts(2000, 5000);
    auto h = b.attach(kFakePid);
    REQUIRE(h.valid());
    g.srv.chaos.close_cmd = ps5::CMD_PROC_WRITE;
    g.srv.chaos.close_after = 4;   // the ack status, then the cut
    std::vector<uint8_t> data(32, 0x5A);
    auto wr = b.write_memory(h, 0x400000, data.data(), data.size());
    CHECK(!wr.ok);
    CHECK(wr.error == ps5::kErrRecvFailed || wr.error == ps5::kErrSendFailed);
    CHECK(!b.connected());
    CHECK(b.drop_count() == 3);

    b.disconnect();
}

TEST_CASE(ps5_connect_refuses_non_ps5_server) {
    // a payload that reports platform 4 is a PS4 debugger, not ps5debug-NG
    wsa();
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(ls != INVALID_SOCKET);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    REQUIRE(bind(ls, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    REQUIRE(listen(ls, 1) == 0);
    slop_socklen_t len = sizeof(addr);
    getsockname(ls, reinterpret_cast<sockaddr*>(&addr), &len);
    const uint16_t port = ntohs(addr.sin_port);
    std::atomic<bool> stop{false};
    std::thread th([&] {
        while (!stop) {
            fd_set rset;
            FD_ZERO(&rset);
            FD_SET(ls, &rset);
            timeval tv{0, 100 * 1000};
            if (select(0, &rset, nullptr, nullptr, &tv) <= 0) continue;
            SOCKET c = accept(ls, nullptr, nullptr);
            if (c == INVALID_SOCKET) continue;
            // answer the handshake as a PS4 payload would
            ps5::packet_header_t hdr{};
            if (recv_all(c, &hdr, sizeof(hdr))) {
                const char* v = "1.3";
                const uint32_t vlen = 3;
                send_u32(c, vlen);
                send_all(c, v, vlen);
                recv_all(c, &hdr, sizeof(hdr));
                static const char brand[] = "ps4debug-NG\0" "1.1";
                const uint32_t blen = static_cast<uint32_t>(sizeof(brand) - 1);
                send_u32(c, blen);
                send_all(c, brand, blen);
                recv_all(c, &hdr, sizeof(hdr));
                const uint16_t fw = 1100;
                send_all(c, &fw, sizeof(fw));
                recv_all(c, &hdr, sizeof(hdr));
                const uint16_t tag = 4;   // PS4
                send_all(c, &tag, sizeof(tag));
            }
            closesocket(c);
        }
    });

    backend_ps5_t b;
    std::string err;
    CHECK(!b.connect("127.0.0.1", port, err));
    CHECK(err.find("platform") != std::string::npos);
    CHECK(!b.connected());

    stop = true;
    ::shutdown(ls, SD_BOTH);
    closesocket(ls);
    th.join();
}

TEST_CASE(ps5_registry_session_and_mcp_tools) {
    server_guard_t g;
    ps5_disconnect_guard_t guard;   // leaves the registry clean on REQUIRE failure
    const uint16_t evport = free_tcp_port();
    REQUIRE(evport != 0);
    g.srv.event_port = evport;

    std::string err;
    REQUIRE(rt::registry_connect_ps5("127.0.0.1", g.srv.port, err));
    REQUIRE(rt::registry_ps5() != nullptr);
    rt::registry_ps5()->set_event_port(evport);
    CHECK(rt::registry_ps5_active());
    CHECK(rt::active_kind() == backend_kind_t::ps5);
    REQUIRE_STR_EQ(rt::active_badge(), "PS5");
    CHECK(rt::registry_ps5_endpoint() == "127.0.0.1:" + std::to_string(g.srv.port));
    CHECK(rt::registry_ps5_branding().find("ps5debug-NG") != std::string::npos);

    REQUIRE(slop::core::process::target_connect_ps5("127.0.0.1", g.srv.port, kFakePid, err));
    auto s = slop::core::process::active_session();
    REQUIRE(s && s->valid());
    CHECK(s->pid() == kFakePid);
    REQUIRE_STR_EQ(s->name(), "eboot.bin");
    CHECK(s->arch() == rt::arch_t::x64);

    const uint64_t val = 0x1122334455667788ull;
    REQUIRE(s->write(0x400200, &val, sizeof(val)).ok);
    uint64_t back = 0;
    REQUIRE(s->read(0x400200, &back, sizeof(back)).ok);
    CHECK(back == val);

    // MCP: target.list enumerates the console
    {
        bool is_err = false;
        json res = slop::core::mcp::call_tool("target", {{"action", "list"}}, is_err);
        CHECK(!is_err);
        CHECK(res.value("count", 0) == 2);
    }
    // MCP: target.status reports the PS5 backend
    {
        bool is_err = false;
        json res = slop::core::mcp::call_tool("target", {{"action", "status"}}, is_err);
        CHECK(!is_err);
        REQUIRE_STR_EQ(res.value("backend", ""), "PS5");
        CHECK(res.value("attached", false) == true);
        CHECK(res.contains("ps5"));
        CHECK(res["ps5"].value("endpoint", "") == "127.0.0.1:" + std::to_string(g.srv.port));
        CHECK(res["ps5"].value("platform", 0) == 5);
        CHECK(res["ps5"].value("fw", "") == "9.00");
    }
    // MCP: memory.read/write ride the session (generic tools, no ps5 action)
    {
        bool is_err = false;
        json res = slop::core::mcp::call_tool(
            "memory",
            {{"action", "read"}, {"addr", 0x400200}, {"len", 8}, {"format", "u64"}},
            is_err);
        CHECK(!is_err);
        REQUIRE(res.contains("values"));
        CHECK(res["values"][0].get<uint64_t>() == val);
        const uint64_t nv = 0xCAFEBABEDEADBEEFull;
        json wres = slop::core::mcp::call_tool(
            "memory",
            {{"action", "write"}, {"addr", 0x400210}, {"hex", "efbeaddebebafeca"}},
            is_err);
        CHECK(!is_err);
        json rres = slop::core::mcp::call_tool(
            "memory",
            {{"action", "read"}, {"addr", 0x400210}, {"len", 8}, {"format", "u64"}},
            is_err);
        CHECK(!is_err);
        CHECK(rres["values"][0].get<uint64_t>() == nv);
    }
    // MCP: target.modules groups the VM map by backing file
    {
        bool is_err = false;
        json res = slop::core::mcp::call_tool("target", {{"action", "modules"}}, is_err);
        CHECK(!is_err);
        CHECK(res.value("count", 0) == 2);
    }
    // MCP: on-screen notification
    {
        bool is_err = false;
        json res = slop::core::mcp::call_tool(
            "target", {{"action", "ps5_notify"}, {"msg", "hello from the test"}}, is_err);
        CHECK(!is_err);
        CHECK(res.value("sent", false) == true);
        CHECK(g.srv.last_notify == "hello from the test");
        CHECK(g.srv.last_notify_type == ps5::kNotifyTypeGeneric);
    }
    // MCP: debugger ps5_* end to end
    {
        bool is_err = false;
        json res = slop::core::mcp::call_tool(
            "debugger", {{"action", "ps5_attach"}, {"pid", kFakePid}}, is_err);
        CHECK(!is_err);
        CHECK(res.value("attached", false) == true);

        res = slop::core::mcp::call_tool(
            "debugger", {{"action", "ps5_bp_set"}, {"addr", 0x400300}}, is_err);
        CHECK(!is_err);
        CHECK(res.value("index", 99) == 0);
        CHECK(g.srv.bps[0].enabled);

        res = slop::core::mcp::call_tool("debugger", {{"action", "ps5_bp_list"}}, is_err);
        CHECK(!is_err);
        CHECK(res["breakpoints"].size() == 1u);

        res = slop::core::mcp::call_tool(
            "debugger", {{"action", "ps5_regs"}, {"lwpid", 101}}, is_err);
        CHECK(!is_err);
        CHECK(res.value("rip", 0ull) == 0x400123ull);

        res = slop::core::mcp::call_tool(
            "debugger", {{"action", "ps5_continue"}, {"stop", 0}}, is_err);
        CHECK(!is_err);
        CHECK(g.srv.last_continue_stop == ps5::kStopResume);

        REQUIRE(wait_until([&] { return g.srv.send_event(101, 0x057F, "main", 0x400300); }, 3000));
        res = slop::core::mcp::call_tool(
            "debugger", {{"action", "ps5_wait"}, {"timeout_ms", 3000}}, is_err);
        CHECK(!is_err);
        CHECK(res.value("halted", false) == true);
        CHECK(res.value("lwpid", 0) == 101);

        res = slop::core::mcp::call_tool("debugger", {{"action", "ps5_status"}}, is_err);
        CHECK(!is_err);
        CHECK(res.value("connected", false) == true);
        CHECK(res.value("platform", 0) == 5);

        res = slop::core::mcp::call_tool("debugger", {{"action", "ps5_detach"}}, is_err);
        CHECK(!is_err);
        CHECK(res.value("attached", true) == false);
    }

    // MCP: disconnect drops the console and returns to the local backend
    {
        bool is_err = false;
        json res = slop::core::mcp::call_tool("target", {{"action", "ps5_disconnect"}}, is_err);
        CHECK(!is_err);
        CHECK(res.value("connected", true) == false);
    }
    CHECK(!rt::registry_ps5_active());
    CHECK(rt::active_kind() != backend_kind_t::ps5);
    CHECK(!slop::core::process::active_session());

    // MCP: ps5_connect with pid attaches in one call
    {
        bool is_err = false;
        json res = slop::core::mcp::call_tool(
            "target",
            {{"action", "ps5_connect"}, {"host", "127.0.0.1"}, {"port", g.srv.port},
             {"pid", kFakePid}},
            is_err);
        CHECK(!is_err);
        CHECK(res.value("connected", false) == true);
        CHECK(res.value("attached", false) == true);
        CHECK(res.value("pid", 0) == kFakePid);
        REQUIRE_STR_EQ(res.value("name", ""), "eboot.bin");
        CHECK(rt::active_kind() == backend_kind_t::ps5);

        json dres = slop::core::mcp::call_tool("target", {{"action", "ps5_disconnect"}}, is_err);
        CHECK(!is_err);
        CHECK(dres.value("connected", true) == false);
    }
    CHECK(!rt::registry_ps5_active());
}
