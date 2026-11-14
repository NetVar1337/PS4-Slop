// src/tests/test_ps4.cpp
// PS4 (ps4debug-NG) tests against the fake payload in ps4_fixture.hpp:
// backend handshake, memory, threads, registry/session and the MCP target tool.

#include "ps4_fixture.hpp"

TEST_CASE(ps4_backend_handshake_and_enums) {
    server_guard_t g;
    backend_ps4_t b;
    std::string err;
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));
    if (!err.empty()) std::printf("  connect err: %s\n", err.c_str());
    CHECK(b.connected());
    CHECK(b.ping());
    CHECK(b.kind() == backend_kind_t::ps4);
    REQUIRE_STR_EQ(b.badge(), "PS4");
    CHECK(b.branding().find("ps4debug-NG") != std::string::npos);
    CHECK(b.fw_version() == 1100);
    CHECK(b.endpoint() == "127.0.0.1:" + std::to_string(g.srv.port));

    auto procs = b.enum_processes();
    REQUIRE(procs.ok);
    CHECK(procs.items.size() == 2u);
    bool found = false;
    for (const auto& p : procs.items) {
        if (p.pid == kFakePid) {
            found = true;
            REQUIRE_STR_EQ(p.name, "eboot.bin");
            CHECK(p.arch == slop::core::runtime::arch_t::x64);
            CHECK(p.elevation == slop::core::runtime::elevation_t::system);
        }
    }
    CHECK(found);

    auto h = b.attach(kFakePid);
    REQUIRE(h.valid());
    auto bad = b.attach(9999);
    CHECK(!bad.valid());

    auto regions = b.enum_regions(h);
    REQUIRE(regions.ok);
    CHECK(regions.items.size() == 6u);   // eboot text/relro/data + anon gap + sprx + stack
    bool saw_eboot = false;
    for (const auto& r : regions.items) {
        if (r.base == 0x400000) {
            saw_eboot = true;
            CHECK(r.size == 0x80000);    // the text segment only
            CHECK(r.protect == 0x20);   // PAGE_EXECUTE_READ
        }
    }
    CHECK(saw_eboot);

    // one record per module: the three eboot segments coalesce into one
    // module spanning text..data (item: per-segment "modules")
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
    auto segs = b.ps4_modules(h);
    REQUIRE(segs.ok);
    REQUIRE(!segs.items.empty());
    CHECK(segs.items[0].name == "eboot.bin");
    REQUIRE(segs.items[0].segments.size() == 3u);
    CHECK(segs.items[0].segments[1].start == 0x480000);
    CHECK(segs.items[0].segments[2].start == 0x4C8000);

    // the handle knows its name/path without another enumeration
    slop::core::runtime::process_info_t pi;
    REQUIRE(b.handle_info(h, pi));
    REQUIRE_STR_EQ(pi.path, "/app0/eboot.bin");
    CHECK(pi.arch == slop::core::runtime::arch_t::x64);

    CHECK(b.query_arch(h) == slop::core::runtime::arch_t::x64);
    CHECK(b.query_elevation() == slop::core::runtime::elevation_t::system);

    b.detach(h);
    CHECK(!h.valid());
    b.disconnect();
    CHECK(!b.connected());
}

TEST_CASE(ps4_backend_memory_rw_protect_alloc) {
    server_guard_t g;
    backend_ps4_t b;
    std::string err;
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));
    auto h = b.attach(kFakePid);
    REQUIRE(h.valid());

    // write then read back
    std::vector<uint8_t> pattern(64);
    for (size_t i = 0; i < pattern.size(); ++i) pattern[i] = static_cast<uint8_t>(0xA0 + i);
    auto w = b.write_memory(h, 0x400100, pattern.data(), pattern.size());
    REQUIRE(w.ok);
    CHECK(w.bytes == pattern.size());
    std::vector<uint8_t> back(pattern.size(), 0);
    auto r = b.read_memory(h, 0x400100, back.data(), back.size());
    REQUIRE(r.ok);
    CHECK(std::memcmp(back.data(), pattern.data(), pattern.size()) == 0);
    // the fake console really got the bytes
    for (size_t i = 0; i < pattern.size(); ++i)
        CHECK(g.srv.mem_byte(0x400100 + i) == pattern[i]);

    // larger multi-chunk transfer (128 KiB crosses the server 64 KiB chunking)
    std::vector<uint8_t> big(0x20000);
    for (size_t i = 0; i < big.size(); ++i) big[i] = static_cast<uint8_t>(i * 7 + 1);
    REQUIRE(b.write_memory(h, 0x400000, big.data(), big.size()).ok);
    std::vector<uint8_t> bigback(big.size(), 0);
    REQUIRE(b.read_memory(h, 0x400000, bigback.data(), bigback.size()).ok);
    CHECK(std::memcmp(bigback.data(), big.data(), big.size()) == 0);

    // read spanning two adjacent maps (eboot -> sprx) is covered
    std::vector<uint8_t> cross(0x20, 0);
    CHECK(b.read_memory(h, 0x4FFFF0, cross.data(), cross.size()).ok);

    // unmapped read must fail (reader contract: false on any unreadable part)
    std::vector<uint8_t> junk(16, 0);
    auto bad = b.read_memory(h, 0xDEAD0000, junk.data(), junk.size());
    CHECK(!bad.ok);

    // protect translates PAGE_EXECUTE_READWRITE -> VM_PROT_ALL and reports old
    uint32_t old = 0;
    auto pr = b.protect_memory(h, 0x500000, 0x1000, 0x40, &old);
    REQUIRE(pr.ok);
    CHECK(old == 0x20);                 // was PAGE_EXECUTE_READ
    CHECK(g.srv.last_protect == ps4::kVmProtAll);

    // alloc / free
    uintptr_t alloc_addr = 0;
    auto al = b.allocate_memory(h, 0, 0x2000, 0x04, &alloc_addr);
    REQUIRE(al.ok);
    CHECK(alloc_addr == 0x600000);
    auto fr = b.free_memory(h, 0x600000);
    CHECK(fr.ok);

    b.detach(h);
    b.disconnect();
}

TEST_CASE(ps4_backend_threads_and_regs) {
    server_guard_t g;
    backend_ps4_t b;
    std::string err;
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));
    auto h = b.attach(kFakePid);
    REQUIRE(h.valid());

    // enum_threads triggers the lazy debug attach (with the 755 callback)
    auto thr = b.enum_threads(kFakePid);
    REQUIRE(thr.ok);
    CHECK(thr.items.size() == 2u);
    CHECK(thr.items[0].tid == 101);
    CHECK(thr.items[1].tid == 102);
    CHECK(thr.items[0].owner_pid == kFakePid);
    CHECK(thr.items[0].priority == 80);

    slop::core::runtime::thread_context_t ctx{};
    auto gr = b.get_thread_context(101, ctx);
    REQUIRE(gr.ok);
    CHECK(ctx.rip == 0x400123);
    CHECK(ctx.rsp == 0x7FFF00008000ull);
    CHECK(ctx.rax == 0x2A);
    CHECK(ctx.flags == 0x202);

    ctx.rip = 0x400999;
    ctx.rax = 0x1234;
    auto sr = b.set_thread_context(101, ctx);
    REQUIRE(sr.ok);
    slop::core::runtime::thread_context_t ctx2{};
    REQUIRE(b.get_thread_context(101, ctx2).ok);
    CHECK(ctx2.rip == 0x400999);
    CHECK(ctx2.rax == 0x1234);

    b.detach(h);   // detaches the debug session too
    b.disconnect();
}

TEST_CASE(ps4_registry_session_and_mcp_tool) {
    server_guard_t g;
    ps4_disconnect_guard_t guard;   // leaves the registry clean on REQUIRE failure

    std::string err;
    REQUIRE(slop::core::runtime::registry_connect_ps4("127.0.0.1", g.srv.port, err));
    CHECK(slop::core::runtime::registry_ps4_active());
    CHECK(slop::core::runtime::active_kind() == backend_kind_t::ps4);
    REQUIRE_STR_EQ(slop::core::runtime::active_badge(), "PS4");
    CHECK(slop::core::runtime::registry_ps4_endpoint() ==
          "127.0.0.1:" + std::to_string(g.srv.port));
    CHECK(slop::core::runtime::registry_ps4_branding().find("ps4debug-NG") != std::string::npos);

    // attach a session through the normal target service path
    REQUIRE(slop::core::process::target_connect_ps4("127.0.0.1", g.srv.port, kFakePid, err));
    auto s = slop::core::process::active_session();
    REQUIRE(s && s->valid());
    CHECK(s->pid() == kFakePid);
    REQUIRE_STR_EQ(s->name(), "eboot.bin");
    CHECK(s->arch() == slop::core::runtime::arch_t::x64);

    // session hot-path read/write over the wire
    const uint64_t val = 0x1122334455667788ull;
    REQUIRE(s->write(0x400200, &val, sizeof(val)).ok);
    uint64_t back = 0;
    REQUIRE(s->read(0x400200, &back, sizeof(back)).ok);
    CHECK(back == val);

    // MCP: target.list now enumerates the console
    {
        bool is_err = false;
        json res = slop::core::mcp::call_tool("target", {{"action", "list"}}, is_err);
        CHECK(!is_err);
        CHECK(res.value("count", 0) == 2);
    }
    // MCP: target.status reports the PS4 backend + endpoint
    {
        bool is_err = false;
        json res = slop::core::mcp::call_tool("target", {{"action", "status"}}, is_err);
        CHECK(!is_err);
        REQUIRE_STR_EQ(res.value("backend", ""), "PS4");
        CHECK(res.value("attached", false) == true);
        CHECK(res.value("pid", 0) == kFakePid);
        CHECK(res.contains("ps4"));
        CHECK(res["ps4"].value("endpoint", "") == "127.0.0.1:" + std::to_string(g.srv.port));
    }
    // MCP: memory.read rides the session
    {
        bool is_err = false;
        json res = slop::core::mcp::call_tool(
            "memory",
            {{"action", "read"}, {"addr", 0x400200}, {"len", 8}, {"format", "u64"}},
            is_err);
        CHECK(!is_err);
        REQUIRE(res.contains("values"));
        CHECK(res["values"].size() == 1);
        CHECK(res["values"][0].get<uint64_t>() == val);
    }
    // MCP: memory.write then read back through the tool surface
    {
        bool is_err = false;
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

    // MCP: disconnect drops the console and returns to the local backend
    {
        bool is_err = false;
        json res = slop::core::mcp::call_tool("target", {{"action", "ps4_disconnect"}}, is_err);
        CHECK(!is_err);
        CHECK(res.value("connected", true) == false);
    }
    CHECK(!slop::core::runtime::registry_ps4_active());
    CHECK(slop::core::runtime::active_kind() != backend_kind_t::ps4);
    CHECK(!slop::core::process::active_session());

    // MCP: ps4_connect with pid attaches in one call
    {
        bool is_err = false;
        json res = slop::core::mcp::call_tool(
            "target",
            {{"action", "ps4_connect"}, {"host", "127.0.0.1"}, {"port", g.srv.port}, {"pid", kFakePid}},
            is_err);
        CHECK(!is_err);
        if (is_err) std::printf("  ps4_connect error: %s\n", res.dump().c_str());
        CHECK(res.value("connected", false) == true);
        CHECK(res.value("attached", false) == true);
        CHECK(res.value("pid", 0) == kFakePid);
        REQUIRE_STR_EQ(res.value("name", ""), "eboot.bin");
        CHECK(slop::core::runtime::active_kind() == backend_kind_t::ps4);

        // threads over MCP while attached
        bool is_err2 = false;
        json tres = slop::core::mcp::call_tool("target", {{"action", "threads"}}, is_err2);
        CHECK(!is_err2);
        CHECK(tres.value("count", 0) == 2);

        json dres = slop::core::mcp::call_tool("target", {{"action", "ps4_disconnect"}}, is_err2);
        CHECK(!is_err2);
        CHECK(dres.value("connected", true) == false);
    }
    CHECK(!slop::core::runtime::registry_ps4_active());
}

TEST_CASE(ps4_connect_refuses_non_ps4debug_server) {
    // a plain TCP listener that never speaks the protocol must fail the handshake
    wsa();
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(ls != INVALID_SOCKET);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    REQUIRE(bind(ls, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    REQUIRE(listen(ls, 1) == 0);
    int len = sizeof(addr);
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
            char buf[64];
            ::recv(c, buf, sizeof(buf), 0);   // swallow the handshake, say nothing
            closesocket(c);
        }
    });

    backend_ps4_t b;
    std::string err;
    CHECK(!b.connect("127.0.0.1", port, err));
    CHECK(!err.empty());
    CHECK(!b.connected());

    stop = true;
    ::shutdown(ls, SD_BOTH);
    closesocket(ls);
    th.join();
}
