// src/tests/test_ps4.cpp
// PS4 (ps4debug-NG) tests against the fake payload in ps4_fixture.hpp:
// backend handshake, memory, threads, registry/session, the MCP target tool
// and the saved-console manager (switch between two fake consoles).

#include "ps4_fixture.hpp"

#include "core/infra/settings.hpp"
#include "core/memory/watch_service.hpp"
#include "core/runtime/console_manager.hpp"

#include <filesystem>
#include <tuple>

namespace {

// the console manager persists through the settings store: point it at a
// scratch file so the real profile is never touched
struct scratch_settings_t {
    std::filesystem::path dir;
    scratch_settings_t() {
        dir = std::filesystem::temp_directory_path() /
              ("slop_ps4_consoles_" + std::to_string(::GetCurrentProcessId()) + "_" +
               std::to_string(static_cast<long long>(::GetTickCount64())));
        std::filesystem::create_directories(dir);
        slop::core::infra::settings::set_file_for_testing((dir / "settings.json").string());
        slop::core::infra::settings::load();
    }
    ~scratch_settings_t() {
        // back to the default store; the real profile is never read or written
        slop::core::infra::settings::set_file_for_testing({});
    }
};

} // namespace

TEST_CASE(ps4_backend_handshake_and_enums) {
    server_guard_t g;
    backend_ps4_t b;
    std::string err;
    REQUIRE(connect_fake(b, g.srv, err));
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
    REQUIRE(connect_fake(b, g.srv, err));
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
    REQUIRE(connect_fake(b, g.srv, err));
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
    REQUIRE(connect_fake_registry(g.srv, err));
    CHECK(slop::core::runtime::registry_ps4_active());
    CHECK(slop::core::runtime::active_kind() == backend_kind_t::ps4);
    REQUIRE_STR_EQ(slop::core::runtime::active_badge(), "PS4");
    CHECK(slop::core::runtime::registry_ps4_endpoint() ==
          "127.0.0.1:" + std::to_string(g.srv.port));
    CHECK(slop::core::runtime::registry_ps4_branding().find("ps4debug-NG") != std::string::npos);

    // attach a session through the normal target service path
    REQUIRE(connect_fake_target(g.srv, kFakePid, err));
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

TEST_CASE(ps4_consoles_crud_persists_and_validates) {
    scratch_settings_t cfg;
    bool e = false;

    json saved = slop::core::mcp::call_tool(
        "target",
        {{"action", "consoles_save"},
         {"name", "devkit-a"},
         {"host", "127.0.0.1"},
         {"port", 744},
         {"notes", "primary devkit"},
         {"default_pid", kFakePid},
         {"title_filter", "eboot"},
         {"auto_connect", true},
         {"profile", {{"watchlist", "a-set"}, {"scan_width", "u32"}, {"scan_kind", "changed"}}}},
        e);
    REQUIRE(!e);
    CHECK(saved.value("saved", false));
    CHECK(saved["console"].value("name", "") == "devkit-a");
    CHECK(saved["console"].value("default_pid", 0u) == kFakePid);
    CHECK(saved["console"]["profile"].value("scan_width", "") == "u32");

    // upsert: the same name replaces instead of appending
    saved = slop::core::mcp::call_tool(
        "target",
        {{"action", "consoles_save"}, {"name", "devkit-a"}, {"host", "10.0.0.9"},
         {"port", 745}, {"notes", "moved"}},
        e);
    REQUIRE(!e);
    json listed = slop::core::mcp::call_tool("target", {{"action", "consoles_list"}}, e);
    REQUIRE(!e);
    CHECK(listed.value("count", 0) == 1);
    CHECK(listed["consoles"][0].value("host", "") == "10.0.0.9");
    CHECK(listed["consoles"][0].value("port", 0) == 745);
    CHECK(listed["consoles"][0].value("notes", "") == "moved");
    CHECK(listed.value("active", "x").empty());

    // invalid endpoint values are refused, the list is untouched
    slop::core::mcp::call_tool(
        "target", {{"action", "consoles_save"}, {"name", "bad name"}, {"host", "1.2.3.4"}}, e);
    CHECK(e);
    e = false;
    slop::core::mcp::call_tool(
        "target", {{"action", "consoles_save"}, {"name", "empty-host"}, {"host", ""}}, e);
    CHECK(e);
    e = false;
    slop::core::mcp::call_tool(
        "target", {{"action", "consoles_save"}, {"name", "bad-port"}, {"host", "1.2.3.4"},
                   {"port", 70000}},
        e);
    CHECK(e);
    e = false;
    listed = slop::core::mcp::call_tool("target", {{"action", "consoles_list"}}, e);
    REQUIRE(!e);
    CHECK(listed.value("count", 0) == 1);

    // persisted: the settings file holds the list and a reload reads it back
    const json raw = slop::core::infra::settings::get_json("target_consoles");
    REQUIRE(raw.is_array());
    CHECK(raw.size() == 1);
    slop::core::infra::settings::load();
    listed = slop::core::mcp::call_tool("target", {{"action", "consoles_list"}}, e);
    REQUIRE(!e);
    CHECK(listed.value("count", 0) == 1);
    CHECK(listed["consoles"][0].value("name", "") == "devkit-a");

    // remove drops the endpoint and its watchlist set
    slop::core::mcp::call_tool("target", {{"action", "consoles_remove"}, {"name", "devkit-a"}}, e);
    REQUIRE(!e);
    listed = slop::core::mcp::call_tool("target", {{"action", "consoles_list"}}, e);
    REQUIRE(!e);
    CHECK(listed.value("count", 0) == 0);
    slop::core::mcp::call_tool("target", {{"action", "consoles_remove"}, {"name", "devkit-a"}}, e);
    CHECK(e);
}

TEST_CASE(ps4_consoles_switch_between_two_consoles_restores_profile) {
    scratch_settings_t cfg;
    server_guard_t a;
    server_guard_t b;
    ps4_disconnect_guard_t guard;
    bool e = false;

    // two saved consoles, each with its own profile
    for (const auto& [name, port, set, width, kind] :
         {std::tuple{"devkit-a", a.srv.port, "a-set", "u32", "changed"},
          std::tuple{"devkit-b", b.srv.port, "b-set", "f32", "exact"}}) {
        slop::core::mcp::call_tool(
            "target",
            {{"action", "consoles_save"},
             {"name", name},
             {"host", "127.0.0.1"},
             {"port", port},
             {"default_pid", kFakePid},
             {"profile",
              {{"watchlist", set}, {"scan_width", width}, {"scan_kind", kind}}}},
            e);
        REQUIRE(!e);
    }

    // switch to A: connects, attaches its default pid, applies its scan defaults
    json sw = slop::core::mcp::call_tool(
        "target", {{"action", "consoles_switch"}, {"name", "devkit-a"}}, e);
    REQUIRE(!e);
    if (e) std::printf("  switch a: %s\n", sw.dump().c_str());
    CHECK(sw.value("switched", false));
    CHECK(sw.value("name", "") == "devkit-a");
    CHECK(sw.value("attached", false));
    CHECK(sw.value("pid", 0u) == kFakePid);
    CHECK(sw.value("endpoint", "") == "127.0.0.1:" + std::to_string(a.srv.port));
    CHECK(sw["profile"].value("scan_width", "") == "u32");
    CHECK(slop::core::runtime::consoles::active() == "devkit-a");
    json st = slop::core::mcp::call_tool("target", {{"action", "status"}}, e);
    REQUIRE(!e);
    CHECK(st.value("console", "") == "devkit-a");

    // the fake payload connects its debug channel back to the fixture's own
    // ephemeral port, not the machine-global 755
    REQUIRE(slop::core::runtime::registry_ps4() != nullptr);
    slop::core::runtime::registry_ps4()->set_event_port(a.srv.event_port);

    // a watch entry and an armed breakpoint belong to A
    slop::core::mcp::call_tool(
        "memory", {{"action", "watch_add"}, {"addr", 0x400200}, {"width", "u32"}}, e);
    REQUIRE(!e);
    CHECK(slop::core::memory::watch::size() == 1);
    slop::core::mcp::call_tool("debugger", {{"action", "ps4_attach"}, {"pid", kFakePid}}, e);
    REQUIRE(!e);
    slop::core::mcp::call_tool("debugger", {{"action", "ps4_bp_set"}, {"addr", 0x400500}}, e);
    REQUIRE(!e);
    REQUIRE(slop::core::runtime::registry_ps4() != nullptr);
    CHECK(slop::core::runtime::registry_ps4()->ps4_breakpoints().size() == 1);

    // switch to B: the session, the debugger slots and the watchlist go, B's
    // profile comes back (empty set + its scan defaults)
    sw = slop::core::mcp::call_tool(
        "target", {{"action", "consoles_switch"}, {"name", "devkit-b"}}, e);
    REQUIRE(!e);
    if (e) std::printf("  switch b: %s\n", sw.dump().c_str());
    CHECK(sw.value("previous", "") == "devkit-a");
    CHECK(sw.value("pid", 0u) == kFakePid);
    CHECK(sw.value("endpoint", "") == "127.0.0.1:" + std::to_string(b.srv.port));
    CHECK(sw.value("watchlist_entries", 99) == 0);
    CHECK(sw["profile"].value("scan_width", "") == "f32");
    CHECK(sw["profile"].value("scan_kind", "") == "exact");
    CHECK(slop::core::memory::watch::size() == 0);
    CHECK(slop::core::runtime::registry_ps4()->ps4_breakpoints().empty());
    json scan = slop::core::mcp::call_tool("memory", {{"action", "scan_state"}}, e);
    REQUIRE(!e);
    CHECK(scan.value("width", "") == "f32");
    CHECK(scan.value("kind", "") == "exact");

    // B gets its own watch entry, then switching back restores A's set
    slop::core::mcp::call_tool(
        "memory", {{"action", "watch_add"}, {"addr", 0x500000}, {"width", "u8"}}, e);
    REQUIRE(!e);
    slop::core::mcp::call_tool(
        "target", {{"action", "consoles_switch"}, {"name", "devkit-a"}}, e);
    REQUIRE(!e);
    CHECK(slop::core::memory::watch::size() == 1);
    const auto entries = slop::core::memory::watch::list();
    REQUIRE(entries.size() == 1u);
    CHECK(entries[0].addr == 0x400200);
    CHECK(entries[0].width == slop::core::memory::value_width_t::u32);
    // A was last seen on its own port, and the switch recorded firmware
    json listed = slop::core::mcp::call_tool("target", {{"action", "consoles_list"}}, e);
    REQUIRE(!e);
    bool saw_fw = false;
    for (const auto& c : listed["consoles"]) {
        if (c.value("name", "") != "devkit-a") continue;
        saw_fw = c.value("last_fw", "") == "11.00";
        CHECK(c.value("active", false));
        CHECK(c.value("last_seen_ms", int64_t{0}) > 0);
    }
    CHECK(saw_fw);

    // switching to an unknown name fails without dropping the live console
    slop::core::mcp::call_tool("target", {{"action", "consoles_switch"}, {"name", "nope"}}, e);
    CHECK(e);
    CHECK(slop::core::runtime::registry_ps4_active());
    CHECK(slop::core::process::active_session() != nullptr);
}

// The CMD_PROC_LIST reply body decoder is pure (no socket), so it is also the
// ps4debug-NG reply parser the fuzz target drives. A short or garbage body
// must never read past the buffer.
TEST_CASE(ps4_parse_proc_list_body) {
    std::vector<uint8_t> body;
    const auto append = [&body](const char* name, int32_t pid) {
        ps4::proc_list_entry_t e{};
        std::strncpy(e.p_comm, name, sizeof(e.p_comm) - 1);
        e.pid = pid;
        const auto* p = reinterpret_cast<const uint8_t*>(&e);
        body.insert(body.end(), p, p + sizeof(e));
    };
    append("eboot.bin", 1234);
    append("SceShellUI", 42);

    auto procs = slop::core::runtime::ps4_parse_proc_list(body.data(), body.size());
    REQUIRE(procs.size() == 2u);
    CHECK(procs[0].pid == 1234u);
    REQUIRE_STR_EQ(procs[0].name, "eboot.bin");
    CHECK(procs[0].arch == slop::core::runtime::arch_t::x64);
    CHECK(procs[1].pid == 42u);
    REQUIRE_STR_EQ(procs[1].name, "SceShellUI");

    // a trailing partial entry is ignored, not decoded from a short read
    body.push_back(0xAA);
    CHECK(slop::core::runtime::ps4_parse_proc_list(body.data(), body.size()).size() == 2u);
    CHECK(slop::core::runtime::ps4_parse_proc_list(body.data(), 0).empty());
    CHECK(slop::core::runtime::ps4_parse_proc_list(nullptr, 0).empty());

    // an unterminated p_comm stops at the field boundary
    std::vector<uint8_t> full(sizeof(ps4::proc_list_entry_t), 'A');
    procs = slop::core::runtime::ps4_parse_proc_list(full.data(), full.size());
    REQUIRE(procs.size() == 1u);
    REQUIRE(procs[0].name.size() == sizeof(ps4::proc_list_entry_t::p_comm));
}
