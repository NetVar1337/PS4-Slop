// src/tests/test_ps4_tooling.cpp
// PS4 (ps4debug-NG) tests against the fake payload in ps4_fixture.hpp:
// console info, module dumps, heartbeat, backend swap, local composites, bulk writes, Turbo Scan, fork extensions and the GDB bridge.

#include "ps4_fixture.hpp"

#include "core/infra/event_bus.hpp"

#include <tlhelp32.h>

TEST_CASE(ps4_status_console_info_and_mcp_reconnect) {
    server_guard_t g;
    ps4_disconnect_guard_t guard;
    std::string err;
    REQUIRE(connect_fake_target(g.srv, kFakePid, err));
    bool e = false;
    auto call = [&](const char* tool, const json& a) {
        return slop::core::mcp::call_tool(tool, a, e);
    };
    json r = call("debugger", {{"action", "ps4_status"}});
    CHECK(!e);
    CHECK(r.value("fw", std::string{}) == "11.00");
    CHECK(r.value("connected", false) == true);
    CHECK(r.value("events_dropped", 99) == 0);
    CHECK(r.value("lost", true) == false);
    r = call("target", {{"action", "status"}});
    CHECK(!e);
    REQUIRE(r.contains("ps4"));
    CHECK(r["ps4"].value("fw", std::string{}) == "11.00");
    CHECK(r["ps4"].value("connected", false) == true);
    r = call("debugger", {{"action", "ps4_console_info"}});
    CHECK(!e);
    if (e) std::printf("  ps4_console_info err: %s\n", r.dump().c_str());
    CHECK(r.value("alive", false) == true);
    CHECK(r.value("fw", std::string{}) == "11.00");
    CHECK(r.value("platform", std::string{}) == "PS4");
    CHECK(r.value("caps", std::string{}) == "1.1");
    CHECK(r["foreground_app"].value("pid", 0) == kFakePid);

    // the console drops mid-read: the error names it, status shows lost
    g.srv.chaos.close_after = 0;
    g.srv.chaos.close_cmd = ps4::CMD_PROC_READ;
    r = call("memory", {{"action", "read"}, {"addr", 0x400000}, {"len", 16}});
    CHECK(e);
    r = call("target", {{"action", "status"}});
    CHECK(!e);
    CHECK(r["ps4"].value("connected", true) == false);
    CHECK(r["ps4"].value("lost", false) == true);
    CHECK(r.value("attached", false) == true);   // the session survives the drop
    r = call("debugger", {{"action", "ps4_regs"}, {"lwpid", 101}});
    CHECK(e);
    CHECK(r.dump().find("ps4_reconnect") != std::string::npos);

    r = call("target", {{"action", "ps4_reconnect"}});
    CHECK(!e);
    if (e) std::printf("  ps4_reconnect err: %s\n", r.dump().c_str());
    CHECK(r.value("connected", false) == true);
    CHECK(r.value("session_kept", false) == true);
    r = call("memory", {{"action", "read"}, {"addr", 0x400000}, {"len", 16}});
    CHECK(!e);
}

TEST_CASE(ps4_dump_module_rebuilds_elf_for_headerless_image) {
    server_guard_t g;
    ps4_disconnect_guard_t guard;
    std::string err;
    REQUIRE(connect_fake_target(g.srv, kFakePid, err));
    // no ELF header in console memory (the SELF loader does not map it);
    // distinct bytes per segment so the file layout can be checked
    const uint8_t text[8] = {0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3};   // push rbp..ret
    const uint8_t relro[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    const uint8_t data[4] = {0x11, 0x22, 0x33, 0x44};
    g.srv.mem_write(0x400000, text, sizeof(text));
    g.srv.mem_write(0x480010, relro, sizeof(relro));
    g.srv.mem_write(0x4C8020, data, sizeof(data));
    bool e = false;
    const char* out = "ps4_dump_elf_test.elf";
    json r = slop::core::mcp::call_tool("target",
        {{"action", "ps4_dump_module"}, {"name", "eboot.bin"}, {"path", out}, {"format", "elf"}}, e);
    CHECK(!e);
    if (e) std::printf("  ps4_dump_module elf err: %s\n", r.dump().c_str());
    CHECK(r.value("elf_header_in_memory", true) == false);
    CHECK(r.value("segment_count", 0) == 3u);
    std::ifstream f(out, std::ios::binary);
    REQUIRE(f.good());
    std::vector<uint8_t> file((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    f.close();
    REQUIRE(file.size() > 64u + 3u * 56u);
    CHECK(std::memcmp(file.data(), "\x7f" "ELF", 4) == 0);
    CHECK(file[4] == 2);   // ELFCLASS64
    uint16_t e_type = 0, e_machine = 0, e_phnum = 0;
    uint64_t e_phoff = 0;
    std::memcpy(&e_type, file.data() + 16, 2);
    std::memcpy(&e_machine, file.data() + 18, 2);
    std::memcpy(&e_phoff, file.data() + 32, 8);
    std::memcpy(&e_phnum, file.data() + 56, 2);
    CHECK(e_type == 2);      // ET_EXEC: p_vaddr are runtime addresses
    CHECK(e_machine == 62);  // EM_X86_64
    REQUIRE(e_phnum == 3);
    const uint64_t want_va[3] = {0x400000, 0x480000, 0x4C8000};
    const uint64_t want_sz[3] = {0x80000, 0x40000, 0x38000};
    const uint32_t want_fl[3] = {5, 4, 6};   // R+X, R, R+W
    const uint64_t probe[3] = {0x400000, 0x480010, 0x4C8020};
    const uint8_t* probe_bytes[3] = {text, relro, data};
    const size_t probe_len[3] = {sizeof(text), sizeof(relro), sizeof(data)};
    for (int i = 0; i < 3; ++i) {
        const uint8_t* ph = file.data() + e_phoff + static_cast<size_t>(i) * 56;
        uint32_t p_type = 0, p_flags = 0;
        uint64_t p_offset = 0, p_vaddr = 0, p_filesz = 0, p_memsz = 0;
        std::memcpy(&p_type, ph, 4);
        std::memcpy(&p_flags, ph + 4, 4);
        std::memcpy(&p_offset, ph + 8, 8);
        std::memcpy(&p_vaddr, ph + 16, 8);
        std::memcpy(&p_filesz, ph + 32, 8);
        std::memcpy(&p_memsz, ph + 40, 8);
        CHECK(p_type == 1);
        CHECK(p_vaddr == want_va[i]);
        CHECK(p_filesz == want_sz[i]);
        CHECK(p_memsz == want_sz[i]);
        CHECK(p_flags == want_fl[i]);
        CHECK(p_offset % 0x1000 == p_vaddr % 0x1000);
        REQUIRE(p_offset + p_filesz <= file.size());
        CHECK(std::memcmp(file.data() + p_offset + (probe[i] - p_vaddr), probe_bytes[i],
                          probe_len[i]) == 0);
    }
    std::remove(out);

    // raw + load is refused; load=true defaults to the rebuilt ELF and opens it
    r = slop::core::mcp::call_tool("target",
        {{"action", "ps4_dump_module"}, {"name", "eboot.bin"}, {"path", out},
         {"format", "raw"}, {"load", true}}, e);
    CHECK(e);
    r = slop::core::mcp::call_tool("target",
        {{"action", "ps4_dump_module"}, {"base", 0x400000}, {"path", out}, {"load", true}}, e);
    CHECK(!e);
    if (e) std::printf("  ps4_dump_module load err: %s\n", r.dump().c_str());
    CHECK(r.value("format", std::string{}) == "elf");
    CHECK(r.value("loaded", false) == true);
    if (!r.value("loaded", false)) std::printf("  load_note: %s\n", r.value("load_note", std::string{}).c_str());
    json l = slop::core::mcp::call_tool("disasm", {{"action", "disassemble"}, {"addr", 0x400000}, {"count", 2}}, e);
    CHECK(!e);
    CHECK(l.dump().find("PUSH") != std::string::npos);   // engine emits capitalized mnemonics
    slop::core::mcp::call_tool("disasm", {{"action", "unload"}}, e);
    std::remove(out);
}

TEST_CASE(ps4_heartbeat_tolerates_misses_and_debug_sessions) {
    namespace proc = slop::core::process;
    server_guard_t g;
    ps4_disconnect_guard_t guard;
    std::string err;
    REQUIRE(connect_fake_target(g.srv, kFakePid, err));
    proc::target_set_heartbeat_interval_ms(0);
    struct restore_t { ~restore_t() { slop::core::process::target_set_heartbeat_interval_ms(1000); } } restore;

    // the pid vanishes from the list: two misses keep the session
    g.srv.chaos.hide_game_pid = true;
    proc::target_tick();
    proc::target_tick();
    CHECK(proc::active_session() != nullptr);
    // the pid comes back: the miss counter resets
    g.srv.chaos.hide_game_pid = false;
    proc::target_tick();
    g.srv.chaos.hide_game_pid = true;
    proc::target_tick();
    proc::target_tick();
    CHECK(proc::active_session() != nullptr);

    // while a debug session is attached the heartbeat stays off the wire
    auto* p = rt::registry_ps4();
    REQUIRE(p != nullptr);
    REQUIRE(p->ps4_debug_attach(kFakePid, err));
    for (int i = 0; i < 5; ++i) proc::target_tick();
    CHECK(proc::active_session() != nullptr);
    p->ps4_debug_detach();

    // three consecutive misses drop it
    proc::target_tick();
    proc::target_tick();
    proc::target_tick();
    CHECK(proc::active_session() == nullptr);
    g.srv.chaos.hide_game_pid = false;
}

TEST_CASE(ps4_backend_swap_detaches_session) {
    namespace proc = slop::core::process;
    server_guard_t a;
    server_guard_t b2;
    ps4_disconnect_guard_t guard;
    std::string err;
    REQUIRE(connect_fake_target(a.srv, kFakePid, err));
    auto held = proc::active_session();   // e.g. a long scan still holding it
    REQUIRE(held && held->valid());
    uint8_t v = 0x5A;
    REQUIRE(held->write(0x7FFF00000040ull, &v, 1).ok);

    // switching consoles detaches the session first ...
    REQUIRE(connect_fake_registry(b2.srv, err));
    CHECK(proc::active_session() == nullptr);
    // ... and the old handle can never reach the new console
    uint8_t got = 0;
    auto io = held->read(0x7FFF00000040ull, &got, 1);
    CHECK(!io.ok);
    CHECK(io.error == ps4::kErrStaleHandle);
    io = held->write(0x7FFF00000040ull, &v, 1);
    CHECK(io.error == ps4::kErrStaleHandle);
    CHECK(b2.srv.mem_byte(0x7FFF00000040ull) == 0);
    held.reset();
}

namespace {

// a local process running an endless call loop we can debug: cmd.exe-free
// shellcode in a PING.EXE that idles until it is killed. `-t` (not `-n N`)
// keeps the debuggee alive past any test duration: the old two-minute budget
// expired under a loaded full-suite run and took the whole test down with it
struct loop_target_t {
    PROCESS_INFORMATION pi{};
    uint64_t base = 0;
    bool ok = false;

    // 0x00 loop: rcx = ++counter; rdx = 0x1234; call func; pause; jmp loop
    // 0x40 func: [data] = rcx; rax = rcx; ret       counter 0x100, data 0x108
    static std::vector<uint8_t> code() {
        std::vector<uint8_t> c(0x200, 0xCC);
        const uint8_t loop[] = {0x48, 0x8B, 0x0D, 0xF9, 0x00, 0x00, 0x00,   // mov rcx,[rip+F9]
                                0x48, 0xFF, 0xC1,                           // inc rcx
                                0x48, 0x89, 0x0D, 0xEF, 0x00, 0x00, 0x00,   // mov [rip+EF],rcx
                                0x48, 0xC7, 0xC2, 0x34, 0x12, 0x00, 0x00,   // mov rdx,0x1234
                                0xE8, 0x23, 0x00, 0x00, 0x00,               // call 0x40
                                0xF3, 0x90,                                 // pause
                                0xEB, 0xDF};                                // jmp 0x00
        const uint8_t func[] = {0x48, 0x89, 0x0D, 0xC1, 0x00, 0x00, 0x00,   // mov [rip+C1],rcx
                                0x48, 0x89, 0xC8,                           // mov rax,rcx
                                0xC3};                                      // ret
        std::memcpy(c.data(), loop, sizeof(loop));
        std::memcpy(c.data() + 0x40, func, sizeof(func));
        std::memset(c.data() + 0x100, 0, 16);
        return c;
    }

    loop_target_t() {
        wchar_t cmd[] = L"C:\\Windows\\System32\\PING.EXE -t 127.0.0.1";
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
        HANDLE nul = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 &sa, OPEN_EXISTING, 0, nullptr);
        si.hStdInput = si.hStdOutput = si.hStdError = nul;
        if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr,
                            &si, &pi)) {
            CloseHandle(nul);
            return;
        }
        CloseHandle(nul);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));   // loader done
        void* mem = VirtualAllocEx(pi.hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
        if (!mem) return;
        base = reinterpret_cast<uint64_t>(mem);
        const auto c = code();
        SIZE_T n = 0;
        if (!WriteProcessMemory(pi.hProcess, mem, c.data(), c.size(), &n) || n != c.size()) return;
        FlushInstructionCache(pi.hProcess, mem, c.size());
        HANDLE th = CreateRemoteThread(pi.hProcess, nullptr, 0,
                                       reinterpret_cast<LPTHREAD_START_ROUTINE>(mem), nullptr, 0, nullptr);
        if (!th) return;
        CloseHandle(th);
        ok = true;
    }
    ~loop_target_t() {
        if (pi.hProcess) {
            TerminateProcess(pi.hProcess, 0);
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hProcess);
        }
        if (pi.hThread) CloseHandle(pi.hThread);
    }
    bool alive() const { return pi.hProcess && WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT; }
};

} // namespace

TEST_CASE_TIMEOUT(ps4_composites_on_local_debugger, 180) {
    // the composite flows run unchanged on the local Win32 debugger, so they
    // are exercised end to end without a console
    slop::core::process::target_disconnect_ps4();
    loop_target_t t;
    REQUIRE(t.ok);
    const uint64_t func = t.base + 0x40, data = t.base + 0x108;
    {
        dbgns::local_debugger_t d;
        std::string err;
        REQUIRE(d.attach(t.pi.dwProcessId, err));
        if (!err.empty()) std::printf("  local attach: %s\n", err.c_str());

        auto u = dbgns::run_until(d, func, 10000);
        REQUIRE(u.ok);
        REQUIRE(u.halted);
        CHECK(u.ev.ctx.rip == func);
        CHECK(u.ev.ctx.rdx == 0x1234);
        CHECK(u.ev.reason == "breakpoint");
        CHECK(d.breakpoints().empty());   // one-shot slot released
        CHECK(d.stopped());

        // three consecutive calls, rcx counts up by one per call
        auto tc = dbgns::trace_calls(d, func, 3, 10000);
        REQUIRE(tc.ok);
        REQUIRE(tc.hits.size() == 3u);
        CHECK(tc.hits[1].ctx.rcx == tc.hits[0].ctx.rcx + 1);
        CHECK(tc.hits[2].ctx.rcx == tc.hits[1].ctx.rcx + 1);
        CHECK(tc.stop_reason == "count_reached");

        // step through func: mov [data] -> mov rax -> ret -> pause -> jmp
        auto ts = dbgns::trace_steps(d, 0, 4, 10000);
        REQUIRE(ts.ok);
        REQUIRE(ts.steps.size() == 4u);
        CHECK(ts.steps[0].rip == func + 0x7);
        CHECK(ts.steps[1].rip == func + 0xA);
        CHECK(ts.steps[2].rip == t.base + 0x1D);
        CHECK(ts.steps[3].rip == t.base + 0x1F);
        CHECK(ts.steps[0].nbytes == 16u);

        // who writes data: the DR trap fires right after func's store
        auto fw = dbgns::find_write(d, data, 8, 10000, 8);
        REQUIRE(fw.ok);
        REQUIRE(fw.halted);
        CHECK(fw.ev.reason == "watchpoint");
        CHECK(fw.ev.ctx.rip == func + 0x7);
        REQUIRE(!fw.frames.empty());
        CHECK(d.watchpoints().empty());

        // reads hide our int3 bytes
        uint32_t idx = 0;
        bool reused = false;
        REQUIRE(d.bp_arm(func, idx, reused).ok);
        uint8_t byte = 0;
        REQUIRE(d.read(func, &byte, 1));
        CHECK(byte == 0x48);
        REQUIRE(d.bp_disarm(func).ok);
        CHECK(d.bp_disarm(func).error == ps4::kErrNotArmed);
        d.detach();
        CHECK(!d.attached());
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(t.alive());   // detaching left the process running

    // the same flow through MCP on an attached local test-lab session
    REQUIRE(slop::core::process::target_attach(t.pi.dwProcessId));
    bool e = false;
    json r = slop::core::mcp::call_tool("debugger",
        {{"action", "ps4_until"}, {"addr", func}, {"timeout_ms", 10000}}, e);
    CHECK(!e);
    if (e) std::printf("  local ps4_until err: %s\n", r.dump().c_str());
    CHECK(r.value("halted", false) == true);
    CHECK(r.value("debugger", std::string{}) == "user");
    CHECK(r.value("rip", 0ull) == func);
    r = slop::core::mcp::call_tool("debugger",
        {{"action", "ps4_trace_calls"}, {"addr", func}, {"count", 2}, {"timeout_ms", 10000}}, e);
    CHECK(!e);
    CHECK(r.value("hits_count", 0) == 2);
    r = slop::core::mcp::call_tool("debugger", {{"action", "ps4_detach"}}, e);
    CHECK(!e);
    CHECK(r.value("was_attached", false) == true);
    slop::core::process::target_detach();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(t.alive());
}

namespace slop::core::mcp::detail { size_t target_icon_cache_size(); }

TEST_CASE(ps4_target_icon_cache_is_bounded) {
    bool e = false;
    for (int batch = 0; batch < 5; ++batch) {
        json paths = json::array();
        for (int i = 0; i < 64; ++i)
            paths.push_back("C:\\nonexistent\\slop_icon_" + std::to_string(batch * 64 + i) + ".exe");
        slop::core::mcp::call_tool("target", {{"action", "icon"}, {"paths", paths}}, e);
        CHECK(!e);
    }
    CHECK(slop::core::mcp::detail::target_icon_cache_size() <= 256u);
    CHECK(slop::core::mcp::detail::target_icon_cache_size() >= 64u);
}

TEST_CASE(ps4_write_multi_bulk_poke) {
    server_guard_t g;
    backend_ps4_t b;
    std::string err;
    REQUIRE(connect_fake(b, g.srv, err));
    CHECK(b.ps4_capability_level() == "1.1");

    std::vector<backend_ps4_t::ps4_write_entry_t> w(3);
    w[0].addr = 0x7FFF00000100; w[0].bytes = {0x11, 0x22, 0x33, 0x44};
    w[1].addr = 0x7FFF00000200; w[1].bytes = {0xAA};
    w[2].addr = 0x7FFF00000300; w[2].bytes.assign(0x2000, 0x5C);   // multi-page entry
    std::vector<uint8_t> status;
    auto io = b.ps4_write_multi(kFakePid, w, true, status);
    REQUIRE(io.ok);
    CHECK(io.bytes == 4u + 1u + 0x2000u);
    REQUIRE(status.size() == 3u);
    CHECK(status[0] == ps4::kWriteStatusOk && status[1] == ps4::kWriteStatusOk &&
          status[2] == ps4::kWriteStatusOk);
    CHECK(g.srv.write_multi_calls == 1);       // one exchange for all three
    CHECK(g.srv.last_write_multi_count == 3u);
    CHECK(g.srv.mem_byte(0x7FFF00000103) == 0x44);
    CHECK(g.srv.mem_byte(0x7FFF00000200) == 0xAA);
    CHECK(g.srv.mem_byte(0x7FFF000022FF) == 0x5C);

    // per-entry failure is reported through the status array, the rest lands
    g.srv.write_deny_addr = 0x7FFF00000200;
    w[0].bytes = {0x01, 0x02, 0x03, 0x04};
    io = b.ps4_write_multi(kFakePid, w, true, status);
    REQUIRE(io.ok);
    REQUIRE(status.size() == 3u);
    CHECK(status[1] == ps4::kWriteStatusVerifyFailed);
    CHECK(status[0] == ps4::kWriteStatusOk);
    CHECK(g.srv.mem_byte(0x7FFF00000100) == 0x01);

    // without a status array a failed entry makes the call fail
    io = b.ps4_write_multi(kFakePid, w, false, status);
    CHECK(!io.ok);
    CHECK(io.error == 7u);
    CHECK(status.empty());

    // caps are enforced locally so the stream never desyncs
    std::vector<backend_ps4_t::ps4_write_entry_t> big(1);
    big[0].addr = 0x7FFF00000000;
    big[0].bytes.assign(ps4::kWriteMultiMaxEntry + 1, 0);
    io = b.ps4_write_multi(kFakePid, big, true, status);
    CHECK(!io.ok);
    CHECK(b.ping());   // connection still in sync
    b.disconnect();
}

TEST_CASE(ps4_turbo_scan_backend) {
    server_guard_t g;
    backend_ps4_t b;
    std::string err;
    REQUIRE(connect_fake(b, g.srv, err));
    REQUIRE(b.ps4_authed());

    backend_ps4_t::ps4_turbo_caps_t caps;
    REQUIRE(b.ps4_turbo_caps(caps).ok);
    CHECK(caps.version == 1u);
    CHECK((caps.engines & ps4::kTseServerResident) != 0);

    const auto put32 = [&](uint64_t a, uint32_t v) {
        g.srv.mem_write(a, reinterpret_cast<const uint8_t*>(&v), 4);
    };
    put32(0x7FFF00000010, 100);
    put32(0x7FFF00000020, 100);
    put32(0x7FFF00000030, 7);

    // resident known-value scan: only a count crosses the wire
    backend_ps4_t::ps4_turbo_start_t req;
    req.pid = kFakePid;
    req.addr = 0x7FFF00000000;
    req.len = 0x1000;
    req.valtype = ps4::kValU32;
    req.cmptype = ps4::kCmpExact;
    req.flags = ps4::kTsServerResident | ps4::kTsUseAliasing;
    req.data = {100, 0, 0, 0};
    backend_ps4_t::ps4_turbo_result_t res;
    auto io = b.ps4_turbo_start(req, res);
    REQUIRE(io.ok);
    CHECK(res.resident);
    CHECK(res.count == 2u);
    CHECK(res.hits.empty());
    CHECK(g.srv.last_turbo_flags == (ps4::kTsServerResident | ps4::kTsUseAliasing));

    std::vector<backend_ps4_t::ps4_turbo_record_t> recs;
    REQUIRE(b.ps4_turbo_get(0, 16, 4, recs).ok);
    REQUIRE(recs.size() == 2u);
    CHECK(recs[0].addr == 0x7FFF00000010ull);
    CHECK(recs[0].current == std::vector<uint8_t>({100, 0, 0, 0}));
    CHECK(recs[0].first.empty());

    // value drops in game -> narrow server-side
    put32(0x7FFF00000020, 90);
    io = b.ps4_turbo_count(kFakePid, req.addr, ps4::kValU32, ps4::kCmpDecreased,
                           ps4::kTsServerResident, {}, {}, {}, res);
    REQUIRE(io.ok);
    CHECK(res.count == 1u);
    REQUIRE(b.ps4_turbo_get(0, 16, 4, recs).ok);
    REQUIRE(recs.size() == 1u);
    CHECK(recs[0].addr == 0x7FFF00000020ull);
    CHECK(recs[0].current == std::vector<uint8_t>({90, 0, 0, 0}));
    CHECK(recs[0].previous == std::vector<uint8_t>({100, 0, 0, 0}));

    REQUIRE(b.ps4_turbo_end().ok);
    CHECK(g.srv.turbo_end_calls == 1);
    REQUIRE(b.ps4_turbo_get(0, 16, 4, recs).ok);
    CHECK(recs.empty());

    // streamed (non-resident) start + client-driven count
    req.flags = 0;
    req.data = {90, 0, 0, 0};
    io = b.ps4_turbo_start(req, res);
    REQUIRE(io.ok);
    CHECK(!res.resident);
    REQUIRE(res.hits.size() == 1u);
    CHECK(res.hits[0].addr == 0x7FFF00000020ull);
    auto prev = res.hits;
    put32(0x7FFF00000020, 95);
    io = b.ps4_turbo_count(kFakePid, req.addr, ps4::kValU32, ps4::kCmpIncreased, 0,
                           {}, {}, prev, res);
    REQUIRE(io.ok);
    REQUIRE(res.hits.size() == 1u);
    CHECK(res.hits[0].value == std::vector<uint8_t>({95, 0, 0, 0}));

    // resident overflow without segments falls back to streamed hits
    g.srv.turbo_resident_cap = 0;
    req.flags = ps4::kTsServerResident;
    req.data = {95, 0, 0, 0};
    io = b.ps4_turbo_start(req, res);
    REQUIRE(io.ok);
    CHECK(!res.resident);
    CHECK(res.hits.size() == 1u);
    // ...and with segments it is an error the caller can explain
    req.segments = {{0x7FFF00000000, 0x800}, {0x7FFF00000800, 0x800}};
    io = b.ps4_turbo_start(req, res);
    CHECK(!io.ok);
    CHECK(io.error == 14u);
    CHECK(b.ping());
    g.srv.turbo_resident_cap = 1u << 20;

    // snapshot (unknown initial value) over two segments, keep first
    backend_ps4_t::ps4_turbo_start_t snap;
    snap.pid = kFakePid;
    snap.valtype = ps4::kValU32;
    snap.cmptype = ps4::kCmpUnknown;
    snap.flags = ps4::kTsServerResident | ps4::kTsSnapshot | ps4::kTsSnapshotKeepFirst;
    snap.segments = {{0x7FFF00000000, 0x20}, {0x7FFF00000020, 0x20}};
    uint64_t progress_calls = 0;
    io = b.ps4_turbo_start(snap, res, [&](uint64_t, uint64_t) { ++progress_calls; });
    REQUIRE(io.ok);
    CHECK(res.snapshot);
    CHECK(res.snapshot_ok);
    CHECK(res.slot_count == 16u);
    CHECK(res.total_bytes == 0x40u);
    CHECK(progress_calls == 1u);
    CHECK(res.count == 3u);   // the three non-zero dwords
    CHECK(g.srv.last_turbo_nseg == 2u);
    CHECK((g.srv.last_turbo_flags & ps4::kTsSnapshotSegments) != 0);
    put32(0x7FFF00000010, 50);
    io = b.ps4_turbo_count(kFakePid, 0x7FFF00000000, ps4::kValU32, ps4::kCmpDecreased,
                           ps4::kTsServerResident, {}, {}, {}, res);
    REQUIRE(io.ok);
    CHECK(res.count == 1u);
    REQUIRE(b.ps4_turbo_get(0, 4, 4, recs).ok);
    REQUIRE(recs.size() == 1u);
    CHECK(recs[0].first == std::vector<uint8_t>({100, 0, 0, 0}));
    CHECK(recs[0].current == std::vector<uint8_t>({50, 0, 0, 0}));

    // regions / config / cancel
    std::vector<backend_ps4_t::ps4_turbo_region_t> regs;
    REQUIRE(b.ps4_turbo_regions(kFakePid, 0, 0, regs).ok);
    CHECK(regs.size() == 6u);
    REQUIRE(b.ps4_turbo_config(256, "/data/turbo").ok);
    CHECK(g.srv.turbo_cfg_mb == 256u);
    CHECK(g.srv.turbo_cfg_dir == "/data/turbo");
    CHECK(!b.ps4_turbo_config(0, std::string(64, 'x')).ok);
    REQUIRE(b.ps4_turbo_cancel(kFakePid, err).ok);   // rides a second connection
    CHECK(g.srv.turbo_cancel_pid == kFakePid);
    CHECK(b.ping());

    // bad seed width is refused before anything is sent
    req.segments.clear();
    req.data = {1, 2};
    CHECK(!b.ps4_turbo_start(req, res).ok);
    CHECK(b.ping());
    b.disconnect();
}

TEST_CASE(ps4_turbo_scan_mcp) {
    server_guard_t g;
    ps4_disconnect_guard_t guard;
    std::string err;
    REQUIRE(connect_fake_registry(g.srv, err));
    REQUIRE(connect_fake_target(g.srv, kFakePid, err));
    auto dbg = [&](const json& a, bool& is_err) {
        return slop::core::mcp::call_tool("debugger", a, is_err);
    };
    bool e = false;

    json caps = dbg({{"action", "ps4_turbo_caps"}}, e);
    CHECK(!e);
    CHECK(caps.value("supported", false) == true);
    CHECK(caps.value("capability_level", std::string{}) == "1.1");

    const uint32_t hp = 500;
    g.srv.mem_write(0x7FFF00000400, reinterpret_cast<const uint8_t*>(&hp), 4);
    json r = dbg({{"action", "ps4_turbo_scan"}, {"regions", "writable"},
                  {"value_type", "u32"}, {"compare", "exact"}, {"value", 500}}, e);
    CHECK(!e);
    if (e) std::printf("  ps4_turbo_scan error: %s\n", r.dump().c_str());
    CHECK(r.value("count", 0) == 1u);
    CHECK(r.value("resident", false) == true);
    CHECK(r.value("segments", 0) == 2u);   // coalesced eboot RW + stack RW
    REQUIRE(r.contains("results") && r["results"].size() == 1u);
    CHECK(r["results"][0].value("value", std::string{}) == "500");

    const uint32_t hp2 = 450;
    g.srv.mem_write(0x7FFF00000400, reinterpret_cast<const uint8_t*>(&hp2), 4);
    json rs = dbg({{"action", "ps4_turbo_rescan"}, {"compare", "decreased"}}, e);
    CHECK(!e);
    CHECK(rs.value("count", 0) == 1u);
    CHECK((g.srv.last_turbo_flags & ps4::kTsRescanAliasing) != 0);
    REQUIRE(rs["results"].size() == 1u);
    CHECK(rs["results"][0].value("previous", std::string{}) == "500");

    json page = dbg({{"action", "ps4_turbo_results"}, {"start", 0}, {"count", 10}}, e);
    CHECK(!e);
    CHECK(page.value("total", 0) == 1u);

    // poke the found address plus a raw patch in one round-trip
    json wm = dbg({{"action", "ps4_write_multi"},
                   {"writes", json::array({
                       {{"addr", 0x7FFF00000400}, {"value", 999}, {"value_type", "u32"}},
                       {{"addr", 0x7FFF00000500}, {"hex", "90 90"}}})}}, e);
    CHECK(!e);
    if (e) std::printf("  ps4_write_multi error: %s\n", wm.dump().c_str());
    CHECK(wm.value("ok", false) == true);
    CHECK(wm.value("count", 0) == 2u);
    CHECK(g.srv.mem_byte(0x7FFF00000400) == static_cast<uint8_t>(999 & 0xFF));
    CHECK(g.srv.mem_byte(0x7FFF00000501) == 0x90);

    g.srv.write_deny_addr = 0x7FFF00000500;
    wm = dbg({{"action", "ps4_write_multi"},
              {"writes", json::array({{{"addr", 0x7FFF00000500}, {"hex", "CC"}}})}}, e);
    CHECK(!e);
    CHECK(wm.value("ok", true) == false);
    REQUIRE(wm["failed"].size() == 1u);
    CHECK(wm["failed"][0].value("reason", std::string{}) == "verify_failed");

    // unknown-value snapshot scan picks snapshot mode by itself
    json sn = dbg({{"action", "ps4_turbo_scan"}, {"addr", 0x7FFF00000400}, {"len", 0x10},
                   {"value_type", "u32"}, {"compare", "unknown"}, {"keep_first", true}}, e);
    CHECK(!e);
    if (e) std::printf("  snapshot error: %s\n", sn.dump().c_str());
    CHECK(sn.value("snapshot", false) == true);
    CHECK(sn.value("count", 0) == 1u);

    json end = dbg({{"action", "ps4_turbo_end"}}, e);
    CHECK(!e);
    json none = dbg({{"action", "ps4_turbo_results"}}, e);
    CHECK(e);   // no session after end

    json cancel = dbg({{"action", "ps4_turbo_cancel"}, {"pid", kFakePid}}, e);
    CHECK(!e);
    CHECK(g.srv.turbo_cancel_pid == kFakePid);

    // an old payload without Turbo Scan reports supported:false
    g.srv.turbo_supported = false;
    json old = dbg({{"action", "ps4_turbo_caps"}}, e);
    CHECK(!e);
    CHECK(old.value("supported", true) == false);
}

TEST_CASE(ps4_fork_modules_snapshot_and_errors) {
    server_guard_t g;   // fork_ext on by default
    backend_ps4_t b;
    std::string err;
    // a second eboot map (data segment) and more stack, added before any
    // maps are cached
    {
        std::lock_guard lk(g.srv.mu);
        ps4::vm_map_entry_t extra{};
        std::strncpy(extra.name, "/app0/eboot.bin", sizeof(extra.name) - 1);
        extra.start = 0x600000;
        extra.end = 0x608000;
        extra.prot = ps4::kVmProtRead | ps4::kVmProtWrite;
        g.srv.maps.push_back(extra);
        ps4::vm_map_entry_t stack2{};
        stack2.start = 0x7FFF00010000ull;
        stack2.end = 0x7FFF00030000ull;
        stack2.prot = ps4::kVmProtRead | ps4::kVmProtWrite;
        g.srv.maps.push_back(stack2);
    }
    REQUIRE(connect_fake(b, g.srv, err));
    CHECK(b.ps4_fork_extensions() == -1);

    // server-side module list
    std::vector<slop::core::runtime::module_info_t> mods;
    REQUIRE(b.ps4_modules(kFakePid, mods).ok);
    CHECK(b.ps4_fork_extensions() == 1);
    REQUIRE(mods.size() == 2u);
    CHECK(mods[0].name == "eboot.bin");
    CHECK(mods[0].base == 0x400000u);
    CHECK(mods[0].size == 0x208000u);   // text..data span

    // enum_modules rides on it now
    auto h = b.attach(kFakePid);
    REQUIRE(h.valid());
    auto em = b.enum_modules(h);
    REQUIRE(em.ok);
    REQUIRE(em.items.size() == 2u);
    CHECK(em.items[0].size == 0x208000u);
    CHECK(g.srv.module_requests == 2);

    // one-round-trip snapshot, larger than one 64 KiB chunk
    std::vector<uint8_t> pat(0x18000);
    for (size_t i = 0; i < pat.size(); ++i) pat[i] = static_cast<uint8_t>(i * 13 + 1);
    g.srv.mem_write(0x7FFF00001000, pat.data(), pat.size());
    std::vector<uint8_t> got;
    auto io = b.ps4_snapshot(kFakePid, 0x7FFF00001000, pat.size(),
                             [&](const uint8_t* d, size_t n) {
                                 got.insert(got.end(), d, d + n);
                                 return true;
                             });
    REQUIRE(io.ok);
    CHECK(io.bytes == pat.size());
    CHECK(got == pat);

    // unreadable range is refused before the payload can drop us mid-stream
    io = b.ps4_snapshot(kFakePid, 0x7FFF0002F000, 0x2000, {});
    CHECK(!io.ok);
    CHECK(io.error == 2u);

    // structured error: bad pid -> CMD_ERR_PID, payload drops the client,
    // the next command transparently reconnects (and re-auths)
    const uint64_t gen0 = b.ps4_connection_generation();
    b.ps4_take_last_status();
    CHECK(!b.ps4_modules(999, mods).ok);
    CHECK(b.ps4_take_last_status() == ps4::CMD_ERR_PID);
    CHECK(std::string(ps4::status_name(ps4::CMD_ERR_PID)).find("CMD_ERR_PID") == 0);
    CHECK(b.ping());
    CHECK(b.ps4_connection_generation() == gen0 + 1);
    CHECK(b.ps4_authed());
    CHECK(b.ps4_fork_extensions() == 1);   // still known after the reconnect

    // process stop is now 8 bytes and passes the fork's datalen guard
    REQUIRE(b.ps4_process_stop(kFakePid, ps4::kStopStop).ok);
    CHECK(g.srv.last_proc_stop_pid == kFakePid);
    CHECK(g.srv.last_proc_stop_state == ps4::kStopStop);

    b.detach(h);
    b.disconnect();
}

TEST_CASE(ps4_upstream_payload_fallback_and_reconnect) {
    server_guard_t g;
    g.srv.fork_ext = false;   // behave like Pharaoh2k upstream
    backend_ps4_t b;
    std::string err;
    REQUIRE(connect_fake(b, g.srv, err));
    auto h = b.attach(kFakePid);
    REQUIRE(h.valid());

    // first enum_modules probes CMD_PROC_MODULES once: upstream answers
    // CMD_ERROR and drops the client; the backend falls back to grouping maps
    auto em = b.enum_modules(h);
    REQUIRE(em.ok);
    CHECK(em.items.size() == 2u);
    CHECK(b.ps4_fork_extensions() == 0);
    CHECK(b.ps4_connection_generation() == 1u);
    CHECK(g.srv.module_requests == 1);

    // no further probes once the payload is known to be upstream
    em = b.enum_modules(h);
    REQUIRE(em.ok);
    CHECK(g.srv.module_requests == 1);
    CHECK(b.ps4_connection_generation() == 1u);
    std::vector<slop::core::runtime::module_info_t> mods;
    auto io = b.ps4_modules(kFakePid, mods);
    CHECK(!io.ok);
    CHECK(io.error == 100u);
    io = b.ps4_snapshot(kFakePid, 0x7FFF00000000, 0x100, {});
    CHECK(io.error == 100u);

    // and memory I/O still works on the reopened connection
    const uint8_t v[4] = {1, 2, 3, 4};
    REQUIRE(b.write_memory(h, 0x7FFF00000040, v, 4).ok);
    uint8_t back[4]{};
    REQUIRE(b.read_memory(h, 0x7FFF00000040, back, 4).ok);
    CHECK(std::memcmp(back, v, 4) == 0);
    b.detach(h);
    b.disconnect();
}

TEST_CASE(ps4_fork_mcp_actions) {
    server_guard_t g;
    ps4_disconnect_guard_t guard;
    std::string err;
    REQUIRE(connect_fake_registry(g.srv, err));
    REQUIRE(connect_fake_target(g.srv, kFakePid, err));
    auto dbg = [&](const json& a, bool& is_err) {
        return slop::core::mcp::call_tool("debugger", a, is_err);
    };
    bool e = false;

    json mods = dbg({{"action", "ps4_modules"}}, e);
    CHECK(!e);
    CHECK(mods.value("count", 0) == 2u);

    json st = dbg({{"action", "ps4_status"}}, e);
    CHECK(!e);
    CHECK(st.value("fork_extensions", std::string{}) == "yes");
    CHECK(st.value("capability_level", std::string{}) == "1.1");

    const uint8_t marker[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
    g.srv.mem_write(0x7FFF00002000, marker, sizeof(marker));
    char tmp[MAX_PATH]{};
    GetTempPathA(MAX_PATH, tmp);
    const std::string out = std::string(tmp) + "slop_ps4_snapshot_test.bin";
    json sn = dbg({{"action", "ps4_snapshot"}, {"addr", 0x7FFF00002000}, {"len", 0x20},
                   {"path", out}}, e);
    CHECK(!e);
    if (e) std::printf("  ps4_snapshot error: %s\n", sn.dump().c_str());
    CHECK(sn.value("bytes", 0) == 0x20u);
    {
        std::ifstream f(out, std::ios::binary);
        std::vector<uint8_t> head(8);
        f.read(reinterpret_cast<char*>(head.data()), 8);
        CHECK(std::memcmp(head.data(), marker, 8) == 0);
    }
    std::remove(out.c_str());

    // console error codes are appended to tool errors
    json bad = dbg({{"action", "ps4_modules"}, {"pid", 999}}, e);
    CHECK(e);
    CHECK(bad.dump().find("CMD_ERR_PID") != std::string::npos);

    // a turbo session does not survive the payload dropping the connection
    const uint32_t v = 77;
    g.srv.mem_write(0x7FFF00000800, reinterpret_cast<const uint8_t*>(&v), 4);
    json ts = dbg({{"action", "ps4_turbo_scan"}, {"addr", 0x7FFF00000000}, {"len", 0x1000},
                   {"value_type", "u32"}, {"compare", "exact"}, {"value", 77}}, e);
    CHECK(!e);
    CHECK(ts.value("count", 0) == 1u);
    dbg({{"action", "ps4_modules"}, {"pid", 999}}, e);   // drops the client
    CHECK(e);
    json rs = dbg({{"action", "ps4_turbo_rescan"}, {"compare", "unchanged"}}, e);
    CHECK(e);
    CHECK(rs.dump().find("dropped the connection") != std::string::npos);
    json st2 = dbg({{"action", "ps4_status"}}, e);
    CHECK(!e);
    CHECK(st2.value("reconnects", uint64_t{0}) >= 2u);   // both drops recovered
}

namespace {

// minimal RSP client for the bridge tests: framed send + frame reader that
// skips ack/nak bytes
std::string rsp_send_pkt(SOCKET s, const std::string& cmd) {
    uint8_t sum = 0;
    std::string f = "$";
    for (char ch : cmd) {
        sum = static_cast<uint8_t>(sum + static_cast<uint8_t>(ch));
        f += ch;
    }
    char tail[8];
    std::snprintf(tail, sizeof(tail), "#%02x", sum);
    f += tail;
    if (::send(s, f.data(), static_cast<int>(f.size()), 0) == SOCKET_ERROR) return "";
    return f;
}

std::string rsp_read_frame(SOCKET s) {
    std::string payload;
    bool in_pkt = false;
    for (;;) {
        char ch;
        const int n = ::recv(s, &ch, 1, 0);
        if (n <= 0) return "";
        if (!in_pkt) {
            if (ch == '$') in_pkt = true;
            continue;   // skip '+', '-', anything else
        }
        if (ch == '#') {
            char cc[2];
            if (::recv(s, cc, 2, 0) != 2) return "";
            return payload;
        }
        payload += ch;
    }
}

uint16_t rsp_free_port() {
    const SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) return 0;
    sockaddr_in b{};
    int len = sizeof(b);
    ::getsockname(s, reinterpret_cast<sockaddr*>(&b), &len);
    const uint16_t p = ntohs(b.sin_port);
    ::closesocket(s);
    return p;
}

} // namespace

TEST_CASE(ps4_gdb_rsp_bridge) {
    server_guard_t g;
    backend_ps4_t b;
    std::string err;
    REQUIRE(connect_fake(b, g.srv, err));

    // seed memory so the RSP 'm' read has known content (done before the
    // debug attach: the lazy handle attach used here is not the debug session)
    {
        auto h = b.attach(kFakePid);
        const uint8_t data[4] = {0xde, 0xad, 0xbe, 0xef};
        REQUIRE(b.write_memory(h, 0x400100, data, 4).ok);
        b.detach(h);
    }

    REQUIRE(b.ps4_debug_attach(kFakePid, err));
    REQUIRE(b.ps4_debug_attached());

    slop::core::runtime::gdb_rsp_server_t rsp;
    const uint16_t rport = rsp_free_port();
    REQUIRE_GT(rport, 0);
    REQUIRE(rsp.start("127.0.0.1", rport, false, err, &b));
    REQUIRE(rsp.running());

    const SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(rport);
    ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    REQUIRE(::connect(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0);
    DWORD to = 5000;
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&to), sizeof(to));

    auto xchg = [&](const std::string& cmd) {
        rsp_send_pkt(s, cmd);
        return rsp_read_frame(s);
    };

    // handshake + target description (no console session needed for these)
    REQUIRE(xchg("qSupported").rfind("PacketSize=4000", 0) == 0);
    REQUIRE_STR_EQ(xchg("QStartNoAckMode").c_str(), "OK");
    const auto xml = xchg("qXfer:features:read:target.xml:0,fff");
    REQUIRE(xml.size() > 10);
    REQUIRE((xml[0] == 'l' || xml[0] == 'm'));
    REQUIRE(xml.substr(1).rfind("<?xml", 0) == 0);
    REQUIRE_STR_EQ(xchg("qAttached").c_str(), "1");
    REQUIRE_STR_EQ(xchg("qHostInfo").find("ostype:freebsd") != std::string::npos
                       ? "ok" : "", "ok");

    // threads: fixture has lwpid 101 (0x65) and 102 (0x66)
    REQUIRE_STR_EQ(xchg("qfThreadInfo").c_str(), "m65,66");
    REQUIRE_STR_EQ(xchg("qsThreadInfo").c_str(), "l");
    REQUIRE_STR_EQ(xchg("qC").c_str(), "QC65");
    REQUIRE_STR_EQ(xchg("Hg66").c_str(), "OK");
    REQUIRE_STR_EQ(xchg("T65").c_str(), "OK");
    REQUIRE_STR_EQ(xchg("T1234").c_str(), "E01");

    // registers: fixture defaults rax=0x2A, rip=0x400123
    const auto gblk = xchg("g");
    REQUIRE(gblk.size() > 1000);
    REQUIRE(gblk.substr(0, 16) == "2a00000000000000");       // rax LE
    REQUIRE_STR_EQ(xchg("p10").c_str(), "2301400000000000"); // rip (regnum 16)

    // memory read over RSP
    REQUIRE_STR_EQ(xchg("m400100,4").c_str(), "deadbeef");
    // writes refused without allow_writes
    REQUIRE_STR_EQ(xchg("M400100,4:01020304").c_str(), "E01");
    REQUIRE_STR_EQ(xchg("P0=0100000000000000").c_str(), "E01");

    // breakpoint via Z0 lands on the fake console
    REQUIRE_STR_EQ(xchg("Z0,400600,1").c_str(), "OK");
    CHECK(g.srv.bps[0].enabled);
    CHECK(g.srv.bps[0].address == 0x400600);

    // continue: no immediate reply, the T.. stop reply arrives async
    rsp_send_pkt(s, "c");
    const auto stop = rsp_read_frame(s);
    REQUIRE_STR_EQ(stop.c_str(), "T05thread:65;");

    // step
    rsp_send_pkt(s, "s");
    const auto stop2 = rsp_read_frame(s);
    REQUIRE(stop2.rfind("T05thread:65;", 0) == 0);

    // clear the breakpoint
    REQUIRE_STR_EQ(xchg("z0,400600,1").c_str(), "OK");
    CHECK(!g.srv.bps[0].enabled);

    // D closes only the RSP connection; the shared debug session stays up
    REQUIRE_STR_EQ(xchg("D").c_str(), "OK");
    ::closesocket(s);
    CHECK(b.ps4_debug_attached());

    rsp.stop();
    CHECK(!rsp.running());
    REQUIRE(b.ps4_debug_detach());
    b.disconnect();
}

// === local debugger: rules, .pdata callstacks ===============================

namespace {

// entry point RVA of a PE32+ file (0 when unreadable)
uint32_t pe_entry_rva(const char* path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return 0;
    std::vector<uint8_t> b((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (b.size() < 0x40) return 0;
    uint32_t lfanew = 0;
    std::memcpy(&lfanew, b.data() + 0x3C, 4);
    if (b.size() < static_cast<size_t>(lfanew) + 24 + 20 + 4) return 0;
    uint32_t sig = 0;
    std::memcpy(&sig, b.data() + lfanew, 4);
    if (sig != 0x4550) return 0;
    uint16_t magic = 0;
    std::memcpy(&magic, b.data() + lfanew + 24, 2);
    if (magic != 0x20B) return 0;
    uint32_t entry = 0;
    std::memcpy(&entry, b.data() + lfanew + 24 + 16, 4);
    return entry;
}

// a CREATE_SUSPENDED process has no module list yet: read PEB.ImageBaseAddress
uint64_t suspended_image_base(HANDLE proc) {
    using ntqip_t = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static auto ntqip = reinterpret_cast<ntqip_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!ntqip) return 0;
    struct pbi_t {
        PVOID reserved1;
        PVOID peb;
        PVOID reserved2[2];
        ULONG_PTR unique_pid;
        PVOID reserved3;
    } pbi{};
    ULONG len = 0;
    if (ntqip(proc, 0 /*ProcessBasicInformation*/, &pbi, sizeof(pbi), &len) != 0) return 0;
    uint64_t base = 0;
    SIZE_T n = 0;
    // PEB.ImageBaseAddress is at offset 0x10 on x64
    if (!ReadProcessMemory(proc, static_cast<const uint8_t*>(pbi.peb) + 0x10, &base,
                           sizeof(base), &n) ||
        n != sizeof(base))
        return 0;
    return base;
}

} // namespace

TEST_CASE_TIMEOUT(ps4_local_breakpoint_rules, 180) {
    // the engine-side rules (hit counts, log breakpoints) also drive the local
    // Win32 debugger, so they are testable without a console
    slop::core::process::target_disconnect_ps4();
    loop_target_t t;
    REQUIRE(t.ok);
    const uint64_t func = t.base + 0x40;
    REQUIRE(slop::core::process::target_attach(t.pi.dwProcessId));

    bool e = false;
    auto dbg = [&](const json& a) { return slop::core::mcp::call_tool("debugger", a, e); };

    json r = dbg({{"action", "ps4_bp_set"}, {"addr", func}, {"hits", 2}});
    CHECK(!e);
    if (e) std::printf("  local bp_set err: %s\n", r.dump().c_str());
    CHECK(r.value("debugger", std::string{}) == "user");
    CHECK(r.value("hits", 0) == 2);
    r = dbg({{"action", "ps4_continue"}});
    CHECK(!e);
    r = dbg({{"action", "ps4_wait"}, {"timeout_ms", 10000}});
    CHECK(!e);
    if (e) std::printf("  local wait err: %s\n", r.dump().c_str());
    CHECK(r.value("halted", false) == true);
    CHECK(r.value("rip", 0ull) == func);
    CHECK(r.value("condition_skipped", 0) == 1);
    r = dbg({{"action", "ps4_bp_list"}});
    CHECK(!e);
    CHECK(r.value("count", 0) == 1u);
    CHECK(r["breakpoints"][0].value("count", 0) == 2u);
    CHECK(r["breakpoints"][0].value("hits", 0) == 2u);

    // log-only breakpoint: records and auto-resumes (bounded skip limit)
    r = dbg({{"action", "ps4_bp_clear"}, {"addr", func}});
    CHECK(!e);
    r = dbg({{"action", "ps4_bp_set"}, {"addr", func},
             {"log", "call rcx={rcx}"}, {"continue", true}});
    CHECK(!e);
    r = dbg({{"action", "ps4_continue"}});
    CHECK(!e);
    r = dbg({{"action", "ps4_wait"}, {"timeout_ms", 1500}});
    CHECK(!e);
    CHECK(r.value("halted", true) == false);
    CHECK(r.value("condition_skipped", 0) > 0);
    bool saw = false;
    for (const auto& l : slop::core::infra::event_bus::output_since(0))
        if (l.text.find("call rcx=0x") != std::string::npos) saw = true;
    CHECK(saw);

    r = dbg({{"action", "ps4_bp_clear"}, {"addr", func}});
    CHECK(!e);
    r = dbg({{"action", "ps4_detach"}});
    CHECK(!e);
    slop::core::process::target_detach();
}

TEST_CASE_TIMEOUT(ps4_local_callstack_unwinds_pdata, 180) {
#ifdef SLOP_TARGET_EXE_PATH
    slop::core::process::target_disconnect_ps4();
    const uint32_t entry_rva = pe_entry_rva(SLOP_TARGET_EXE_PATH);
    REQUIRE(entry_rva != 0);

    // start suspended so the breakpoint lands on the entry point itself
    std::string cmd = std::string("\"") + SLOP_TARGET_EXE_PATH + "\" --auto 50";
    std::vector<char> cmdline(cmd.begin(), cmd.end());
    cmdline.push_back('\0');
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE nul = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr);
    si.hStdInput = si.hStdOutput = si.hStdError = nul;
    PROCESS_INFORMATION pi{};
    REQUIRE(CreateProcessA(nullptr, cmdline.data(), nullptr, nullptr, TRUE,
                           CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi));
    CloseHandle(nul);
    struct target_guard_t {
        PROCESS_INFORMATION& pi;
        ~target_guard_t() {
            TerminateProcess(pi.hProcess, 0);
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    } tguard{pi};

    const uint64_t base = suspended_image_base(pi.hProcess);
    REQUIRE(base != 0);
    REQUIRE(slop::core::process::target_attach(pi.dwProcessId));

    bool e = false;
    auto dbg = [&](const json& a) { return slop::core::mcp::call_tool("debugger", a, e); };
    json r = dbg({{"action", "ps4_bp_set"}, {"addr", base + entry_rva}});
    CHECK(!e);
    if (e) std::printf("  local entry bp err: %s\n", r.dump().c_str());
    ResumeThread(pi.hThread);

    r = dbg({{"action", "ps4_wait"}, {"timeout_ms", 15000}});
    CHECK(!e);
    if (e) std::printf("  local entry wait err: %s\n", r.dump().c_str());
    CHECK(r.value("halted", false) == true);
    CHECK(r.value("rip", 0ull) == base + entry_rva);

    // .pdata (RUNTIME_FUNCTION/UNWIND_INFO) walks past the entry point into
    // the loader frames; an rbp chain would stop at one frame
    r = dbg({{"action", "ps4_callstack"}, {"depth", 16}});
    CHECK(!e);
    if (e) std::printf("  local callstack err: %s\n", r.dump().c_str());
    CHECK(r.value("unwind", std::string{}) == "pdata");
    CHECK(r.value("count", 0) >= 2u);
    REQUIRE(r.contains("frames"));
    REQUIRE(r["frames"].size() >= 2);
    CHECK(r["frames"][0].value("ret_addr", 0ull) == base + entry_rva);
    CHECK(r["frames"][1].value("ret_addr", 0ull) != 0ull);

    r = dbg({{"action", "ps4_detach"}});
    CHECK(!e);
    slop::core::process::target_detach();
#endif
}
