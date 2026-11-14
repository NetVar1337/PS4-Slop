// src/tests/test_ps4_chaos.cpp
// PS4 (ps4debug-NG) tests against the fake payload in ps4_fixture.hpp:
// wire fault injection, reconnect, event reassembly, slots and the console composites.

#include "ps4_fixture.hpp"

TEST_CASE(ps4_io_error_strings) {
    CHECK(ps4::io_error_str(ps4::kErrNotConnected).find("not connected") != std::string::npos);
    CHECK(ps4::io_error_str(ps4::kErrTimeout).find("did not answer in time") != std::string::npos);
    CHECK(ps4::io_error_str(ps4::kErrDataNull).find("CMD_DATA_NULL") != std::string::npos);
    CHECK(ps4::io_error_str(ps4::kErrNoSlot).find("no free slot") != std::string::npos);
    // local backend Win32 codes get the system text
    CHECK(ps4::io_error_str(ERROR_ACCESS_DENIED).find("Win32 error 5") == 0);
    CHECK(ps4::io_error_str(0xE00000FFu).find("0xE00000FF") != std::string::npos);
    CHECK(ps4::status_to_err(ps4::CMD_ALREADY_DEBUG) == ps4::kErrAlreadyDebug);
    CHECK(ps4::status_to_err(0x12345678u) == ps4::kErrProtocol);
}

TEST_CASE(ps4_chaos_fragmented_replies_still_work) {
    // every reply leaves the fake in 1..3-byte pieces: headers, status words
    // and payloads all arrive split
    server_guard_t g;
    g.srv.chaos.fragment = true;
    backend_ps4_t b;
    std::string err;
    REQUIRE(connect_fake(b, g.srv, err));
    CHECK(b.fw_string() == "11.00");
    CHECK(b.ps4_authed());
    auto procs = b.enum_processes();
    REQUIRE(procs.ok);
    CHECK(procs.items.size() == 2u);
    auto h = b.attach(kFakePid);
    REQUIRE(h.valid());
    std::vector<uint8_t> data(300);
    for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i * 13);
    REQUIRE(b.write_memory(h, 0x7FFF00000100ull, data.data(), data.size()).ok);
    std::vector<uint8_t> back(data.size());
    REQUIRE(b.read_memory(h, 0x7FFF00000100ull, back.data(), back.size()).ok);
    CHECK(back == data);
    CHECK(b.connected());
    b.detach(h);
}

TEST_CASE(ps4_chaos_peer_close_drops_socket_and_reconnect_restores) {
    server_guard_t g;
    backend_ps4_t b;
    std::string err;
    REQUIRE(connect_fake(b, g.srv, err));
    auto h = b.attach(kFakePid);
    REQUIRE(h.valid());
    REQUIRE(b.ps4_debug_attach(kFakePid, err));
    uint32_t bpi = 0, wpi = 0;
    REQUIRE(b.ps4_bp_arm(0x400500, backend_ps4_t::kAutoSlot, bpi).ok);
    REQUIRE(b.ps4_wp_arm(0x7FFF00001000ull, 8, ps4::kWpWrite, backend_ps4_t::kAutoSlot, wpi).ok);

    // the console drops the connection in the middle of a read reply
    g.srv.chaos.close_after = 6;   // status word + 2 data bytes, then the cut
    g.srv.chaos.close_cmd = ps4::CMD_PROC_READ;
    uint8_t buf[64]{};
    auto io = b.read_memory(h, 0x400000, buf, sizeof(buf));
    CHECK(!io.ok);
    CHECK(io.error == ps4::kErrRecvFailed);
    CHECK(!b.connected());
    CHECK(b.lost());
    CHECK(b.drop_count() == 1u);
    CHECK(!b.lost_reason().empty());
    CHECK(!b.ps4_debug_attached());   // the payload drops debug state per connection
    // slots are kept for the reconnect but are not armed right now
    auto bps = b.ps4_breakpoints();
    REQUIRE(bps.size() == 1u);
    if (bps.size() != 1u)
        std::printf("  chaos: bps.size=%zu wps.size=%zu\n", bps.size(), b.ps4_watchpoints().size());
    CHECK(!bps[0].armed);

    // every later call fails fast instead of paying another timeout
    const auto t0 = std::chrono::steady_clock::now();
    io = b.read_memory(h, 0x400000, buf, sizeof(buf));
    CHECK(!io.ok);
    CHECK(io.error == ps4::kErrNotConnected);
    CHECK(!b.ping());
    CHECK(ms_since(t0) < 500);

    // reconnect: handshake + auth again, debuggee re-attached, slots re-armed
    backend_ps4_t::reconnect_report_t rep;
    REQUIRE(b.reconnect(err, &rep));
    CHECK(b.connected());
    CHECK(!b.lost());
    CHECK(rep.authed);
    CHECK(rep.debug_pid == kFakePid);
    CHECK(rep.debug_restored);
    CHECK(rep.bp_rearmed == 1u);
    CHECK(rep.wp_rearmed == 1u);
    CHECK(rep.bp_failed == 0u);
    CHECK(b.ps4_debug_attached());
    CHECK(g.srv.connections == 2);
    CHECK(g.srv.bps[bpi].enabled);
    CHECK(g.srv.bps[bpi].address == 0x400500);
    CHECK(g.srv.wps[wpi].enabled);
    CHECK(g.srv.wps[wpi].address == 0x7FFF00001000ull);
    bps = b.ps4_breakpoints();
    REQUIRE(bps.size() == 1u);
    CHECK(bps[0].armed);
    // the handle from before the drop keeps working
    REQUIRE(b.read_memory(h, 0x400000, buf, sizeof(buf)).ok);
    b.detach(h);
    b.disconnect();
}

TEST_CASE(ps4_chaos_stall_hits_idle_timeout) {
    server_guard_t g;
    backend_ps4_t b;
    std::string err;
    REQUIRE(connect_fake(b, g.srv, err));
    auto h = b.attach(kFakePid);
    REQUIRE(h.valid());
    // the tight command budget is for the stall below; the handshake above
    // runs with the default budget so a loaded machine cannot time it out
    b.set_timeouts(250, 2000, 2000);
    g.srv.chaos.stall_cmd = ps4::CMD_PROC_WRITE;   // the payload never answers
    const uint8_t v[4] = {1, 2, 3, 4};
    const auto t0 = std::chrono::steady_clock::now();
    auto io = b.write_memory(h, 0x7FFF00000000ull, v, sizeof(v));
    CHECK(!io.ok);
    CHECK(io.error == ps4::kErrTimeout);
    CHECK(ms_since(t0) < 1500);
    CHECK(!b.connected());
    // a fresh connection serves again
    std::string rerr;
    REQUIRE(b.reconnect(rerr));
    CHECK(b.ping());
    b.detach(h);
}

TEST_CASE(ps4_chaos_dribble_hits_command_deadline) {
    // one byte every 40 ms never trips the 250 ms idle timeout, but the whole
    // command budget (600 ms) stops it instead of stalling for minutes
    server_guard_t g;
    backend_ps4_t b;
    std::string err;
    REQUIRE(connect_fake(b, g.srv, err));
    auto h = b.attach(kFakePid);
    REQUIRE(h.valid());
    b.set_timeouts(250, 600, 600);
    std::vector<uint8_t> warm(16);
    // fill the maps cache first so only the read itself is dribbled
    REQUIRE(b.read_memory(h, 0x400000, warm.data(), warm.size()).ok);
    g.srv.chaos.dribble_ms = 40;
    std::vector<uint8_t> buf(512);
    const auto t0 = std::chrono::steady_clock::now();
    auto io = b.read_memory(h, 0x400000, buf.data(), buf.size());
    const int64_t took = ms_since(t0);
    CHECK(!io.ok);
    CHECK(io.error == ps4::kErrTimeout);
    CHECK(took >= 400);
    CHECK(took < 3000);
    CHECK(!b.connected());
    g.srv.chaos.dribble_ms = 0;
    b.detach(h);
}

TEST_CASE(ps4_chaos_garbage_status_is_protocol_error) {
    server_guard_t g;
    backend_ps4_t b;
    std::string err;
    REQUIRE(connect_fake(b, g.srv, err));
    auto h = b.attach(kFakePid);
    REQUIRE(h.valid());
    // a word that is no status at all means the stream is misaligned
    g.srv.chaos.garbage_cmd = ps4::CMD_PROC_WRITE;
    const uint8_t v[2] = {9, 9};
    auto io = b.write_memory(h, 0x7FFF00000000ull, v, sizeof(v));
    CHECK(!io.ok);
    CHECK(io.error == ps4::kErrProtocol);
    CHECK(!b.connected());
    CHECK(b.lost_reason().find("desync") != std::string::npos);
    // a non-success *status* is a clean error that keeps the connection
    REQUIRE(b.reconnect(err));
    auto bad = b.attach(9999);   // CMD_PROC_INFO -> CMD_ERROR, list fallback misses
    CHECK(!bad.valid());
    CHECK(b.connected());
    b.detach(h);
}

TEST_CASE(ps4_disasm_region_drains_to_sentinel) {
    server_guard_t g;
    g.srv.chaos.disasm_extra = 50;   // the payload streams past max_entries
    backend_ps4_t b;
    std::string err;
    REQUIRE(connect_fake(b, g.srv, err));
    std::vector<backend_ps4_t::ps4_disasm_entry_t> out;
    bool truncated = false;
    auto io = b.ps4_disasm_region(kFakePid, 0x400000, 0x100, 10, out, &truncated);
    REQUIRE(io.ok);
    CHECK(out.size() == 10u);
    CHECK(truncated);
    // the stream is still aligned: the next command parses cleanly
    CHECK(b.ping());
    CHECK(b.connected());
    io = b.ps4_disasm_region(kFakePid, 0x400000, 0x100, 100, out, &truncated);
    REQUIRE(io.ok);
    CHECK(out.size() == 52u);
    CHECK(!truncated);
    CHECK(b.ping());
}

TEST_CASE(ps4_read_stack_truncated_bundle_reports_error) {
    server_guard_t g;
    backend_ps4_t b;
    std::string err;
    REQUIRE(connect_fake(b, g.srv, err));
    // two-frame chain at 0x7FFF00007FF0 -> 0x7FFF00008100 -> 0
    uint64_t v = 0x7FFF00008100ull;
    g.srv.mem_write(0x7FFF00007FF0ull, reinterpret_cast<uint8_t*>(&v), 8);
    v = 0x400111;
    g.srv.mem_write(0x7FFF00007FF8ull, reinterpret_cast<uint8_t*>(&v), 8);
    std::vector<backend_ps4_t::ps4_stack_frame_t> frames;
    auto io = b.ps4_read_stack(kFakePid, 0x7FFF00007FF0ull, 0x7FFF00007F00ull, 8, frames);
    REQUIRE(io.ok);
    const size_t full = frames.size();
    CHECK(full >= 2u);
    g.srv.chaos.stack_truncate = true;   // bundle claims one frame more than it holds
    io = b.ps4_read_stack(kFakePid, 0x7FFF00007FF0ull, 0x7FFF00007F00ull, 8, frames);
    CHECK(!io.ok);
    CHECK(io.error == ps4::kErrProtocol);
    CHECK(frames.size() == full);   // what parsed is kept
    CHECK(b.connected());           // the bundle was consumed: stream in sync
    CHECK(b.ping());
}

TEST_CASE(ps4_threads_info_is_pipelined_with_names) {
    server_guard_t g;
    g.srv.chaos.thread_count = 150;   // three THREAD_INFO batches
    backend_ps4_t b;
    std::string err;
    REQUIRE(connect_fake(b, g.srv, err));
    auto thr = b.enum_threads(kFakePid);
    REQUIRE(thr.ok);
    REQUIRE(thr.items.size() == 150u);
    REQUIRE_STR_EQ(thr.items[0].name, "main");
    REQUIRE_STR_EQ(thr.items[149].name, "worker250");
    for (const auto& t : thr.items) CHECK(t.priority == 80);
    CHECK(b.ping());
    b.disconnect();
}

TEST_CASE(ps4_scan_next_crosses_chunk_boundaries) {
    server_guard_t g;
    g.srv.add_map("", 0x10000000ull, 0x10040000ull, ps4::kVmProtRead | ps4::kVmProtWrite);
    backend_ps4_t b;
    std::string err;
    REQUIRE(connect_fake(b, g.srv, err));
    REQUIRE(b.ps4_authed());

    // unknown-initial-value seed scan: every aligned u32 of 256 KiB
    std::vector<backend_ps4_t::ps4_scan_hit_t> hits;
    auto io = b.ps4_scan_first(kFakePid, 0x10000000ull, 0x40000, ps4::kValU32, ps4::kCmpUnknown,
                               4, {}, hits);
    REQUIRE(io.ok);
    REQUIRE(hits.size() == 65536u);   // 4 SCAN_COUNT chunks of 16384 entries (0x20000 bytes)

    // two changes: one in the first chunk, one right at the start of the third
    const uint32_t five = 5, seven = 7;
    g.srv.mem_write(0x10000010ull, reinterpret_cast<const uint8_t*>(&five), 4);
    g.srv.mem_write(0x10020000ull, reinterpret_cast<const uint8_t*>(&seven), 4);
    std::vector<backend_ps4_t::ps4_scan_hit_t> changed;
    io = b.ps4_scan_next(kFakePid, 0x10000000ull, ps4::kValU32, ps4::kCmpChanged, hits, {}, changed);
    REQUIRE(io.ok);
    REQUIRE(changed.size() == 2u);
    CHECK(changed[0].addr == 0x10000010ull);
    CHECK(changed[1].addr == 0x10020000ull);
    std::vector<backend_ps4_t::ps4_scan_hit_t> same;
    io = b.ps4_scan_next(kFakePid, 0x10000000ull, ps4::kValU32, ps4::kCmpUnchanged, changed, {}, same);
    REQUIRE(io.ok);
    CHECK(same.size() == 2u);

    // malformed previous hits are refused before a byte goes out
    auto bad = changed;
    bad[1].value.pop_back();   // 3 bytes where the payload reads 4
    std::vector<backend_ps4_t::ps4_scan_hit_t> none;
    io = b.ps4_scan_next(kFakePid, 0x10000000ull, ps4::kValU32, ps4::kCmpChanged, bad, {}, none);
    CHECK(!io.ok);
    CHECK(io.error == ps4::kErrBadArg);
    bad = changed;
    bad[0].addr = 0x0FFFFFF0ull;   // below the base: no u32 offset
    io = b.ps4_scan_next(kFakePid, 0x10000000ull, ps4::kValU32, ps4::kCmpChanged, bad, {}, none);
    CHECK(io.error == ps4::kErrBadArg);
    // a variable-width type needs seed data to define its width
    io = b.ps4_scan_next(kFakePid, 0x10000000ull, ps4::kValArrBytes, ps4::kCmpChanged, changed, {}, none);
    CHECK(io.error == ps4::kErrBadArg);
    // an empty previous set sends no chunk at all (never a zero-length one)
    io = b.ps4_scan_next(kFakePid, 0x10000000ull, ps4::kValU32, ps4::kCmpChanged, {}, {}, none);
    REQUIRE(io.ok);
    CHECK(none.empty());
    CHECK(b.connected());
    CHECK(b.ping());
}

TEST_CASE(ps4_event_reassembler_unit) {
    constexpr size_t kN = ps4::kDebugEventSize;
    std::vector<uint8_t> stream(kN * 3);
    for (size_t i = 0; i < stream.size(); ++i) stream[i] = static_cast<uint8_t>(i * 7 + i / kN);
    std::vector<std::vector<uint8_t>> got;
    auto sink = [&](const uint8_t* p) { got.emplace_back(p, p + kN); };
    // one byte at a time
    {
        rt::ps4_event_reassembler_t ra(kN);
        size_t n = 0;
        for (uint8_t byte : stream) n += ra.feed(&byte, 1, sink);
        CHECK(n == 3u);
        CHECK(ra.buffered() == 0u);
    }
    // ragged pieces: 1.5 packets, then the rest plus half a packet of the next feed
    {
        rt::ps4_event_reassembler_t ra(kN);
        size_t n = ra.feed(stream.data(), kN + kN / 2, sink);
        CHECK(n == 1u);
        CHECK(ra.buffered() == kN / 2);
        n = ra.feed(stream.data() + kN + kN / 2, kN + kN / 2, sink);
        CHECK(n == 2u);
        CHECK(ra.buffered() == 0u);
    }
    REQUIRE(got.size() == 6u);
    for (size_t i = 0; i < 6; ++i)
        CHECK(std::memcmp(got[i].data(), stream.data() + (i % 3) * kN, kN) == 0);
    rt::ps4_event_t ev;
    CHECK(!rt::ps4_decode_event(stream.data(), kN - 1, ev));
}

TEST_CASE(ps4_events_fragmented_on_the_wire) {
    server_guard_t g;
    backend_ps4_t b;
    std::string err;
    REQUIRE(connect_fake(b, g.srv, err));
    REQUIRE(b.ps4_debug_attach(kFakePid, err));
    std::vector<uint8_t> wire;
    for (uint32_t i = 0; i < 3; ++i) {
        auto pkt = g.srv.make_event(7 + i, 5u << 8, "frag", 0x401000 + i, 0);
        const auto* p = reinterpret_cast<const uint8_t*>(&pkt);
        wire.insert(wire.end(), p, p + sizeof(pkt));
    }
    g.srv.send_event_bytes(wire.data(), wire.size(), 37, 1);   // 37-byte pieces
    for (uint32_t i = 0; i < 3; ++i) {
        rt::ps4_event_t ev{};
        REQUIRE(b.ps4_wait_event(ev, 5000));
        CHECK(ev.lwpid == 7 + i);
        CHECK(ev.ctx.rip == 0x401000ull + i);
        REQUIRE_STR_EQ(ev.thread_name, "frag");
    }
    CHECK(b.ps4_events_received() == 3u);
    CHECK(b.ps4_events_dropped() == 0u);
    b.disconnect();
}

TEST_CASE_TIMEOUT(ps4_event_queue_drop_is_counted, 120) {
    server_guard_t g;
    backend_ps4_t b;
    std::string err;
    REQUIRE(connect_fake(b, g.srv, err));
    REQUIRE(b.ps4_debug_attach(kFakePid, err));
    constexpr uint32_t kTotal = 5000;
    std::vector<uint8_t> wire;
    wire.reserve(kTotal * ps4::kDebugEventSize);
    for (uint32_t i = 0; i < kTotal; ++i) {
        auto pkt = g.srv.make_event(i, 5u << 8, "storm", 0x400000 + i, 0);
        const auto* p = reinterpret_cast<const uint8_t*>(&pkt);
        wire.insert(wire.end(), p, p + sizeof(pkt));
    }
    g.srv.send_event_bytes(wire.data(), wire.size(), 0x10000, 0);
    REQUIRE(wait_until([&] { return b.ps4_events_received() == kTotal; }, 30000));
    const uint64_t cap = backend_ps4_t::kMaxQueuedEvents;
    CHECK(b.ps4_pending_events() == cap);
    CHECK(b.ps4_events_dropped() == kTotal - cap);
    // the oldest were dropped: the queue starts at event #904
    auto evs = b.ps4_drain_events(1, false);
    REQUIRE(evs.size() == 1u);
    CHECK(evs[0].lwpid == kTotal - cap);
    b.disconnect();
}

TEST_CASE(ps4_debug_session_end_clears_slots) {
    server_guard_t g;
    server_guard_t other;
    backend_ps4_t b;
    std::string err;
    REQUIRE(connect_fake(b, g.srv, err));

    // 1) the payload closes the event channel (debuggee gone)
    REQUIRE(b.ps4_debug_attach(kFakePid, err));
    uint32_t idx = 0;
    REQUIRE(b.ps4_bp_arm(0x400500, backend_ps4_t::kAutoSlot, idx).ok);
    CHECK(b.ps4_breakpoints().size() == 1u);
    g.srv.close_event_channel();
    REQUIRE(wait_until([&] { return !b.ps4_debug_attached(); }, 5000));
    CHECK(b.ps4_breakpoints().empty());

    // 2) a SIGKILL stop tears the session down
    REQUIRE(b.ps4_debug_attach(kFakePid, err));
    REQUIRE(b.ps4_bp_arm(0x400600, backend_ps4_t::kAutoSlot, idx).ok);
    REQUIRE(b.ps4_wp_arm(0x7FFF00001000ull, 4, ps4::kWpWrite, backend_ps4_t::kAutoSlot, idx).ok);
    g.srv.send_event(101, 9u << 8, "main", 0);
    REQUIRE(wait_until([&] { return !b.ps4_debug_attached(); }, 5000));
    CHECK(b.ps4_breakpoints().empty());
    CHECK(b.ps4_watchpoints().empty());
    g.srv.close_event_channel();   // the payload's own cleanup after the kill

    // 3) explicit detach clears; disarming a slot we never armed fails
    REQUIRE(b.ps4_debug_attach(kFakePid, err));
    REQUIRE(b.ps4_bp_arm(0x400700, backend_ps4_t::kAutoSlot, idx).ok);
    CHECK(b.ps4_wp_disarm(2).error == ps4::kErrNotArmed);
    CHECK(b.ps4_bp_disarm_addr(0x999999).error == ps4::kErrNotArmed);
    REQUIRE(b.ps4_debug_detach());
    CHECK(b.ps4_breakpoints().empty());

    // 4) connecting to another console starts from nothing
    REQUIRE(b.ps4_debug_attach(kFakePid, err));
    REQUIRE(b.ps4_bp_arm(0x400800, backend_ps4_t::kAutoSlot, idx).ok);
    uint64_t stub = 0;
    REQUIRE(b.ps4_install(kFakePid, stub).ok);
    REQUIRE(b.connect("127.0.0.1", other.srv.port, err));
    CHECK(!b.ps4_debug_attached());
    CHECK(b.ps4_breakpoints().empty());
    REQUIRE(b.ps4_install(kFakePid, stub).ok);
    CHECK(other.srv.intall_count == 1);   // stub cache was per connection
    b.disconnect();
}

TEST_CASE(ps4_slot_arming_reuses_and_reserves) {
    server_guard_t g;
    backend_ps4_t b;
    std::string err;
    REQUIRE(connect_fake(b, g.srv, err));
    uint32_t idx = 0;
    // not attached: nothing is reserved
    CHECK(b.ps4_bp_arm(0x400500, backend_ps4_t::kAutoSlot, idx).error == ps4::kErrNotAttached);
    REQUIRE(b.ps4_debug_attach(kFakePid, err));
    bool reused = true;
    REQUIRE(b.ps4_bp_arm(0x400500, backend_ps4_t::kAutoSlot, idx, &reused).ok);
    CHECK(idx == 0u);
    CHECK(!reused);
    uint32_t idx2 = 99;
    REQUIRE(b.ps4_bp_arm(0x400500, backend_ps4_t::kAutoSlot, idx2, &reused).ok);
    CHECK(idx2 == 0u);
    CHECK(reused);
    REQUIRE(b.ps4_bp_arm(0x400510, backend_ps4_t::kAutoSlot, idx2).ok);
    CHECK(idx2 == 1u);
    // fill the four DR slots, the fifth has nowhere to go
    for (uint64_t i = 0; i < 4; ++i)
        REQUIRE(b.ps4_wp_arm(0x7FFF00001000ull + i * 8, 8, ps4::kWpRdWr, backend_ps4_t::kAutoSlot, idx).ok);
    CHECK(b.ps4_wp_arm(0x7FFF00002000ull, 8, ps4::kWpRdWr, backend_ps4_t::kAutoSlot, idx).error ==
          ps4::kErrNoSlot);
    CHECK(b.ps4_wp_arm(0x7FFF00002000ull, 3, ps4::kWpRdWr, backend_ps4_t::kAutoSlot, idx).error ==
          ps4::kErrBadArg);
    // a payload-side failure leaves the slot free again
    CHECK(b.ps4_bp_arm(0x400520, 31, idx).error == ps4::kErrBadArg);
    CHECK(b.ps4_breakpoints().size() == 2u);
    b.disconnect();
}

TEST_CASE(ps4_detach_refused_reports_both_pids) {
    server_guard_t g;
    backend_ps4_t b;
    std::string err;
    REQUIRE(connect_fake(b, g.srv, err));
    REQUIRE(b.ps4_debug_attach(kFakePid, err));
    g.srv.chaos.refuse_detach = true;
    std::string aerr;
    CHECK(!b.ps4_debug_attach(42, aerr));
    CHECK(aerr.find("refused to detach pid 1234") != std::string::npos);
    CHECK(aerr.find("42") != std::string::npos);
    CHECK(b.ps4_debug_pid() == kFakePid);   // still the old debuggee
    CHECK(b.connected());
    g.srv.chaos.refuse_detach = false;
    REQUIRE(b.ps4_debug_attach(42, aerr));
    CHECK(b.ps4_debug_pid() == 42u);
    b.disconnect();
}

TEST_CASE(ps4_debug_port_in_use_names_owner) {
    server_guard_t g;
    wsa();
    SOCKET hog = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(hog != INVALID_SOCKET);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    REQUIRE(bind(hog, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);
    REQUIRE(listen(hog, 1) == 0);
    slop_socklen_t alen = sizeof(a);
    getsockname(hog, reinterpret_cast<sockaddr*>(&a), &alen);
    const uint16_t port = ntohs(a.sin_port);

    backend_ps4_t b;
    b.set_event_port(port);
    g.srv.event_port = port;
    std::string err;
    REQUIRE(connect_fake(b, g.srv, err));
    std::string aerr;
    CHECK(!b.ps4_debug_attach(kFakePid, aerr));
    CHECK(aerr.find("already in use by pid " + std::to_string(GetCurrentProcessId())) != std::string::npos);
    CHECK(aerr.find("this process") != std::string::npos);
    CHECK(b.connected());
    closesocket(hog);
    b.disconnect();
}

TEST_CASE(ps4_composites_on_console_debugger) {
    server_guard_t g;
    ps4_disconnect_guard_t guard;
    std::string err;
    REQUIRE(connect_fake_target(g.srv, kFakePid, err));
    auto dbg = [](const json& a, bool& is_err) {
        return slop::core::mcp::call_tool("debugger", a, is_err);
    };
    bool e = false;
    json r = dbg({{"action", "ps4_until"}, {"addr", 0x400500}}, e);
    CHECK(e);   // needs a debug session first
    r = dbg({{"action", "ps4_attach"}, {"pid", kFakePid}}, e);
    REQUIRE(!e);

    // run until: one-shot bp, stop at it, slot released afterwards
    r = dbg({{"action", "ps4_until"}, {"addr", 0x400500}, {"timeout_ms", 3000}}, e);
    CHECK(!e);
    if (e) std::printf("  ps4_until err: %s\n", r.dump().c_str());
    CHECK(r.value("halted", false) == true);
    CHECK(r.value("rip", 0) == 0x400500);
    CHECK(r.value("debugger", std::string{}) == "ps4");
    CHECK(!g.srv.bps[r.value("index", 0u)].enabled);
    r = dbg({{"action", "ps4_bp_list"}}, e);
    CHECK(r.value("count", 99) == 0);

    // trace every call: three hits, args recorded, stays stopped
    r = dbg({{"action", "ps4_trace_calls"}, {"addr", 0x400600}, {"count", 3}, {"timeout_ms", 3000}}, e);
    CHECK(!e);
    CHECK(r.value("hits_count", 0) == 3);
    CHECK(r.value("stop_reason", std::string{}) == "count_reached");
    REQUIRE(r["hits"].size() == 3u);
    CHECK(r["hits"][2].value("rip", 0) == 0x400600);

    // writer of an address: write watchpoint, stop event + callstack
    r = dbg({{"action", "ps4_find_write"}, {"addr", 0x7FFF00002000ull}, {"len", 8},
             {"timeout_ms", 3000}}, e);
    CHECK(!e);
    CHECK(r.value("halted", false) == true);
    CHECK(r["event"].value("reason", std::string{}) == "watchpoint");
    CHECK(r["callstack"].is_array());
    CHECK(!g.srv.wps[r.value("index", 0u)].enabled);

    // single-step trace
    r = dbg({{"action", "ps4_trace_steps"}, {"lwpid", 101}, {"count", 3}, {"timeout_ms", 3000}}, e);
    CHECK(!e);
    REQUIRE(r["steps"].size() == 3u);
    const uint64_t r0 = r["steps"][0].value("rip", 0ull);
    CHECK(r["steps"][1].value("rip", 0ull) == r0 + 1);
    CHECK(r["steps"][2].value("rip", 0ull) == r0 + 2);

    // a stop that is not the target is resumed past; the user's own bp stays
    r = dbg({{"action", "ps4_bp_set"}, {"addr", 0x400700}}, e);
    REQUIRE(!e);
    r = dbg({{"action", "ps4_until"}, {"addr", 0x400800}, {"timeout_ms", 600}}, e);
    CHECK(!e);
    CHECK(r.value("halted", true) == false);
    CHECK(r.value("skipped_stops", 0) > 0);
    r = dbg({{"action", "ps4_bp_list"}}, e);
    CHECK(r.value("count", 0) == 1);
    r = dbg({{"action", "ps4_detach"}}, e);
    CHECK(!e);
}
