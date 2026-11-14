// src/tests/ps5_fixture.hpp
// Shared by the test_ps5 area: the fake ps5debug-NG payload server on loopback
// TCP (implements the wire protocol subset in ps5_protocol.hpp), its fault
// injection knobs and small wait helpers. Everything lives in an anonymous
// namespace, so each area gets its own copy.

#pragma once

#include "harness.hpp"

#include "core/mcp/mcp_tools.hpp"
#include "core/process/target_service.hpp"
#include "core/runtime/backend_ps5.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/ps5_protocol.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

using json = nlohmann::json;
namespace ps5 = slop::core::runtime::ps5;
using slop::core::runtime::backend_ps5_t;
using slop::core::runtime::backend_kind_t;

constexpr uint32_t kFakePid = 4242;

struct wsa_init_t {
    wsa_init_t() { WSADATA d; WSAStartup(MAKEWORD(2, 2), &d); }
    ~wsa_init_t() { WSACleanup(); }
};
wsa_init_t& wsa() {
    static wsa_init_t w;
    return w;
}

// an ephemeral loopback port for the payload's port-755 connect-back, so the
// tests never fight over the fixed port
uint16_t free_tcp_port() {
    wsa();
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;
    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        closesocket(s);
        return 0;
    }
    int len = sizeof(addr);
    getsockname(s, reinterpret_cast<sockaddr*>(&addr), &len);
    const uint16_t port = ntohs(addr.sin_port);
    closesocket(s);
    return port;
}

// fault injection for the fake payload's replies (server thread only)
struct chaos_t {
    std::atomic<bool>     fragment{false};    // replies leave 1-3 bytes per send
    std::atomic<uint32_t> stall_cmd{0};       // never answer this command (one-shot)
    std::atomic<uint32_t> close_cmd{0};       // cut the connection while answering (one-shot)
    std::atomic<int>      close_after{0};     // reply bytes sent before the cut
    std::atomic<uint32_t> garbage_cmd{0};     // answer with a non-status word (one-shot)
    std::atomic<bool>     refuse_detach{false};
    std::atomic<bool>     hide_game_pid{false};   // process list omits kFakePid
    std::atomic<uint32_t> thread_count{2};
};
thread_local chaos_t* tl_chaos = nullptr;
thread_local int tl_budget = -1;   // reply bytes left before the cut, -1 = unlimited

bool send_raw(SOCKET s, const char* p, size_t left) {
    while (left > 0) {
        int n = ::send(s, p, static_cast<int>(left), 0);
        if (n <= 0) return false;
        p += n;
        left -= static_cast<size_t>(n);
    }
    return true;
}

bool send_all(SOCKET s, const void* buf, size_t len) {
    const char* p = static_cast<const char*>(buf);
    chaos_t* ch = tl_chaos;
    if (!ch) return send_raw(s, p, len);
    size_t left = len;
    const bool frag = ch->fragment.load();
    int step = 1;
    while (left > 0) {
        size_t n = frag ? std::min<size_t>(left, static_cast<size_t>(step)) : left;
        step = step % 3 + 1;
        if (tl_budget >= 0) {
            if (tl_budget == 0) {
                ::shutdown(s, SD_BOTH);
                return false;
            }
            n = std::min<size_t>(n, static_cast<size_t>(tl_budget));
            tl_budget -= static_cast<int>(n);
        }
        if (!send_raw(s, p, n)) return false;
        p += n;
        left -= n;
    }
    if (tl_budget == 0) {   // budget ended exactly at a reply boundary: cut now
        ::shutdown(s, SD_BOTH);
        return false;
    }
    return true;
}

bool recv_all(SOCKET s, void* buf, size_t len) {
    char* p = static_cast<char*>(buf);
    size_t left = len;
    while (left > 0) {
        int n = ::recv(s, p, static_cast<int>(left), 0);
        if (n <= 0) return false;
        p += n;
        left -= static_cast<size_t>(n);
    }
    return true;
}

bool send_u32(SOCKET s, uint32_t v) { return send_all(s, &v, sizeof(v)); }

// ---------------------------------------------------------------------------
// fake ps5debug-NG payload

struct fake_ps5_server_t {
    SOCKET listen_fd = INVALID_SOCKET;
    uint16_t port = 0;
    std::thread th;
    std::atomic<bool> stop_flag{false};

    std::mutex mu;
    std::map<uint64_t, std::array<uint8_t, 0x1000>> mem;   // 4 KiB pages
    std::vector<ps5::vm_map_entry_t> maps;
    bool debug_attached = false;
    uint32_t debug_pid = 0;
    SOCKET event_fd = INVALID_SOCKET;   // our side of the port-755 callback
    uint16_t event_port = 0;            // where the debug channel connects back
    uint32_t last_protect = 0xFFFFFFFF;
    uint32_t last_alloc_hint = 0;
    std::map<uint32_t, ps5::reg64_t> thread_regs;
    chaos_t chaos;
    int connections = 0;
    int commands_seen = 0;
    int detach_count = 0;

    // debug-session state observed by the tests
    struct bp_t { bool enabled = false; uint64_t address = 0; };
    struct wp_t { bool enabled = false; uint32_t length = 0; uint32_t breaktype = 0; uint64_t address = 0; };
    std::map<uint32_t, bp_t> bps;
    std::map<uint32_t, wp_t> wps;
    uint32_t last_continue_stop = 0xFFFFFFFF;
    uint32_t last_suspend = 0, last_resume = 0;
    int step_calls = 0, step_thread_calls = 0;

    // console state observed by the tests
    std::string last_notify, last_print;
    uint32_t last_notify_type = 0;

    void add_map(const char* name, uint64_t start, uint64_t end, uint16_t prot) {
        std::lock_guard lk(mu);
        ps5::vm_map_entry_t m{};
        std::strncpy(m.name, name, sizeof(m.name) - 1);
        m.start = start;
        m.end = end;
        m.offset = 0;
        m.prot = prot;
        maps.push_back(m);
    }

    // eboot text/relro, an anonymous RW gap, eboot data, a shared library and
    // the stack: the same shape the PS4 fixture uses
    void seed_maps() {
        add_map("/app0/eboot.bin", 0x400000, 0x480000, ps5::kVmProtRead | ps5::kVmProtExec);
        add_map("/app0/eboot.bin", 0x480000, 0x4C0000, ps5::kVmProtRead);
        add_map("", 0x4C0000, 0x4C8000, ps5::kVmProtRead | ps5::kVmProtWrite);
        add_map("/app0/eboot.bin", 0x4C8000, 0x500000, ps5::kVmProtRead | ps5::kVmProtWrite);
        add_map("/app0/libSceLibcInternal.sprx", 0x500000, 0x510000,
                ps5::kVmProtRead | ps5::kVmProtExec);
        add_map("", 0x7FFF00000000ull, 0x7FFF00010000ull,
                ps5::kVmProtRead | ps5::kVmProtWrite);
    }

    bool start() {
        wsa();
        seed_maps();
        listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listen_fd == INVALID_SOCKET) return false;
        int flag = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char*>(&flag), sizeof(flag));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;   // ephemeral
        if (bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) return false;
        if (listen(listen_fd, 4) != 0) return false;
        int len = sizeof(addr);
        getsockname(listen_fd, reinterpret_cast<sockaddr*>(&addr), &len);
        port = ntohs(addr.sin_port);
        th = std::thread([this] { accept_loop(); });
        return true;
    }

    void shutdown() {
        stop_flag = true;
        if (listen_fd != INVALID_SOCKET) {
            ::shutdown(listen_fd, SD_BOTH);
            closesocket(listen_fd);
            listen_fd = INVALID_SOCKET;
        }
        {
            std::lock_guard lk(mu);
            if (event_fd != INVALID_SOCKET) {
                closesocket(event_fd);
                event_fd = INVALID_SOCKET;
            }
        }
        if (th.joinable()) th.join();
        std::vector<std::thread> ths;
        {
            std::lock_guard lk(conn_mu);
            for (SOCKET c : conn_socks) {
                ::shutdown(c, SD_BOTH);
                closesocket(c);
            }
            conn_socks.clear();
            ths.swap(conn_threads);
        }
        for (auto& t : ths)
            if (t.joinable()) t.join();
    }

    ~fake_ps5_server_t() { shutdown(); }

    uint8_t mem_byte(uint64_t addr) {
        std::lock_guard lk(mu);
        auto it = mem.find(addr & ~0xFFFull);
        return it == mem.end() ? 0 : it->second[addr & 0xFFF];
    }

    void mem_write(uint64_t addr, const uint8_t* data, size_t len) {
        std::lock_guard lk(mu);
        for (size_t i = 0; i < len; ++i) {
            const uint64_t a = addr + i;
            mem[a & ~0xFFFull][a & 0xFFF] = data[i];
        }
    }

    // drop the port-755 channel the way the payload's teardown does
    void close_event_channel() {
        std::lock_guard lk(mu);
        debug_attached = false;
        bps.clear();
        wps.clear();
        if (event_fd != INVALID_SOCKET) {
            ::shutdown(event_fd, SD_BOTH);
            closesocket(event_fd);
            event_fd = INVALID_SOCKET;
        }
    }

    // push one stop packet on the port-755 channel (false when not attached)
    bool send_event(uint32_t lwpid, uint32_t status, const char* name, uint64_t rip) {
        SOCKET ev = INVALID_SOCKET;
        {
            std::lock_guard lk(mu);
            ev = event_fd;
        }
        if (ev == INVALID_SOCKET) return false;
        const auto pkt = make_event(lwpid, status, name, rip);
        return send_raw(ev, reinterpret_cast<const char*>(&pkt), sizeof(pkt));
    }

    ps5::debug_event_packet_t make_event(uint32_t lwpid, uint32_t status, const char* name,
                                         uint64_t rip) {
        std::lock_guard lk(mu);
        ps5::debug_event_packet_t pkt{};
        pkt.lwpid  = lwpid;
        pkt.status = status;
        std::strncpy(pkt.tdname, name, sizeof(pkt.tdname) - 1);
        pkt.regs = thread_regs[lwpid];
        if (pkt.regs.rip == 0) {
            pkt.regs.rip = 0x400123;
            pkt.regs.rsp = 0x7FFF00008000ull;
            pkt.regs.rbp = 0x7FFF00007FF0ull;
            pkt.regs.rax = 0x2A;
            pkt.regs.rflags = 0x202;
        }
        if (rip) pkt.regs.rip = rip;
        for (int i = 0; i < 16; ++i) {
            const uint64_t v = 0x1000ull + static_cast<uint64_t>(i);
            std::memcpy(pkt.dbregs + i * 8, &v, sizeof(v));
        }
        return pkt;
    }

private:
    void accept_loop() {
        while (!stop_flag) {
            fd_set rset;
            FD_ZERO(&rset);
            FD_SET(listen_fd, &rset);
            timeval tv{};
            tv.tv_sec = 0;
            tv.tv_usec = 200 * 1000;
            if (select(0, &rset, nullptr, nullptr, &tv) <= 0) continue;
            SOCKET c = accept(listen_fd, nullptr, nullptr);
            if (c == INVALID_SOCKET) continue;
            std::lock_guard lk(conn_mu);
            conn_socks.push_back(c);
            conn_threads.emplace_back([this, c] { handle_conn(c); });
        }
    }

    std::mutex conn_mu;
    std::vector<SOCKET> conn_socks;
    std::vector<std::thread> conn_threads;

    void handle_conn(SOCKET c) {
        tl_chaos = &chaos;
        tl_budget = -1;
        {
            // the payload keeps debug state per connection: reset it when the
            // new connection starts, not when the old one ends
            std::lock_guard lk(mu);
            ++connections;
            debug_attached = false;
            debug_pid = 0;
            bps.clear();
            wps.clear();
            if (event_fd != INVALID_SOCKET) {
                ::shutdown(event_fd, SD_BOTH);
                closesocket(event_fd);
                event_fd = INVALID_SOCKET;
            }
        }
        handle_conn_loop(c);
        ::shutdown(c, SD_BOTH);
    }

    void handle_conn_loop(SOCKET c) {
        while (!stop_flag) {
            ps5::packet_header_t hdr{};
            if (!recv_all(c, &hdr, sizeof(hdr))) return;
            if (hdr.magic != ps5::kPacketMagic) return;
            if (hdr.datalen > ps5::kMaxDatalen) { send_u32(c, ps5::CMD_TOO_MUCH_DATA); return; }
            std::vector<uint8_t> body(hdr.datalen);
            if (hdr.datalen > 0 && !recv_all(c, body.data(), hdr.datalen)) return;
            {
                std::lock_guard lk(mu);
                ++commands_seen;
            }
            const bool ok = dispatch(c, hdr.cmd, body.data(), hdr.datalen);
            tl_budget = -1;
            if (!ok) return;
        }
    }

    // block until the client gives up on this connection (stall injection)
    static void wait_for_close(SOCKET c, const std::atomic<bool>& stop) {
        char sink[256];
        while (!stop) {
            fd_set rset;
            FD_ZERO(&rset);
            FD_SET(c, &rset);
            timeval tv{0, 100 * 1000};
            if (select(0, &rset, nullptr, nullptr, &tv) <= 0) continue;
            if (::recv(c, sink, sizeof(sink), 0) <= 0) return;
        }
    }

    bool dispatch(SOCKET c, uint32_t cmd, const uint8_t* body, uint32_t bodylen) {
        if (cmd != 0 && chaos.stall_cmd.load() == cmd) {
            chaos.stall_cmd = 0;
            wait_for_close(c, stop_flag);
            return false;
        }
        if (cmd != 0 && chaos.close_cmd.load() == cmd) {
            chaos.close_cmd = 0;
            tl_budget = chaos.close_after.load();
        }
        if (cmd != 0 && chaos.garbage_cmd.load() == cmd) {
            chaos.garbage_cmd = 0;
            return send_u32(c, 0x12345678u);   // not a status word at all
        }
        return dispatch_cmd(c, cmd, body, bodylen);
    }

    bool dispatch_cmd(SOCKET c, uint32_t cmd, const uint8_t* body, uint32_t bodylen) {
        switch (cmd) {
        case ps5::CMD_VERSION: {
            const char* v = "1.3";
            const uint32_t len = 3;
            return send_u32(c, len) && send_all(c, v, len);
        }
        case ps5::CMD_BRANDING: {
            static const char b[] = "ps5debug-NG by OSR v1.3.2 [test000000000000]\0" "1.1";
            const uint32_t len = static_cast<uint32_t>(sizeof(b) - 1);
            return send_u32(c, len) && send_all(c, b, len);
        }
        case ps5::CMD_FW_VERSION: {
            const uint16_t fw = 900;   // 9.00
            return send_all(c, &fw, sizeof(fw));
        }
        case ps5::CMD_PLATFORM_ID: {
            const uint16_t tag = ps5::kPlatformPs5;
            return send_all(c, &tag, sizeof(tag));
        }
        case ps5::CMD_PROC_NOP:
            return send_u32(c, ps5::CMD_SUCCESS);

        case ps5::CMD_PROC_LIST: {
            const bool hide = chaos.hide_game_pid.load();
            if (!send_u32(c, ps5::CMD_SUCCESS)) return false;
            if (!send_u32(c, hide ? 1u : 2u)) return false;
            ps5::proc_list_entry_t e{};
            if (!hide) {
                std::strncpy(e.name, "eboot.bin", sizeof(e.name) - 1);
                e.pid = static_cast<int32_t>(kFakePid);
                if (!send_all(c, &e, sizeof(e))) return false;
            }
            std::memset(&e, 0, sizeof(e));
            std::strncpy(e.name, "SceShellCore", sizeof(e.name) - 1);
            e.pid = 42;
            return send_all(c, &e, sizeof(e));
        }

        case ps5::CMD_PROC_INFO: {
            if (bodylen < sizeof(ps5::proc_info_packet_t))
                return send_u32(c, ps5::CMD_DATA_NULL), false;
            const auto* p = reinterpret_cast<const ps5::proc_info_packet_t*>(body);
            if (p->pid != kFakePid && p->pid != 42) return send_u32(c, ps5::CMD_ERROR), true;
            ps5::proc_info_response_t r{};
            r.pid = p->pid;
            std::strncpy(r.name, p->pid == kFakePid ? "eboot.bin" : "SceShellCore",
                         sizeof(r.name) - 1);
            std::strncpy(r.path, p->pid == kFakePid ? "/app0/eboot.bin" : "/system/sce_shell.elf",
                         sizeof(r.path) - 1);
            std::strncpy(r.titleid, "PPSA00001", sizeof(r.titleid) - 1);
            std::strncpy(r.contentid, "UP0000-PPSA00001_00-TEST000000000000",
                         sizeof(r.contentid) - 1);
            return send_u32(c, ps5::CMD_SUCCESS) && send_all(c, &r, sizeof(r));
        }

        case ps5::CMD_PROC_READ: {
            if (bodylen < sizeof(ps5::proc_read_packet_t))
                return send_u32(c, ps5::CMD_DATA_NULL), false;
            const auto* p = reinterpret_cast<const ps5::proc_read_packet_t*>(body);
            if (!send_u32(c, ps5::CMD_SUCCESS)) return false;
            std::vector<uint8_t> out(p->length, 0);
            {
                std::lock_guard lk(mu);
                for (uint32_t i = 0; i < p->length; ++i) {
                    const uint64_t a = p->address + i;
                    auto it = mem.find(a & ~0xFFFull);
                    if (it != mem.end()) out[i] = it->second[a & 0xFFF];
                }
            }
            // stream in 64 KiB chunks like the payload
            for (size_t off = 0; off < out.size(); off += ps5::kChunkSize) {
                const size_t n = std::min<size_t>(ps5::kChunkSize, out.size() - off);
                if (!send_all(c, out.data() + off, n)) return false;
            }
            return true;
        }

        case ps5::CMD_PROC_WRITE: {
            if (bodylen < sizeof(ps5::proc_write_packet_t))
                return send_u32(c, ps5::CMD_DATA_NULL), false;
            const auto* p = reinterpret_cast<const ps5::proc_write_packet_t*>(body);
            if (!send_u32(c, ps5::CMD_SUCCESS)) return false;   // ack, then the data phase
            std::vector<uint8_t> data(p->length, 0);
            if (p->length > 0 && !recv_all(c, data.data(), data.size())) return false;
            mem_write(p->address, data.data(), data.size());
            return send_u32(c, ps5::CMD_SUCCESS);
        }

        case ps5::CMD_PROC_MAPS: {
            if (bodylen < sizeof(ps5::proc_maps_packet_t))
                return send_u32(c, ps5::CMD_DATA_NULL), false;
            std::lock_guard lk(mu);
            if (!send_u32(c, ps5::CMD_SUCCESS)) return false;
            if (!send_u32(c, static_cast<uint32_t>(maps.size()))) return false;
            for (const auto& m : maps)
                if (!send_all(c, &m, sizeof(m))) return false;
            return true;
        }

        case ps5::CMD_PROC_PROTECT: {
            if (bodylen < sizeof(ps5::proc_protect_packet_t))
                return send_u32(c, ps5::CMD_DATA_NULL), false;
            const auto* p = reinterpret_cast<const ps5::proc_protect_packet_t*>(body);
            {
                std::lock_guard lk(mu);
                last_protect = p->newprot;
            }
            return send_u32(c, ps5::CMD_SUCCESS);
        }

        case ps5::CMD_PROC_ALLOC: {
            if (bodylen < sizeof(ps5::proc_alloc_packet_t))
                return send_u32(c, ps5::CMD_DATA_NULL), false;
            const auto* p = reinterpret_cast<const ps5::proc_alloc_packet_t*>(body);
            const uint64_t addr = 0x600000;
            add_map("", addr, addr + p->length, ps5::kVmProtRead | ps5::kVmProtWrite);
            return send_u32(c, ps5::CMD_SUCCESS) && send_all(c, &addr, sizeof(addr));
        }
        case ps5::CMD_PROC_ALLOC_HINTED: {
            if (bodylen < sizeof(ps5::proc_alloc_hinted_packet_t))
                return send_u32(c, ps5::CMD_DATA_NULL), false;
            const auto* p = reinterpret_cast<const ps5::proc_alloc_hinted_packet_t*>(body);
            {
                std::lock_guard lk(mu);
                last_alloc_hint = static_cast<uint32_t>(p->hint);
            }
            const uint64_t addr = p->hint;
            add_map("", addr, addr + p->length, ps5::kVmProtRead | ps5::kVmProtWrite);
            return send_u32(c, ps5::CMD_SUCCESS) && send_all(c, &addr, sizeof(addr));
        }
        case ps5::CMD_PROC_FREE: {
            if (bodylen < sizeof(ps5::proc_free_packet_t))
                return send_u32(c, ps5::CMD_DATA_NULL), false;
            return send_u32(c, ps5::CMD_SUCCESS);
        }

        case ps5::CMD_DEBUG_ATTACH: {
            if (bodylen < sizeof(ps5::debug_attach_packet_t))
                return send_u32(c, ps5::CMD_DATA_NULL), false;
            const auto* p = reinterpret_cast<const ps5::debug_attach_packet_t*>(body);
            {
                std::lock_guard lk(mu);
                if (debug_attached) return send_u32(c, ps5::CMD_ALREADY_DEBUG), true;
                debug_attached = true;
                debug_pid = p->pid;
            }
            // the payload connects back to the client's port 755 or attach fails
            SOCKET ev = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (ev != INVALID_SOCKET) {
                sockaddr_in dst{};
                dst.sin_family      = AF_INET;
                dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                dst.sin_port        = htons(event_port);
                if (::connect(ev, reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) != 0) {
                    closesocket(ev);
                    ev = INVALID_SOCKET;
                }
            }
            if (ev == INVALID_SOCKET) {
                std::lock_guard lk(mu);
                debug_attached = false;
                return send_u32(c, ps5::CMD_ERROR), true;
            }
            {
                std::lock_guard lk(mu);
                event_fd = ev;
            }
            return send_u32(c, ps5::CMD_SUCCESS);
        }
        case ps5::CMD_DEBUG_DETACH: {
            if (chaos.refuse_detach.load()) return send_u32(c, ps5::CMD_ERROR), true;
            {
                std::lock_guard lk(mu);
                ++detach_count;
                debug_attached = false;
                debug_pid = 0;
                bps.clear();
                wps.clear();
                if (event_fd != INVALID_SOCKET) {
                    ::shutdown(event_fd, SD_BOTH);
                    closesocket(event_fd);
                    event_fd = INVALID_SOCKET;
                }
            }
            return send_u32(c, ps5::CMD_SUCCESS);
        }
        case ps5::CMD_DEBUG_GET_THREAD_LIST: {
            if (!debug_attached) return send_u32(c, ps5::CMD_ERROR), true;
            const uint32_t n = chaos.thread_count.load();
            if (!send_u32(c, ps5::CMD_SUCCESS)) return false;
            if (!send_u32(c, n)) return false;
            for (uint32_t i = 0; i < n; ++i) {
                const uint32_t lwpid = 101 + i;
                if (!send_all(c, &lwpid, sizeof(lwpid))) return false;
            }
            return true;
        }
        case ps5::CMD_DEBUG_THREAD_INFO: {
            if (!debug_attached) return send_u32(c, ps5::CMD_ERROR), true;
            if (bodylen < sizeof(ps5::debug_lwpid_packet_t))
                return send_u32(c, ps5::CMD_DATA_NULL), false;
            const auto* p = reinterpret_cast<const ps5::debug_lwpid_packet_t*>(body);
            ps5::debug_thread_info_response_t r{};
            r.lwpid = p->lwpid;
            r.priority = 80;
            std::strncpy(r.name, p->lwpid == 101 ? "main" : "worker", sizeof(r.name) - 1);
            return send_u32(c, ps5::CMD_SUCCESS) && send_all(c, &r, sizeof(r));
        }
        case ps5::CMD_DEBUG_GETREGS: {
            if (!debug_attached) return send_u32(c, ps5::CMD_ERROR), true;
            if (bodylen < sizeof(ps5::debug_lwpid_packet_t))
                return send_u32(c, ps5::CMD_DATA_NULL), false;
            const auto* p = reinterpret_cast<const ps5::debug_lwpid_packet_t*>(body);
            ps5::reg64_t reg{};
            {
                std::lock_guard lk(mu);
                reg = thread_regs[p->lwpid];
            }
            if (reg.rip == 0) {
                reg.rip = 0x400123;
                reg.rsp = 0x7FFF00008000ull;
                reg.rbp = 0x7FFF00007FF0ull;
                reg.rax = 0x2A;
                reg.rflags = 0x202;
            }
            return send_u32(c, ps5::CMD_SUCCESS) && send_all(c, &reg, sizeof(reg));
        }
        case ps5::CMD_DEBUG_SETREGS: {
            if (!debug_attached) return send_u32(c, ps5::CMD_ERROR), true;
            if (bodylen < sizeof(ps5::debug_setregs_packet_t))
                return send_u32(c, ps5::CMD_DATA_NULL), false;
            const auto* p = reinterpret_cast<const ps5::debug_setregs_packet_t*>(body);
            if (!send_u32(c, ps5::CMD_SUCCESS)) return false;   // ack, then the blob
            ps5::reg64_t reg{};
            if (p->length != sizeof(reg) || !recv_all(c, &reg, sizeof(reg))) return false;
            {
                std::lock_guard lk(mu);
                thread_regs[p->lwpid] = reg;
            }
            return send_u32(c, ps5::CMD_SUCCESS);
        }
        case ps5::CMD_DEBUG_SET_BREAKPOINT: {
            if (!debug_attached) return send_u32(c, ps5::CMD_ERROR), true;
            if (bodylen < sizeof(ps5::debug_set_breakpoint_packet_t))
                return send_u32(c, ps5::CMD_DATA_NULL), false;
            const auto* p = reinterpret_cast<const ps5::debug_set_breakpoint_packet_t*>(body);
            if (p->index >= ps5::kMaxSwBreakpoints)
                return send_u32(c, ps5::CMD_INVALID_INDEX), true;
            {
                std::lock_guard lk(mu);
                bps[p->index] = {p->enabled != 0, p->address};
            }
            return send_u32(c, ps5::CMD_SUCCESS);
        }
        case ps5::CMD_DEBUG_SET_WATCHPOINT: {
            if (!debug_attached) return send_u32(c, ps5::CMD_ERROR), true;
            if (bodylen < sizeof(ps5::debug_set_watchpoint_packet_t))
                return send_u32(c, ps5::CMD_DATA_NULL), false;
            const auto* p = reinterpret_cast<const ps5::debug_set_watchpoint_packet_t*>(body);
            if (p->index >= ps5::kMaxWatchpoints)
                return send_u32(c, ps5::CMD_INVALID_INDEX), true;
            {
                std::lock_guard lk(mu);
                wps[p->index] = {p->enabled != 0, p->length, p->breaktype, p->address};
            }
            return send_u32(c, ps5::CMD_SUCCESS);
        }
        case ps5::CMD_DEBUG_CONTINUE: {
            if (!debug_attached) return send_u32(c, ps5::CMD_ERROR), true;
            if (bodylen < sizeof(ps5::debug_continue_packet_t))
                return send_u32(c, ps5::CMD_DATA_NULL), false;
            const auto* p = reinterpret_cast<const ps5::debug_continue_packet_t*>(body);
            {
                std::lock_guard lk(mu);
                last_continue_stop = p->stop;
            }
            return send_u32(c, ps5::CMD_SUCCESS);
        }
        case ps5::CMD_DEBUG_STEP: {
            if (!debug_attached) return send_u32(c, ps5::CMD_ERROR), true;
            {
                std::lock_guard lk(mu);
                ++step_calls;
            }
            return send_u32(c, ps5::CMD_SUCCESS);
        }
        case ps5::CMD_DEBUG_STEP_THREAD: {
            if (!debug_attached) return send_u32(c, ps5::CMD_ERROR), true;
            {
                std::lock_guard lk(mu);
                ++step_thread_calls;
            }
            return send_u32(c, ps5::CMD_SUCCESS);
        }
        case ps5::CMD_DEBUG_SUSPEND:
        case ps5::CMD_DEBUG_RESUME: {
            if (!debug_attached) return send_u32(c, ps5::CMD_ERROR), true;
            if (bodylen < sizeof(ps5::debug_lwpid_packet_t))
                return send_u32(c, ps5::CMD_DATA_NULL), false;
            const auto* p = reinterpret_cast<const ps5::debug_lwpid_packet_t*>(body);
            {
                std::lock_guard lk(mu);
                if (cmd == ps5::CMD_DEBUG_SUSPEND) last_suspend = p->lwpid;
                else last_resume = p->lwpid;
            }
            return send_u32(c, ps5::CMD_SUCCESS);
        }

        case ps5::CMD_CONSOLE_NOTIFY: {
            if (bodylen < sizeof(ps5::console_notify_packet_t))
                return send_u32(c, ps5::CMD_DATA_NULL), false;
            const auto* p = reinterpret_cast<const ps5::console_notify_packet_t*>(body);
            std::string text(p->length, '\0');
            if (p->length > 0 && !recv_all(c, text.data(), text.size())) return false;
            if (!text.empty() && text.back() == '\0') text.pop_back();   // trailing NUL
            {
                std::lock_guard lk(mu);
                last_notify = text;
                last_notify_type = p->messageType;
            }
            return send_u32(c, ps5::CMD_SUCCESS);
        }
        case ps5::CMD_CONSOLE_PRINT: {
            if (bodylen < sizeof(ps5::console_print_packet_t))
                return send_u32(c, ps5::CMD_DATA_NULL), false;
            const auto* p = reinterpret_cast<const ps5::console_print_packet_t*>(body);
            std::string text(p->length, '\0');
            if (p->length > 0 && !recv_all(c, text.data(), text.size())) return false;
            {
                std::lock_guard lk(mu);
                last_print = text;
            }
            return send_u32(c, ps5::CMD_SUCCESS);
        }
        case ps5::CMD_CONSOLE_INFO:
            return send_u32(c, ps5::CMD_SUCCESS);
        case ps5::CMD_CONSOLE_FOREGROUND_APP: {
            ps5::console_foreground_app_response_t r{};
            r.pid = kFakePid;
            std::strncpy(r.titleid, "PPSA00001", sizeof(r.titleid) - 1);
            std::strncpy(r.contentid, "UP0000-PPSA00001_00-TEST000000000000",
                         sizeof(r.contentid) - 1);
            std::strncpy(r.name, "Test Game", sizeof(r.name) - 1);
            std::strncpy(r.app_ver, "01.02", sizeof(r.app_ver) - 1);
            return send_u32(c, ps5::CMD_SUCCESS) && send_all(c, &r, sizeof(r));
        }

        default:
            // the payload answers CMD_ERROR and closes the client
            return send_u32(c, ps5::CMD_ERROR), false;
        }
    }
};

struct server_guard_t {
    fake_ps5_server_t srv;
    server_guard_t() { REQUIRE(srv.start()); }
    ~server_guard_t() { srv.shutdown(); }
};

// drop the global PS5 connection even when a REQUIRE throws mid-test
struct ps5_disconnect_guard_t {
    ~ps5_disconnect_guard_t() {
        slop::core::process::target_disconnect_ps5();
    }
};

bool wait_until(const std::function<bool()>& pred, int timeout_ms) {
    const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < until) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return pred();
}

} // namespace
