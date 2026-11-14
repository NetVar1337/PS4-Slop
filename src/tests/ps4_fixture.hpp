// src/tests/ps4_fixture.hpp
// Shared by the test_ps4*.cpp areas: the fake ps4debug-NG payload server on
// loopback TCP (implements the wire protocol subset in ps4_protocol.hpp),
// its guards and small wait helpers. Everything lives in an anonymous
// namespace, so each area gets its own copy.

#pragma once

#include "harness.hpp"

#include "core/debugger/composite.hpp"
#include "core/debugger/local_debugger.hpp"
#include "core/mcp/mcp_tools.hpp"
#include "core/process/target_service.hpp"
#include "core/runtime/backend_ps4.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/gdb_rsp.hpp"
#include "core/runtime/ps4_protocol.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include "core/compat/posix_socket.hpp"
#endif
#include "core/compat/portable.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>

#include <array>

#include <cstdio>

#include <fstream>

#include <atomic>
#include <chrono>
#include <functional>
#include <iterator>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

using json = nlohmann::json;
namespace ps4 = slop::core::runtime::ps4;
using slop::core::runtime::backend_ps4_t;
using slop::core::runtime::backend_kind_t;

constexpr uint32_t kFakePid = 1234;

struct wsa_init_t {
    wsa_init_t() { WSADATA d; WSAStartup(MAKEWORD(2, 2), &d); }
    ~wsa_init_t() { WSACleanup(); }
};
wsa_init_t& wsa() {
    static wsa_init_t w;
    return w;
}

// A free loopback port for the payload's debug-event callback. The protocol
// port (755) is machine-global: a concurrent test process, another checkout's
// suite or a real payload holding it makes the backend's listener bind fail,
// which is what made the debug-session tests flaky. Every fake payload takes
// its own ephemeral port instead and the backend is pointed at it.
inline uint16_t ephemeral_port() {
    wsa();
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    uint16_t port = 0;
    if (bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0) {
        slop_socklen_t len = sizeof(a);
        getsockname(s, reinterpret_cast<sockaddr*>(&a), &len);
        port = ntohs(a.sin_port);
    }
    closesocket(s);
    return port;
}

// fault injection for the fake payload's replies (server thread only):
// fragmented / dribbled sends and a byte budget after which the connection
// is cut mid-reply
struct chaos_t {
    std::atomic<bool>     fragment{false};    // replies leave 1-3 bytes per send
    std::atomic<int>      dribble_ms{0};      // sleep between reply fragments
    std::atomic<uint32_t> stall_cmd{0};       // never answer this command (one-shot)
    std::atomic<uint32_t> close_cmd{0};       // cut the connection while answering (one-shot)
    std::atomic<int>      close_after{0};     // reply bytes sent before the cut
    std::atomic<uint32_t> garbage_cmd{0};     // answer with a non-status word (one-shot)
    std::atomic<bool>     refuse_detach{false};
    std::atomic<bool>     hide_game_pid{false};   // process list omits kFakePid
    std::atomic<bool>     stack_truncate{false};  // bundle claims one frame more than it has
    std::atomic<int>      disasm_extra{0};        // entries beyond the two canned ones
    std::atomic<uint32_t> thread_count{2};
};
thread_local chaos_t* tl_chaos = nullptr;
thread_local int tl_budget = -1;   // reply bytes left before the cut, -1 = unlimited

bool send_raw(SOCKET s, const char* p, size_t left) {
    while (left > 0) {
        int n = ::send(s, p, static_cast<int>(left), SLOP_SEND_FLAGS);
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
    const bool frag = ch->fragment.load() || ch->dribble_ms.load() > 0;
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
        if (ch->dribble_ms.load() > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(ch->dribble_ms.load()));
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
// fake ps4debug-NG payload

struct fake_ps4_server_t {
    SOCKET listen_fd = INVALID_SOCKET;
    uint16_t port = 0;
    std::thread th;
    std::atomic<bool> stop_flag{false};

    std::mutex mu;
    std::map<uint64_t, std::array<uint8_t, 0x1000>> mem;   // 4 KiB pages
    bool debug_attached = false;
    uint32_t debug_pid = 0;
    SOCKET event_fd = INVALID_SOCKET;   // our side of the port-755 callback
    uint32_t last_protect = 0xFFFFFFFF;
    std::map<uint32_t, ps4::reg64_t> thread_regs;
    std::vector<ps4::vm_map_entry_t> maps;
    chaos_t chaos;
    uint16_t event_port = ephemeral_port();   // where the debug channel connects back
    int connections = 0;                     // accepted command connections
    int detach_count = 0;

    // debug-session state observed by the tests
    struct bp_t { bool enabled = false; uint64_t address = 0; };
    struct wp_t { bool enabled = false; uint32_t length = 0; uint32_t breaktype = 0; uint64_t address = 0; };
    std::map<uint32_t, bp_t> bps;
    std::map<uint32_t, wp_t> wps;
    uint32_t last_continue_stop = 0xFFFFFFFF;
    uint32_t last_suspend = 0, last_resume = 0;
    uint32_t last_proc_stop_pid = 0, last_proc_stop_state = 0xFFFFFFFF;
    int intall_count = 0;
    uint64_t rpcstub = 0x700000;
    ps4::proc_call_packet_t last_call{};

    // console-side capability state observed by the tests
    bool auth_ok = false;
    int auth_attempts = 0;
    std::string last_notify, last_print;
    uint32_t last_notify_type = 0;
    uint64_t elf_rpc_entry = 0;
    int elf_rpc_count = 0, elf_load_count = 0;
    uint8_t last_fpregs[848]{};
    uint32_t setfpregs_len = 0;
    uint8_t last_dbregs[128]{};
    bool setdbregs_called = false;
    uint64_t last_fsgs_fs = 0, last_fsgs_gs = 0;

    // drop the port-755 channel the way the payload's debug cleanup does
    // (debuggee gone): the debug session and its slots end with it
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

    // raw bytes on the port-755 channel, in caller-chosen pieces
    void send_event_bytes(const uint8_t* data, size_t n, size_t piece, int pause_ms) {
        SOCKET ev = INVALID_SOCKET;
        {
            std::lock_guard lk(mu);
            ev = event_fd;
        }
        if (ev == INVALID_SOCKET) return;
        for (size_t off = 0; off < n; off += piece) {
            send_raw(ev, reinterpret_cast<const char*>(data + off), std::min(piece, n - off));
            if (pause_ms) std::this_thread::sleep_for(std::chrono::milliseconds(pause_ms));
        }
    }

    // NetVar1337 fork behaviour
    bool fork_ext = true;          // CMD_PROC_MODULES / CMD_PROC_SNAPSHOT present
    int guard_rejects = 0;         // requests the fork's datalen guard refused
    uint32_t last_guard_cmd = 0;
    int commands_seen = 0;
    int module_requests = 0;

    // bulk write (0xBDAACC04) state
    int write_multi_calls = 0;
    uint32_t last_write_multi_count = 0;
    uint64_t write_deny_addr = 0;   // entries at this address report verify_failed

    // Turbo Scan state (one session, like the payload's per-connection slot)
    struct turbo_rec_t {
        uint64_t addr = 0;
        std::vector<uint8_t> cur, prev, first;
    };
    bool turbo_supported = true;
    bool turbo_used = false;
    bool turbo_snapshot = false;
    bool turbo_has_first = false;
    uint32_t turbo_vlen = 0;
    std::vector<turbo_rec_t> turbo_recs;
    SOCKET turbo_owner = INVALID_SOCKET;
    uint32_t last_turbo_flags = 0;
    uint32_t last_turbo_nseg = 0;
    size_t turbo_resident_cap = 1u << 20;   // shrink to force the overflow path
    uint32_t turbo_cancel_pid = 0;
    int turbo_end_calls = 0;
    uint32_t turbo_cfg_mb = 0;
    std::string turbo_cfg_dir;

    ps4::debug_event_packet_t make_event(uint32_t lwpid, uint32_t status, const char* name,
                                         uint64_t rip, uint64_t dr6) {
        std::lock_guard lk(mu);
        ps4::debug_event_packet_t pkt{};
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
        for (int i = 0; i < 16; ++i)
            reinterpret_cast<uint64_t*>(pkt.dbregs)[i] = 0xD000 + i;
        reinterpret_cast<uint64_t*>(pkt.dbregs)[6] = dr6;
        return pkt;
    }

    // send one packed 0x4A0 debug event on the port-755 connection; dr6 says
    // what kind of trap it was (0 = int3, bit i = DR slot i, 0x4000 = step)
    void send_event(uint32_t lwpid, uint32_t status, const char* name, uint64_t rip_override,
                    uint64_t dr6 = 0) {
        const ps4::debug_event_packet_t pkt = make_event(lwpid, status, name, rip_override, dr6);
        std::lock_guard lk(mu);
        if (event_fd == INVALID_SOCKET) return;
        send_raw(event_fd, reinterpret_cast<const char*>(&pkt), sizeof(pkt));
    }

    void add_map(const char* name, uint64_t start, uint64_t end, uint16_t prot) {
        ps4::vm_map_entry_t m{};
        std::strncpy(m.name, name, sizeof(m.name) - 1);
        m.start = start;
        m.end = end;
        m.offset = 0;
        m.prot = prot;
        std::lock_guard lk(mu);
        maps.push_back(m);
    }

    fake_ps4_server_t() {
        wsa();
        // the eboot is mapped the way a real console maps a SELF: text,
        // relro and data as separate entries of the same name (an anonymous
        // mapping in between), no ELF header at the base
        add_map("/app0/eboot.bin", 0x400000, 0x480000, ps4::kVmProtRead | ps4::kVmProtExec);
        add_map("/app0/eboot.bin", 0x480000, 0x4C0000, ps4::kVmProtRead);
        add_map("", 0x4C0000, 0x4C8000, ps4::kVmProtRead | ps4::kVmProtWrite);
        add_map("/app0/eboot.bin", 0x4C8000, 0x500000, ps4::kVmProtRead | ps4::kVmProtWrite);
        add_map("/app0/libSceLibcInternal.sprx", 0x500000, 0x510000,
                ps4::kVmProtRead | ps4::kVmProtExec);
        add_map("", 0x7FFF00000000ull, 0x7FFF00010000ull,
                ps4::kVmProtRead | ps4::kVmProtWrite);
    }

    bool start() {
        listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listen_fd == INVALID_SOCKET) return false;
        int flag = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&flag), sizeof(flag));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;   // ephemeral
        if (bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) return false;
        if (listen(listen_fd, 4) != 0) return false;
        slop_socklen_t len = sizeof(addr);
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

    ~fake_ps4_server_t() { shutdown(); }

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
            // one thread per connection: Turbo Scan CANCEL arrives on a
            // second connection while the first is still open
            std::lock_guard lk(conn_mu);
            conn_socks.push_back(c);
            conn_threads.emplace_back([this, c] { handle_conn(c); });
        }
    }

    std::mutex conn_mu;
    std::vector<SOCKET> conn_socks;
    std::vector<std::thread> conn_threads;

    // the NetVar1337 fork's cmd_guards.c table: requests shorter than this
    // get CMD_DATA_NULL before dispatch (connection kept). Mirroring it makes
    // every test check the backend's request sizes against the fork
    static uint32_t fork_min_datalen(uint32_t cmd) {
        switch (cmd) {
        case ps4::CMD_PROC_READ: case ps4::CMD_PROC_WRITE: case ps4::CMD_PROC_FREE:
        case ps4::CMD_PROC_ALLOC_HINTED:                        return 16;
        case ps4::CMD_PROC_MAPS: case ps4::CMD_PROC_INTALL: case ps4::CMD_PROC_INFO:
        case ps4::CMD_PROC_MODULES:                             return 4;
        case ps4::CMD_PROC_CALL:                                return 68;
        case ps4::CMD_PROC_ELF: case ps4::CMD_PROC_ELF_RPC:
        case ps4::CMD_PROC_ALLOC: case ps4::CMD_PROC_AUTH:
        case ps4::CMD_PROC_SCAN_GET:                            return 8;
        case ps4::CMD_PROC_PROTECT: case ps4::CMD_PROC_DISASM_REGION:
        case ps4::CMD_PROC_EXTRACT_CODE_XREFS: case ps4::CMD_PROC_SNAPSHOT: return 20;
        case ps4::CMD_PROC_SCAN:                                return 10;
        case ps4::CMD_PROC_FIND_XREFS_TO: case ps4::CMD_PROC_READ_STACK: return 24;
        case ps4::CMD_PROC_ASSEMBLE: case ps4::CMD_PROC_WRITE_MULTI: return 12;
        case ps4::CMD_PROC_SCAN_AOB:                            return 22;
        case ps4::CMD_PROC_SCAN_AOB_MULTI:                      return 21;
        case ps4::CMD_PROC_SCAN_START:                          return 23;
        case ps4::CMD_PROC_SCAN_COUNT:                          return 18;
        case ps4::CMD_DEBUG_PROCESS_STOP: case ps4::CMD_DEBUG_SETREGS:
        case ps4::CMD_DEBUG_SETFPREGS: case ps4::CMD_DEBUG_SETDBREGS:
        case ps4::CMD_DEBUG_SETFSGSBASE: case ps4::CMD_CONSOLE_NOTIFY: return 8;
        case ps4::CMD_DEBUG_ATTACH: case ps4::CMD_DEBUG_SUSPEND: case ps4::CMD_DEBUG_RESUME:
        case ps4::CMD_DEBUG_GETREGS: case ps4::CMD_DEBUG_GETFPREGS: case ps4::CMD_DEBUG_GETDBREGS:
        case ps4::CMD_DEBUG_GETFSGSBASE: case ps4::CMD_DEBUG_CONTINUE:
        case ps4::CMD_DEBUG_THREAD_INFO: case ps4::CMD_CONSOLE_PRINT:  return 4;
        case ps4::CMD_DEBUG_SET_BREAKPOINT:                     return 16;
        case ps4::CMD_DEBUG_SET_WATCHPOINT:                     return 24;
        default:                                                return 0;
        }
    }

    void handle_conn(SOCKET c) {
        tl_chaos = &chaos;
        tl_budget = -1;
        {
            // The payload keeps debug + auth state per connection. Reset it
            // when the new connection starts, not when the old one ends: the
            // old handler's cleanup could otherwise wipe the re-armed slots
            // of a reconnect that already landed.
            std::lock_guard lk(mu);
            ++connections;
            debug_attached = false;
            debug_pid = 0;
            bps.clear();
            wps.clear();
            auth_ok = false;
            if (event_fd != INVALID_SOCKET) {
                ::shutdown(event_fd, SD_BOTH);
                closesocket(event_fd);
                event_fd = INVALID_SOCKET;
            }
        }
        handle_conn_loop(c);
        {
            // free_client frees the dropped client's Turbo Scan session
            std::lock_guard lk(mu);
            if (turbo_owner == c) {
                turbo_used = false;
                turbo_recs.clear();
                turbo_owner = INVALID_SOCKET;
            }
        }
        // like free_client: a failed handler closes the client. Shut the
        // socket down so the backend sees the hang-up; the handle itself is
        // closed in shutdown()
        ::shutdown(c, SD_BOTH);
    }

    void handle_conn_loop(SOCKET c) {
        while (!stop_flag) {
            ps4::packet_header_t hdr{};
            if (!recv_all(c, &hdr, sizeof(hdr))) return;
            if (hdr.magic != ps4::kPacketMagic) return;
            if (hdr.datalen > ps4::kMaxDatalen) { send_u32(c, ps4::CMD_TOO_MUCH_DATA); return; }
            if (hdr.datalen < fork_min_datalen(hdr.cmd)) {
                std::lock_guard lk(mu);
                ++guard_rejects;
                last_guard_cmd = hdr.cmd;
                send_u32(c, ps4::CMD_DATA_NULL);
                continue;   // the fork rejects before reading a body
            }
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
        case ps4::CMD_VERSION: {
            const char* v = "1.3";
            uint32_t len = 3;
            return send_u32(c, len) && send_all(c, v, len);
        }
        case ps4::CMD_BRANDING: {
            static const char b[] = "ps4debug-NG by Pharaoh2k v1.3.4\0" "1.1";
            const uint32_t len = static_cast<uint32_t>(sizeof(b) - 1);
            return send_u32(c, len) && send_all(c, b, len);
        }
        case ps4::CMD_FW_VERSION: {
            // the payload reports major * 100 + minor (see fw.c), so 11.00 is 1100
            uint16_t fw = 1100;
            return send_all(c, &fw, sizeof(fw));
        }
        case ps4::CMD_PLATFORM_ID: {
            uint16_t tag = 4;
            return send_all(c, &tag, sizeof(tag));
        }
        case ps4::CMD_PROC_NOP:
            return send_u32(c, ps4::CMD_SUCCESS);

        case ps4::CMD_PROC_LIST: {
            const bool hide = chaos.hide_game_pid.load();
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            if (!send_u32(c, hide ? 1u : 2u)) return false;
            ps4::proc_list_entry_t e{};
            if (!hide) {
                std::strncpy(e.p_comm, "eboot.bin", sizeof(e.p_comm) - 1);
                e.pid = static_cast<int32_t>(kFakePid);
                if (!send_all(c, &e, sizeof(e))) return false;
            }
            std::memset(&e, 0, sizeof(e));
            std::strncpy(e.p_comm, "SceShellCore", sizeof(e.p_comm) - 1);
            e.pid = 42;
            return send_all(c, &e, sizeof(e));
        }

        case ps4::CMD_PROC_INFO: {
            if (bodylen < sizeof(ps4::proc_info_packet_t)) return send_u32(c, ps4::CMD_DATA_NULL), false;
            const auto* p = reinterpret_cast<const ps4::proc_info_packet_t*>(body);
            if (p->pid != kFakePid && p->pid != 42) return send_u32(c, ps4::CMD_ERROR), true;
            ps4::proc_info_response_t r{};
            r.pid = p->pid;
            std::strncpy(r.name, p->pid == kFakePid ? "eboot.bin" : "SceShellCore", sizeof(r.name) - 1);
            std::strncpy(r.path, p->pid == kFakePid ? "/app0/eboot.bin" : "/system/privileged/SceShellCore", sizeof(r.path) - 1);
            std::strncpy(r.titleid, "CUSA12345_00", sizeof(r.titleid) - 1);
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            return send_all(c, &r, sizeof(r));
        }

        case ps4::CMD_PROC_READ: {
            const auto* p = reinterpret_cast<const ps4::proc_read_packet_t*>(body);
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            std::vector<uint8_t> out(p->length);
            for (uint32_t i = 0; i < p->length; ++i)
                out[i] = mem_byte(p->address + i);
            // server streams in 64 KiB chunks; one send is equivalent on the wire
            return p->length == 0 || send_all(c, out.data(), out.size());
        }

        case ps4::CMD_PROC_WRITE: {
            const auto* p = reinterpret_cast<const ps4::proc_write_packet_t*>(body);
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;   // ack
            std::vector<uint8_t> data(p->length);
            if (p->length > 0 && !recv_all(c, data.data(), p->length)) return false;
            mem_write(p->address, data.data(), data.size());
            return send_u32(c, ps4::CMD_SUCCESS);               // terminal
        }

        case ps4::CMD_PROC_MAPS: {
            const auto* mp = reinterpret_cast<const ps4::proc_maps_packet_t*>(body);
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            std::lock_guard lk(mu);
            if (mp->pid == 42) {
                // system process: no /app0/ maps, so ps4_auto skips it
                ps4::vm_map_entry_t m{};
                std::strncpy(m.name, "/system/privileged/SceShellCore", sizeof(m.name) - 1);
                m.start = 0x800000;
                m.end   = 0x900000;
                m.prot  = ps4::kVmProtRead | ps4::kVmProtExec;
                if (!send_u32(c, 1)) return false;
                return send_all(c, &m, sizeof(m));
            }
            if (!send_u32(c, static_cast<uint32_t>(maps.size()))) return false;
            for (const auto& m : maps)
                if (!send_all(c, &m, sizeof(m))) return false;
            return true;
        }

        case ps4::CMD_PROC_PROTECT: {
            const auto* p = reinterpret_cast<const ps4::proc_protect_packet_t*>(body);
            {
                std::lock_guard lk(mu);
                last_protect = p->newprot;
            }
            // payload quirk: success status is followed by CMD_DATA_NULL
            return send_u32(c, ps4::CMD_SUCCESS) && send_u32(c, ps4::CMD_DATA_NULL);
        }

        case ps4::CMD_PROC_ALLOC:
        case ps4::CMD_PROC_ALLOC_HINTED: {
            uint64_t addr = 0x600000;
            if (cmd == ps4::CMD_PROC_ALLOC_HINTED) {
                const auto* p = reinterpret_cast<const ps4::proc_alloc_hinted_packet_t*>(body);
                if (p->hint != 0) addr = p->hint;
            }
            const uint32_t len = cmd == ps4::CMD_PROC_ALLOC
                ? reinterpret_cast<const ps4::proc_alloc_packet_t*>(body)->length
                : reinterpret_cast<const ps4::proc_alloc_hinted_packet_t*>(body)->length;
            {
                std::lock_guard lk(mu);
                ps4::vm_map_entry_t m{};
                m.start = addr;
                m.end = addr + len;
                m.prot = ps4::kVmProtRead | ps4::kVmProtWrite;
                maps.push_back(m);
            }
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            ps4::proc_alloc_response_t r{};
            r.address = addr;
            return send_all(c, &r, sizeof(r));
        }

        case ps4::CMD_PROC_FREE:
            return send_u32(c, ps4::CMD_SUCCESS);

        case ps4::CMD_DEBUG_ATTACH: {
            const auto* p = reinterpret_cast<const ps4::debug_attach_packet_t*>(body);
            std::lock_guard lk(mu);
            if (debug_attached) { send_u32(c, ps4::CMD_ALREADY_DEBUG); return true; }
            // the real payload connects back to the client on 755 or fails
            SOCKET ev = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            a.sin_port = htons(event_port);
            // Bound the connect: a listener that stopped accepting must fail
            // the attach fast instead of blocking this handler (and the test)
            // for the whole command budget.
            u_long nb = 1;
            ::ioctlsocket(ev, FIONBIO, &nb);
            int rc = ::connect(ev, reinterpret_cast<sockaddr*>(&a), sizeof(a));
            if (rc != 0 && (::WSAGetLastError() == WSAEWOULDBLOCK ||
                            ::WSAGetLastError() == WSAEINPROGRESS)) {
                fd_set wf;
                FD_ZERO(&wf);
                FD_SET(ev, &wf);
                timeval tv{};
                tv.tv_sec = 2;
                rc = ::select(0, nullptr, &wf, nullptr, &tv);
                int soerr = 0;
                slop_socklen_t slen = sizeof(soerr);
                if (rc <= 0 ||
                    ::getsockopt(ev, SOL_SOCKET, SO_ERROR,
                                 reinterpret_cast<char*>(&soerr), &slen) != 0 ||
                    soerr != 0)
                    rc = -1;
                else
                    rc = 0;
            }
            nb = 0;
            ::ioctlsocket(ev, FIONBIO, &nb);
            if (rc != 0) {
                closesocket(ev);
                send_u32(c, ps4::CMD_ERROR);
                return true;
            }
            event_fd = ev;
            debug_attached = true;
            debug_pid = p->pid;
            return send_u32(c, ps4::CMD_SUCCESS);
        }

        case ps4::CMD_DEBUG_DETACH: {
            std::lock_guard lk(mu);
            ++detach_count;
            if (chaos.refuse_detach.load()) return send_u32(c, ps4::CMD_ERROR);
            debug_attached = false;
            bps.clear();
            wps.clear();
            if (event_fd != INVALID_SOCKET) {
                closesocket(event_fd);
                event_fd = INVALID_SOCKET;
            }
            return send_u32(c, ps4::CMD_SUCCESS);
        }

        case ps4::CMD_DEBUG_GET_THREAD_LIST: {
            std::lock_guard lk(mu);
            if (!debug_attached) return send_u32(c, ps4::CMD_ERROR), true;
            const uint32_t n = chaos.thread_count.load();
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            if (!send_u32(c, n)) return false;
            std::vector<uint32_t> ids(n);
            for (uint32_t i = 0; i < n; ++i) ids[i] = 101 + i;
            return n == 0 || send_all(c, ids.data(), ids.size() * sizeof(uint32_t));
        }

        case ps4::CMD_DEBUG_THREAD_INFO: {
            std::lock_guard lk(mu);
            if (!debug_attached) return send_u32(c, ps4::CMD_ERROR), true;
            const auto* p = reinterpret_cast<const ps4::debug_lwpid_packet_t*>(body);
            ps4::debug_thread_info_response_t r{};
            r.lwpid = p->lwpid;
            r.priority = 80;
            const std::string nm = p->lwpid == 101 ? "main" : "worker" + std::to_string(p->lwpid);
            std::strncpy(r.name, nm.c_str(), sizeof(r.name) - 1);
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            return send_all(c, &r, sizeof(r));
        }

        case ps4::CMD_DEBUG_GETREGS: {
            std::lock_guard lk(mu);
            if (!debug_attached) return send_u32(c, ps4::CMD_ERROR), true;
            const auto* p = reinterpret_cast<const ps4::debug_lwpid_packet_t*>(body);
            ps4::reg64_t r = thread_regs[p->lwpid];   // zero if unseen
            if (r.rip == 0) {
                r.rip = 0x400123;
                r.rsp = 0x7FFF00008000ull;
                r.rbp = 0x7FFF00007FF0ull;
                r.rax = 0x2A;
                r.rflags = 0x202;
            }
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            return send_all(c, &r, sizeof(r));   // server sends exactly 176 bytes
        }

        case ps4::CMD_DEBUG_SETREGS: {
            std::lock_guard lk(mu);
            if (!debug_attached) return send_u32(c, ps4::CMD_ERROR), true;
            const auto* p = reinterpret_cast<const ps4::debug_setregs_packet_t*>(body);
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;   // ack
            ps4::reg64_t r{};
            if (p->length != sizeof(r) || !recv_all(c, &r, p->length)) {
                send_u32(c, ps4::CMD_ERROR);
                return true;
            }
            thread_regs[p->lwpid] = r;
            return send_u32(c, ps4::CMD_SUCCESS);               // terminal
        }

        case ps4::CMD_DEBUG_SET_BREAKPOINT: {
            const auto* p = reinterpret_cast<const ps4::debug_set_breakpoint_packet_t*>(body);
            std::lock_guard lk(mu);
            if (!debug_attached) {
                send_u32(c, ps4::CMD_ERROR);
                send_u32(c, ps4::CMD_ERROR);   // payload quirk: duplicated on error
                return true;
            }
            if (p->index >= 30) return send_u32(c, ps4::CMD_ERROR), true;
            bps[p->index] = {p->enabled != 0, p->address};
            return send_u32(c, ps4::CMD_SUCCESS);
        }

        case ps4::CMD_DEBUG_SET_WATCHPOINT: {
            const auto* p = reinterpret_cast<const ps4::debug_set_watchpoint_packet_t*>(body);
            std::lock_guard lk(mu);
            if (!debug_attached) return send_u32(c, ps4::CMD_ERROR), true;
            if (p->index > 3) return send_u32(c, ps4::CMD_ERROR), true;
            wps[p->index] = {p->enabled != 0, p->length, p->breaktype, p->address};
            return send_u32(c, ps4::CMD_SUCCESS);
        }

        case ps4::CMD_DEBUG_CONTINUE: {
            const auto* p = reinterpret_cast<const ps4::debug_continue_packet_t*>(body);
            uint64_t hit = 0;
            bool wp_hit = false;
            uint32_t wp_index = 0;
            {
                std::lock_guard lk(mu);
                last_continue_stop = p->stop;
                if (!debug_attached) return send_u32(c, ps4::CMD_ERROR), true;
                for (const auto& [idx, bp] : bps)
                    if (bp.enabled) { hit = bp.address; break; }
                if (!hit)
                    for (const auto& [idx, wp] : wps)
                        if (wp.enabled) { wp_hit = true; wp_index = idx; break; }
            }
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            // resuming into an armed breakpoint or watchpoint stops the main
            // thread with SIGTRAP (watchpoint: rip stays at the faulting insn)
            if (p->stop == 0 && hit) send_event(101, 5u << 8, "main", hit, 0);
            else if (p->stop == 0 && wp_hit) send_event(101, 5u << 8, "main", 0, 1ull << wp_index);
            return true;
        }

        case ps4::CMD_DEBUG_STEP: {
            uint64_t newrip = 0;
            {
                std::lock_guard lk(mu);
                if (!debug_attached) return send_u32(c, ps4::CMD_ERROR), true;
                auto& r = thread_regs[101];
                if (r.rip == 0) r.rip = 0x400123;
                r.rip += 1;
                newrip = r.rip;
            }
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            send_event(101, 5u << 8, "main", newrip, 0x4000);
            return true;
        }

        case ps4::CMD_DEBUG_STEP_THREAD: {
            const auto* p = reinterpret_cast<const ps4::debug_lwpid_packet_t*>(body);
            uint64_t newrip = 0;
            uint32_t lw = p->lwpid;
            {
                std::lock_guard lk(mu);
                if (!debug_attached) return send_u32(c, ps4::CMD_ERROR), true;
                auto& r = thread_regs[lw];
                if (r.rip == 0) r.rip = 0x400123;
                r.rip += 1;
                newrip = r.rip;
            }
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            send_event(lw, 5u << 8, "worker", newrip, 0x4000);
            return true;
        }

        case ps4::CMD_DEBUG_SUSPEND: {
            const auto* p = reinterpret_cast<const ps4::debug_lwpid_packet_t*>(body);
            std::lock_guard lk(mu);
            if (!debug_attached) return send_u32(c, ps4::CMD_ERROR), true;
            last_suspend = p->lwpid;
            return send_u32(c, ps4::CMD_SUCCESS);
        }

        case ps4::CMD_DEBUG_RESUME: {
            const auto* p = reinterpret_cast<const ps4::debug_lwpid_packet_t*>(body);
            std::lock_guard lk(mu);
            if (!debug_attached) return send_u32(c, ps4::CMD_ERROR), true;
            last_resume = p->lwpid;
            return send_u32(c, ps4::CMD_SUCCESS);
        }

        case ps4::CMD_DEBUG_PROCESS_STOP: {
            const auto* p = reinterpret_cast<const ps4::debug_process_stop_packet_t*>(body);
            std::lock_guard lk(mu);
            last_proc_stop_pid = p->pid;
            last_proc_stop_state = p->state;
            return send_u32(c, ps4::CMD_SUCCESS);
        }

        case ps4::CMD_DEBUG_GETDBREGS: {
            std::lock_guard lk(mu);
            if (!debug_attached) return send_u32(c, ps4::CMD_ERROR), true;
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            uint8_t dr[128]{};
            for (int i = 0; i < 16; ++i)
                reinterpret_cast<uint64_t*>(dr)[i] = 0xD000 + i;
            return send_all(c, dr, sizeof(dr));
        }

        case ps4::CMD_PROC_INTALL: {
            std::lock_guard lk(mu);
            ++intall_count;
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            return send_all(c, &rpcstub, sizeof(rpcstub));
        }

        case ps4::CMD_PROC_CALL: {
            const auto* p = reinterpret_cast<const ps4::proc_call_packet_t*>(body);
            {
                std::lock_guard lk(mu);
                last_call = *p;
            }
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            ps4::proc_call_response_t resp{};
            resp.pid = p->pid;
            resp.rax = p->rdi + 1;   // fake target function: return arg0 + 1
            return send_all(c, &resp, sizeof(resp));
        }

        case ps4::CMD_PROC_AUTH: {
            const auto* p = reinterpret_cast<const ps4::proc_auth_packet_t*>(body);
            {
                std::lock_guard lk(mu);
                ++auth_attempts;
                if (!p || p->magic != ps4::CMD_PROC_AUTH_MAGIC) {
                    auth_ok = false;
                    return send_u32(c, ps4::CMD_DATA_NULL), true;
                }
            }
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            const uint16_t chlen = 64;
            uint8_t challenge[64], response[64];
            for (uint16_t i = 0; i < chlen; ++i) challenge[i] = static_cast<uint8_t>(i * 7 + 3);
            if (!send_all(c, &chlen, sizeof(chlen))) return false;
            if (!send_all(c, challenge, chlen)) return false;
            if (!recv_all(c, response, chlen)) return false;
            // same LFSR keystream as the payload (proc.c auth_lfsr_next)
            uint32_t s1 = 200, s2 = 300, s3 = 400, s4 = 500;
            bool match = true;
            for (uint16_t i = 0; i < chlen; ++i) {
                s1 = ((s1 << 18) & 0xFFF80000u) ^ ((s1 ^ (s1 << 6)) >> 13);
                s2 = ((s2 << 2) & 0xFFFFFFE0u) ^ ((s2 ^ (s2 << 2)) >> 27);
                s3 = ((s3 << 7) & 0xFFFFF800u) ^ ((s3 ^ (s3 << 13)) >> 21);
                s4 = ((s4 << 13) & 0xFFF00000u) ^ ((s4 ^ (s4 << 3)) >> 12);
                const uint8_t ks = static_cast<uint8_t>(s1 ^ s2 ^ s3 ^ s4);
                if (response[i] != static_cast<uint8_t>(challenge[i] ^ ks)) { match = false; break; }
            }
            {
                std::lock_guard lk(mu);
                auth_ok = match;
            }
            return send_u32(c, match ? ps4::CMD_SUCCESS : ps4::CMD_DATA_NULL), true;
        }

        case ps4::CMD_PROC_SCAN_START: {
            bool authed;
            { std::lock_guard lk(mu); authed = auth_ok; }
            if (!authed) return send_u32(c, ps4::CMD_DATA_NULL), true;
            if (bodylen < sizeof(ps4::proc_scan_start_packet_t))
                return send_u32(c, ps4::CMD_DATA_NULL), true;
            const auto* sp = reinterpret_cast<const ps4::proc_scan_start_packet_t*>(body);
            const uint32_t raw_vlen = ps4::scan_value_size(sp->valueType);
            const uint32_t vlen = raw_vlen ? raw_vlen : sp->lenData;
            const bool needs_val = ps4::scan_cmp_needs_value(sp->compareType);
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            std::vector<uint8_t> pattern(needs_val ? sp->lenData : 0);
            if (needs_val && sp->lenData && !recv_all(c, pattern.data(), sp->lenData)) return false;
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            std::vector<uint8_t> region(sp->length);
            for (uint32_t i = 0; i < sp->length; ++i) region[i] = mem_byte(sp->address + i);
            std::vector<uint8_t> block;
            const uint64_t step = sp->alignment ? sp->alignment : vlen;
            for (uint64_t a = 0; a + vlen <= sp->length; a += step) {
                bool match = !needs_val;   // value-less compares match all in the fake
                if (needs_val) {
                    uint64_t cur = 0, pat = 0;
                    for (uint32_t i = 0; i < vlen && i < 8; ++i) {
                        cur |= static_cast<uint64_t>(region[a + i]) << (8 * i);
                        pat |= static_cast<uint64_t>(pattern[i]) << (8 * i);
                    }
                    if (sp->compareType == ps4::kCmpBigger) match = cur > pat;
                    else if (sp->compareType == ps4::kCmpSmaller) match = cur < pat;
                    else match = cur == pat;   // exact/fuzzy/between-ish
                }
                if (!match) continue;
                const uint32_t off = static_cast<uint32_t>(a);
                block.insert(block.end(), reinterpret_cast<const uint8_t*>(&off),
                             reinterpret_cast<const uint8_t*>(&off) + 4);
                block.insert(block.end(), region.begin() + a, region.begin() + a + vlen);
            }
            const uint64_t blen = block.size();
            if (!send_all(c, &blen, sizeof(blen))) return false;
            if (blen && !send_all(c, block.data(), block.size())) return false;
            const uint64_t sentinel = 0xFFFFFFFFFFFFFFFFull;
            if (!send_all(c, &sentinel, sizeof(sentinel))) return false;
            return send_u32(c, ps4::CMD_SUCCESS);
        }

        case ps4::CMD_PROC_SCAN_COUNT: {
            bool authed;
            { std::lock_guard lk(mu); authed = auth_ok; }
            if (!authed) return send_u32(c, ps4::CMD_DATA_NULL), true;
            if (bodylen < sizeof(ps4::proc_scan_count_packet_t))
                return send_u32(c, ps4::CMD_DATA_NULL), true;
            const auto* cp = reinterpret_cast<const ps4::proc_scan_count_packet_t*>(body);
            const uint32_t raw_vlen = ps4::scan_value_size(cp->valueType);
            const uint32_t vlen = raw_vlen ? raw_vlen : cp->lenData;
            const bool needs_val = ps4::scan_cmp_needs_value(cp->compareType);
            const bool needs_prev = ps4::scan_cmp_needs_previous(cp->compareType);
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            std::vector<uint8_t> pattern(needs_val ? cp->lenData : 0);
            if (needs_val && cp->lenData && !recv_all(c, pattern.data(), cp->lenData)) return false;
            const size_t esz = 4 + (needs_prev ? vlen : 0);
            for (;;) {
                uint32_t chunkLen = 0;
                if (!recv_all(c, &chunkLen, sizeof(chunkLen))) return false;
                if (chunkLen == 0xFFFFFFFFu) break;
                if (chunkLen == 0) {
                    const uint64_t s = 0xFFFFFFFFFFFFFFFFull;
                    if (!send_all(c, &s, sizeof(s))) return false;
                    continue;
                }
                std::vector<uint8_t> chunk(chunkLen);
                if (!recv_all(c, chunk.data(), chunkLen)) return false;
                std::vector<uint8_t> res;
                for (size_t off = 0; off + esz <= chunk.size(); off += esz) {
                    uint32_t eo = 0;
                    std::memcpy(&eo, chunk.data() + off, 4);
                    const uint64_t a = cp->base_address + eo;
                    bool match = false;
                    if (needs_prev) {
                        bool same = true;
                        for (uint32_t i = 0; i < vlen; ++i)
                            if (mem_byte(a + i) != chunk[off + 4 + i]) { same = false; break; }
                        if (cp->compareType == ps4::kCmpChanged) match = !same;
                        else if (cp->compareType == ps4::kCmpUnchanged) match = same;
                    } else if (needs_val) {
                        match = true;
                        for (uint32_t i = 0; i < vlen; ++i)
                            if (mem_byte(a + i) != pattern[i]) { match = false; break; }
                    }
                    if (!match) continue;
                    res.insert(res.end(), chunk.data() + off, chunk.data() + off + 4);
                    for (uint32_t i = 0; i < vlen; ++i) res.push_back(mem_byte(a + i));
                }
                const uint64_t rlen = res.size();
                if (!send_all(c, &rlen, sizeof(rlen))) return false;
                if (rlen && !send_all(c, res.data(), res.size())) return false;
                const uint64_t s = 0xFFFFFFFFFFFFFFFFull;
                if (!send_all(c, &s, sizeof(s))) return false;
            }
            return send_u32(c, ps4::CMD_SUCCESS);
        }

        case ps4::CMD_PROC_SCAN: {
            bool authed;
            { std::lock_guard lk(mu); authed = auth_ok; }
            if (!authed) return send_u32(c, ps4::CMD_DATA_NULL), true;
            const auto* sp = reinterpret_cast<const ps4::proc_scan_packet_t*>(body);
            const uint32_t raw_vlen = ps4::scan_value_size(sp->valueType);
            const uint32_t vlen = raw_vlen ? raw_vlen : sp->lenData;
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            std::vector<uint8_t> data(sp->lenData);
            if (sp->lenData && !recv_all(c, data.data(), sp->lenData)) return false;
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            std::vector<ps4::vm_map_entry_t> maps_copy;
            { std::lock_guard lk(mu); maps_copy = maps; }
            for (const auto& m : maps_copy) {
                if (!(m.prot & ps4::kVmProtRead)) continue;
                for (uint64_t a = m.start; a + vlen <= m.end; a += vlen) {
                    bool match = true;
                    for (uint32_t i = 0; i < vlen; ++i)
                        if (mem_byte(a + i) != data[i]) { match = false; break; }
                    if (match && !send_all(c, &a, sizeof(a))) return false;
                }
            }
            const uint64_t end = 0xFFFFFFFFFFFFFFFFull;
            return send_all(c, &end, sizeof(end));
        }

        case ps4::CMD_PROC_SCAN_AOB: {
            bool authed;
            { std::lock_guard lk(mu); authed = auth_ok; }
            if (!authed) return send_u32(c, ps4::CMD_DATA_NULL), true;
            const auto* sp = reinterpret_cast<const ps4::proc_scan_aob_packet_t*>(body);
            const uint32_t plen = sp->pattern_length;
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            std::vector<uint8_t> pat(plen), msk(plen);
            if (!recv_all(c, pat.data(), plen) || !recv_all(c, msk.data(), plen)) return false;
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            const uint32_t target = sp->max_matches ? sp->max_matches : 1;
            uint64_t match_addr = 0;
            uint32_t count = 0;
            for (uint64_t a = sp->address; a + plen <= sp->address + sp->length; ++a) {
                bool m = true;
                for (uint32_t k = 0; k < plen; ++k)
                    if (msk[k] == 1 && mem_byte(a + k) != pat[k]) { m = false; break; }
                if (!m) continue;
                if (++count == target) { match_addr = a; break; }
            }
            if (!send_all(c, &match_addr, sizeof(match_addr))) return false;
            return send_u32(c, ps4::CMD_SUCCESS);
        }

        case ps4::CMD_PROC_DISASM_REGION: {
            const auto* dp = reinterpret_cast<const ps4::proc_disasm_packet_t*>(body);
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            ps4::disasm_instr_entry_t e{};
            e.addr = dp->address;
            e.length = 3;
            e.kind = 0x01 | 0x20;
            e.rip_rel_target = dp->address + 0x100;
            e.mnemonic_lo = 0x10;
            if (!send_all(c, &e, sizeof(e))) return false;
            std::memset(&e, 0, sizeof(e));
            e.addr = dp->address + 3;
            e.length = 1;
            e.kind = 0x02;
            e.mnemonic_lo = 0x20;
            if (!send_all(c, &e, sizeof(e))) return false;
            // a payload that ignores max_entries keeps streaming entries; the
            // client must still read to the sentinel
            for (int k = 0; k < chaos.disasm_extra.load(); ++k) {
                std::memset(&e, 0, sizeof(e));
                e.addr = dp->address + 4 + static_cast<uint64_t>(k);
                e.length = 1;
                e.mnemonic_lo = 0x30;
                if (!send_all(c, &e, sizeof(e))) return false;
            }
            uint8_t sentinel[ps4::kDisasmEntrySize];
            std::memset(sentinel, 0xFF, sizeof(sentinel));
            return send_all(c, sentinel, sizeof(sentinel));
        }

        case ps4::CMD_PROC_EXTRACT_CODE_XREFS: {
            const auto* dp = reinterpret_cast<const ps4::proc_disasm_packet_t*>(body);
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            const uint64_t t = dp->address + 0x100;
            if (!send_all(c, &t, sizeof(t))) return false;
            const uint64_t s = 0xFFFFFFFFFFFFFFFFull;
            return send_all(c, &s, sizeof(s));
        }

        case ps4::CMD_PROC_FIND_XREFS_TO: {
            const auto* xp = reinterpret_cast<const ps4::proc_xrefs_to_packet_t*>(body);
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            if (xp->target_address == xp->scan_address + 0x100) {
                const uint64_t a = xp->scan_address + 3;
                if (!send_all(c, &a, sizeof(a))) return false;
            }
            const uint64_t s = 0xFFFFFFFFFFFFFFFFull;
            return send_all(c, &s, sizeof(s));
        }

        case ps4::CMD_PROC_READ_STACK: {
            const auto* sp = reinterpret_cast<const ps4::proc_read_stack_packet_t*>(body);
            std::vector<uint8_t> buf(4);
            auto put = [&](const void* p, size_t n) {
                const uint8_t* b = static_cast<const uint8_t*>(p);
                buf.insert(buf.end(), b, b + n);
            };
            uint32_t depth = sp->depth ? sp->depth : 1;
            if (depth > ps4::kReadStackMaxDepth) depth = ps4::kReadStackMaxDepth;
            uint32_t n_frames = 0;
            uint64_t cur_rbp = sp->rbp, cur_rsp = sp->rsp;
            for (uint32_t i = 0; i < depth; ++i) {
                uint64_t pair[2] = {0, 0};
                for (int k = 0; k < 2; ++k)
                    for (int b = 0; b < 8; ++b)
                        reinterpret_cast<uint8_t*>(pair)[k * 8 + b] = mem_byte(cur_rbp + k * 8 + b);
                const uint64_t saved_rbp = pair[0];
                const uint64_t ret_addr = pair[1];
                const int64_t fs = static_cast<int64_t>(cur_rbp) - static_cast<int64_t>(cur_rsp) + 8;
                uint32_t flags = 0, locals_len = 0;
                if (fs <= 0 || static_cast<uint64_t>(fs) > ps4::kReadStackLocalsCap) flags |= 1;
                else locals_len = static_cast<uint32_t>(fs);
                const uint32_t code_len = ps4::kReadStackCodeLen;
                put(&cur_rbp, 8); put(&cur_rsp, 8); put(&saved_rbp, 8); put(&ret_addr, 8);
                put(&flags, 4); put(&locals_len, 4); put(&code_len, 4);
                for (uint32_t k = 0; k < locals_len; ++k) { const uint8_t v = mem_byte(cur_rsp + k); put(&v, 1); }
                for (uint32_t k = 0; k < code_len; ++k) {
                    const uint8_t v = mem_byte(ret_addr - ps4::kReadStackCodeOff + k);
                    put(&v, 1);
                }
                ++n_frames;
                if (saved_rbp == 0 || saved_rbp <= cur_rbp) break;
                cur_rsp = cur_rbp + 8;
                cur_rbp = saved_rbp;
            }
            uint32_t claimed = n_frames + (chaos.stack_truncate.load() ? 1u : 0u);
            std::memcpy(buf.data(), &claimed, 4);
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            const uint32_t off = static_cast<uint32_t>(buf.size());
            if (!send_all(c, &off, sizeof(off))) return false;
            return send_all(c, buf.data(), buf.size());
        }

        case ps4::CMD_PROC_ASSEMBLE: {
            // the asm text is the tail of the packet body (datalen = 12 + text)
            const uint32_t textlen = bodylen >= sizeof(ps4::proc_assemble_packet_t)
                ? bodylen - static_cast<uint32_t>(sizeof(ps4::proc_assemble_packet_t)) : 0;
            std::vector<uint8_t> t(body + (bodylen - textlen), body + bodylen);
            const std::string text(t.begin(), t.end());
            if (text.find("zzz") != std::string::npos) {
                if (!send_u32(c, ps4::CMD_ERROR)) return false;
                ps4::proc_assemble_err_t e{1, 10};
                static const char msg[] = "ks error!!";
                if (!send_all(c, &e, sizeof(e))) return false;
                return send_all(c, msg, e.msg_len);
            }
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            ps4::proc_assemble_ok_t ok{1, 1};
            const uint8_t byte = 0xCC;
            if (!send_all(c, &ok, sizeof(ok))) return false;
            return send_all(c, &byte, 1);
        }

        case ps4::CMD_PROC_ELF_RPC:
        case ps4::CMD_PROC_ELF: {
            const auto* ep = reinterpret_cast<const ps4::proc_elf_packet_t*>(body);
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            std::vector<uint8_t> elf(ep->length);
            if (ep->length && !recv_all(c, elf.data(), ep->length)) return false;
            {
                std::lock_guard lk(mu);
                if (cmd == ps4::CMD_PROC_ELF_RPC) { elf_rpc_entry = 0x400500; ++elf_rpc_count; }
                else ++elf_load_count;
            }
            if (cmd == ps4::CMD_PROC_ELF) return send_u32(c, ps4::CMD_SUCCESS);
            ps4::proc_elf_rpc_response_t r{};
            { std::lock_guard lk(mu); r.entry = elf_rpc_entry; }
            return send_all(c, &r, sizeof(r));
        }

        case ps4::CMD_CONSOLE_NOTIFY: {
            const auto* np = reinterpret_cast<const ps4::console_notify_packet_t*>(body);
            std::vector<uint8_t> msg(np->length);
            if (np->length && !recv_all(c, msg.data(), np->length)) return false;
            {
                std::lock_guard lk(mu);
                last_notify.assign(msg.begin(), msg.end());
                last_notify_type = np->messageType;
            }
            return send_u32(c, ps4::CMD_SUCCESS);
        }

        case ps4::CMD_CONSOLE_PRINT: {
            const uint32_t len = bodylen >= 4 ? *reinterpret_cast<const uint32_t*>(body) : 0;
            std::vector<uint8_t> msg(len);
            if (len && !recv_all(c, msg.data(), len)) return false;
            { std::lock_guard lk(mu); last_print.assign(msg.begin(), msg.end()); }
            return send_u32(c, ps4::CMD_SUCCESS);
        }

        case ps4::CMD_CONSOLE_INFO:   // payload: bare CMD_SUCCESS (ping variant)
            return send_u32(c, ps4::CMD_SUCCESS);

        case ps4::CMD_CONSOLE_FOREGROUND_APP: {
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            ps4::console_foreground_app_response_t r{};
            r.pid = kFakePid;
            std::strncpy(r.titleid, "CUSA12345_00", sizeof(r.titleid) - 1);
            std::strncpy(r.contentid, "EP1234-CUSA12345_00-A0000000000000", sizeof(r.contentid) - 1);
            std::strncpy(r.name, "eboot.bin", sizeof(r.name) - 1);
            std::strncpy(r.app_ver, "01.00", sizeof(r.app_ver) - 1);
            return send_all(c, &r, sizeof(r));
        }

        case ps4::CMD_DEBUG_GETFPREGS: {
            std::lock_guard lk(mu);
            if (!debug_attached) return send_u32(c, ps4::CMD_ERROR), true;
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            uint8_t buf[ps4::kFpregsSize];
            for (uint32_t i = 0; i < sizeof(buf); ++i)
                buf[i] = static_cast<uint8_t>(0xF0 + (i & 0xF));
            return send_all(c, buf, sizeof(buf));
        }

        case ps4::CMD_DEBUG_SETFPREGS: {
            std::lock_guard lk(mu);
            if (!debug_attached) return send_u32(c, ps4::CMD_ERROR), true;
            const auto* p = reinterpret_cast<const ps4::debug_setregs_packet_t*>(body);
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            std::vector<uint8_t> d(p->length);
            if (p->length && !recv_all(c, d.data(), p->length)) return false;
            const size_t n = p->length < sizeof(last_fpregs) ? p->length : sizeof(last_fpregs);
            std::memcpy(last_fpregs, d.data(), n);
            setfpregs_len = p->length;
            return send_u32(c, ps4::CMD_SUCCESS);
        }

        case ps4::CMD_DEBUG_SETDBREGS: {
            std::lock_guard lk(mu);
            if (!debug_attached) return send_u32(c, ps4::CMD_ERROR), true;
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            uint8_t dr[ps4::kDbregsSize]{};
            if (!recv_all(c, dr, sizeof(dr))) return false;
            std::memcpy(last_dbregs, dr, sizeof(dr));
            setdbregs_called = true;
            return send_u32(c, ps4::CMD_SUCCESS);
        }

        case ps4::CMD_DEBUG_GETFSGSBASE: {
            std::lock_guard lk(mu);
            if (!debug_attached) return send_u32(c, ps4::CMD_ERROR), true;
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            uint8_t buf[16]{};
            const uint64_t fs = 0x7FFF0000ull, gs = 0x1000ull;
            std::memcpy(buf, &fs, 8);
            std::memcpy(buf + 8, &gs, 8);
            return send_all(c, buf, sizeof(buf));
        }

        case ps4::CMD_DEBUG_SETFSGSBASE: {
            std::lock_guard lk(mu);
            if (!debug_attached) return send_u32(c, ps4::CMD_ERROR), true;
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            uint8_t buf[16]{};
            if (!recv_all(c, buf, sizeof(buf))) return false;
            std::memcpy(&last_fsgs_fs, buf, 8);
            std::memcpy(&last_fsgs_gs, buf + 8, 8);
            return send_u32(c, ps4::CMD_SUCCESS);
        }
        case ps4::CMD_PROC_MODULES: {
            {
                std::lock_guard lk(mu);
                ++module_requests;
                if (!fork_ext) {   // upstream: unknown command -> CMD_ERROR + drop
                    send_u32(c, ps4::CMD_ERROR);
                    return false;
                }
            }
            const auto* mp = reinterpret_cast<const ps4::proc_maps_packet_t*>(body);
            if (static_cast<int32_t>(mp->pid) <= 0 || (mp->pid != kFakePid && mp->pid != 42)) {
                send_u32(c, ps4::CMD_ERR_PID);
                return false;      // the fork's handler returns 1 -> client dropped
            }
            std::vector<ps4::proc_module_entry_t> out;
            {
                std::lock_guard lk(mu);
                std::vector<ps4::vm_map_entry_t> pm = maps;
                if (mp->pid == 42) {   // same per-pid view as CMD_PROC_MAPS
                    ps4::vm_map_entry_t m{};
                    std::strncpy(m.name, "/system/privileged/SceShellCore", sizeof(m.name) - 1);
                    m.start = 0x800000;
                    m.end   = 0x900000;
                    m.prot  = ps4::kVmProtRead | ps4::kVmProtExec;
                    pm = {m};
                }
                for (const auto& m : pm) {
                    if (!m.name[0]) continue;
                    auto it = std::find_if(out.begin(), out.end(), [&](const auto& e) {
                        return std::strncmp(e.name, m.name, sizeof(e.name)) == 0;
                    });
                    if (it == out.end()) {
                        ps4::proc_module_entry_t e{};
                        std::memcpy(e.name, m.name, sizeof(e.name));
                        e.base = m.start;
                        e.size = m.end - m.start;
                        out.push_back(e);
                    } else {
                        const uint64_t lo = std::min(it->base, m.start);
                        const uint64_t hi = std::max(it->base + it->size, m.end);
                        it->base = lo;
                        it->size = hi - lo;
                    }
                }
            }
            const uint32_t n = static_cast<uint32_t>(out.size());
            return send_u32(c, ps4::CMD_SUCCESS) && send_u32(c, n) &&
                   (n == 0 || send_all(c, out.data(), n * sizeof(out[0])));
        }

        case ps4::CMD_PROC_SNAPSHOT: {
            {
                std::lock_guard lk(mu);
                if (!fork_ext) {
                    send_u32(c, ps4::CMD_ERROR);
                    return false;
                }
            }
            const auto sp = *reinterpret_cast<const ps4::proc_snapshot_packet_t*>(body);
            if (static_cast<int32_t>(sp.pid) <= 0 || sp.pid != kFakePid) {
                send_u32(c, ps4::CMD_ERR_PID);
                return false;
            }
            if (sp.length == 0 || sp.address + sp.length < sp.address) {
                send_u32(c, ps4::CMD_ERR_RANGE);
                return false;
            }
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            for (uint64_t off = 0; off < sp.length; off += ps4::kSnapshotChunk) {
                const uint32_t n = static_cast<uint32_t>(
                    std::min<uint64_t>(ps4::kSnapshotChunk, sp.length - off));
                auto chunk = mem_read(sp.address + off, n);
                if (!send_all(c, chunk.data(), chunk.size())) return false;
            }
            return true;
        }

        case ps4::CMD_PROC_WRITE_MULTI: {
            if (bodylen < sizeof(ps4::proc_write_multi_packet_t))
                return send_u32(c, ps4::CMD_DATA_NULL), true;
            const auto* mp = reinterpret_cast<const ps4::proc_write_multi_packet_t*>(body);
            if (mp->count > ps4::kWriteMultiMaxCount) return send_u32(c, ps4::CMD_ERROR), true;
            const bool want_status = (mp->flags & ps4::kWriteMultiFlagStatus) != 0;
            uint64_t deny;
            {
                std::lock_guard lk(mu);
                ++write_multi_calls;
                last_write_multi_count = mp->count;
                deny = write_deny_addr;
            }
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            std::vector<uint8_t> status(mp->count, ps4::kWriteStatusOk);
            bool any_failed = false;
            for (uint32_t i = 0; i < mp->count; ++i) {
                ps4::proc_write_multi_entry_t e{};
                if (!recv_all(c, &e, sizeof(e))) return false;
                if (e.length > ps4::kWriteMultiMaxEntry) return send_u32(c, ps4::CMD_ERROR), false;
                std::vector<uint8_t> data(e.length);
                if (e.length && !recv_all(c, data.data(), e.length)) return false;
                if (mp->pid != kFakePid) {
                    status[i] = ps4::kWriteStatusInvalid;
                } else if (deny && e.address == deny) {
                    status[i] = ps4::kWriteStatusVerifyFailed;
                } else {
                    mem_write(e.address, data.data(), data.size());
                }
                if (status[i] != ps4::kWriteStatusOk) any_failed = true;
            }
            if (want_status && !status.empty() && !send_all(c, status.data(), status.size()))
                return false;
            return send_u32(c, !want_status && any_failed ? ps4::CMD_ERROR : ps4::CMD_SUCCESS);
        }

        case ps4::CMD_TURBO_CAPS: {
            bool sup;
            { std::lock_guard lk(mu); sup = turbo_supported; }
            if (!sup) return send_u32(c, ps4::CMD_ERROR), true;
            ps4::turbo_caps_response_t r{};
            r.version = 1;
            r.engines = 0xFFF;
            r.max_threads = 4;
            return send_u32(c, ps4::CMD_SUCCESS) && send_all(c, &r, sizeof(r));
        }

        case ps4::CMD_TURBO_START: {
            if (!turbo_authed()) return send_u32(c, ps4::CMD_DATA_NULL), true;
            if (bodylen < sizeof(ps4::turbo_start_packet_t)) return send_u32(c, ps4::CMD_DATA_NULL), true;
            const auto sp = *reinterpret_cast<const ps4::turbo_start_packet_t*>(body);
            const bool snapshot = (sp.flags & ps4::kTsSnapshot) != 0;
            const bool resident = (sp.flags & ps4::kTsServerResident) != 0;
            if (sp.compareType > 12 || (sp.lenData == 0 && !snapshot))
                return send_u32(c, ps4::CMD_DATA_NULL), true;
            const bool needs_val = ps4::scan_cmp_needs_value(sp.compareType);
            const uint32_t vlen = ps4::scan_value_size(sp.valueType)
                                      ? ps4::scan_value_size(sp.valueType) : sp.lenData;
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            std::vector<uint8_t> pattern(needs_val ? sp.lenData : 0);
            if (!pattern.empty() && !recv_all(c, pattern.data(), pattern.size())) return false;
            std::vector<uint8_t> mask;
            if (sp.valueType == ps4::kValArrBytes) {
                mask.resize(vlen);
                if (!recv_all(c, mask.data(), vlen)) return false;
            }
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            std::vector<ps4::turbo_snap_segment_t> segs;
            const bool use_segs = (sp.flags & ps4::kTsSnapshotSegments) && (snapshot || resident);
            if (use_segs) {
                uint32_t n = 0;
                if (!recv_all(c, &n, 4)) return false;
                segs.resize(n);
                if (n && !recv_all(c, segs.data(), n * sizeof(ps4::turbo_snap_segment_t))) return false;
            } else {
                segs.push_back({sp.address, sp.length});
            }
            {
                std::lock_guard lk(mu);
                last_turbo_flags = sp.flags;
                last_turbo_nseg = static_cast<uint32_t>(segs.size());
                if (turbo_cancel_pid == sp.pid) turbo_cancel_pid = 0;
            }
            const uint64_t step = sp.alignment ? sp.alignment : vlen;

            if (snapshot) {
                uint64_t slots = 0, total = 0;
                for (const auto& g : segs) {
                    total += g.length;
                    if (g.length >= vlen) slots += (g.length - vlen) / step + 1;
                }
                ps4::turbo_snap_plan_t plan{slots, total};
                if (!send_all(c, &plan, sizeof(plan))) return false;
                if (!send_all(c, &total, 8)) return false;   // one progress word
                const uint64_t sentinel = ps4::kTurboSentinel;
                if (!send_all(c, &sentinel, 8)) return false;
                const bool zeros = (sp.flags & ps4::kTsSnapshotIncludeZeros) != 0;
                std::vector<turbo_rec_t> recs;
                for (const auto& g : segs) {
                    for (uint64_t a = 0; a + vlen <= g.length; a += step) {
                        turbo_rec_t r;
                        r.addr = g.address + a;
                        r.cur = mem_read(r.addr, vlen);
                        if (!zeros && std::all_of(r.cur.begin(), r.cur.end(), [](uint8_t b) { return b == 0; }))
                            continue;
                        r.prev = r.cur;
                        r.first = r.cur;
                        recs.push_back(std::move(r));
                    }
                }
                ps4::turbo_snap_summary_t sum{1, recs.size()};
                {
                    std::lock_guard lk(mu);
                    turbo_used = true;
                    turbo_owner = c;
                    turbo_snapshot = true;
                    turbo_has_first = (sp.flags & ps4::kTsSnapshotKeepFirst) != 0;
                    turbo_vlen = vlen;
                    turbo_recs = std::move(recs);
                }
                return send_all(c, &sum, sizeof(sum)) && send_u32(c, ps4::CMD_SUCCESS);
            }

            std::vector<turbo_rec_t> hits;
            for (const auto& g : segs) {
                for (uint64_t a = 0; a + vlen <= g.length; a += step) {
                    turbo_rec_t r;
                    r.addr = g.address + a;
                    r.cur = mem_read(r.addr, vlen);
                    if (!turbo_match(sp.compareType, r.cur, r.cur, pattern, mask)) continue;
                    r.prev = r.cur;
                    hits.push_back(std::move(r));
                }
            }
            if (resident) {
                size_t cap;
                { std::lock_guard lk(mu); cap = turbo_resident_cap; }
                if (hits.size() <= cap) {
                    ps4::turbo_resident_summary_t sum{1, hits.size()};
                    {
                        std::lock_guard lk(mu);
                        turbo_used = true;
                        turbo_owner = c;
                        turbo_snapshot = false;
                        turbo_has_first = false;
                        turbo_vlen = vlen;
                        turbo_recs = hits;
                    }
                    return send_all(c, &sum, sizeof(sum)) && send_u32(c, ps4::CMD_SUCCESS);
                }
                {
                    std::lock_guard lk(mu);
                    turbo_used = false;
                    turbo_recs.clear();
                }
                ps4::turbo_resident_summary_t sum{0, 0};
                if (!send_all(c, &sum, sizeof(sum))) return false;
                if (use_segs) {
                    const uint64_t sentinel = ps4::kTurboSentinel;
                    return send_all(c, &sentinel, 8) && send_u32(c, ps4::CMD_SUCCESS);
                }
            }
            // streamed runs relative to sp.address, split across two blocks
            std::vector<uint8_t> blocks[2];
            for (size_t i = 0; i < hits.size(); ++i) {
                auto& b = blocks[i % 2 == 0 ? 0 : 1];
                const uint32_t off = static_cast<uint32_t>(hits[i].addr - sp.address);
                b.insert(b.end(), reinterpret_cast<const uint8_t*>(&off),
                         reinterpret_cast<const uint8_t*>(&off) + 4);
                b.insert(b.end(), hits[i].cur.begin(), hits[i].cur.end());
            }
            for (auto& b : blocks) {
                if (b.empty()) continue;
                const uint64_t blen = b.size();
                if (!send_all(c, &blen, 8) || !send_all(c, b.data(), b.size())) return false;
            }
            const uint64_t sentinel = ps4::kTurboSentinel;
            return send_all(c, &sentinel, 8) && send_u32(c, ps4::CMD_SUCCESS);
        }

        case ps4::CMD_TURBO_COUNT: {
            if (!turbo_authed()) return send_u32(c, ps4::CMD_DATA_NULL), true;
            if (bodylen < sizeof(ps4::turbo_count_packet_t)) return send_u32(c, ps4::CMD_DATA_NULL), true;
            const auto cp = *reinterpret_cast<const ps4::turbo_count_packet_t*>(body);
            if (cp.compareType > 12) return send_u32(c, ps4::CMD_DATA_NULL), true;
            const bool needs_val = ps4::scan_cmp_needs_value(cp.compareType);
            const bool needs_prev = ps4::scan_cmp_needs_previous(cp.compareType);
            const uint32_t vlen = ps4::scan_value_size(cp.valueType)
                                      ? ps4::scan_value_size(cp.valueType) : cp.lenData;
            if (vlen == 0 || vlen > 0x1000) return send_u32(c, ps4::CMD_DATA_NULL), true;
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            std::vector<uint8_t> pattern(needs_val ? cp.lenData : 0);
            if (!pattern.empty() && !recv_all(c, pattern.data(), pattern.size())) return false;
            std::vector<uint8_t> mask;
            if (cp.valueType == ps4::kValArrBytes) {
                mask.resize(vlen);
                if (!recv_all(c, mask.data(), vlen)) return false;
            }
            {
                std::lock_guard lk(mu);
                last_turbo_flags = cp.flags;
            }
            if (cp.flags & ps4::kTsServerResident) {
                std::vector<turbo_rec_t> recs;
                { std::lock_guard lk(mu); recs = turbo_recs; }
                std::vector<turbo_rec_t> keep;
                for (auto& r : recs) {
                    auto now = mem_read(r.addr, vlen);
                    if (!turbo_match(cp.compareType, now, r.cur, pattern, mask)) continue;
                    r.prev = r.cur;
                    r.cur = std::move(now);
                    keep.push_back(std::move(r));
                }
                const uint64_t n = keep.size();
                { std::lock_guard lk(mu); turbo_recs = std::move(keep); }
                const uint64_t progress = 1, sentinel = ps4::kTurboSentinel;
                return send_all(c, &progress, 8) && send_all(c, &sentinel, 8) &&
                       send_all(c, &n, 8) && send_u32(c, ps4::CMD_SUCCESS);
            }
            // client-driven chunk stream, like SCAN_COUNT
            const size_t esz = 4 + (needs_prev ? vlen : 0);
            for (;;) {
                uint32_t clen = 0;
                if (!recv_all(c, &clen, 4)) return false;
                if (clen == 0xFFFFFFFFu) break;
                std::vector<uint8_t> chunk(clen);
                if (clen && !recv_all(c, chunk.data(), clen)) return false;
                std::vector<uint8_t> res;
                for (size_t off = 0; off + esz <= chunk.size(); off += esz) {
                    uint32_t eo = 0;
                    std::memcpy(&eo, chunk.data() + off, 4);
                    const uint64_t a = cp.base_address + eo;
                    auto now = mem_read(a, vlen);
                    std::vector<uint8_t> prev = needs_prev
                        ? std::vector<uint8_t>(chunk.begin() + off + 4, chunk.begin() + off + esz)
                        : now;
                    if (!turbo_match(cp.compareType, now, prev, pattern, mask)) continue;
                    res.insert(res.end(), chunk.data() + off, chunk.data() + off + 4);
                    res.insert(res.end(), now.begin(), now.end());
                }
                if (!res.empty()) {
                    const uint64_t rlen = res.size();
                    if (!send_all(c, &rlen, 8) || !send_all(c, res.data(), res.size())) return false;
                }
                const uint64_t s = ps4::kTurboSentinel;
                if (!send_all(c, &s, 8)) return false;
            }
            return send_u32(c, ps4::CMD_SUCCESS);
        }

        case ps4::CMD_TURBO_GET: {
            if (!turbo_authed()) return send_u32(c, ps4::CMD_DATA_NULL), true;
            const auto* gp = reinterpret_cast<const ps4::turbo_get_packet_t*>(body);
            std::vector<turbo_rec_t> recs;
            bool used, has_first;
            uint32_t vlen;
            {
                std::lock_guard lk(mu);
                recs = turbo_recs; used = turbo_used; has_first = turbo_has_first; vlen = turbo_vlen;
            }
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            if (!used) {
                const uint32_t zero = 0;
                return send_u32(c, zero) && send_u32(c, ps4::CMD_SUCCESS);
            }
            const size_t start = std::min<size_t>(gp->start_index, recs.size());
            const size_t end = std::min<size_t>(start + gp->count, recs.size());
            const uint32_t hdr = static_cast<uint32_t>(end - start) |
                                 (has_first ? ps4::kTurboGetHasFirst : 0u);
            if (!send_u32(c, hdr)) return false;
            std::vector<uint8_t> out;
            for (size_t i = start; i < end; ++i) {
                const auto& r = recs[i];
                out.insert(out.end(), reinterpret_cast<const uint8_t*>(&r.addr),
                           reinterpret_cast<const uint8_t*>(&r.addr) + 8);
                out.insert(out.end(), r.cur.begin(), r.cur.end());
                out.insert(out.end(), r.prev.begin(), r.prev.end());
                if (has_first) {
                    auto f = r.first.empty() ? std::vector<uint8_t>(vlen, 0) : r.first;
                    out.insert(out.end(), f.begin(), f.end());
                }
            }
            if (!out.empty() && !send_all(c, out.data(), out.size())) return false;
            return send_u32(c, ps4::CMD_SUCCESS);
        }

        case ps4::CMD_TURBO_END: {
            if (!turbo_authed()) return send_u32(c, ps4::CMD_DATA_NULL), true;
            {
                std::lock_guard lk(mu);
                turbo_used = false;
                turbo_recs.clear();
                ++turbo_end_calls;
            }
            return send_u32(c, ps4::CMD_SUCCESS);
        }

        case ps4::CMD_TURBO_CONFIG: {
            if (!turbo_authed()) return send_u32(c, ps4::CMD_DATA_NULL), true;
            if (bodylen < sizeof(ps4::turbo_config_packet_t)) return send_u32(c, ps4::CMD_DATA_NULL), true;
            const auto* cp = reinterpret_cast<const ps4::turbo_config_packet_t*>(body);
            if (cp->spill_path_len > 63 || sizeof(*cp) + cp->spill_path_len > bodylen)
                return send_u32(c, ps4::CMD_DATA_NULL), true;
            {
                std::lock_guard lk(mu);
                turbo_cfg_mb = cp->ram_thresh_mb;
                turbo_cfg_dir.assign(reinterpret_cast<const char*>(body) + sizeof(*cp),
                                     cp->spill_path_len);
            }
            return send_u32(c, ps4::CMD_SUCCESS);
        }

        case ps4::CMD_TURBO_REGIONS: {
            if (!turbo_authed()) return send_u32(c, ps4::CMD_DATA_NULL), true;
            std::vector<ps4::turbo_region_info_t> out;
            for (const auto& m : maps) {
                if (!(m.prot & ps4::kVmProtRead)) continue;
                ps4::turbo_region_info_t r{};
                r.start = m.start;
                r.end = m.end;
                r.prot = m.prot;
                r.flags = (m.prot & ps4::kVmProtExec) ? 1u : 0u;   // pretend code is uncached
                r.mbps = 900;
                out.push_back(r);
            }
            const uint32_t n = static_cast<uint32_t>(out.size());
            return send_u32(c, ps4::CMD_SUCCESS) && send_u32(c, n) &&
                   send_all(c, out.data(), out.size() * sizeof(out[0])) &&
                   send_u32(c, ps4::CMD_SUCCESS);
        }

        case ps4::CMD_TURBO_CANCEL: {
            if (!turbo_authed()) return send_u32(c, ps4::CMD_DATA_NULL), true;
            if (bodylen < 4) return send_u32(c, ps4::CMD_DATA_NULL), true;
            uint32_t pid = 0;
            std::memcpy(&pid, body, 4);
            if (pid == 0) return send_u32(c, ps4::CMD_DATA_NULL), true;
            { std::lock_guard lk(mu); turbo_cancel_pid = pid; }
            return send_u32(c, ps4::CMD_SUCCESS);
        }
        }
        return send_u32(c, ps4::CMD_ERROR), true;
    }

    bool turbo_authed() {
        std::lock_guard lk(mu);
        return auth_ok;
    }

    std::vector<uint8_t> mem_read(uint64_t addr, uint32_t len) {
        std::vector<uint8_t> v(len);
        for (uint32_t i = 0; i < len; ++i) v[i] = mem_byte(addr + i);
        return v;
    }

    static uint64_t le_u64(const std::vector<uint8_t>& b, size_t off = 0) {
        uint64_t v = 0;
        for (size_t i = 0; i < 8 && off + i < b.size(); ++i)
            v |= static_cast<uint64_t>(b[off + i]) << (8 * i);
        return v;
    }

    // unsigned little-endian compare, enough for the fake
    static bool turbo_match(uint8_t ct, const std::vector<uint8_t>& now,
                            const std::vector<uint8_t>& prev,
                            const std::vector<uint8_t>& pattern,
                            const std::vector<uint8_t>& mask) {
        const uint64_t cur = le_u64(now), old = le_u64(prev);
        const uint64_t pat = le_u64(pattern);
        switch (ct) {
        case ps4::kCmpExact:
        case ps4::kCmpFuzzy:
            if (!mask.empty()) {
                for (size_t i = 0; i < now.size() && i < pattern.size(); ++i)
                    if (mask[i] && now[i] != pattern[i]) return false;
                return true;
            }
            return now == std::vector<uint8_t>(pattern.begin(), pattern.begin() +
                                               std::min(pattern.size(), now.size()));
        case ps4::kCmpBigger:    return cur > pat;
        case ps4::kCmpSmaller:   return cur < pat;
        case ps4::kCmpBetween:   return cur >= pat && cur <= le_u64(pattern, now.size());
        case ps4::kCmpIncreased: return cur > old;
        case ps4::kCmpDecreased: return cur < old;
        case ps4::kCmpChanged:   return now != prev;
        case ps4::kCmpUnchanged: return now == prev;
        case ps4::kCmpUnknown:   return true;
        default:                 return false;
        }
    }
};

struct server_guard_t {
    fake_ps4_server_t srv;
    server_guard_t() { REQUIRE(srv.start()); }
    ~server_guard_t() {
        srv.shutdown();
        // no request may be shorter than the fork's cmd_guards.c minimum
        if (srv.guard_rejects != 0)
            std::printf("  fork datalen guard rejected cmd 0x%08X\n", srv.last_guard_cmd);
        CHECK(srv.guard_rejects == 0);
    }
};

// drop the global ps4 connection even when a REQUIRE throws mid-test
struct ps4_disconnect_guard_t {
    ~ps4_disconnect_guard_t() {
        slop::core::process::target_disconnect_ps4();
    }
};

// Connect a backend to the fake payload with the payload's per-test debug-event
// port wired in, so ps4_debug_attach never competes for the machine-global 755.
inline bool connect_fake(backend_ps4_t& b, fake_ps4_server_t& srv, std::string& err) {
    b.set_event_port(srv.event_port);
    return b.connect("127.0.0.1", srv.port, err);
}

// Same for the process-wide console session (target_connect_ps4 / the MCP
// target.ps4_connect path): the registry backend gets the per-test port.
inline bool connect_fake_target(fake_ps4_server_t& srv, uint32_t pid, std::string& err) {
    if (!slop::core::process::target_connect_ps4("127.0.0.1", srv.port, pid, err)) return false;
    if (auto* p = slop::core::runtime::registry_ps4()) p->set_event_port(srv.event_port);
    return true;
}

// registry-only variant (connect without attaching a process)
inline bool connect_fake_registry(fake_ps4_server_t& srv, std::string& err) {
    if (!slop::core::runtime::registry_connect_ps4("127.0.0.1", srv.port, err)) return false;
    if (auto* p = slop::core::runtime::registry_ps4()) p->set_event_port(srv.event_port);
    return true;
}

} // namespace

namespace {

namespace rt = slop::core::runtime;
namespace dbgns = slop::core::debugger;

bool wait_until(const std::function<bool()>& pred, int timeout_ms) {
    const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < until) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return pred();
}

int64_t ms_since(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
}

} // namespace
