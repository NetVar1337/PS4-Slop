// src/tests/test_ps4.cpp
// PS4 (ps4debug-NG) backend tests: a fake payload server on loopback TCP
// implements the wire protocol subset (see ps4_protocol.hpp), then the real
// backend_ps4_t, the backend registry, the target session and the MCP target
// tool are driven against it.

#include "harness.hpp"

#include "core/debugger/composite.hpp"
#include "core/debugger/local_debugger.hpp"
#include "core/mcp/mcp_tools.hpp"
#include "core/process/target_service.hpp"
#include "core/runtime/backend_ps4.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/ps4_protocol.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

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
    uint16_t event_port = ps4::kDebugPort;   // where the debug channel connects back
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
            handle_conn(c);
            closesocket(c);
        }
    }

    void handle_conn(SOCKET c) {
        tl_chaos = &chaos;
        tl_budget = -1;
        {
            std::lock_guard lk(mu);
            ++connections;
        }
        while (!stop_flag) {
            ps4::packet_header_t hdr{};
            if (!recv_all(c, &hdr, sizeof(hdr))) break;
            if (hdr.magic != ps4::kPacketMagic) break;
            std::vector<uint8_t> body(hdr.datalen);
            if (hdr.datalen > 0 && !recv_all(c, body.data(), hdr.datalen)) break;
            const bool ok = dispatch(c, hdr.cmd, body.data(), hdr.datalen);
            tl_budget = -1;
            if (!ok) break;
        }
        // the payload keeps debug + auth state per connection: a dropped
        // client loses its debuggee, its breakpoints and its auth bits
        std::lock_guard lk(mu);
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
            uint16_t fw = 0x1100;   // 11.00 BCD
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
            if (::connect(ev, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
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
        }
        return send_u32(c, ps4::CMD_ERROR), true;
    }
};

struct server_guard_t {
    fake_ps4_server_t srv;
    server_guard_t() { REQUIRE(srv.start()); }
    ~server_guard_t() { srv.shutdown(); }
};

// drop the global ps4 connection even when a REQUIRE throws mid-test
struct ps4_disconnect_guard_t {
    ~ps4_disconnect_guard_t() {
        slop::core::process::target_disconnect_ps4();
    }
};

} // namespace

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
    CHECK(b.fw_version() == 0x1100);
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

TEST_CASE(ps4_debug_control_and_events) {
    server_guard_t g;
    backend_ps4_t b;
    std::string err;
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));

    // explicit debug attach (starts the 755 listener, connects the fake back)
    REQUIRE(b.ps4_debug_attach(kFakePid, err));
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

// ===========================================================================
// wire fault injection, reconnect, events, slots, composites, heartbeat

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
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));
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
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));
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
    b.set_timeouts(250, 2000, 2000);
    std::string err;
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));
    auto h = b.attach(kFakePid);
    REQUIRE(h.valid());
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
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));
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
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));
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
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));
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
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));
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
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));
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
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));
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
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));
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
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));
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
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));

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
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));
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
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));
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
    int alen = sizeof(a);
    getsockname(hog, reinterpret_cast<sockaddr*>(&a), &alen);
    const uint16_t port = ntohs(a.sin_port);

    backend_ps4_t b;
    b.set_event_port(port);
    g.srv.event_port = port;
    std::string err;
    REQUIRE(b.connect("127.0.0.1", g.srv.port, err));
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
    REQUIRE(slop::core::process::target_connect_ps4("127.0.0.1", g.srv.port, kFakePid, err));
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

TEST_CASE(ps4_status_console_info_and_mcp_reconnect) {
    server_guard_t g;
    ps4_disconnect_guard_t guard;
    std::string err;
    REQUIRE(slop::core::process::target_connect_ps4("127.0.0.1", g.srv.port, kFakePid, err));
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
    REQUIRE(slop::core::process::target_connect_ps4("127.0.0.1", g.srv.port, kFakePid, err));
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
    REQUIRE(proc::target_connect_ps4("127.0.0.1", g.srv.port, kFakePid, err));
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
    REQUIRE(proc::target_connect_ps4("127.0.0.1", a.srv.port, kFakePid, err));
    auto held = proc::active_session();   // e.g. a long scan still holding it
    REQUIRE(held && held->valid());
    uint8_t v = 0x5A;
    REQUIRE(held->write(0x7FFF00000040ull, &v, 1).ok);

    // switching consoles detaches the session first ...
    REQUIRE(rt::registry_connect_ps4("127.0.0.1", b2.srv.port, err));
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
// shellcode in a PING.EXE that idles for two minutes
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
        wchar_t cmd[] = L"C:\\Windows\\System32\\PING.EXE -n 120 127.0.0.1";
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
