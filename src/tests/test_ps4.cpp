// src/tests/test_ps4.cpp
// PS4 (ps4debug-NG) backend tests: a fake payload server on loopback TCP
// implements the wire protocol subset (see ps4_protocol.hpp), then the real
// backend_ps4_t, the backend registry, the target session and the MCP target
// tool are driven against it.

#include "harness.hpp"

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

bool send_all(SOCKET s, const void* buf, size_t len) {
    const char* p = static_cast<const char*>(buf);
    size_t left = len;
    while (left > 0) {
        int n = ::send(s, p, static_cast<int>(left), 0);
        if (n <= 0) return false;
        p += n;
        left -= static_cast<size_t>(n);
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

    // send one packed 0x4A0 debug event on the port-755 connection
    void send_event(uint32_t lwpid, uint32_t status, const char* name, uint64_t rip_override) {
        std::lock_guard lk(mu);
        if (event_fd == INVALID_SOCKET) return;
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
        if (rip_override) pkt.regs.rip = rip_override;
        for (int i = 0; i < 16; ++i)
            reinterpret_cast<uint64_t*>(pkt.dbregs)[i] = 0xD000 + i;
        send_all(event_fd, &pkt, sizeof(pkt));
    }

    fake_ps4_server_t() {
        wsa();

        auto add_map = [&](const char* name, uint64_t start, uint64_t end, uint16_t prot) {
            ps4::vm_map_entry_t m{};
            std::strncpy(m.name, name, sizeof(m.name) - 1);
            m.start = start;
            m.end = end;
            m.offset = 0;
            m.prot = prot;
            maps.push_back(m);
        };
        add_map("/app0/eboot.bin", 0x400000, 0x500000, ps4::kVmProtRead | ps4::kVmProtExec);
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
        while (!stop_flag) {
            ps4::packet_header_t hdr{};
            if (!recv_all(c, &hdr, sizeof(hdr))) return;
            if (hdr.magic != ps4::kPacketMagic) return;
            std::vector<uint8_t> body(hdr.datalen);
            if (hdr.datalen > 0 && !recv_all(c, body.data(), hdr.datalen)) return;
            if (!dispatch(c, hdr.cmd, body.data(), hdr.datalen)) return;
        }
    }

    bool dispatch(SOCKET c, uint32_t cmd, const uint8_t* body, uint32_t bodylen) {
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
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            if (!send_u32(c, 2)) return false;
            ps4::proc_list_entry_t e{};
            std::strncpy(e.p_comm, "eboot.bin", sizeof(e.p_comm) - 1);
            e.pid = static_cast<int32_t>(kFakePid);
            if (!send_all(c, &e, sizeof(e))) return false;
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
            a.sin_port = htons(ps4::kDebugPort);
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
            debug_attached = false;
            if (event_fd != INVALID_SOCKET) {
                closesocket(event_fd);
                event_fd = INVALID_SOCKET;
            }
            return send_u32(c, ps4::CMD_SUCCESS);
        }

        case ps4::CMD_DEBUG_GET_THREAD_LIST: {
            std::lock_guard lk(mu);
            if (!debug_attached) return send_u32(c, ps4::CMD_ERROR), true;
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            if (!send_u32(c, 2)) return false;
            return send_u32(c, 101) && send_u32(c, 102);
        }

        case ps4::CMD_DEBUG_THREAD_INFO: {
            std::lock_guard lk(mu);
            if (!debug_attached) return send_u32(c, ps4::CMD_ERROR), true;
            const auto* p = reinterpret_cast<const ps4::debug_lwpid_packet_t*>(body);
            struct { uint32_t lwpid; uint32_t priority; char name[32]; } r{};
            r.lwpid = p->lwpid;
            r.priority = 80;
            std::strncpy(r.name, "main", sizeof(r.name) - 1);
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
            {
                std::lock_guard lk(mu);
                last_continue_stop = p->stop;
                if (!debug_attached) return send_u32(c, ps4::CMD_ERROR), true;
                for (const auto& [idx, bp] : bps)
                    if (bp.enabled) { hit = bp.address; break; }
                if (!hit)
                    for (const auto& [idx, wp] : wps)
                        if (wp.enabled) { wp_hit = true; break; }
            }
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            // resuming into an armed breakpoint or watchpoint stops the main
            // thread with SIGTRAP (watchpoint: rip stays at the faulting insn)
            if (p->stop == 0 && hit) send_event(101, 5u << 8, "main", hit);
            else if (p->stop == 0 && wp_hit) send_event(101, 5u << 8, "main", 0);
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
            send_event(101, 5u << 8, "main", newrip);
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
            send_event(lw, 5u << 8, "worker", newrip);
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
            std::memcpy(buf.data(), &n_frames, 4);
            if (!send_u32(c, ps4::CMD_SUCCESS)) return false;
            const uint32_t off = static_cast<uint32_t>(buf.size());
            if (!send_all(c, &off, sizeof(off))) return false;
            return send_all(c, buf.data(), buf.size());
        }

        case ps4::CMD_PROC_ASSEMBLE: {
            const uint32_t textlen = bodylen >= sizeof(ps4::proc_assemble_packet_t)
                ? bodylen - static_cast<uint32_t>(sizeof(ps4::proc_assemble_packet_t)) : 0;
            std::vector<uint8_t> t(textlen);
            if (textlen && !recv_all(c, t.data(), textlen)) return false;
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
    CHECK(regions.items.size() == 3u);
    bool saw_eboot = false;
    for (const auto& r : regions.items) {
        if (r.base == 0x400000) {
            saw_eboot = true;
            CHECK(r.size == 0x100000);
            CHECK(r.protect == 0x20);   // PAGE_EXECUTE_READ
        }
    }
    CHECK(saw_eboot);

    auto mods = b.enum_modules(h);
    REQUIRE(mods.ok);
    bool saw_mod = false;
    for (const auto& m : mods.items) {
        if (m.base == 0x400000) {
            saw_mod = true;
            REQUIRE_STR_EQ(m.name, "eboot.bin");
            REQUIRE_STR_EQ(m.path, "/app0/eboot.bin");
        }
    }
    CHECK(saw_mod);

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
        CHECK(a.value("region_count", 0) == 3);
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
        CHECK(r.value("bytes_written", 0) == 0x100000ull);
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
