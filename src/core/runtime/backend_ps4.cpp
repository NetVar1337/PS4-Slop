// src/core/runtime/backend_ps4.cpp
// Remote PS4 backend over the ps4debug-NG wire protocol (TCP 744).
// Wire formats verified against the payload sources: every request is a
// 12-byte header {magic, cmd, datalen} followed by datalen body bytes, all
// little-endian; replies start with a u32 status unless noted.

#include "core/runtime/backend_ps4.hpp"
#include "core/runtime/ps4_protocol.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "core/infra/clock.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

namespace slop::core::runtime {

namespace {

constexpr int kIoTimeoutMs      = 10000;  // normal command roundtrips
constexpr int kShortTimeoutMs   = 500;    // optional trailing status words
constexpr int kConnectTimeoutMs = 5000;
constexpr size_t kMaxListEntries = 4096;
constexpr int64_t kMapsCacheTtlMs = 1500;

struct wsa_init_t {
    wsa_init_t() { WSADATA d; WSAStartup(MAKEWORD(2, 2), &d); }
    ~wsa_init_t() { WSACleanup(); }
};
wsa_init_t& wsa() { static wsa_init_t w; return w; }

// ---------------------------------------------------------------------------
// conn_t: one TCP connection to the ps4debug-NG command server

class conn_t {
public:
    SOCKET fd = INVALID_SOCKET;
    std::string host;
    uint16_t port = 0;
    std::mutex mu;   // serializes whole command exchanges

    bool connected() const noexcept { return fd != INVALID_SOCKET; }

    bool open(const std::string& h, uint16_t p, std::string& err) {
        wsa();
        close();
        host = h;
        port = p;

        addrinfo hints{};
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        addrinfo* list = nullptr;
        char port_str[8];
        std::snprintf(port_str, sizeof(port_str), "%u", p);
        if (getaddrinfo(h.c_str(), port_str, &hints, &list) != 0 || !list) {
            err = "cannot resolve " + h;
            return false;
        }

        SOCKET s = socket(list->ai_family, list->ai_socktype, list->ai_protocol);
        if (s == INVALID_SOCKET) {
            freeaddrinfo(list);
            err = "socket() failed";
            return false;
        }

        // connect with a timeout: non-blocking connect + select
        u_long nonblock = 1;
        ioctlsocket(s, FIONBIO, &nonblock);
        int r = ::connect(s, list->ai_addr, static_cast<int>(list->ai_addrlen));
        freeaddrinfo(list);
        if (r == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
            closesocket(s);
            err = "connect to " + h + ":" + port_str + " failed (WSA " +
                  std::to_string(WSAGetLastError()) + ")";
            return false;
        }
        if (r == SOCKET_ERROR) {
            fd_set wset;
            FD_ZERO(&wset);
            FD_SET(s, &wset);
            timeval tv{};
            tv.tv_sec  = kConnectTimeoutMs / 1000;
            tv.tv_usec = (kConnectTimeoutMs % 1000) * 1000;
            if (select(0, nullptr, &wset, nullptr, &tv) <= 0) {
                closesocket(s);
                err = "connect to " + h + ":" + port_str + " timed out";
                return false;
            }
            int soerr = 0;
            int slen  = sizeof(soerr);
            getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &slen);
            if (soerr != 0) {
                closesocket(s);
                err = "connect to " + h + ":" + port_str + " failed (SO_ERROR " +
                      std::to_string(soerr) + ")";
                return false;
            }
        }
        u_long block = 0;
        ioctlsocket(s, FIONBIO, &block);

        int flag = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&flag), sizeof(flag));
        timeval tv{};
        tv.tv_sec  = kIoTimeoutMs / 1000;
        tv.tv_usec = (kIoTimeoutMs % 1000) * 1000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));

        fd = s;
        return true;
    }

    void close() {
        if (fd != INVALID_SOCKET) {
            shutdown(fd, SD_BOTH);
            closesocket(fd);
            fd = INVALID_SOCKET;
        }
    }

    bool send_all(const void* buf, size_t len, int timeout_ms = kIoTimeoutMs) {
        const char* p = static_cast<const char*>(buf);
        size_t left = len;
        while (left > 0) {
            fd_set wset;
            FD_ZERO(&wset);
            FD_SET(fd, &wset);
            timeval tv{};
            tv.tv_sec  = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            if (select(0, nullptr, &wset, nullptr, &tv) <= 0) return false;
            int n = ::send(fd, p, static_cast<int>(left > 0x10000 ? 0x10000 : left), 0);
            if (n <= 0) return false;
            p    += n;
            left -= static_cast<size_t>(n);
        }
        return true;
    }

    bool recv_all(void* buf, size_t len, int timeout_ms = kIoTimeoutMs) {
        char* p = static_cast<char*>(buf);
        size_t left = len;
        while (left > 0) {
            fd_set rset;
            FD_ZERO(&rset);
            FD_SET(fd, &rset);
            timeval tv{};
            tv.tv_sec  = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            int sel = select(0, &rset, nullptr, nullptr, &tv);
            if (sel <= 0) return false;   // timeout or error
            int n = ::recv(fd, p, static_cast<int>(left > 0x10000 ? 0x10000 : left), 0);
            if (n <= 0) return false;
            p    += n;
            left -= static_cast<size_t>(n);
        }
        return true;
    }

    bool recv_u32(uint32_t& v, int timeout_ms = kIoTimeoutMs) {
        return recv_all(&v, sizeof(v), timeout_ms);
    }

    // send one request header + body; the caller then drives the reply
    bool send_cmd(uint32_t cmd, const void* body, uint32_t bodylen) {
        ps4::packet_header_t hdr{};
        hdr.magic   = ps4::kPacketMagic;
        hdr.cmd     = cmd;
        hdr.datalen = bodylen;
        if (!send_all(&hdr, sizeof(hdr))) return false;
        if (bodylen > 0 && body) return send_all(body, bodylen);
        return true;
    }

    // our IPv4 as the sin_addr.s_addr numeric value, for CMD_DEBUG_ATTACH
    uint32_t local_ip_value() {
        sockaddr_in sa{};
        int len = sizeof(sa);
        if (getsockname(fd, reinterpret_cast<sockaddr*>(&sa), &len) != 0)
            return 0;
        uint32_t v;
        std::memcpy(&v, &sa.sin_addr, sizeof(v));
        return v;
    }
};

// ---------------------------------------------------------------------------
// event_listener_t: accepts the server->client debug-event connection on 755.
// CMD_DEBUG_ATTACH fails server-side unless it can connect back to us, so we
// listen and drain interrupt packets (0x4A0 bytes each) for the session life.

class event_listener_t {
public:
    ~event_listener_t() { stop(); }

    // called from the listener thread for every complete 0x4A0-byte packet;
    // set once before start() and never mutated afterwards
    std::function<void(const uint8_t* pkt, size_t len)> on_packet;

    bool start(uint16_t port) {
        std::lock_guard lk(mu_);
        if (running_) return true;
        wsa();
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return false;
        int flag = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&flag), sizeof(flag));
        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = htons(port);
        if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
            listen(s, 4) != 0) {
            closesocket(s);
            return false;
        }
        listen_fd_ = s;
        running_   = true;
        stop_      = false;
        th_ = std::thread([this] { run(); });
        return true;
    }

    void stop() {
        {
            std::lock_guard lk(mu_);
            if (!running_) return;
            stop_ = true;
        }
        if (listen_fd_ != INVALID_SOCKET) {
            shutdown(listen_fd_, SD_BOTH);
            closesocket(listen_fd_);
            listen_fd_ = INVALID_SOCKET;
        }
        if (th_.joinable()) th_.join();
        std::lock_guard lk(mu_);
        running_ = false;
    }

    bool running() const {
        std::lock_guard lk(mu_);
        return running_;
    }

    uint64_t events() const { return events_.load(); }

private:
    void run() {
        while (!stop_) {
            SOCKET ls = listen_fd_;
            if (ls == INVALID_SOCKET) break;
            fd_set rset;
            FD_ZERO(&rset);
            FD_SET(ls, &rset);
            timeval tv{};
            tv.tv_sec  = 0;
            tv.tv_usec = 200 * 1000;
            if (select(0, &rset, nullptr, nullptr, &tv) <= 0) continue;
            SOCKET c = accept(ls, nullptr, nullptr);
            if (c == INVALID_SOCKET) continue;
            // short recv timeout so stop_ is noticed even with no traffic
            timeval rt{};
            rt.tv_sec  = 0;
            rt.tv_usec = 500 * 1000;
            setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&rt), sizeof(rt));
            // drain this event connection until the server drops it; TCP can
            // split/coalesce the fixed 0x4A0 packets, so reassemble the stream
            auto cb = on_packet;
            std::vector<uint8_t> acc;
            acc.reserve(ps4::kDebugEventSize * 2);
            uint8_t buf[0x8000];
            while (!stop_) {
                int n = ::recv(c, reinterpret_cast<char*>(buf), sizeof(buf), 0);
                if (n == 0) break;   // server closed the event connection
                if (n < 0) {
                    // the recv timeout exists only to notice stop_; keep the
                    // connection open so later events from the payload arrive
                    if (WSAGetLastError() == WSAETIMEDOUT) continue;
                    break;
                }
                events_.fetch_add(1);
                acc.insert(acc.end(), buf, buf + n);
                while (acc.size() >= ps4::kDebugEventSize) {
                    if (cb) cb(acc.data(), ps4::kDebugEventSize);
                    acc.erase(acc.begin(),
                              acc.begin() + static_cast<ptrdiff_t>(ps4::kDebugEventSize));
                }
            }
            closesocket(c);
        }
    }

    mutable std::mutex mu_;
    SOCKET listen_fd_ = INVALID_SOCKET;
    std::thread th_;
    std::atomic<bool> stop_{false};
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> events_{0};
};

// ---------------------------------------------------------------------------
// prot translation: callers pass Windows PAGE_* constants, ps4debug wants
// FreeBSD VM_PROT_* bits

uint32_t win_to_vm_prot(uint32_t page) {
    page &= ~(0x100u | 0x200u | 0x400u);   // drop PAGE_GUARD/NOCACHE/WRITECOMBINE
    switch (page) {
    case 0x01: return ps4::kVmProtNone;                     // PAGE_NOACCESS
    case 0x02: return ps4::kVmProtRead;                     // PAGE_READONLY
    case 0x04: return ps4::kVmProtRead | ps4::kVmProtWrite; // PAGE_READWRITE
    case 0x08: return ps4::kVmProtRead | ps4::kVmProtWrite; // PAGE_WRITECOPY
    case 0x10: return ps4::kVmProtExec;                     // PAGE_EXECUTE
    case 0x20: return ps4::kVmProtRead | ps4::kVmProtExec;  // PAGE_EXECUTE_READ
    case 0x40: return ps4::kVmProtAll;                      // PAGE_EXECUTE_READWRITE
    case 0x80: return ps4::kVmProtAll;                      // PAGE_EXECUTE_WRITECOPY
    default:   return ps4::kVmProtAll;
    }
}

uint32_t vm_to_win_prot(uint16_t vm) {
    static const uint32_t kTable[8] = {
        0x01, 0x02, 0x04, 0x04, 0x10, 0x20, 0x40, 0x40
    };
    return kTable[vm & 0x7];
}

std::string fixed_str(const char* s, size_t cap) {
    size_t n = 0;
    while (n < cap && s[n] != '\0') ++n;
    return std::string(s, n);
}

std::string base_name(const std::string& path) {
    const size_t slash = path.find_last_of("/\\");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

void reg64_from_ctx(ps4::reg64_t& r, const thread_context_t& c) {
    r = {};
    r.r15 = c.r15; r.r14 = c.r14; r.r13 = c.r13; r.r12 = c.r12;
    r.r11 = c.r11; r.r10 = c.r10; r.r9  = c.r9;  r.r8  = c.r8;
    r.rdi = c.rdi; r.rsi = c.rsi; r.rbp = c.rbp; r.rbx = c.rbx;
    r.rdx = c.rdx; r.rcx = c.rcx; r.rax = c.rax;
    r.rip = c.rip; r.rsp = c.rsp; r.rflags = c.flags;
}

void ctx_from_reg64(thread_context_t& c, const ps4::reg64_t& r) {
    c = {};
    c.r15 = r.r15; c.r14 = r.r14; c.r13 = r.r13; c.r12 = r.r12;
    c.r11 = r.r11; c.r10 = r.r10; c.r9  = r.r9;  c.r8  = r.r8;
    c.rdi = r.rdi; c.rsi = r.rsi; c.rbp = r.rbp; c.rbx = r.rbx;
    c.rdx = r.rdx; c.rcx = r.rcx; c.rax = r.rax;
    c.rip = r.rip; c.rsp = r.rsp; c.flags = r.rflags;
}

} // namespace

// ---------------------------------------------------------------------------
// backend impl

struct backend_ps4_t::impl_t {
    static constexpr size_t kMaxEvents = 4096;

    impl_t() {
        listener.on_packet = [this](const uint8_t* pkt, size_t n) { push_event(pkt, n); };
    }

    std::shared_ptr<conn_t> conn = std::make_shared<conn_t>();
    std::string branding;
    uint16_t    fw = 0;
    uint32_t    dbg_pid = 0;          // pid the debug session is attached to, 0 = none
    event_listener_t listener;

    // debug event queue, fed by the port-755 listener thread
    std::mutex ev_mu;
    std::condition_variable ev_cv;
    std::deque<ps4_event_t> evq;

    // rpc stub per pid (CMD_PROC_INTALL result) so ps4_call doesn't reinstall
    std::map<uint32_t, uint64_t> rpcstubs;

    void push_event(const uint8_t* pkt, size_t n) {
        if (n < ps4::kDebugEventSize) return;
        const auto* ep = reinterpret_cast<const ps4::debug_event_packet_t*>(pkt);
        ps4_event_t e{};
        e.lwpid  = ep->lwpid;
        e.status = ep->status;
        e.signal = static_cast<int>((ep->status >> 8) & 0xFF);
        std::memcpy(e.thread_name, ep->tdname, sizeof(ep->tdname));
        e.thread_name[sizeof(ep->tdname)] = '\0';
        ctx_from_reg64(e.ctx, ep->regs);
        std::memcpy(e.dr, ep->dbregs, sizeof(e.dr));
        {
            std::lock_guard lk(ev_mu);
            if (evq.size() >= kMaxEvents) evq.pop_front();   // drop oldest
            evq.push_back(std::move(e));
        }
        ev_cv.notify_all();
    }

    void clear_events() {
        std::lock_guard lk(ev_mu);
        evq.clear();
    }

    // maps cache so read-coverage checks don't hammer the console
    std::mutex cache_mu;
    uint32_t cache_pid = 0;
    int64_t  cache_at = 0;
    std::vector<ps4::vm_map_entry_t> cache;

    // fetch fresh maps for pid (caller does NOT hold conn->mu)
    bool fetch_maps(uint32_t pid, std::vector<ps4::vm_map_entry_t>& out, uint32_t& err) {
        auto& c = *conn;
        std::lock_guard lk(c.mu);
        if (!c.connected()) { err = 1; return false; }
        ps4::proc_maps_packet_t pkt{};
        pkt.pid = pid;
        if (!c.send_cmd(ps4::CMD_PROC_MAPS, &pkt, sizeof(pkt))) { err = 2; return false; }
        uint32_t status = 0;
        if (!c.recv_u32(status) || status != ps4::CMD_SUCCESS) { err = 3; return false; }
        uint32_t num = 0;
        if (!c.recv_u32(num) || num > kMaxListEntries) { err = 4; return false; }
        out.resize(num);
        if (num > 0 && !c.recv_all(out.data(), num * sizeof(ps4::vm_map_entry_t))) {
            err = 5;
            return false;
        }
        return true;
    }

    void invalidate_maps_cache() {
        std::lock_guard lk(cache_mu);
        cache_at = 0;
        cache.clear();
        cache_pid = 0;
    }

    // cached maps with a short TTL; coverage checks ride on this
    bool maps_cached(uint32_t pid, std::vector<ps4::vm_map_entry_t>& out, uint32_t& err) {
        {
            std::lock_guard lk(cache_mu);
            if (cache_pid == pid && cache_at != 0 &&
                infra::steady_ms() - cache_at < kMapsCacheTtlMs) {
                out = cache;
                return true;
            }
        }
        std::vector<ps4::vm_map_entry_t> fresh;
        if (!fetch_maps(pid, fresh, err)) return false;
        std::lock_guard lk(cache_mu);
        cache_pid = pid;
        cache_at  = infra::steady_ms();
        cache = fresh;
        out = std::move(fresh);
        return true;
    }

    // is [addr, addr+len) fully covered by readable maps? adjacent maps count
    static bool covered_by(const std::vector<ps4::vm_map_entry_t>& maps,
                           uint64_t addr, uint64_t len, uint16_t prot_bit) {
        if (len == 0) return true;
        const uint64_t end = addr + len;
        uint64_t cur = addr;
        int guard = 0;
        while (cur < end && guard++ < 4096) {
            const ps4::vm_map_entry_t* hit = nullptr;
            for (const auto& m : maps) {
                if (m.start <= cur && cur < m.end) { hit = &m; break; }
            }
            if (!hit || (hit->prot & prot_bit) == 0) return false;
            cur = hit->end;
        }
        return cur >= end;
    }

    const ps4::vm_map_entry_t* find_map(const std::vector<ps4::vm_map_entry_t>& maps,
                                        uint64_t addr) {
        for (const auto& m : maps)
            if (m.start <= addr && addr < m.end) return &m;
        return nullptr;
    }

    // lazy debug attach; ps4debug-NG allows one debuggee at a time
    bool ensure_debug(uint32_t pid, uint32_t& err) {
        auto& c = *conn;
        std::lock_guard lk(c.mu);
        if (!c.connected()) { err = 1; return false; }
        if (dbg_pid == pid) return true;
        if (dbg_pid != 0) {
            c.send_cmd(ps4::CMD_DEBUG_DETACH, nullptr, 0);
            uint32_t st = 0;
            c.recv_u32(st);
            dbg_pid = 0;
        }
        // the payload connects back to us on 755 or attach fails
        if (!listener.running() && !listener.start(ps4::kDebugPort)) {
            err = 2;
            return false;
        }
        ps4::debug_attach_packet_t pkt{};
        pkt.pid       = pid;
        pkt.client_ip = c.local_ip_value();
        if (!c.send_cmd(ps4::CMD_DEBUG_ATTACH, &pkt, sizeof(pkt))) { err = 3; return false; }
        uint32_t status = 0;
        if (!c.recv_u32(status)) { err = 4; return false; }
        if (status == ps4::CMD_ALREADY_DEBUG) { err = 5; return false; }
        if (status != ps4::CMD_SUCCESS) { err = 6; return false; }
        dbg_pid = pid;
        {
            std::lock_guard lk(ev_mu);
            evq.clear();   // fresh debug session: drop stale events
        }
        return true;
    }
};

namespace {

struct attach_state_t {
    uint32_t pid = 0;
    std::shared_ptr<conn_t> conn;
    std::string name;
    std::string path;
};

uint32_t handle_pid(const target_handle_t& h) {
    return h.pid;
}

std::shared_ptr<conn_t> handle_conn(const target_handle_t& h) {
    auto* st = static_cast<attach_state_t*>(h.native);
    return st ? st->conn : nullptr;
}

} // namespace

// ---------------------------------------------------------------------------
// connection management

backend_ps4_t::backend_ps4_t() : m_impl(std::make_unique<impl_t>()) {}
backend_ps4_t::~backend_ps4_t() { disconnect(); }

bool backend_ps4_t::connect(const std::string& host, uint16_t port, std::string& err) {
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    if (c.connected() && c.host == host && c.port == port) return true;
    if (c.connected()) {
        if (m_impl->dbg_pid != 0) {
            c.send_cmd(ps4::CMD_DEBUG_DETACH, nullptr, 0);
            uint32_t st = 0;
            c.recv_u32(st);
            m_impl->dbg_pid = 0;
        }
        c.close();
    }
    if (!c.open(host, port, err)) return false;

    // handshake: version + branding + fw + platform tag, then a NOP probe.
    // version/branding reply with u32 len + bytes (no status word), fw and
    // platform reply with a bare u16, NOP replies with a u32 status
    if (!c.send_cmd(ps4::CMD_VERSION, nullptr, 0)) goto fail;
    {
        uint32_t len = 0;
        if (!c.recv_u32(len) || len == 0 || len > 64) goto fail;
        std::string v(len, '\0');
        if (!c.recv_all(v.data(), len)) goto fail;
    }
    if (!c.send_cmd(ps4::CMD_BRANDING, nullptr, 0)) goto fail;
    {
        uint32_t len = 0;
        if (!c.recv_u32(len) || len == 0 || len > 256) goto fail;
        std::string b(len, '\0');
        if (!c.recv_all(b.data(), len)) goto fail;
        m_impl->branding = b;   // "brand\0caps"; NUL-trimmed by branding()
    }
    if (!c.send_cmd(ps4::CMD_FW_VERSION, nullptr, 0)) goto fail;
    {
        uint16_t fw = 0;
        if (!c.recv_all(&fw, sizeof(fw))) goto fail;
        m_impl->fw = fw;
    }
    if (!c.send_cmd(ps4::CMD_PLATFORM_ID, nullptr, 0)) goto fail;
    {
        uint16_t tag = 0;
        if (!c.recv_all(&tag, sizeof(tag)) || tag != 4) goto fail;   // 4 = PS4
    }
    if (!c.send_cmd(ps4::CMD_PROC_NOP, nullptr, 0)) goto fail;
    {
        uint32_t st = 0;
        if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) goto fail;
    }
    return true;

fail:
    err = "handshake with " + host + ":" + std::to_string(port) +
          " failed (not a ps4debug-NG server?)";
    c.close();
    return false;
}

void backend_ps4_t::disconnect() {
    auto& c = *m_impl->conn;
    {
        std::lock_guard lk(c.mu);
        if (c.connected() && m_impl->dbg_pid != 0) {
            c.send_cmd(ps4::CMD_DEBUG_DETACH, nullptr, 0);
            uint32_t st = 0;
            c.recv_u32(st);
            m_impl->dbg_pid = 0;
        }
        c.close();
    }
    m_impl->listener.stop();
    m_impl->branding.clear();
    m_impl->fw = 0;
    m_impl->clear_events();
    {
        std::lock_guard lk(m_impl->ev_mu);
        m_impl->rpcstubs.clear();
    }
}

bool backend_ps4_t::connected() const noexcept {
    return m_impl->conn->connected();
}

bool backend_ps4_t::ping() {
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    if (!c.connected()) return false;
    if (!c.send_cmd(ps4::CMD_PROC_NOP, nullptr, 0)) return false;
    uint32_t st = 0;
    return c.recv_u32(st) && st == ps4::CMD_SUCCESS;
}

std::string backend_ps4_t::endpoint() const {
    auto& c = *m_impl->conn;
    if (!c.connected()) return {};
    return c.host + ":" + std::to_string(c.port);
}

std::string backend_ps4_t::branding() const {
    std::string b = m_impl->branding;
    const size_t nul = b.find('\0');
    if (nul != std::string::npos) b.resize(nul);
    return b;
}

uint16_t backend_ps4_t::fw_version() const noexcept {
    return m_impl->fw;
}

// ---------------------------------------------------------------------------
// identity

backend_kind_t backend_ps4_t::kind() const noexcept {
    return backend_kind_t::ps4;
}

const char* backend_ps4_t::badge() const noexcept {
    return "PS4";
}

// ---------------------------------------------------------------------------
// attach / detach

target_handle_t backend_ps4_t::attach(uint32_t pid) {
    target_handle_t t;
    auto& c = *m_impl->conn;
    if (!c.connected()) return t;

    // validate the pid and pull name/path via CMD_PROC_INFO; fall back to the
    // process list when info is unavailable
    std::string name, path;
    {
        std::lock_guard lk(c.mu);
        ps4::proc_info_packet_t pkt{};
        pkt.pid = pid;
        if (c.send_cmd(ps4::CMD_PROC_INFO, &pkt, sizeof(pkt))) {
            uint32_t st = 0;
            if (c.recv_u32(st) && st == ps4::CMD_SUCCESS) {
                ps4::proc_info_response_t resp{};
                if (c.recv_all(&resp, sizeof(resp))) {
                    name = fixed_str(resp.name, sizeof(resp.name));
                    path = fixed_str(resp.path, sizeof(resp.path));
                }
            }
        }
        if (name.empty()) {
            if (!c.send_cmd(ps4::CMD_PROC_LIST, nullptr, 0)) return t;
            uint32_t st = 0, num = 0;
            if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) return t;
            if (!c.recv_u32(num) || num > kMaxListEntries) return t;
            bool found = false;
            for (uint32_t i = 0; i < num; ++i) {   // consume every entry
                ps4::proc_list_entry_t e{};
                if (!c.recv_all(&e, sizeof(e))) return t;
                if (!found && static_cast<uint32_t>(e.pid) == pid) {
                    name  = fixed_str(e.p_comm, sizeof(e.p_comm));
                    found = true;
                }
            }
            if (!found) return t;
        }
    }

    auto* st = new attach_state_t{};
    st->pid  = pid;
    st->conn = m_impl->conn;
    st->name = name;
    st->path = path;
    t.native = st;
    t.pid    = pid;
    return t;
}

void backend_ps4_t::detach(target_handle_t& h) {
    if (auto* st = static_cast<attach_state_t*>(h.native)) {
        if (m_impl->dbg_pid == st->pid) {
            auto& c = *m_impl->conn;
            std::lock_guard lk(c.mu);
            if (c.connected()) {
                c.send_cmd(ps4::CMD_DEBUG_DETACH, nullptr, 0);
                uint32_t s = 0;
                c.recv_u32(s);
            }
            m_impl->dbg_pid = 0;
            m_impl->clear_events();
        }
        delete st;
    }
    h = {};
}

// ---------------------------------------------------------------------------
// memory

io_result_t backend_ps4_t::read_memory(const target_handle_t& h, uintptr_t addr,
                                       void* buf, size_t len) {
    io_result_t r;
    if (len == 0) { r.ok = true; return r; }
    if (len > ps4::kMaxIoLen) { r.error = ERROR_INVALID_PARAMETER; return r; }
    auto conn = handle_conn(h);
    if (!conn || !conn->connected()) { r.error = 1; return r; }

    // ps4debug zero-fills unreadable chunks and still reports success, so
    // check coverage against the vm map first to keep the reader contract
    // honest (false = any part unreadable). A maps failure is not fatal.
    std::vector<ps4::vm_map_entry_t> maps;
    uint32_t merr = 0;
    if (m_impl->maps_cached(handle_pid(h), maps, merr) &&
        !impl_t::covered_by(maps, addr, len, ps4::kVmProtRead)) {
        r.error = 2;   // unmapped or not readable
        return r;
    }

    auto& c = *conn;
    std::lock_guard lk(c.mu);
    ps4::proc_read_packet_t pkt{};
    pkt.pid     = handle_pid(h);
    pkt.address = addr;
    pkt.length  = static_cast<uint32_t>(len);
    if (!c.send_cmd(ps4::CMD_PROC_READ, &pkt, sizeof(pkt))) { r.error = 3; return r; }
    uint32_t st = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 4; return r; }
    // the server then streams exactly `length` bytes (64 KiB chunks)
    if (!c.recv_all(buf, len)) { r.error = 5; return r; }
    r.ok    = true;
    r.bytes = len;
    return r;
}

io_result_t backend_ps4_t::write_memory(const target_handle_t& h, uintptr_t addr,
                                        const void* buf, size_t len) {
    io_result_t r;
    if (len == 0) { r.ok = true; return r; }
    if (len > ps4::kMaxIoLen) { r.error = ERROR_INVALID_PARAMETER; return r; }
    auto conn = handle_conn(h);
    if (!conn || !conn->connected()) { r.error = 1; return r; }

    auto& c = *conn;
    std::lock_guard lk(c.mu);
    ps4::proc_write_packet_t pkt{};
    pkt.pid     = handle_pid(h);
    pkt.address = addr;
    pkt.length  = static_cast<uint32_t>(len);
    if (!c.send_cmd(ps4::CMD_PROC_WRITE, &pkt, sizeof(pkt))) { r.error = 2; return r; }
    // two-phase: server acks, we stream the bytes, server sends terminal status
    uint32_t ack = 0;
    if (!c.recv_u32(ack) || ack != ps4::CMD_SUCCESS) { r.error = 3; return r; }
    if (!c.send_all(buf, len)) { r.error = 4; return r; }
    uint32_t term = 0;
    if (!c.recv_u32(term) || term != ps4::CMD_SUCCESS) {
        r.error = 5;   // server readback verification failed
        return r;
    }
    r.ok    = true;
    r.bytes = len;
    return r;
}

io_result_t backend_ps4_t::protect_memory(const target_handle_t& h, uintptr_t addr,
                                          size_t len, uint32_t new_prot, uint32_t* old_prot) {
    io_result_t r;
    auto conn = handle_conn(h);
    if (!conn || !conn->connected()) { r.error = 1; return r; }
    if (old_prot) {
        std::vector<ps4::vm_map_entry_t> maps;
        uint32_t merr = 0;
        if (m_impl->maps_cached(handle_pid(h), maps, merr)) {
            if (auto* m = m_impl->find_map(maps, addr))
                *old_prot = vm_to_win_prot(m->prot);
        }
    }

    auto& c = *conn;
    std::lock_guard lk(c.mu);
    ps4::proc_protect_packet_t pkt{};
    pkt.pid     = handle_pid(h);
    pkt.address = addr;
    pkt.length  = static_cast<uint32_t>(len);
    pkt.newprot = win_to_vm_prot(new_prot);
    if (!c.send_cmd(ps4::CMD_PROC_PROTECT, &pkt, sizeof(pkt))) { r.error = 2; return r; }
    uint32_t st = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 3; return r; }
    // payload quirk: proc_protect_handle also sends CMD_DATA_NULL after the
    // success status; consume it so the stream stays in sync
    uint32_t extra = 0;
    c.recv_u32(extra, kShortTimeoutMs);
    r.ok = true;
    m_impl->invalidate_maps_cache();
    return r;
}

io_result_t backend_ps4_t::allocate_memory(const target_handle_t& h, uintptr_t addr,
                                           size_t len, uint32_t prot, uintptr_t* out_addr) {
    io_result_t r;
    if (len == 0 || len > ps4::kMaxIoLen) { r.error = ERROR_INVALID_PARAMETER; return r; }
    auto conn = handle_conn(h);
    if (!conn || !conn->connected()) { r.error = 1; return r; }

    auto& c = *conn;
    std::lock_guard lk(c.mu);
    uint32_t st = 0;
    if (addr != 0) {
        ps4::proc_alloc_hinted_packet_t pkt{};
        pkt.pid    = handle_pid(h);
        pkt.hint   = addr;
        pkt.length = static_cast<uint32_t>(len);
        if (!c.send_cmd(ps4::CMD_PROC_ALLOC_HINTED, &pkt, sizeof(pkt))) { r.error = 2; return r; }
    } else {
        ps4::proc_alloc_packet_t pkt{};
        pkt.pid    = handle_pid(h);
        pkt.length = static_cast<uint32_t>(len);
        if (!c.send_cmd(ps4::CMD_PROC_ALLOC, &pkt, sizeof(pkt))) { r.error = 2; return r; }
    }
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 3; return r; }
    ps4::proc_alloc_response_t resp{};
    if (!c.recv_all(&resp, sizeof(resp)) || resp.address == 0) { r.error = 4; return r; }
    const uint64_t out = resp.address;

    if (out_addr) *out_addr = static_cast<uintptr_t>(out);
    r.ok    = true;
    r.bytes = len;
    // ps4debug allocates RW; tighten to the requested protection when given
    if (prot != 0) {
        ps4::proc_protect_packet_t pp{};
        pp.pid     = handle_pid(h);
        pp.address = out;
        pp.length  = static_cast<uint32_t>(len);
        pp.newprot = win_to_vm_prot(prot);
        if (c.send_cmd(ps4::CMD_PROC_PROTECT, &pp, sizeof(pp))) {
            uint32_t s2 = 0;
            if (c.recv_u32(s2) && s2 == ps4::CMD_SUCCESS) {
                uint32_t extra = 0;
                c.recv_u32(extra, kShortTimeoutMs);
            }
        }
    }
    m_impl->invalidate_maps_cache();
    return r;
}

io_result_t backend_ps4_t::free_memory(const target_handle_t& h, uintptr_t addr) {
    io_result_t r;
    auto conn = handle_conn(h);
    if (!conn || !conn->connected()) { r.error = 1; return r; }

    std::vector<ps4::vm_map_entry_t> maps;
    uint32_t merr = 0;
    if (!m_impl->maps_cached(handle_pid(h), maps, merr)) { r.error = 2; return r; }
    auto* m = m_impl->find_map(maps, addr);
    if (!m) { r.error = 3; return r; }

    auto& c = *conn;
    std::lock_guard lk(c.mu);
    ps4::proc_free_packet_t pkt{};
    pkt.pid     = handle_pid(h);
    pkt.address = m->start;
    pkt.length  = static_cast<uint32_t>(m->end - m->start);
    if (!c.send_cmd(ps4::CMD_PROC_FREE, &pkt, sizeof(pkt))) { r.error = 4; return r; }
    uint32_t st = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 5; return r; }
    r.ok = true;
    m_impl->invalidate_maps_cache();
    return r;
}

// ---------------------------------------------------------------------------
// enumeration

enum_result_t<process_info_t> backend_ps4_t::enum_processes() {
    enum_result_t<process_info_t> res;
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    if (!c.connected()) { res.error = 1; return res; }
    if (!c.send_cmd(ps4::CMD_PROC_LIST, nullptr, 0)) { res.error = 2; return res; }
    uint32_t st = 0, num = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { res.error = 3; return res; }
    if (!c.recv_u32(num) || num > kMaxListEntries) { res.error = 4; return res; }
    res.items.reserve(num);
    for (uint32_t i = 0; i < num; ++i) {
        ps4::proc_list_entry_t e{};
        if (!c.recv_all(&e, sizeof(e))) { res.error = 5; return res; }
        process_info_t p;
        p.pid       = static_cast<uint32_t>(e.pid);
        p.name      = fixed_str(e.p_comm, sizeof(e.p_comm));
        p.arch      = arch_t::x64;   // Orbis userland is x86-64
        p.elevation = elevation_t::system;
        res.items.push_back(std::move(p));
    }
    res.ok = true;
    return res;
}

enum_result_t<module_info_t> backend_ps4_t::enum_modules(const target_handle_t& h) {
    enum_result_t<module_info_t> res;
    std::vector<ps4::vm_map_entry_t> maps;
    uint32_t err = 0;
    if (!m_impl->fetch_maps(handle_pid(h), maps, err)) { res.error = err ? err : 1; return res; }
    for (const auto& m : maps) {
        const std::string name = fixed_str(m.name, sizeof(m.name));
        if (name.empty()) continue;
        module_info_t mi;
        mi.base = static_cast<uintptr_t>(m.start);
        mi.size = static_cast<uint32_t>(m.end - m.start);
        mi.name = base_name(name);
        mi.path = name;
        res.items.push_back(std::move(mi));
    }
    res.ok = true;
    return res;
}

enum_result_t<thread_info_t> backend_ps4_t::enum_threads(uint32_t pid) {
    enum_result_t<thread_info_t> res;
    uint32_t err = 0;
    if (!m_impl->ensure_debug(pid, err)) { res.error = err; return res; }
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    if (!c.send_cmd(ps4::CMD_DEBUG_GET_THREAD_LIST, nullptr, 0)) { res.error = 2; return res; }
    uint32_t st = 0, num = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { res.error = 3; return res; }
    if (!c.recv_u32(num) || num > kMaxListEntries) { res.error = 4; return res; }
    // the server sends the whole lwpid array in one go; read it all before
    // issuing any follow-up command or the stream desyncs
    std::vector<uint32_t> lwpids(num);
    for (uint32_t i = 0; i < num; ++i)
        if (!c.recv_u32(lwpids[i])) { res.error = 5; return res; }
    for (uint32_t lwpid : lwpids) {
        thread_info_t t;
        t.tid       = lwpid;
        t.owner_pid = pid;
        // enrich with priority via CMD_DEBUG_THREAD_INFO (best effort)
        ps4::debug_lwpid_packet_t tp{};
        tp.lwpid = lwpid;
        if (c.send_cmd(ps4::CMD_DEBUG_THREAD_INFO, &tp, sizeof(tp))) {
            uint32_t st2 = 0;
            struct { uint32_t lwpid; uint32_t priority; char name[32]; } info{};
            if (c.recv_u32(st2) && st2 == ps4::CMD_SUCCESS &&
                c.recv_all(&info, sizeof(info))) {
                t.priority = static_cast<int32_t>(info.priority);
            }
        }
        res.items.push_back(t);
    }
    res.ok = true;
    return res;
}

enum_result_t<region_info_t> backend_ps4_t::enum_regions(const target_handle_t& h) {
    enum_result_t<region_info_t> res;
    std::vector<ps4::vm_map_entry_t> maps;
    uint32_t err = 0;
    if (!m_impl->fetch_maps(handle_pid(h), maps, err)) { res.error = err ? err : 1; return res; }
    for (const auto& m : maps) {
        region_info_t r;
        r.base    = static_cast<uintptr_t>(m.start);
        r.size    = static_cast<size_t>(m.end - m.start);
        r.protect = vm_to_win_prot(m.prot);
        r.state   = 0x1000;   // MEM_COMMIT
        const std::string name = fixed_str(m.name, sizeof(m.name));
        r.type    = name.empty() ? 0x20000 : 0x40000;  // MEM_PRIVATE : MEM_MAPPED
        res.items.push_back(r);
    }
    res.ok = true;
    return res;
}

enum_result_t<handle_info_t> backend_ps4_t::enum_handles(uint32_t /*pid*/) {
    // Orbis has no Win32-style handle table exposed by ps4debug-NG
    enum_result_t<handle_info_t> res;
    res.ok = true;
    return res;
}

// ---------------------------------------------------------------------------
// thread context

io_result_t backend_ps4_t::get_thread_context(uint32_t tid, thread_context_t& ctx) {
    io_result_t r;
    if (m_impl->dbg_pid == 0) { r.error = 1; return r; }
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    ps4::debug_lwpid_packet_t pkt{};
    pkt.lwpid = tid;
    if (!c.send_cmd(ps4::CMD_DEBUG_GETREGS, &pkt, sizeof(pkt))) { r.error = 2; return r; }
    uint32_t st = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 3; return r; }
    ps4::reg64_t reg{};
    if (!c.recv_all(&reg, sizeof(reg))) { r.error = 4; return r; }
    ctx_from_reg64(ctx, reg);
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::set_thread_context(uint32_t tid, const thread_context_t& ctx) {
    io_result_t r;
    if (m_impl->dbg_pid == 0) { r.error = 1; return r; }
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    // read-modify-write so trapno/segments survive the roundtrip
    ps4::reg64_t reg{};
    {
        ps4::debug_lwpid_packet_t gp{};
        gp.lwpid = tid;
        if (c.send_cmd(ps4::CMD_DEBUG_GETREGS, &gp, sizeof(gp))) {
            uint32_t st = 0;
            if (c.recv_u32(st) && st == ps4::CMD_SUCCESS)
                c.recv_all(&reg, sizeof(reg));
        }
    }
    ps4::reg64_t out{};
    reg64_from_ctx(out, ctx);
    out.trapno = reg.trapno;
    out.fs = reg.fs; out.gs = reg.gs; out.err = reg.err;
    out.es = reg.es; out.ds = reg.ds;
    out.cs = reg.cs; out.ss = reg.ss;

    ps4::debug_setregs_packet_t pkt{};
    pkt.lwpid  = tid;
    pkt.length = sizeof(out);
    if (!c.send_cmd(ps4::CMD_DEBUG_SETREGS, &pkt, sizeof(pkt))) { r.error = 2; return r; }
    uint32_t ack = 0;
    if (!c.recv_u32(ack) || ack != ps4::CMD_SUCCESS) { r.error = 3; return r; }
    if (!c.send_all(&out, sizeof(out))) { r.error = 4; return r; }
    uint32_t term = 0;
    if (!c.recv_u32(term) || term != ps4::CMD_SUCCESS) { r.error = 5; return r; }
    r.ok = true;
    return r;
}

// ---------------------------------------------------------------------------
// live debug session (ps4debug-NG CMD_DEBUG_*)

bool backend_ps4_t::ps4_debug_attach(uint32_t pid, std::string& err) {
    uint32_t e = 0;
    if (!m_impl->ensure_debug(pid, e)) {
        switch (e) {
        case 1:  err = "not connected to a PS4 console"; break;
        case 2:  err = "cannot listen on port 755 for debug events "
                       "(the payload connects back there); is 755 free?"; break;
        case 5:  err = "console reports CMD_ALREADY_DEBUG: another client is "
                       "debugging this process"; break;
        case 6:  err = "payload refused CMD_DEBUG_ATTACH (process gone or not "
                       "debuggable)"; break;
        default: err = "CMD_DEBUG_ATTACH failed (code " + std::to_string(e) + ")"; break;
        }
        return false;
    }
    return true;
}

bool backend_ps4_t::ps4_debug_detach() {
    auto& c = *m_impl->conn;
    {
        std::lock_guard lk(c.mu);
        if (c.connected() && m_impl->dbg_pid != 0) {
            c.send_cmd(ps4::CMD_DEBUG_DETACH, nullptr, 0);
            uint32_t st = 0;
            c.recv_u32(st, kShortTimeoutMs);
            m_impl->dbg_pid = 0;
        }
    }
    m_impl->clear_events();
    return true;
}

bool backend_ps4_t::ps4_debug_attached() const noexcept {
    return m_impl->dbg_pid != 0;
}

uint32_t backend_ps4_t::ps4_debug_pid() const noexcept {
    return m_impl->dbg_pid;
}

io_result_t backend_ps4_t::ps4_set_breakpoint(uint32_t index, bool enabled, uintptr_t addr) {
    io_result_t r;
    if (index >= ps4::kMaxSwBreakpoints) { r.error = 1; return r; }
    if (m_impl->dbg_pid == 0) { r.error = 2; return r; }   // not attached
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    ps4::debug_set_breakpoint_packet_t pkt{};
    pkt.index   = index;
    pkt.enabled = enabled ? 1 : 0;
    pkt.address = addr;
    if (!c.send_cmd(ps4::CMD_DEBUG_SET_BREAKPOINT, &pkt, sizeof(pkt))) { r.error = 3; return r; }
    uint32_t st = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) {
        // some payload builds send the error status twice on the failure
        // paths; consume a possible duplicate so the stream stays in sync
        uint32_t dup = 0;
        c.recv_u32(dup, kShortTimeoutMs);
        r.error = 4;
        return r;
    }
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_set_watchpoint(uint32_t index, bool enabled, uint32_t len,
                                              uint32_t type, uintptr_t addr) {
    io_result_t r;
    if (index >= ps4::kMaxWatchpoints) { r.error = 1; return r; }
    if (len != 1 && len != 2 && len != 4 && len != 8) { r.error = 2; return r; }
    if (m_impl->dbg_pid == 0) { r.error = 3; return r; }
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    ps4::debug_set_watchpoint_packet_t pkt{};
    pkt.index     = index;
    pkt.enabled   = enabled ? 1 : 0;
    pkt.length    = len;
    pkt.breaktype = type;
    pkt.address   = addr;
    if (!c.send_cmd(ps4::CMD_DEBUG_SET_WATCHPOINT, &pkt, sizeof(pkt))) { r.error = 4; return r; }
    uint32_t st = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 5; return r; }
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_continue(uint32_t stop) {
    io_result_t r;
    if (m_impl->dbg_pid == 0) { r.error = 1; return r; }
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    ps4::debug_continue_packet_t pkt{};
    pkt.stop = stop;
    if (!c.send_cmd(ps4::CMD_DEBUG_CONTINUE, &pkt, sizeof(pkt))) { r.error = 2; return r; }
    uint32_t st = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 3; return r; }
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_step(uint32_t lwpid) {
    io_result_t r;
    if (m_impl->dbg_pid == 0) { r.error = 1; return r; }
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    if (lwpid == 0) {
        if (!c.send_cmd(ps4::CMD_DEBUG_STEP, nullptr, 0)) { r.error = 2; return r; }
    } else {
        ps4::debug_lwpid_packet_t pkt{};
        pkt.lwpid = lwpid;
        if (!c.send_cmd(ps4::CMD_DEBUG_STEP_THREAD, &pkt, sizeof(pkt))) { r.error = 2; return r; }
    }
    uint32_t st = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 3; return r; }
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_suspend_thread(uint32_t lwpid) {
    io_result_t r;
    if (m_impl->dbg_pid == 0) { r.error = 1; return r; }
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    ps4::debug_lwpid_packet_t pkt{};
    pkt.lwpid = lwpid;
    if (!c.send_cmd(ps4::CMD_DEBUG_SUSPEND, &pkt, sizeof(pkt))) { r.error = 2; return r; }
    uint32_t st = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 3; return r; }
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_resume_thread(uint32_t lwpid) {
    io_result_t r;
    if (m_impl->dbg_pid == 0) { r.error = 1; return r; }
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    ps4::debug_lwpid_packet_t pkt{};
    pkt.lwpid = lwpid;
    if (!c.send_cmd(ps4::CMD_DEBUG_RESUME, &pkt, sizeof(pkt))) { r.error = 2; return r; }
    uint32_t st = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 3; return r; }
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_process_stop(uint32_t pid, uint32_t state) {
    io_result_t r;
    if (state > ps4::kStopKill) { r.error = 1; return r; }
    auto& c = *m_impl->conn;
    if (!c.connected()) { r.error = 2; return r; }
    std::lock_guard lk(c.mu);
    ps4::debug_process_stop_packet_t pkt{};
    pkt.pid   = pid;
    pkt.state = static_cast<uint8_t>(state);
    if (!c.send_cmd(ps4::CMD_DEBUG_PROCESS_STOP, &pkt, sizeof(pkt))) { r.error = 3; return r; }
    uint32_t st = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 4; return r; }
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_get_dbregs(uint32_t lwpid, uint64_t dr[16]) {
    io_result_t r;
    if (m_impl->dbg_pid == 0) { r.error = 1; return r; }
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    ps4::debug_lwpid_packet_t pkt{};
    pkt.lwpid = lwpid;
    if (!c.send_cmd(ps4::CMD_DEBUG_GETDBREGS, &pkt, sizeof(pkt))) { r.error = 2; return r; }
    uint32_t st = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 3; return r; }
    if (!c.recv_all(dr, 128)) { r.error = 4; return r; }   // exactly 128 bytes
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_install(uint32_t pid, uint64_t& rpcstub) {
    io_result_t r;
    {
        std::lock_guard lk(m_impl->ev_mu);   // reuse as the rpcstub cache lock
        if (auto it = m_impl->rpcstubs.find(pid); it != m_impl->rpcstubs.end()) {
            rpcstub = it->second;
            r.ok = true;
            return r;
        }
    }
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    if (!c.connected()) { r.error = 1; return r; }
    ps4::proc_intall_packet_t pkt{};
    pkt.pid = pid;
    if (!c.send_cmd(ps4::CMD_PROC_INTALL, &pkt, sizeof(pkt))) { r.error = 2; return r; }
    uint32_t st = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 3; return r; }
    uint64_t stub = 0;
    if (!c.recv_all(&stub, sizeof(stub)) || stub == 0) { r.error = 4; return r; }
    rpcstub = stub;
    {
        std::lock_guard lk2(m_impl->ev_mu);
        m_impl->rpcstubs[pid] = stub;
    }
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_call(uint32_t pid, uint64_t rpcstub, uint64_t rip,
                                    const uint64_t args[6], uint64_t& out_rax) {
    io_result_t r;
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    if (!c.connected()) { r.error = 1; return r; }
    ps4::proc_call_packet_t pkt{};
    pkt.pid     = pid;
    pkt.rpcstub = rpcstub;
    pkt.rip     = rip;
    pkt.rdi = args[0]; pkt.rsi = args[1]; pkt.rdx = args[2];
    pkt.rcx = args[3]; pkt.r8  = args[4]; pkt.r9  = args[5];
    if (!c.send_cmd(ps4::CMD_PROC_CALL, &pkt, sizeof(pkt))) { r.error = 2; return r; }
    uint32_t st = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 3; return r; }
    ps4::proc_call_response_t resp{};
    if (!c.recv_all(&resp, sizeof(resp))) { r.error = 4; return r; }
    out_rax = resp.rax;
    r.ok = true;
    return r;
}

size_t backend_ps4_t::ps4_pending_events() {
    std::lock_guard lk(m_impl->ev_mu);
    return m_impl->evq.size();
}

bool backend_ps4_t::ps4_wait_event(ps4_event_t& out, int timeout_ms) {
    std::unique_lock lk(m_impl->ev_mu);
    if (m_impl->evq.empty())
        m_impl->ev_cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                               [this] { return !m_impl->evq.empty(); });
    if (m_impl->evq.empty()) return false;
    out = m_impl->evq.front();
    m_impl->evq.pop_front();
    return true;
}

std::vector<ps4_event_t> backend_ps4_t::ps4_drain_events(size_t max, bool clear) {
    std::lock_guard lk(m_impl->ev_mu);
    std::vector<ps4_event_t> out;
    out.reserve(std::min(max, m_impl->evq.size()));
    while (!m_impl->evq.empty() && out.size() < max) {
        out.push_back(std::move(m_impl->evq.front()));
        m_impl->evq.pop_front();
    }
    if (clear) m_impl->evq.clear();
    return out;
}

// ---------------------------------------------------------------------------
// query

arch_t backend_ps4_t::query_arch(const target_handle_t& /*h*/) {
    return arch_t::x64;
}

elevation_t backend_ps4_t::query_elevation() {
    return elevation_t::system;   // ps4debug-NG runs with kernel privileges
}

} // namespace slop::core::runtime
