// src/core/runtime/backend_ps4.cpp
// Remote PS4 backend over the ps4debug-NG wire protocol (TCP 744).
// Wire formats verified against the payload sources: every request is a
// 12-byte header {magic, cmd, datalen} followed by datalen body bytes, all
// little-endian; replies start with a u32 status unless noted.
//
// Failure model: every exchange runs under the connection mutex with a
// whole-command deadline on top of the per-chunk idle timeout. Any send/recv
// failure, timeout or malformed reply closes the socket (the stream can no
// longer be trusted), so connected() goes false and every later call fails
// fast instead of paying another timeout. reconnect() restores the session.

#include "core/runtime/backend_ps4.hpp"
#include "core/runtime/ps4_protocol.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include "core/infra/clock.hpp"
#include "core/infra/diag.hpp"
#include "core/infra/event_bus.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")

namespace slop::core::runtime {

namespace infra = slop::core::infra;

namespace {

constexpr int     kDefaultIoTimeoutMs   = 10000;   // idle time per chunk
constexpr int64_t kDefaultCmdBudgetMs   = 60000;   // whole normal command
constexpr int64_t kDefaultLongBudgetMs  = 600000;  // scans / analysis / elf upload
constexpr int     kShortTimeoutMs       = 500;     // optional trailing status words
constexpr int     kConnectTimeoutMs     = 5000;
constexpr uint32_t kMaxListEntries      = 1u << 20; // protocol sanity ceiling
constexpr int64_t kMapsCacheTtlMs       = 1500;
constexpr uint32_t kThreadInfoBatch     = 64;      // pipelined THREAD_INFO requests

struct wsa_init_t {
    wsa_init_t() { WSADATA d; WSAStartup(MAKEWORD(2, 2), &d); }
    ~wsa_init_t() { WSACleanup(); }
};
wsa_init_t& wsa() { static wsa_init_t w; return w; }

std::string hex32(uint32_t v) {
    char b[16];
    std::snprintf(b, sizeof(b), "0x%08X", v);
    return b;
}

// ---------------------------------------------------------------------------
// conn_t: one TCP connection to the ps4debug-NG command server

class conn_t {
public:
    std::atomic<SOCKET> fd{INVALID_SOCKET};
    std::mutex mu;   // serializes whole command exchanges

    // guarded by mu: the exchange in progress
    int64_t  deadline_ms   = 0;     // steady clock; 0 = none
    int      io_timeout_ms = kDefaultIoTimeoutMs;
    uint32_t last_err      = 0;     // ps4::io_err_t of the last failure
    std::atomic<uint32_t> last_status{0};  // last error status word seen (structured errors)

    // invoked under mu when an I/O failure invalidates the socket
    std::function<void(uint32_t code, const std::string& why)> on_lost;

    // transparent reopen after the payload dropped us (the payload closes a
    // client whenever a handler fails). on_reopen re-runs per-connection
    // setup (handshake/auth) and resets state the payload tore down; it runs
    // with mu held
    std::function<bool(conn_t&)> on_reopen;
    std::atomic<uint64_t> generation{0};   // bumped on every transparent reopen
    // set when an error status arrived: the payload usually closes the
    // socket right after sending it, so the next liveness check waits a
    // moment for that FIN instead of racing it
    bool suspect = false;

    // current endpoint for revive(); "" when never opened
    std::string host;
    uint16_t    port = 0;

    // bumped by every fresh connect(); handles remember the epoch they
    // were created in so a handle never reaches a different console
    std::atomic<uint64_t> epoch{0};

    bool connected() const noexcept {
        return fd.load(std::memory_order_acquire) != INVALID_SOCKET;
    }

    // true when the server hung up, the socket errored, or stray bytes are
    // queued (a previous exchange desynced, e.g. a snapshot that stopped
    // streaming mid-region); any of those means the stream is unusable
    bool peer_gone() {
        if (fd == INVALID_SOCKET) return false;
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(fd, &rset);
        timeval tv{};
        if (suspect) tv.tv_usec = 100 * 1000;
        suspect = false;
        if (select(0, &rset, nullptr, nullptr, &tv) <= 0) return false;
        char b;
        const int n = ::recv(fd, &b, 1, MSG_PEEK);
        (void)n;
        return true;   // closed (0), error (<0) or unexpected bytes (>0)
    }

    bool revive() {
        std::string err;
        const std::string h = host;
        const uint16_t p = port;
        if (!open(h, p, err)) return false;
        if (on_reopen && !on_reopen(*this)) { close(); return false; }
        generation.fetch_add(1);
        return true;
    }

    bool open(const std::string& h, uint16_t p, std::string& err) {
        wsa();
        close();

        addrinfo hints{};
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        addrinfo* list = nullptr;
        char port_str[8];
        std::snprintf(port_str, sizeof(port_str), "%u", static_cast<unsigned>(p));
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
            const int wsa_err = WSAGetLastError();
            closesocket(s);
            err = "connect to " + h + ":" + port_str + " failed (WSA " +
                  std::to_string(wsa_err) + ")";
            return false;
        }
        if (r == SOCKET_ERROR) {
            fd_set wset;
            FD_ZERO(&wset);
            FD_SET(s, &wset);
            fd_set eset;
            FD_ZERO(&eset);
            FD_SET(s, &eset);
            timeval tv{};
            tv.tv_sec  = kConnectTimeoutMs / 1000;
            tv.tv_usec = (kConnectTimeoutMs % 1000) * 1000;
            if (select(0, nullptr, &wset, &eset, &tv) <= 0) {
                closesocket(s);
                err = "connect to " + h + ":" + port_str + " timed out";
                return false;
            }
            int soerr = 0;
            int slen  = sizeof(soerr);
            getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &slen);
            if (soerr != 0 || FD_ISSET(s, &eset)) {
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
        fd.store(s, std::memory_order_release);
        host = h;
        port = p;
        return true;
    }

    // explicit close (no on_lost notification)
    void close() noexcept {
        SOCKET s = fd.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
        if (s != INVALID_SOCKET) {
            shutdown(s, SD_BOTH);
            closesocket(s);
        }
    }

    // the stream can no longer be trusted: drop the socket and tell the owner
    bool fail(uint32_t code, const std::string& why) {
        last_err = code;
        if (!connected()) return false;
        close();
        if (on_lost) on_lost(code, why);
        return false;
    }

    // milliseconds the next select may wait; -1 when the command deadline
    // already passed
    int wait_budget_ms() const {
        if (deadline_ms == 0) return io_timeout_ms;
        const int64_t left = deadline_ms - infra::steady_ms();
        if (left <= 0) return -1;
        return static_cast<int>(std::min<int64_t>(left, io_timeout_ms));
    }

    // wait for readability/writability; 1 ready, 0 timed out, -1 error
    static int wait_sock(SOCKET s, bool for_write, int ms) {
        fd_set set;
        FD_ZERO(&set);
        FD_SET(s, &set);
        timeval tv{};
        tv.tv_sec  = ms / 1000;
        tv.tv_usec = (ms % 1000) * 1000;
        const int sel = for_write ? select(0, nullptr, &set, nullptr, &tv)
                                  : select(0, &set, nullptr, nullptr, &tv);
        return sel < 0 ? -1 : (sel == 0 ? 0 : 1);
    }

    bool send_all(const void* buf, size_t len) {
        const SOCKET s = fd.load(std::memory_order_acquire);
        if (s == INVALID_SOCKET) { last_err = ps4::kErrNotConnected; return false; }
        const char* p = static_cast<const char*>(buf);
        size_t left = len;
        while (left > 0) {
            const int budget = wait_budget_ms();
            if (budget < 0) return fail(ps4::kErrTimeout, "command deadline exceeded while sending");
            const int w = wait_sock(s, true, budget);
            if (w == 0) return fail(ps4::kErrTimeout, "console stopped accepting data (send timeout)");
            if (w < 0) return fail(ps4::kErrSendFailed, "select failed while sending (WSA " +
                                                         std::to_string(WSAGetLastError()) + ")");
            const int n = ::send(s, p, static_cast<int>(left > 0x10000 ? 0x10000 : left), 0);
            if (n <= 0) return fail(ps4::kErrSendFailed, "send failed (WSA " +
                                                         std::to_string(WSAGetLastError()) + ")");
            p    += n;
            left -= static_cast<size_t>(n);
        }
        return true;
    }

    bool recv_all(void* buf, size_t len) {
        const SOCKET s = fd.load(std::memory_order_acquire);
        if (s == INVALID_SOCKET) { last_err = ps4::kErrNotConnected; return false; }
        char* p = static_cast<char*>(buf);
        size_t left = len;
        while (left > 0) {
            const int budget = wait_budget_ms();
            if (budget < 0) return fail(ps4::kErrTimeout, "command deadline exceeded while receiving");
            const int w = wait_sock(s, false, budget);
            if (w == 0) return fail(ps4::kErrTimeout, "console did not answer within " +
                                                      std::to_string(budget) + " ms");
            if (w < 0) return fail(ps4::kErrRecvFailed, "select failed while receiving (WSA " +
                                                        std::to_string(WSAGetLastError()) + ")");
            const int n = ::recv(s, p, static_cast<int>(left > 0x10000 ? 0x10000 : left), 0);
            if (n == 0) return fail(ps4::kErrRecvFailed, "console closed the connection");
            if (n < 0) return fail(ps4::kErrRecvFailed, "recv failed (WSA " +
                                                        std::to_string(WSAGetLastError()) + ")");
            p    += n;
            left -= static_cast<size_t>(n);
        }
        return true;
    }

    // timed variant for long-running streaming commands; the whole-command
    // budget still applies on top
    bool recv_all(void* buf, size_t len, int timeout_ms) {
        const int saved = io_timeout_ms;
        io_timeout_ms = timeout_ms > 0 ? timeout_ms : io_timeout_ms;
        const bool ok = recv_all(buf, len);
        io_timeout_ms = saved;
        return ok;
    }

    bool recv_u32(uint32_t& v) {
        if (!recv_all(&v, sizeof(v))) return false;
        // remember error status words so callers can explain a failure; the
        // set is narrow enough that counts/lengths never collide in practice
        if (ps4::status_name(v)[0] != '\0') {
            last_status = v;
            suspect = true;
        }
        return true;
    }

    // timed variant for long-running streaming commands (Turbo Scan passes);
    // the whole-command budget still applies on top
    bool recv_u32(uint32_t& v, int timeout_ms) {
        const int saved = io_timeout_ms;
        io_timeout_ms = timeout_ms > 0 ? timeout_ms : io_timeout_ms;
        const bool ok = recv_u32(v);
        io_timeout_ms = saved;
        return ok;
    }

    // an optional trailing word: none when nothing arrives within timeout_ms
    // (stream still in sync), failed when a partial word or error broke it
    enum class opt_t { got, none, failed };
    opt_t recv_u32_optional(uint32_t& v, int timeout_ms) {
        const SOCKET s = fd.load(std::memory_order_acquire);
        if (s == INVALID_SOCKET) { last_err = ps4::kErrNotConnected; return opt_t::failed; }
        const int w = wait_sock(s, false, timeout_ms);
        if (w == 0) return opt_t::none;
        if (w < 0) { fail(ps4::kErrRecvFailed, "select failed"); return opt_t::failed; }
        return recv_u32(v) ? opt_t::got : opt_t::failed;
    }

    // send one request header + body; the caller then drives the reply
    bool send_cmd(uint32_t cmd, const void* body, uint32_t bodylen) {
        if (bodylen > ps4::kMaxDatalen) return false;   // payload would desync us
        if (peer_gone() && !revive()) return false;
        ps4::packet_header_t hdr{};
        hdr.magic   = ps4::kPacketMagic;
        hdr.cmd     = cmd;
        hdr.datalen = bodylen;
        if (!send_all(&hdr, sizeof(hdr))) return false;
        if (bodylen > 0 && body) return send_all(body, bodylen);
        return true;
    }

    // our IPv4 as the sin_addr.s_addr numeric value, for CMD_DEBUG_ATTACH
    uint32_t local_ip_value() const {
        sockaddr_in sa{};
        int len = sizeof(sa);
        if (getsockname(fd.load(), reinterpret_cast<sockaddr*>(&sa), &len) != 0)
            return 0;
        uint32_t v;
        std::memcpy(&v, &sa.sin_addr, sizeof(v));
        return v;
    }
};

// holds the connection for one exchange and arms its overall deadline
class cmd_lock_t {
public:
    cmd_lock_t(conn_t& c, int64_t budget_ms) : c_(c), lk_(c.mu) {
        c_.deadline_ms = infra::steady_ms() + budget_ms;
        c_.last_err = 0;
    }
    ~cmd_lock_t() { c_.deadline_ms = 0; }
    cmd_lock_t(const cmd_lock_t&) = delete;
    cmd_lock_t& operator=(const cmd_lock_t&) = delete;

private:
    conn_t& c_;
    std::unique_lock<std::mutex> lk_;
};

// failed wire step -> io_result_t
io_result_t wire_fail(const conn_t& c) {
    io_result_t r;
    r.error = c.last_err ? c.last_err : ps4::kErrNotConnected;
    return r;
}

io_result_t err_result(uint32_t code) {
    io_result_t r;
    r.error = code;
    return r;
}

// read a status word. A non-success *status* is a clean error; a word that
// is not a status at all means the stream is misaligned, so drop the socket
bool expect_success(conn_t& c, io_result_t& r) {
    uint32_t st = 0;
    if (!c.recv_u32(st)) { r.error = c.last_err; return false; }
    if (st == ps4::CMD_SUCCESS) return true;
    r.error = ps4::status_to_err(st);
    if (r.error == ps4::kErrProtocol)
        c.fail(ps4::kErrProtocol, "expected a status word, got " + hex32(st) + " (stream desync)");
    return false;
}

// owner of a TCP listener on port, "pid N (name)" or ""
std::string tcp_port_owner(uint16_t port) {
    ULONG size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
    if (size == 0) return {};
    std::vector<uint8_t> buf(size);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_LISTENER, 0) != NO_ERROR)
        return {};
    const auto* t = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < t->dwNumEntries; ++i) {
        const auto& row = t->table[i];
        if (ntohs(static_cast<u_short>(row.dwLocalPort)) != port) continue;
        std::string who = "pid " + std::to_string(row.dwOwningPid);
        if (row.dwOwningPid == GetCurrentProcessId()) return who + " (this process)";
        if (HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, row.dwOwningPid)) {
            wchar_t path[MAX_PATH]{};
            DWORD n = MAX_PATH;
            if (QueryFullProcessImageNameW(h, 0, path, &n)) {
                char narrow[MAX_PATH * 3]{};
                WideCharToMultiByte(CP_UTF8, 0, path, -1, narrow, sizeof(narrow), nullptr, nullptr);
                std::string s = narrow;
                const size_t slash = s.find_last_of("\\/");
                who += " (" + (slash == std::string::npos ? s : s.substr(slash + 1)) + ")";
            }
            CloseHandle(h);
        }
        return who;
    }
    return {};
}

// ---------------------------------------------------------------------------
// event_listener_t: accepts the server->client debug-event connection on 755.
// CMD_DEBUG_ATTACH fails server-side unless it can connect back to us, so we
// listen and drain interrupt packets (0x4A0 bytes each) for the session life.

class event_listener_t {
public:
    ~event_listener_t() { stop(); }

    // set once before start() and never mutated afterwards. Both run on the
    // listener thread. on_closed gets the attach id that was in flight when
    // the connection was accepted
    std::function<void(const uint8_t* pkt)> on_packet;
    std::function<void(uint64_t attach_id)> on_closed;
    // attach id currently in flight (set by ensure_debug before ATTACH)
    std::atomic<uint64_t> current_attach{0};

    // Only the console we attached to may deliver stop events. Port 755 is
    // bound on every interface because the payload connects back to us, so
    // without this any LAN host could forge a stop (fake RIP/DR6) or send
    // SIGKILL. 0 = no filter yet (before the first attach).
    void set_peer(const std::string& host) {
        uint32_t addr = 0;
        addrinfo hints{};
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        if (::getaddrinfo(host.c_str(), nullptr, &hints, &res) == 0 && res) {
            addr = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr.s_addr;
            ::freeaddrinfo(res);
        }
        allow_peer_.store(addr);
    }

    // false + err on failure (port in use names the owner)
    bool start(uint16_t port, std::string& err) {
        // A stop() in flight closes the socket and joins the accept thread
        // without holding mu_ the whole time; starting in that window used to
        // return true for a listener that no longer accepts (the payload's
        // connect-back then sat in a dead backlog and the attach timed out).
        for (int i = 0; i < 200 && stopping_.load(std::memory_order_acquire); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::lock_guard lk(mu_);
        if (running_ && !stop_ && listen_fd_.load() != INVALID_SOCKET) {
            if (port == port_) return true;
            err = "debug-event listener already bound to port " + std::to_string(port_);
            return false;
        }
        wsa();
        // SO_REUSEADDR lets two sockets share a port on Windows, so refuse
        // up front when someone else is already listening there
        const std::string owner = tcp_port_owner(port);
        if (!owner.empty()) {
            err = "TCP port " + std::to_string(port) + " is already in use by " + owner +
                  "; the ps4debug-NG payload always connects back to port 755, so close "
                  "that program (or the other reverse-slop instance) and retry";
            return false;
        }
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) { err = "socket() failed for the debug-event listener"; return false; }
        int flag = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&flag), sizeof(flag));
        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = htons(port);
        if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
            listen(s, 4) != 0) {
            const int e = WSAGetLastError();
            closesocket(s);
            err = "cannot listen on TCP port " + std::to_string(port) + " (WSA " +
                  std::to_string(e) + ")";
            const std::string who = tcp_port_owner(port);
            if (!who.empty()) err += "; held by " + who;
            return false;
        }
        listen_fd_.store(s);
        port_    = port;
        running_ = true;
        stop_    = false;
        th_ = std::thread([this] { run(); });
        return true;
    }

    void stop() {
        stopping_.store(true, std::memory_order_release);
        {
            std::lock_guard lk(mu_);
            if (!running_) {
                stopping_.store(false, std::memory_order_release);
                return;
            }
            stop_ = true;
        }
        SOCKET s = listen_fd_.exchange(INVALID_SOCKET);
        if (s != INVALID_SOCKET) {
            shutdown(s, SD_BOTH);
            closesocket(s);
        }
        if (th_.joinable()) th_.join();
        std::vector<std::thread> conns;
        {
            std::lock_guard lk(mu_);
            conns.swap(conns_);
        }
        for (auto& t : conns)
            if (t.joinable()) t.join();
        std::lock_guard lk(mu_);
        running_ = false;
        stopping_.store(false, std::memory_order_release);
    }

    bool running() const {
        std::lock_guard lk(mu_);
        return running_;
    }

private:
    // Drain one event connection. Runs on its own thread so a silent peer can
    // no longer block accept() and starve the console's connect-back.
    void drain(SOCKET c, uint64_t attach_id) {
        ps4_event_reassembler_t ra(ps4::kDebugEventSize);
        // short recv timeout so stop_ is noticed even with no traffic
        DWORD rt = 500;
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&rt), sizeof(rt));
        uint8_t buf[0x8000];
        bool peer_closed = false;
        while (!stop_) {
            const int n = ::recv(c, reinterpret_cast<char*>(buf), sizeof(buf), 0);
            if (n == 0) { peer_closed = true; break; }   // server closed the channel
            if (n < 0) {
                // the recv timeout exists only to notice stop_; keep the
                // connection open so later events from the payload arrive
                if (WSAGetLastError() == WSAETIMEDOUT) continue;
                peer_closed = true;
                break;
            }
            ra.feed(buf, static_cast<size_t>(n), [this](const uint8_t* pkt) {
                if (on_packet) on_packet(pkt);
            });
        }
        closesocket(c);
        if (peer_closed && on_closed) on_closed(attach_id);
    }

    void run() {
        while (!stop_) {
            const SOCKET ls = listen_fd_.load();
            if (ls == INVALID_SOCKET) break;
            fd_set rset;
            FD_ZERO(&rset);
            FD_SET(ls, &rset);
            timeval tv{};
            tv.tv_sec  = 0;
            tv.tv_usec = 200 * 1000;
            if (select(0, &rset, nullptr, nullptr, &tv) <= 0) continue;
            sockaddr_in peer{};
            int peer_len = static_cast<int>(sizeof(peer));
            SOCKET c = accept(ls, reinterpret_cast<sockaddr*>(&peer), &peer_len);
            if (c == INVALID_SOCKET) continue;
            const uint32_t want = allow_peer_.load();
            if (want != 0 && peer.sin_addr.s_addr != want) {
                closesocket(c);   // not the console this session is attached to
                continue;
            }
            const uint64_t attach_id = current_attach.load();
            std::lock_guard lk(mu_);
            if (conns_.size() >= 4) { closesocket(c); continue; }
            conns_.emplace_back([this, c, attach_id] { drain(c, attach_id); });
        }
    }

    mutable std::mutex mu_;
    std::atomic<SOCKET> listen_fd_{INVALID_SOCKET};
    std::atomic<uint32_t> allow_peer_{0};
    std::atomic<bool>     stopping_{false};   // stop() in flight
    std::vector<std::thread> conns_;   // guarded by mu_
    uint16_t port_ = 0;
    std::thread th_;
    std::atomic<bool> stop_{false};
    std::atomic<bool> running_{false};
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

uint32_t handle_pid(const target_handle_t& h) {
    return h.pid;
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

ps4_segment_t segment_from_entry(const ps4::vm_map_entry_t& m) {
    ps4_segment_t s;
    s.start  = m.start;
    s.end    = m.end;
    s.offset = m.offset;
    s.prot   = m.prot;
    s.name   = fixed_str(m.name, sizeof(m.name));
    return s;
}

struct attach_state_t {
    uint32_t pid = 0;
    uint64_t epoch = 0;
    std::shared_ptr<conn_t> conn;
    std::string name;
    std::string path;
};

} // namespace

// ---------------------------------------------------------------------------
// public helpers

bool ps4_decode_event(const uint8_t* pkt, size_t n, ps4_event_t& e) {
    if (!pkt || n < ps4::kDebugEventSize) return false;
    ps4::debug_event_packet_t ep{};
    std::memcpy(&ep, pkt, sizeof(ep));
    e = ps4_event_t{};
    e.lwpid  = ep.lwpid;
    e.status = ep.status;
    e.signal = static_cast<int>((ep.status >> 8) & 0xFF);
    std::memcpy(e.thread_name, ep.tdname, sizeof(ep.tdname));
    e.thread_name[sizeof(ep.tdname)] = '\0';
    ctx_from_reg64(e.ctx, ep.regs);
    std::memcpy(e.dr, ep.dbregs, sizeof(e.dr));
    return true;
}

ps4_event_reassembler_t::ps4_event_reassembler_t(size_t packet_size)
    : packet_size_(packet_size ? packet_size : 1) {
    buf_.reserve(packet_size_ * 2);
}

size_t ps4_event_reassembler_t::feed(const uint8_t* data, size_t n,
                                     const std::function<void(const uint8_t*)>& on_packet) {
    size_t delivered = 0;
    size_t off = 0;
    // fast path: whole packets straight from the input when nothing is pending
    if (buf_.empty()) {
        while (n - off >= packet_size_) {
            if (on_packet) on_packet(data + off);
            off += packet_size_;
            ++delivered;
        }
        if (off < n) buf_.assign(data + off, data + n);
        return delivered;
    }
    buf_.insert(buf_.end(), data, data + n);
    size_t pos = 0;
    while (buf_.size() - pos >= packet_size_) {
        if (on_packet) on_packet(buf_.data() + pos);
        pos += packet_size_;
        ++delivered;
    }
    if (pos > 0) buf_.erase(buf_.begin(), buf_.begin() + static_cast<ptrdiff_t>(pos));
    return delivered;
}

std::vector<ps4_module_t> ps4_coalesce_modules(std::vector<ps4_segment_t> maps) {
    std::sort(maps.begin(), maps.end(),
              [](const ps4_segment_t& a, const ps4_segment_t& b) { return a.start < b.start; });
    std::vector<ps4_module_t> out;
    bool open = false;
    for (auto& m : maps) {
        if (m.name.empty()) continue;   // anonymous mapping: neither joins nor breaks
        if (open && out.back().path == m.name && m.start >= out.back().end) {
            out.back().end = std::max(out.back().end, m.end);
            out.back().segments.push_back(m);
            continue;
        }
        ps4_module_t mod;
        mod.path = m.name;
        mod.name = base_name(m.name);
        mod.base = m.start;
        mod.end  = m.end;
        mod.segments.push_back(m);
        out.push_back(std::move(mod));
        open = true;
    }
    return out;
}

std::vector<process_info_t> ps4_parse_proc_list(const uint8_t* data, size_t len) {
    std::vector<process_info_t> out;
    if (!data) return out;
    const size_t count = len / sizeof(ps4::proc_list_entry_t);
    out.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        ps4::proc_list_entry_t e{};
        std::memcpy(&e, data + i * sizeof(e), sizeof(e));
        process_info_t p;
        p.pid       = static_cast<uint32_t>(e.pid);
        p.name      = fixed_str(e.p_comm, sizeof(e.p_comm));
        p.arch      = arch_t::x64;   // Orbis userland is x86-64
        p.elevation = elevation_t::system;
        out.push_back(std::move(p));
    }
    return out;
}

namespace ps4 {

std::string io_error_str(uint32_t code) {
    switch (code) {
    case kErrNone:          return "ok";
    case kErrNotConnected:  return "not connected to a PS4 console (target.ps4_connect, or "
                                   "target.ps4_reconnect after a dropped connection)";
    case kErrSendFailed:    return "send to the console failed; the connection was dropped "
                                   "(target.ps4_reconnect restores it)";
    case kErrRecvFailed:    return "the console closed the connection or a receive failed; "
                                   "the connection was dropped (target.ps4_reconnect restores it)";
    case kErrTimeout:       return "the console did not answer in time (idle or whole-command "
                                   "deadline); the connection was dropped to keep the stream in "
                                   "sync (target.ps4_reconnect restores it)";
    case kErrStatus:        return "the payload rejected the command (CMD_ERROR): bad pid/address, "
                                   "process gone, or the operation is not allowed";
    case kErrProtocol:      return "malformed reply from the payload (stream desync); the "
                                   "connection was dropped";
    case kErrBadArg:        return "invalid argument (rejected before anything was sent)";
    case kErrUnmapped:      return "address range is not mapped (or lacks the needed protection) "
                                   "in the target process";
    case kErrNotAttached:   return "no ps4 debug session (debugger.ps4_attach first)";
    case kErrAlreadyDebug:  return "the payload is already debugging a process on this "
                                   "connection (CMD_ALREADY_DEBUG)";
    case kErrDataNull:      return "the payload reported CMD_DATA_NULL (missing data, or the "
                                   "scan family is locked: run debugger.ps4_auth)";
    case kErrTooMuchData:   return "the payload reported CMD_TOO_MUCH_DATA (request too large)";
    case kErrNoSlot:        return "no free slot (30 software breakpoints / 4 hardware "
                                   "watchpoints); clear one first";
    case kErrNotArmed:      return "that slot/address is not armed by this client";
    case kErrStaleHandle:   return "the target handle belongs to an earlier console connection; "
                                   "attach again";
    case kErrAsm:           return "the on-device assembler reported an error";
    case kErrListen:        return "cannot listen on the debug-event port 755 (the payload "
                                   "connects back there); is another program using it?";
    case kErrDetachFailed:  return "the payload refused to detach the previous debuggee; it is "
                                   "still being debugged";
    case kErrTooMany:       return "result larger than the client cap";
    case kErrSlotBusy:      return "that slot is being armed/cleared by another request";
    default: break;
    }
    if (code < 0xE0000000u) {
        char* msg = nullptr;
        const DWORD n = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                       FORMAT_MESSAGE_IGNORE_INSERTS,
                                       nullptr, code, 0, reinterpret_cast<LPSTR>(&msg), 0, nullptr);
        std::string text = "Win32 error " + std::to_string(code);
        if (n && msg) {
            std::string m(msg, n);
            while (!m.empty() && (m.back() == '\n' || m.back() == '\r' || m.back() == ' '))
                m.pop_back();
            text += ": " + m;
        }
        if (msg) LocalFree(msg);
        return text;
    }
    return "error " + hex32(code);
}

} // namespace ps4

// ---------------------------------------------------------------------------
// backend impl

struct backend_ps4_t::impl_t {
    impl_t() {
        conn->on_lost = [this](uint32_t code, const std::string& why) { on_conn_lost(code, why); };
        listener.on_packet = [this](const uint8_t* pkt) { push_event(pkt); };
        listener.on_closed = [this](uint64_t id) { on_event_channel_closed(id); };
        // transparent reopen after the payload dropped us (see conn_t). The
        // payload's free_client tore down this client's debug session and
        // Turbo Scan session, so forget them; auth is global on the payload
        // but is re-run when it had succeeded before (an old payload without
        // AUTH would drop us again)
        conn->on_reopen = [this](conn_t& c) {
            if (authed) {
                std::string e;
                bool ok = authed.load();
                const bool resumed = auth_locked(c, ok, 0x3, e);
                authed = ok;
                if (!resumed) return false;
            }
            dbg_pid = 0;
            invalidate_maps_cache();
            std::lock_guard lk(ev_mu);
            evq.clear();
            return true;
        };
    }

    // tuning
    int     io_timeout_ms = kDefaultIoTimeoutMs;
    int64_t cmd_budget_ms = kDefaultCmdBudgetMs;
    int64_t long_budget_ms = kDefaultLongBudgetMs;
    uint16_t event_port = ps4::kDebugPort;

    std::shared_ptr<conn_t> conn = std::make_shared<conn_t>();

    // handshake facts + endpoint bookkeeping
    mutable std::mutex info_mu;
    std::string host;            // current endpoint ("" when not connected)
    uint16_t    port = 0;
    std::string last_host;       // remembered for reconnect
    uint16_t    last_port = 0;
    std::string branding, version;
    uint16_t    fw = 0, platform = 0;
    bool        lost = false;
    std::string lost_reason;
    uint32_t    lost_dbg_pid = 0;    // debuggee the dropped connection had
    std::atomic<uint64_t> drops{0};
    std::atomic<bool> authed{false};

    // debug session. dbg_mu orders dbg_pid transitions against the
    // listener's channel-closed notification
    std::mutex dbg_mu;
    std::atomic<uint32_t> dbg_pid{0};
    std::atomic<bool>     dbg_held{false};   // a stop event is holding the debuggee
    uint64_t attach_counter = 0;     // ids handed to ATTACH attempts (dbg_mu)
    uint64_t live_attach = 0;        // id of the attach that is live (dbg_mu)
    event_listener_t listener;

    // debug event queue, fed by the port-755 listener thread
    std::mutex ev_mu;
    std::condition_variable ev_cv;
    std::deque<ps4_event_t> evq;
    std::atomic<uint64_t> ev_received{0};
    std::atomic<uint64_t> ev_dropped{0};

    // rpc stub per pid (CMD_PROC_INTALL result) so ps4_call doesn't reinstall
    std::mutex stub_mu;
    std::map<uint32_t, uint64_t> rpcstubs;

    // breakpoint / watchpoint slot records
    struct slot_rec_t {
        enum state_t : uint8_t { free_, reserved, armed };
        state_t  st = free_;
        uint64_t addr = 0;
        uint32_t len = 0, type = 0;
    };
    mutable std::mutex slot_mu;
    std::array<slot_rec_t, ps4::kMaxSwBreakpoints> bps{};
    std::array<slot_rec_t, ps4::kMaxWatchpoints>   wps{};
    bool     slots_stale = false;    // connection dropped, awaiting reconnect
    uint64_t slot_gen = 0;           // bumped whenever the records are wiped

    // live attach states (a handle from another backend, or one already
    // detached, is never dereferenced) and handles per pid, so dropping one
    // stale session never ends the debug session another handle relies on
    mutable std::mutex attach_mu;
    std::set<const void*> live_states;
    std::map<uint32_t, int> attach_refs;

    // NetVar1337 fork extensions (CMD_PROC_MODULES/SNAPSHOT): -1 unknown,
    // 0 absent (upstream payload), 1 present. Learned from the first
    // CMD_PROC_MODULES reply; reset on connect
    int fork_ext = -1;

    bool is_live(const void* p) const {
        std::lock_guard lk(attach_mu);
        return p && live_states.count(p) != 0;
    }

    // maps cache so read-coverage checks don't hammer the console
    std::mutex cache_mu;
    uint32_t cache_pid = 0;
    int64_t  cache_at = 0;
    std::vector<ps4::vm_map_entry_t> cache;

    // ---- connection loss ----------------------------------------------
    // runs under conn->mu (from conn_t::fail)
    void on_conn_lost(uint32_t code, const std::string& why) {
        uint32_t had = 0;
        {
            std::lock_guard lk(dbg_mu);
            had = dbg_pid.exchange(0);
        }
        {
            std::lock_guard lk(info_mu);
            lost = true;
            lost_reason = why;
            if (had) lost_dbg_pid = had;
        }
        authed = false;
        {
            std::lock_guard lk(slot_mu);
            slots_stale = true;   // payload dropped them with the connection
        }
        drops.fetch_add(1);
        invalidate_maps_cache();
        infra::diag::warn("ps4", "console connection lost (" + ps4::io_error_str(code) +
                                 "): " + why);
    }

    void clear_lost() {
        std::lock_guard lk(info_mu);
        lost = false;
        lost_reason.clear();
        lost_dbg_pid = 0;
    }

    // ---- slots --------------------------------------------------------
    void wipe_slots_locked() {
        for (auto& s : bps) s = slot_rec_t{};
        for (auto& s : wps) s = slot_rec_t{};
        slots_stale = false;
        ++slot_gen;
    }
    void wipe_slots() {
        std::lock_guard lk(slot_mu);
        wipe_slots_locked();
    }

    // the debug session is over (detach, SIGKILL, channel closed): drop
    // every per-session record. Caller holds dbg_mu.
    // keep_slots: the console connection died with the session — the
    // records still describe what was armed and are re-armed after a
    // reconnect, so they are only marked stale instead of wiped.
    void end_debug_session_locked(const std::string& why, bool keep_slots = false) {
        dbg_held.store(false);
        if (keep_slots) {
            std::lock_guard lk(slot_mu);
            slots_stale = true;
        } else {
            wipe_slots();
        }
        // last: "detached" must never be observable with the old slots still listed
        const uint32_t was_pid = dbg_pid.exchange(0);
        if (was_pid != 0) {
            if (!why.empty()) infra::diag::info("ps4", "debug session ended: " + why);
            infra::event_bus::publish("debugger.state",
                nlohmann::json{{"attached", false}, {"pid", 0}, {"held", false},
                               {"reason", why}});
        }
    }

    // ---- events -------------------------------------------------------
    void push_event(const uint8_t* pkt) {
        ps4_event_t e{};
        if (!ps4_decode_event(pkt, ps4::kDebugEventSize, e)) return;
        ev_received.fetch_add(1);
        const bool killed = e.signal == 9;   // SIGKILL tears the session down
        // a stop event freezes the debuggee until continue; publish that before
        // the event is visible, or a waiter that takes it could still read
        // "running" and skip the resume its next composite needs
        dbg_held.store(!killed);
        {
            std::lock_guard lk(ev_mu);
            if (evq.size() >= kMaxQueuedEvents) {   // drop oldest, count it
                evq.pop_front();
                ev_dropped.fetch_add(1);
            }
            evq.push_back(std::move(e));
        }
        ev_cv.notify_all();
        // push the stop to the UI/agents over /events; polling ps4_wait stays
        // available for callers that need the stop synchronously
        infra::event_bus::publish("debugger.stop",
            nlohmann::json{{"lwpid", e.lwpid}, {"signal", e.signal}, {"status", e.status},
                           {"thread", std::string(e.thread_name)},
                           {"rip", e.ctx.rip}, {"rsp", e.ctx.rsp}, {"rbp", e.ctx.rbp},
                           {"rax", e.ctx.rax}, {"rbx", e.ctx.rbx},
                           {"rcx", e.ctx.rcx}, {"rdx", e.ctx.rdx},
                           {"rsi", e.ctx.rsi}, {"rdi", e.ctx.rdi},
                           {"r8", e.ctx.r8}, {"r9", e.ctx.r9},
                           {"r10", e.ctx.r10}, {"r11", e.ctx.r11},
                           {"r12", e.ctx.r12}, {"r13", e.ctx.r13},
                           {"r14", e.ctx.r14}, {"r15", e.ctx.r15},
                           {"flags", e.ctx.flags}});
        if (killed) {
            std::lock_guard lk(dbg_mu);
            end_debug_session_locked("debuggee received SIGKILL");
        }
    }

    void on_event_channel_closed(uint64_t attach_id) {
        // only the channel of the live attach means "session gone"; failed
        // attach attempts and earlier sessions close their channels too
        const auto live = [&] {
            return attach_id != 0 && attach_id == live_attach && dbg_pid.load() != 0;
        };
        {
            std::lock_guard lk(dbg_mu);
            if (!live()) return;
        }
        // Probe the command socket under the command lock and without dbg_mu
        // (commands take conn->mu, then dbg_mu). Unlocked, the probe raced a
        // command's reply read and then blocked in recv while holding dbg_mu,
        // deadlocking that command (the slop_tests_ps4 watchdog hang).
        bool cmd_gone = false;
        {
            std::lock_guard cl(conn->mu);
            cmd_gone = conn->peer_gone();
        }
        std::lock_guard lk(dbg_mu);
        if (live())
            end_debug_session_locked("the payload closed the debug-event channel",
                                     /*keep_slots=*/cmd_gone);
    }

    void clear_events() {
        std::lock_guard lk(ev_mu);
        evq.clear();
    }

    // ---- maps ---------------------------------------------------------
    // fetch fresh maps for pid (caller does NOT hold conn->mu)
    bool fetch_maps(uint32_t pid, std::vector<ps4::vm_map_entry_t>& out, uint32_t& err) {
        auto& c = *conn;
        cmd_lock_t lk(c, cmd_budget_ms);
        if (!c.connected()) { err = ps4::kErrNotConnected; return false; }
        ps4::proc_maps_packet_t pkt{};
        pkt.pid = pid;
        if (!c.send_cmd(ps4::CMD_PROC_MAPS, &pkt, sizeof(pkt))) { err = c.last_err; return false; }
        io_result_t r;
        if (!expect_success(c, r)) { err = r.error; return false; }
        uint32_t num = 0;
        if (!c.recv_u32(num)) { err = c.last_err; return false; }
        if (num > kMaxListEntries) {
            c.fail(ps4::kErrProtocol, "maps reply claims " + std::to_string(num) + " entries");
            err = ps4::kErrProtocol;
            return false;
        }
        out.resize(num);
        if (num > 0 && !c.recv_all(out.data(), num * sizeof(ps4::vm_map_entry_t))) {
            err = c.last_err;
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

    // is [addr, addr+len) fully covered by maps with prot_bit? adjacent maps count
    static bool covered_by(const std::vector<ps4::vm_map_entry_t>& maps,
                           uint64_t addr, uint64_t len, uint16_t prot_bit) {
        if (len == 0) return true;
        const uint64_t end = addr + len;
        uint64_t cur = addr;
        int guard = 0;
        while (cur < end && guard++ < 1 << 20) {
            const ps4::vm_map_entry_t* hit = nullptr;
            for (const auto& m : maps) {
                if (m.start <= cur && cur < m.end) { hit = &m; break; }
            }
            if (!hit || (hit->prot & prot_bit) == 0) return false;
            cur = hit->end;
        }
        return cur >= end;
    }

    static const ps4::vm_map_entry_t* find_map(const std::vector<ps4::vm_map_entry_t>& maps,
                                               uint64_t addr) {
        for (const auto& m : maps)
            if (m.start <= addr && addr < m.end) return &m;
        return nullptr;
    }

    // ---- handshake (caller holds the command lock) --------------------
    bool handshake_locked(conn_t& c, std::string& err) {
        // version + branding + fw + platform tag, then a NOP probe.
        // version/branding reply with u32 len + bytes (no status word), fw and
        // platform reply with a bare u16, NOP replies with a u32 status
        std::string ver, brand;
        uint16_t fwv = 0, tag = 0;
        uint32_t len = 0;
        if (!c.send_cmd(ps4::CMD_VERSION, nullptr, 0) || !c.recv_u32(len) ||
            len == 0 || len > 64) goto bad;
        ver.assign(len, '\0');
        if (!c.recv_all(ver.data(), len)) goto bad;
        if (!c.send_cmd(ps4::CMD_BRANDING, nullptr, 0) || !c.recv_u32(len) ||
            len == 0 || len > 256) goto bad;
        brand.assign(len, '\0');
        if (!c.recv_all(brand.data(), len)) goto bad;   // "brand\0caps"
        if (!c.send_cmd(ps4::CMD_FW_VERSION, nullptr, 0) || !c.recv_all(&fwv, sizeof(fwv))) goto bad;
        if (!c.send_cmd(ps4::CMD_PLATFORM_ID, nullptr, 0) || !c.recv_all(&tag, sizeof(tag)) ||
            tag != 4) goto bad;   // 4 = PS4
        {
            uint32_t st = 0;
            if (!c.send_cmd(ps4::CMD_PROC_NOP, nullptr, 0) || !c.recv_u32(st) ||
                st != ps4::CMD_SUCCESS) goto bad;
        }
        {
            std::lock_guard lk(info_mu);
            version  = ver;
            branding = brand;
            fw       = fwv;
            platform = tag;
        }
        {
            // unlock the scan family; failure is not fatal (older payloads lack AUTH)
            std::string aerr;
            bool ok = false;
            auth_locked(c, ok, 0x3, aerr);
            authed = ok;
        }
        return c.connected();
    bad:
        err = "handshake failed (not a ps4debug-NG server?)";
        return false;
    }

    // payload-side auth keystream: four LFSRs seeded 200/300/400/500, response
    // is challenge XOR low byte of (s1^s2^s3^s4) per step (proc.c auth_lfsr_next)
    static uint8_t auth_lfsr_next(uint32_t& s1, uint32_t& s2, uint32_t& s3, uint32_t& s4) {
        s1 = ((s1 << 18) & 0xFFF80000u) ^ ((s1 ^ (s1 << 6))  >> 13);
        s2 = ((s2 <<  2) & 0xFFFFFFE0u) ^ ((s2 ^ (s2 << 2))  >> 27);
        s3 = ((s3 <<  7) & 0xFFFFF800u) ^ ((s3 ^ (s3 << 13)) >> 21);
        s4 = ((s4 << 13) & 0xFFF00000u) ^ ((s4 ^ (s4 << 3))  >> 12);
        return static_cast<uint8_t>(s1 ^ s2 ^ s3 ^ s4);
    }

    // caller holds the command lock
    static bool auth_locked(conn_t& c, bool& ok_out, uint32_t flags, std::string& err) {
        ok_out = false;
        ps4::proc_auth_packet_t pkt{};
        pkt.magic = ps4::CMD_PROC_AUTH_MAGIC;
        pkt.flags = flags;
        if (!c.send_cmd(ps4::CMD_PROC_AUTH, &pkt, sizeof(pkt))) {
            err = "auth send failed"; return false;
        }
        io_result_t r;
        if (!expect_success(c, r)) {
            err = "auth rejected (" + ps4::io_error_str(r.error) + ")"; return false;
        }
        uint16_t chlen = 0;
        if (!c.recv_all(&chlen, sizeof(chlen))) { err = "auth challenge truncated"; return false; }
        if (chlen == 0 || chlen > 4096) {
            c.fail(ps4::kErrProtocol, "auth challenge length " + std::to_string(chlen));
            err = "auth challenge malformed";
            return false;
        }
        std::vector<uint8_t> challenge(chlen), response(chlen);
        if (!c.recv_all(challenge.data(), chlen)) { err = "auth challenge short"; return false; }
        uint32_t s1 = 200, s2 = 300, s3 = 400, s4 = 500;
        for (uint16_t i = 0; i < chlen; ++i)
            response[i] = challenge[i] ^ auth_lfsr_next(s1, s2, s3, s4);
        if (!c.send_all(response.data(), response.size())) { err = "auth response send failed"; return false; }
        uint32_t st = 0;
        if (!c.recv_u32(st)) { err = "auth reply truncated"; return false; }
        if (st != ps4::CMD_SUCCESS) { err = "auth challenge mismatch"; return false; }
        ok_out = true;
        return true;
    }

    // ---- debug attach -------------------------------------------------
    // lazy debug attach; ps4debug-NG allows one debuggee per connection.
    // keep_slots: reconnect path, the records are re-armed afterwards
    uint32_t ensure_debug(uint32_t pid, std::string& detail, bool keep_slots = false) {
        auto& c = *conn;
        cmd_lock_t lk(c, cmd_budget_ms);
        if (!c.connected()) { detail = "not connected to a PS4 console"; return ps4::kErrNotConnected; }
        const uint32_t cur = dbg_pid.load();
        if (cur == pid) return 0;
        if (cur != 0) {
            // detach the previous debuggee and check the reply: if the payload
            // still debugs it, ATTACH would only say CMD_ALREADY_DEBUG
            if (!c.send_cmd(ps4::CMD_DEBUG_DETACH, nullptr, 0)) {
                detail = "detach of pid " + std::to_string(cur) + " failed: " +
                         ps4::io_error_str(c.last_err);
                return c.last_err;
            }
            uint32_t st = 0;
            if (!c.recv_u32(st)) {
                detail = "no reply to the detach of pid " + std::to_string(cur);
                return c.last_err;
            }
            if (st != ps4::CMD_SUCCESS) {
                if (ps4::status_to_err(st) == ps4::kErrProtocol)
                    c.fail(ps4::kErrProtocol, "detach reply " + hex32(st));
                detail = "the payload refused to detach pid " + std::to_string(cur) +
                         " (status " + hex32(st) + "); it is still being debugged, so pid " +
                         std::to_string(pid) + " cannot be attached";
                return ps4::kErrDetachFailed;
            }
            std::lock_guard dl(dbg_mu);
            end_debug_session_locked("");
        }
        // the payload connects back to us on 755 or attach fails; pin the
        // listener to this console so another LAN host cannot forge events
        {
            std::lock_guard il(info_mu);
            if (!host.empty()) listener.set_peer(host);
        }
        std::string lerr;
        if (!listener.start(event_port, lerr)) {
            detail = lerr;
            return ps4::kErrListen;
        }
        uint64_t id = 0;
        {
            std::lock_guard dl(dbg_mu);
            id = ++attach_counter;
        }
        listener.current_attach.store(id);
        ps4::debug_attach_packet_t pkt{};
        pkt.pid       = pid;
        pkt.client_ip = c.local_ip_value();
        if (!c.send_cmd(ps4::CMD_DEBUG_ATTACH, &pkt, sizeof(pkt)) ) {
            detail = "CMD_DEBUG_ATTACH send failed: " + ps4::io_error_str(c.last_err);
            return c.last_err;
        }
        uint32_t status = 0;
        if (!c.recv_u32(status)) {
            detail = "no reply to CMD_DEBUG_ATTACH: " + ps4::io_error_str(c.last_err);
            return c.last_err;
        }
        if (status != ps4::CMD_SUCCESS) {
            const uint32_t e = ps4::status_to_err(status);
            if (e == ps4::kErrProtocol) c.fail(e, "attach reply " + hex32(status));
            if (e == ps4::kErrAlreadyDebug)
                detail = "the payload reports CMD_ALREADY_DEBUG: this connection already has "
                         "a debuggee server-side (client thought: " +
                         (cur ? "pid " + std::to_string(cur) : std::string("none")) + ")";
            else
                detail = "the payload refused CMD_DEBUG_ATTACH for pid " + std::to_string(pid) +
                         " (process gone, not debuggable, or the payload could not connect "
                         "back to port " + std::to_string(event_port) + ")";
            return e;
        }
        {
            std::lock_guard dl(dbg_mu);
            live_attach = id;
            dbg_pid = pid;
            // ptrace-style attach leaves the debuggee stopped until the first
            // CMD_DEBUG_CONTINUE (unlike the local Win32 attach, which runs)
            dbg_held.store(true);
            if (!keep_slots) wipe_slots();
            infra::event_bus::publish("debugger.state",
                nlohmann::json{{"attached", true}, {"pid", pid}, {"held", true}});
        }
        clear_events();   // fresh debug session: drop stale events
        return 0;
    }

    // ---- slot helpers -------------------------------------------------
    io_result_t wire_set_bp(uint32_t index, bool enabled, uint64_t addr) {
        if (index >= ps4::kMaxSwBreakpoints) return err_result(ps4::kErrBadArg);
        if (dbg_pid.load() == 0) return err_result(ps4::kErrNotAttached);
        auto& c = *conn;
        cmd_lock_t lk(c, cmd_budget_ms);
        if (!c.connected()) return err_result(ps4::kErrNotConnected);
        ps4::debug_set_breakpoint_packet_t pkt{};
        pkt.index   = index;
        pkt.enabled = enabled ? 1 : 0;
        pkt.address = addr;
        if (!c.send_cmd(ps4::CMD_DEBUG_SET_BREAKPOINT, &pkt, sizeof(pkt))) return wire_fail(c);
        io_result_t r;
        uint32_t st = 0;
        if (!c.recv_u32(st)) return wire_fail(c);
        if (st == ps4::CMD_SUCCESS) { r.ok = true; return r; }
        r.error = ps4::status_to_err(st);
        if (r.error == ps4::kErrProtocol) {
            c.fail(r.error, "breakpoint reply " + hex32(st));
            return r;
        }
        // some payload builds send the error status twice on the failure
        // paths. Consume a duplicate; anything else means the stream is
        // misaligned and gets the connection reset
        uint32_t dup = 0;
        if (c.recv_u32_optional(dup, kShortTimeoutMs) == conn_t::opt_t::got && dup != st) {
            infra::diag::warn("ps4", "unexpected word " + hex32(dup) +
                                     " after a breakpoint error status " + hex32(st));
            c.fail(ps4::kErrProtocol, "unexpected trailing word after breakpoint error");
        }
        return r;
    }

    io_result_t wire_set_wp(uint32_t index, bool enabled, uint32_t len, uint32_t type,
                            uint64_t addr) {
        if (index >= ps4::kMaxWatchpoints) return err_result(ps4::kErrBadArg);
        if (len != 1 && len != 2 && len != 4 && len != 8) return err_result(ps4::kErrBadArg);
        if (dbg_pid.load() == 0) return err_result(ps4::kErrNotAttached);
        auto& c = *conn;
        cmd_lock_t lk(c, cmd_budget_ms);
        if (!c.connected()) return err_result(ps4::kErrNotConnected);
        ps4::debug_set_watchpoint_packet_t pkt{};
        pkt.index     = index;
        pkt.enabled   = enabled ? 1 : 0;
        pkt.length    = len;
        pkt.breaktype = type;
        pkt.address   = addr;
        if (!c.send_cmd(ps4::CMD_DEBUG_SET_WATCHPOINT, &pkt, sizeof(pkt))) return wire_fail(c);
        io_result_t r;
        if (!expect_success(c, r)) return r;
        r.ok = true;
        return r;
    }

    template <size_t N>
    io_result_t arm(std::array<slot_rec_t, N>& tab, bool bp, uint64_t addr, uint32_t len,
                    uint32_t type, uint32_t index, uint32_t& out_index, bool* reused) {
        if (reused) *reused = false;
        if (dbg_pid.load() == 0) return err_result(ps4::kErrNotAttached);
        uint32_t idx = 0;
        slot_rec_t prev{};
        uint64_t gen = 0;
        {
            std::lock_guard lk(slot_mu);
            if (index == backend_ps4_t::kAutoSlot) {
                bool found = false;
                for (uint32_t i = 0; i < N; ++i)
                    if (tab[i].st == slot_rec_t::armed && tab[i].addr == addr) {
                        idx = i; found = true;
                        if (reused) *reused = true;
                        break;
                    }
                if (!found) {
                    for (uint32_t i = 0; i < N; ++i)
                        if (tab[i].st == slot_rec_t::free_) { idx = i; found = true; break; }
                }
                if (!found) return err_result(ps4::kErrNoSlot);
            } else {
                if (index >= N) return err_result(ps4::kErrBadArg);
                if (tab[index].st == slot_rec_t::reserved) return err_result(ps4::kErrSlotBusy);
                idx = index;
                if (reused) *reused = tab[idx].st == slot_rec_t::armed && tab[idx].addr == addr;
            }
            if (tab[idx].st == slot_rec_t::reserved) return err_result(ps4::kErrSlotBusy);
            prev = tab[idx];
            tab[idx].st = slot_rec_t::reserved;
            gen = slot_gen;
        }
        // the wire call runs without the slot lock
        io_result_t io = bp ? wire_set_bp(idx, true, addr) : wire_set_wp(idx, true, len, type, addr);
        {
            std::lock_guard lk(slot_mu);
            if (gen == slot_gen) {
                if (io.ok) {
                    tab[idx].st = slot_rec_t::armed;
                    tab[idx].addr = addr;
                    tab[idx].len = len;
                    tab[idx].type = type;
                } else {
                    tab[idx] = prev;
                }
            }
        }
        out_index = idx;
        return io;
    }

    template <size_t N>
    io_result_t disarm(std::array<slot_rec_t, N>& tab, bool bp, uint32_t index, uint64_t* out_addr) {
        slot_rec_t prev{};
        uint64_t gen = 0;
        {
            std::lock_guard lk(slot_mu);
            if (index >= N) return err_result(ps4::kErrBadArg);
            if (tab[index].st == slot_rec_t::reserved) return err_result(ps4::kErrSlotBusy);
            if (tab[index].st != slot_rec_t::armed) return err_result(ps4::kErrNotArmed);
            prev = tab[index];
            tab[index].st = slot_rec_t::reserved;
            gen = slot_gen;
        }
        if (out_addr) *out_addr = prev.addr;
        io_result_t io = bp ? wire_set_bp(index, false, prev.addr)
                            : wire_set_wp(index, false, prev.len ? prev.len : 8,
                                          prev.type, prev.addr);
        std::lock_guard lk(slot_mu);
        if (gen == slot_gen) tab[index] = io.ok ? slot_rec_t{} : prev;
        return io;
    }

    template <size_t N>
    bool find_armed(const std::array<slot_rec_t, N>& tab, uint64_t addr, uint32_t& idx) const {
        std::lock_guard lk(slot_mu);
        for (uint32_t i = 0; i < N; ++i)
            if (tab[i].st == slot_rec_t::armed && tab[i].addr == addr) { idx = i; return true; }
        return false;
    }

    template <size_t N>
    std::vector<backend_ps4_t::ps4_slot_t> list_slots(const std::array<slot_rec_t, N>& tab) const {
        std::lock_guard lk(slot_mu);
        std::vector<backend_ps4_t::ps4_slot_t> out;
        for (uint32_t i = 0; i < N; ++i) {
            if (tab[i].st != slot_rec_t::armed) continue;
            backend_ps4_t::ps4_slot_t s;
            s.index = i;
            s.addr  = tab[i].addr;
            s.len   = tab[i].len;
            s.type  = tab[i].type;
            s.armed = !slots_stale;
            out.push_back(s);
        }
        return out;
    }

    // attach_state of a handle, null when stale/foreign
    attach_state_t* state_of(const target_handle_t& h, uint32_t& err) const {
        if (!is_live(h.native)) { err = ps4::kErrBadArg; return nullptr; }
        auto* st = static_cast<attach_state_t*>(h.native);
        if (st->conn != conn) { err = ps4::kErrBadArg; return nullptr; }
        if (st->epoch != conn->epoch.load()) { err = ps4::kErrStaleHandle; return nullptr; }
        if (!conn->connected()) { err = ps4::kErrNotConnected; return nullptr; }
        return st;
    }

    // full logical disconnect: every per-connection record goes
    void reset_session_state() {
        {
            std::lock_guard dl(dbg_mu);
            dbg_pid = 0;
            live_attach = 0;
        }
        wipe_slots();
        clear_events();
        {
            std::lock_guard lk(stub_mu);
            rpcstubs.clear();
        }
        invalidate_maps_cache();
        authed = false;
    }
};

// ---------------------------------------------------------------------------
// connection management

backend_ps4_t::backend_ps4_t() : m_impl(std::make_unique<impl_t>()) {}
backend_ps4_t::~backend_ps4_t() { disconnect(); }

void backend_ps4_t::set_timeouts(int io_timeout_ms, int64_t command_budget_ms,
                                 int64_t long_command_budget_ms) {
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    m_impl->io_timeout_ms  = io_timeout_ms > 0 ? io_timeout_ms : kDefaultIoTimeoutMs;
    m_impl->cmd_budget_ms  = command_budget_ms > 0 ? command_budget_ms : kDefaultCmdBudgetMs;
    m_impl->long_budget_ms = long_command_budget_ms > 0 ? long_command_budget_ms
                                                        : kDefaultLongBudgetMs;
    c.io_timeout_ms = m_impl->io_timeout_ms;
}

void backend_ps4_t::set_event_port(uint16_t port) {
    m_impl->event_port = port ? port : ps4::kDebugPort;
}

bool backend_ps4_t::connect(const std::string& host, uint16_t port, std::string& err) {
    auto& c = *m_impl->conn;
    {
        std::lock_guard lk(m_impl->info_mu);
        if (c.connected() && m_impl->host == host && m_impl->port == port) return true;
    }
    disconnect();   // a different console (or a dropped one): start clean
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.open(host, port, err)) return false;
    m_impl->fork_ext = -1;
    c.last_status = 0;
    if (!m_impl->handshake_locked(c, err)) {
        err = "handshake with " + host + ":" + std::to_string(port) +
              " failed (not a ps4debug-NG server?)";
        c.close();
        return false;
    }
    c.epoch.fetch_add(1);
    {
        std::lock_guard il(m_impl->info_mu);
        m_impl->host = host;
        m_impl->port = port;
        m_impl->last_host = host;
        m_impl->last_port = port;
    }
    m_impl->clear_lost();
    return true;
}

void backend_ps4_t::disconnect() {
    auto& c = *m_impl->conn;
    {
        cmd_lock_t lk(c, m_impl->cmd_budget_ms);
        if (c.connected() && m_impl->dbg_pid.load() != 0) {
            if (c.send_cmd(ps4::CMD_DEBUG_DETACH, nullptr, 0)) {
                uint32_t st = 0;
                c.recv_u32_optional(st, kShortTimeoutMs);
            }
        }
        c.close();
    }
    m_impl->listener.stop();
    m_impl->reset_session_state();
    {
        std::lock_guard lk(m_impl->info_mu);
        m_impl->host.clear();
        m_impl->port = 0;
        m_impl->branding.clear();
        m_impl->version.clear();
        m_impl->fw = 0;
        m_impl->platform = 0;
    }
    m_impl->clear_lost();
}

bool backend_ps4_t::connected() const noexcept {
    return m_impl->conn->connected();
}

bool backend_ps4_t::lost() const noexcept {
    std::lock_guard lk(m_impl->info_mu);
    return m_impl->lost;
}

std::string backend_ps4_t::lost_reason() const {
    std::lock_guard lk(m_impl->info_mu);
    return m_impl->lost_reason;
}

uint64_t backend_ps4_t::drop_count() const noexcept {
    return m_impl->drops.load();
}

std::string backend_ps4_t::last_endpoint() const {
    std::lock_guard lk(m_impl->info_mu);
    if (m_impl->last_host.empty()) return {};
    return m_impl->last_host + ":" + std::to_string(m_impl->last_port);
}

bool backend_ps4_t::reconnect(std::string& err, reconnect_report_t* report) {
    reconnect_report_t rep;
    std::string host;
    uint16_t port = 0;
    uint32_t want_dbg = 0;
    {
        std::lock_guard lk(m_impl->info_mu);
        host = m_impl->last_host;
        port = m_impl->last_port;
        want_dbg = m_impl->lost ? m_impl->lost_dbg_pid : 0;
    }
    if (host.empty()) {
        err = "no previous console endpoint to reconnect to (use target.ps4_connect)";
        return false;
    }
    if (want_dbg == 0) want_dbg = m_impl->dbg_pid.load();
    auto& c = *m_impl->conn;
    {
        cmd_lock_t lk(c, m_impl->cmd_budget_ms);
        c.close();   // a forced reconnect drops a live socket too
        {
            std::lock_guard dl(m_impl->dbg_mu);
            m_impl->dbg_pid = 0;      // the payload drops debug state per connection
        }
        {
            std::lock_guard sl(m_impl->slot_mu);
            m_impl->slots_stale = true;
        }
        if (!c.open(host, port, err)) return false;
        if (!m_impl->handshake_locked(c, err)) {
            err = "handshake with " + host + ":" + std::to_string(port) + " failed";
            c.close();
            return false;
        }
    }
    {
        std::lock_guard il(m_impl->info_mu);
        m_impl->host = host;
        m_impl->port = port;
    }
    m_impl->clear_lost();
    m_impl->invalidate_maps_cache();
    rep.authed = m_impl->authed.load();
    rep.debug_pid = want_dbg;

    if (want_dbg != 0) {
        // the old connection's debug context may still be tearing down on the
        // console; give it a few short tries
        std::string detail;
        uint32_t e = 0;
        for (int attempt = 0; attempt < 3; ++attempt) {
            e = m_impl->ensure_debug(want_dbg, detail, /*keep_slots=*/true);
            if (e == 0 || !connected()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
        }
        rep.debug_restored = e == 0;
        if (e != 0) rep.debug_error = detail.empty() ? ps4::io_error_str(e) : detail;
    }

    // re-arm every slot this client had armed
    std::vector<std::pair<uint32_t, impl_t::slot_rec_t>> bps, wps;
    {
        std::lock_guard sl(m_impl->slot_mu);
        for (uint32_t i = 0; i < m_impl->bps.size(); ++i)
            if (m_impl->bps[i].st == impl_t::slot_rec_t::armed) bps.emplace_back(i, m_impl->bps[i]);
        for (uint32_t i = 0; i < m_impl->wps.size(); ++i)
            if (m_impl->wps[i].st == impl_t::slot_rec_t::armed) wps.emplace_back(i, m_impl->wps[i]);
    }
    if (rep.debug_restored) {
        for (const auto& [i, rec] : bps) {
            if (m_impl->wire_set_bp(i, true, rec.addr).ok) { ++rep.bp_rearmed; continue; }
            ++rep.bp_failed;
            std::lock_guard sl(m_impl->slot_mu);
            m_impl->bps[i] = impl_t::slot_rec_t{};
        }
        for (const auto& [i, rec] : wps) {
            if (m_impl->wire_set_wp(i, true, rec.len, rec.type, rec.addr).ok) { ++rep.wp_rearmed; continue; }
            ++rep.wp_failed;
            std::lock_guard sl(m_impl->slot_mu);
            m_impl->wps[i] = impl_t::slot_rec_t{};
        }
        std::lock_guard sl(m_impl->slot_mu);
        m_impl->slots_stale = false;
    } else {
        // nothing to re-arm into: the records no longer describe anything
        rep.bp_failed = static_cast<uint32_t>(bps.size());
        rep.wp_failed = static_cast<uint32_t>(wps.size());
        m_impl->wipe_slots();
    }
    if (report) *report = rep;
    return connected();
}

bool backend_ps4_t::ping() {
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return false;
    if (!c.send_cmd(ps4::CMD_PROC_NOP, nullptr, 0)) return false;
    io_result_t r;
    return expect_success(c, r);
}

std::string backend_ps4_t::endpoint() const {
    if (!connected()) return {};
    std::lock_guard lk(m_impl->info_mu);
    if (m_impl->host.empty()) return {};
    return m_impl->host + ":" + std::to_string(m_impl->port);
}

std::string backend_ps4_t::branding() const {
    std::lock_guard lk(m_impl->info_mu);
    std::string b = m_impl->branding;
    const size_t nul = b.find('\0');
    if (nul != std::string::npos) b.resize(nul);
    return b;
}

std::string backend_ps4_t::server_caps() const {
    std::lock_guard lk(m_impl->info_mu);
    const std::string& b = m_impl->branding;
    const size_t nul = b.find('\0');
    if (nul == std::string::npos) return {};
    std::string caps = b.substr(nul + 1);
    while (!caps.empty() && caps.back() == '\0') caps.pop_back();
    return caps;
}

std::string backend_ps4_t::server_version() const {
    std::lock_guard lk(m_impl->info_mu);
    std::string v = m_impl->version;
    const size_t nul = v.find('\0');
    if (nul != std::string::npos) v.resize(nul);
    return v;
}

uint16_t backend_ps4_t::fw_version() const noexcept {
    std::lock_guard lk(m_impl->info_mu);
    return m_impl->fw;
}

std::string backend_ps4_t::fw_string() const {
    const uint16_t fw = fw_version();
    // the payload reports major*100+minor (fw.c: cached = major * 100 + minor),
    // so 1400 is 14.00 and 505 is 5.05. 0xFFFF is the payload's "unknown" sentinel.
    if (fw == 0 || fw == 0xFFFFu) return {};
    char b[16];
    std::snprintf(b, sizeof(b), "%u.%02u", static_cast<unsigned>(fw / 100u),
                  static_cast<unsigned>(fw % 100u));
    return b;
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

    // validate the pid and pull name/path via CMD_PROC_INFO; fall back to the
    // process list when info is unavailable
    std::string name, path;
    {
        cmd_lock_t lk(c, m_impl->cmd_budget_ms);
        if (!c.connected()) return t;
        ps4::proc_info_packet_t pkt{};
        pkt.pid = pid;
        if (!c.send_cmd(ps4::CMD_PROC_INFO, &pkt, sizeof(pkt))) return t;
        io_result_t r;
        if (expect_success(c, r)) {
            ps4::proc_info_response_t resp{};
            if (!c.recv_all(&resp, sizeof(resp))) return t;
            name = fixed_str(resp.name, sizeof(resp.name));
            path = fixed_str(resp.path, sizeof(resp.path));
        } else if (!c.connected()) {
            return t;
        }
        if (name.empty()) {
            if (!c.send_cmd(ps4::CMD_PROC_LIST, nullptr, 0)) return t;
            if (!expect_success(c, r)) return t;
            uint32_t num = 0;
            if (!c.recv_u32(num)) return t;
            if (num > kMaxListEntries) {
                c.fail(ps4::kErrProtocol, "process list claims " + std::to_string(num) + " entries");
                return t;
            }
            // one recv for the whole list, then look for the pid
            std::vector<ps4::proc_list_entry_t> ents(num);
            if (num && !c.recv_all(ents.data(), num * sizeof(ps4::proc_list_entry_t))) return t;
            bool found = false;
            for (const auto& e : ents) {
                if (static_cast<uint32_t>(e.pid) == pid) {
                    name  = fixed_str(e.p_comm, sizeof(e.p_comm));
                    found = true;
                    break;
                }
            }
            if (!found) return t;
        }
    }

    auto* st = new attach_state_t{};
    st->pid   = pid;
    st->epoch = c.epoch.load();
    st->conn  = m_impl->conn;
    st->name  = name;
    st->path  = path;
    {
        std::lock_guard lk(m_impl->attach_mu);
        m_impl->live_states.insert(st);
        ++m_impl->attach_refs[pid];
    }
    t.native = st;
    t.pid    = pid;
    return t;
}

void backend_ps4_t::detach(target_handle_t& h) {
    if (m_impl->is_live(h.native)) {
        auto* st = static_cast<attach_state_t*>(h.native);
        bool last = false;
        {
            std::lock_guard lk(m_impl->attach_mu);
            m_impl->live_states.erase(st);
            auto it = m_impl->attach_refs.find(st->pid);
            if (it != m_impl->attach_refs.end() && --it->second <= 0) {
                m_impl->attach_refs.erase(it);
                last = true;
            }
        }
        // the last handle of the debuggee ends its debug session, but only
        // when it belongs to the current connection
        if (last && st->epoch == m_impl->conn->epoch.load() &&
            m_impl->dbg_pid.load() == st->pid)
            ps4_debug_detach();
        delete st;
    }
    h = {};
}

bool backend_ps4_t::handle_info(const target_handle_t& h, process_info_t& out) {
    if (!m_impl->is_live(h.native)) return false;
    const auto* st = static_cast<const attach_state_t*>(h.native);
    out = process_info_t{};
    out.pid       = st->pid;
    out.name      = st->name;
    out.path      = st->path;
    out.arch      = arch_t::x64;          // Orbis userland is x86-64
    out.elevation = elevation_t::system;
    return true;
}

// ---------------------------------------------------------------------------
// memory

io_result_t backend_ps4_t::read_memory(const target_handle_t& h, uintptr_t addr,
                                       void* buf, size_t len) {
    if (len == 0) { io_result_t r; r.ok = true; return r; }
    if (len > ps4::kMaxIoLen) return err_result(ps4::kErrBadArg);
    uint32_t herr = 0;
    auto* st = m_impl->state_of(h, herr);
    if (!st) return err_result(herr);

    // ps4debug zero-fills unreadable chunks and still reports success, so
    // check coverage against the vm map first to keep the reader contract
    // honest (false = any part unreadable). A maps failure is not fatal.
    std::vector<ps4::vm_map_entry_t> maps;
    uint32_t merr = 0;
    if (m_impl->maps_cached(st->pid, maps, merr) &&
        !impl_t::covered_by(maps, addr, len, ps4::kVmProtRead))
        return err_result(ps4::kErrUnmapped);

    auto& c = *st->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    ps4::proc_read_packet_t pkt{};
    pkt.pid     = st->pid;
    pkt.address = addr;
    pkt.length  = static_cast<uint32_t>(len);
    if (!c.send_cmd(ps4::CMD_PROC_READ, &pkt, sizeof(pkt))) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    // the server then streams exactly `length` bytes (64 KiB chunks)
    if (!c.recv_all(buf, len)) return wire_fail(c);
    r.ok    = true;
    r.bytes = len;
    return r;
}

io_result_t backend_ps4_t::write_memory(const target_handle_t& h, uintptr_t addr,
                                        const void* buf, size_t len) {
    if (len == 0) { io_result_t r; r.ok = true; return r; }
    if (len > ps4::kMaxIoLen) return err_result(ps4::kErrBadArg);
    uint32_t herr = 0;
    auto* st = m_impl->state_of(h, herr);
    if (!st) return err_result(herr);

    auto& c = *st->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    ps4::proc_write_packet_t pkt{};
    pkt.pid     = st->pid;
    pkt.address = addr;
    pkt.length  = static_cast<uint32_t>(len);
    if (!c.send_cmd(ps4::CMD_PROC_WRITE, &pkt, sizeof(pkt))) return wire_fail(c);
    // two-phase: server acks, we stream the bytes, server sends terminal status
    io_result_t r;
    if (!expect_success(c, r)) return r;
    if (!c.send_all(buf, len)) return wire_fail(c);
    if (!expect_success(c, r)) return r;   // server readback verification
    r.ok    = true;
    r.bytes = len;
    return r;
}

io_result_t backend_ps4_t::protect_memory(const target_handle_t& h, uintptr_t addr,
                                          size_t len, uint32_t new_prot, uint32_t* old_prot) {
    uint32_t herr = 0;
    auto* st = m_impl->state_of(h, herr);
    if (!st) return err_result(herr);
    if (len == 0 || len > 0xFFFFFFFFull) return err_result(ps4::kErrBadArg);
    if (old_prot) {
        std::vector<ps4::vm_map_entry_t> maps;
        uint32_t merr = 0;
        if (m_impl->maps_cached(st->pid, maps, merr)) {
            if (auto* m = impl_t::find_map(maps, addr))
                *old_prot = vm_to_win_prot(m->prot);
        }
    }

    auto& c = *st->conn;
    io_result_t r;
    {
        cmd_lock_t lk(c, m_impl->cmd_budget_ms);
        if (!c.connected()) return err_result(ps4::kErrNotConnected);
        ps4::proc_protect_packet_t pkt{};
        pkt.pid     = st->pid;
        pkt.address = addr;
        pkt.length  = static_cast<uint32_t>(len);
        pkt.newprot = win_to_vm_prot(new_prot);
        if (!c.send_cmd(ps4::CMD_PROC_PROTECT, &pkt, sizeof(pkt))) return wire_fail(c);
        if (!expect_success(c, r)) return r;
        // payload quirk: proc_protect_handle also sends CMD_DATA_NULL after the
        // success status; consume it so the stream stays in sync. Any other
        // word means the stream is misaligned
        uint32_t extra = 0;
        const auto o = c.recv_u32_optional(extra, kShortTimeoutMs);
        if (o == conn_t::opt_t::failed) return wire_fail(c);
        if (o == conn_t::opt_t::got && extra != ps4::CMD_DATA_NULL &&
            extra != ps4::CMD_SUCCESS) {
            infra::diag::warn("ps4", "unexpected word " + hex32(extra) + " after protect");
            c.fail(ps4::kErrProtocol, "unexpected trailing word after protect");
            return wire_fail(c);
        }
    }
    r.ok = true;
    m_impl->invalidate_maps_cache();
    return r;
}

io_result_t backend_ps4_t::allocate_memory(const target_handle_t& h, uintptr_t addr,
                                           size_t len, uint32_t prot, uintptr_t* out_addr) {
    if (len == 0 || len > ps4::kMaxIoLen) return err_result(ps4::kErrBadArg);
    uint32_t herr = 0;
    auto* st = m_impl->state_of(h, herr);
    if (!st) return err_result(herr);

    auto& c = *st->conn;
    io_result_t r;
    {
        cmd_lock_t lk(c, m_impl->cmd_budget_ms);
        if (!c.connected()) return err_result(ps4::kErrNotConnected);
        if (addr != 0) {
            ps4::proc_alloc_hinted_packet_t pkt{};
            pkt.pid    = st->pid;
            pkt.hint   = addr;
            pkt.length = static_cast<uint32_t>(len);
            if (!c.send_cmd(ps4::CMD_PROC_ALLOC_HINTED, &pkt, sizeof(pkt))) return wire_fail(c);
        } else {
            ps4::proc_alloc_packet_t pkt{};
            pkt.pid    = st->pid;
            pkt.length = static_cast<uint32_t>(len);
            if (!c.send_cmd(ps4::CMD_PROC_ALLOC, &pkt, sizeof(pkt))) return wire_fail(c);
        }
        if (!expect_success(c, r)) return r;
        ps4::proc_alloc_response_t resp{};
        if (!c.recv_all(&resp, sizeof(resp))) return wire_fail(c);
        if (resp.address == 0) return err_result(ps4::kErrStatus);
        const uint64_t out = resp.address;

        if (out_addr) *out_addr = static_cast<uintptr_t>(out);
        r.ok    = true;
        r.bytes = len;
        // ps4debug allocates RW; tighten to the requested protection when given
        if (prot != 0) {
            ps4::proc_protect_packet_t pp{};
            pp.pid     = st->pid;
            pp.address = out;
            pp.length  = static_cast<uint32_t>(len);
            pp.newprot = win_to_vm_prot(prot);
            if (c.send_cmd(ps4::CMD_PROC_PROTECT, &pp, sizeof(pp))) {
                io_result_t pr;
                if (expect_success(c, pr)) {
                    uint32_t extra = 0;
                    const auto o = c.recv_u32_optional(extra, kShortTimeoutMs);
                    if (o == conn_t::opt_t::got && extra != ps4::CMD_DATA_NULL &&
                        extra != ps4::CMD_SUCCESS)
                        c.fail(ps4::kErrProtocol, "unexpected trailing word after protect");
                }
            }
        }
    }
    m_impl->invalidate_maps_cache();
    return r;
}

io_result_t backend_ps4_t::free_memory(const target_handle_t& h, uintptr_t addr) {
    uint32_t herr = 0;
    auto* st = m_impl->state_of(h, herr);
    if (!st) return err_result(herr);

    std::vector<ps4::vm_map_entry_t> maps;
    uint32_t merr = 0;
    if (!m_impl->maps_cached(st->pid, maps, merr)) return err_result(merr);
    auto* m = impl_t::find_map(maps, addr);
    if (!m) return err_result(ps4::kErrUnmapped);

    auto& c = *st->conn;
    io_result_t r;
    {
        cmd_lock_t lk(c, m_impl->cmd_budget_ms);
        if (!c.connected()) return err_result(ps4::kErrNotConnected);
        ps4::proc_free_packet_t pkt{};
        pkt.pid     = st->pid;
        pkt.address = m->start;
        pkt.length  = static_cast<uint32_t>(m->end - m->start);
        if (!c.send_cmd(ps4::CMD_PROC_FREE, &pkt, sizeof(pkt))) return wire_fail(c);
        if (!expect_success(c, r)) return r;
    }
    r.ok = true;
    m_impl->invalidate_maps_cache();
    return r;
}

// ---------------------------------------------------------------------------
// enumeration

enum_result_t<process_info_t> backend_ps4_t::enum_processes() {
    enum_result_t<process_info_t> res;
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) { res.error = ps4::kErrNotConnected; return res; }
    if (!c.send_cmd(ps4::CMD_PROC_LIST, nullptr, 0)) { res.error = c.last_err; return res; }
    io_result_t r;
    if (!expect_success(c, r)) { res.error = r.error; return res; }
    uint32_t num = 0;
    if (!c.recv_u32(num)) { res.error = c.last_err; return res; }
    if (num > kMaxListEntries) {
        c.fail(ps4::kErrProtocol, "process list claims " + std::to_string(num) + " entries");
        res.error = ps4::kErrProtocol;
        return res;
    }
    // the whole list in one receive, not one select+recv per 36-byte entry
    std::vector<ps4::proc_list_entry_t> ents(num);
    if (num && !c.recv_all(ents.data(), num * sizeof(ps4::proc_list_entry_t))) {
        res.error = c.last_err;
        return res;
    }
    res.items = ps4_parse_proc_list(reinterpret_cast<const uint8_t*>(ents.data()),
                                    ents.size() * sizeof(ps4::proc_list_entry_t));
    res.ok = true;
    return res;
}

enum_result_t<ps4_segment_t> backend_ps4_t::ps4_maps(const target_handle_t& h) {
    enum_result_t<ps4_segment_t> res;
    uint32_t herr = 0;
    auto* st = m_impl->state_of(h, herr);
    if (!st) { res.error = herr; return res; }
    std::vector<ps4::vm_map_entry_t> maps;
    uint32_t err = 0;
    if (!m_impl->fetch_maps(st->pid, maps, err)) { res.error = err; return res; }
    res.items.reserve(maps.size());
    for (const auto& m : maps) res.items.push_back(segment_from_entry(m));
    res.ok = true;
    return res;
}

enum_result_t<ps4_module_t> backend_ps4_t::ps4_modules(const target_handle_t& h) {
    enum_result_t<ps4_module_t> res;
    auto maps = ps4_maps(h);
    if (!maps.ok) { res.error = maps.error; return res; }
    res.items = ps4_coalesce_modules(std::move(maps.items));
    res.ok = true;
    return res;
}

enum_result_t<module_info_t> backend_ps4_t::enum_modules(const target_handle_t& h) {
    enum_result_t<module_info_t> res;
    // the fork's CMD_PROC_MODULES groups maps server-side. Probing it on an
    // unknown payload costs a reconnect on upstream (unknown command -> drop),
    // which would also kill a live debug session, so only probe when idle
    const int ext = m_impl->fork_ext;
    if (ext == 1 || (ext == -1 && m_impl->dbg_pid == 0)) {
        std::vector<module_info_t> mods;
        if (ps4_modules(handle_pid(h), mods).ok) {
            res.items = std::move(mods);
            res.ok = true;
            return res;
        }
        if (m_impl->fork_ext == 1) {
            // supported but failed (bad pid etc.): report, don't mask it
            res.error = 2;
            return res;
        }
    }
    // upstream fallback: group the vm map by backing name, base = lowest
    // start, size = span, like the fork does
    std::vector<ps4::vm_map_entry_t> maps;
    uint32_t err = 0;
    if (!m_impl->fetch_maps(handle_pid(h), maps, err)) { res.error = err ? err : 1; return res; }
    for (const auto& m : maps) {
        const std::string name = fixed_str(m.name, sizeof(m.name));
        if (name.empty()) continue;
        auto it = std::find_if(res.items.begin(), res.items.end(),
                               [&](const module_info_t& x) { return x.path == name; });
        if (it == res.items.end()) {
            module_info_t mi;
            mi.base = static_cast<uintptr_t>(m.start);
            mi.size = static_cast<uint32_t>(m.end - m.start);
            mi.name = base_name(name);
            mi.path = name;
            res.items.push_back(std::move(mi));
            continue;
        }
        const uint64_t lo  = std::min<uint64_t>(it->base, m.start);
        const uint64_t hi  = std::max<uint64_t>(it->base + it->size, m.end);
        it->base = static_cast<uintptr_t>(lo);
        it->size = static_cast<uint32_t>(std::min<uint64_t>(hi - lo, 0xFFFFFFFFull));
    }
    res.ok = true;
    return res;
}

enum_result_t<thread_info_t> backend_ps4_t::enum_threads(uint32_t pid) {
    enum_result_t<thread_info_t> res;
    std::string detail;
    if (const uint32_t e = m_impl->ensure_debug(pid, detail)) { res.error = e; return res; }
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) { res.error = ps4::kErrNotConnected; return res; }
    if (!c.send_cmd(ps4::CMD_DEBUG_GET_THREAD_LIST, nullptr, 0)) { res.error = c.last_err; return res; }
    io_result_t r;
    if (!expect_success(c, r)) { res.error = r.error; return res; }
    uint32_t num = 0;
    if (!c.recv_u32(num)) { res.error = c.last_err; return res; }
    if (num > kMaxListEntries) {
        c.fail(ps4::kErrProtocol, "thread list claims " + std::to_string(num) + " entries");
        res.error = ps4::kErrProtocol;
        return res;
    }
    // the server sends the whole lwpid array in one go; read it all before
    // issuing any follow-up command or the stream desyncs
    std::vector<uint32_t> lwpids(num);
    if (num && !c.recv_all(lwpids.data(), num * sizeof(uint32_t))) { res.error = c.last_err; return res; }
    res.items.reserve(num);
    for (uint32_t lwpid : lwpids) {
        thread_info_t t;
        t.tid       = lwpid;
        t.owner_pid = pid;
        res.items.push_back(t);
    }
    // enrich with priority/name via CMD_DEBUG_THREAD_INFO: requests go out
    // in pipelined batches (one roundtrip per batch, small enough that the
    // replies never fill the socket buffers while we are still sending)
    for (size_t at = 0; at < res.items.size(); at += kThreadInfoBatch) {
        const size_t n = std::min<size_t>(kThreadInfoBatch, res.items.size() - at);
        std::vector<uint8_t> batch;
        batch.reserve(n * (sizeof(ps4::packet_header_t) + sizeof(ps4::debug_lwpid_packet_t)));
        for (size_t i = 0; i < n; ++i) {
            ps4::packet_header_t hdr{ps4::kPacketMagic, ps4::CMD_DEBUG_THREAD_INFO,
                                     sizeof(ps4::debug_lwpid_packet_t)};
            ps4::debug_lwpid_packet_t tp{res.items[at + i].tid};
            const auto* hp = reinterpret_cast<const uint8_t*>(&hdr);
            const auto* bp = reinterpret_cast<const uint8_t*>(&tp);
            batch.insert(batch.end(), hp, hp + sizeof(hdr));
            batch.insert(batch.end(), bp, bp + sizeof(tp));
        }
        if (!c.send_all(batch.data(), batch.size())) { res.error = c.last_err; return res; }
        for (size_t i = 0; i < n; ++i) {
            io_result_t tr;
            if (!expect_success(c, tr)) {
                if (!c.connected()) { res.error = tr.error; return res; }
                continue;   // that thread is gone; the info is best effort
            }
            ps4::debug_thread_info_response_t info{};
            if (!c.recv_all(&info, sizeof(info))) { res.error = c.last_err; return res; }
            res.items[at + i].priority = static_cast<int32_t>(info.priority);
            res.items[at + i].name = fixed_str(info.name, sizeof(info.name));
        }
    }
    res.ok = true;
    return res;
}

enum_result_t<region_info_t> backend_ps4_t::enum_regions(const target_handle_t& h) {
    enum_result_t<region_info_t> res;
    std::vector<ps4_segment_t> segs;
    if (!h.native && h.pid != 0) {
        // unattached pid-only query (e.g. ps4_turbo_segments_for after ps4_connect)
        std::vector<ps4::vm_map_entry_t> raw;
        uint32_t err = 0;
        if (!m_impl->fetch_maps(h.pid, raw, err)) { res.error = err; return res; }
        segs.reserve(raw.size());
        for (const auto& m : raw) segs.push_back(segment_from_entry(m));
    } else {
        auto maps = ps4_maps(h);
        if (!maps.ok) { res.error = maps.error; return res; }
        segs = std::move(maps.items);
    }
    res.items.reserve(segs.size());
    for (const auto& m : segs) {
        region_info_t r;
        r.base    = static_cast<uintptr_t>(m.start);
        r.size    = static_cast<size_t>(m.end - m.start);
        r.protect = vm_to_win_prot(m.prot);
        r.state   = 0x1000;   // MEM_COMMIT
        r.type    = m.name.empty() ? 0x20000 : 0x40000;  // MEM_PRIVATE : MEM_MAPPED
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
    if (m_impl->dbg_pid.load() == 0) return err_result(ps4::kErrNotAttached);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    ps4::debug_lwpid_packet_t pkt{};
    pkt.lwpid = tid;
    if (!c.send_cmd(ps4::CMD_DEBUG_GETREGS, &pkt, sizeof(pkt))) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    ps4::reg64_t reg{};
    if (!c.recv_all(&reg, sizeof(reg))) return wire_fail(c);
    ctx_from_reg64(ctx, reg);
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::set_thread_context(uint32_t tid, const thread_context_t& ctx) {
    if (m_impl->dbg_pid.load() == 0) return err_result(ps4::kErrNotAttached);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    // read-modify-write so trapno/segments survive the roundtrip
    ps4::reg64_t reg{};
    {
        ps4::debug_lwpid_packet_t gp{};
        gp.lwpid = tid;
        if (!c.send_cmd(ps4::CMD_DEBUG_GETREGS, &gp, sizeof(gp))) return wire_fail(c);
        io_result_t gr;
        if (expect_success(c, gr)) {
            if (!c.recv_all(&reg, sizeof(reg))) return wire_fail(c);
        } else if (!c.connected()) {
            return gr;
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
    if (!c.send_cmd(ps4::CMD_DEBUG_SETREGS, &pkt, sizeof(pkt))) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    if (!c.send_all(&out, sizeof(out))) return wire_fail(c);
    if (!expect_success(c, r)) return r;
    r.ok = true;
    return r;
}

// ---------------------------------------------------------------------------
// live debug session (ps4debug-NG CMD_DEBUG_*)

bool backend_ps4_t::ps4_debug_attach(uint32_t pid, std::string& err) {
    std::string detail;
    const uint32_t e = m_impl->ensure_debug(pid, detail);
    if (e == 0) return true;
    err = detail.empty() ? ps4::io_error_str(e) : detail;
    return false;
}

bool backend_ps4_t::ps4_debug_detach() {
    auto& c = *m_impl->conn;
    bool ok = true;
    {
        cmd_lock_t lk(c, m_impl->cmd_budget_ms);
        if (c.connected() && m_impl->dbg_pid.load() != 0) {
            if (c.send_cmd(ps4::CMD_DEBUG_DETACH, nullptr, 0)) {
                uint32_t st = 0;
                const auto o = c.recv_u32_optional(st, m_impl->io_timeout_ms);
                ok = o == conn_t::opt_t::got && st == ps4::CMD_SUCCESS;
            } else {
                ok = false;
            }
        }
        std::lock_guard dl(m_impl->dbg_mu);
        m_impl->end_debug_session_locked("");
    }
    m_impl->clear_events();
    return ok;
}

bool backend_ps4_t::ps4_debug_attached() const noexcept {
    return m_impl->dbg_pid.load() != 0;
}

bool backend_ps4_t::ps4_debug_held() const noexcept {
    return m_impl->dbg_held.load();
}

uint32_t backend_ps4_t::ps4_debug_pid() const noexcept {
    return m_impl->dbg_pid.load();
}

io_result_t backend_ps4_t::ps4_set_breakpoint(uint32_t index, bool enabled, uintptr_t addr) {
    io_result_t r = m_impl->wire_set_bp(index, enabled, addr);
    if (r.ok) {
        std::lock_guard lk(m_impl->slot_mu);
        auto& s = m_impl->bps[index];
        if (s.st != impl_t::slot_rec_t::reserved) {
            if (enabled) { s.st = impl_t::slot_rec_t::armed; s.addr = addr; }
            else s = impl_t::slot_rec_t{};
        }
    }
    return r;
}

io_result_t backend_ps4_t::ps4_set_watchpoint(uint32_t index, bool enabled, uint32_t len,
                                              uint32_t type, uintptr_t addr) {
    io_result_t r = m_impl->wire_set_wp(index, enabled, len, type, addr);
    if (r.ok) {
        std::lock_guard lk(m_impl->slot_mu);
        auto& s = m_impl->wps[index];
        if (s.st != impl_t::slot_rec_t::reserved) {
            if (enabled) {
                s.st = impl_t::slot_rec_t::armed;
                s.addr = addr; s.len = len; s.type = type;
            } else {
                s = impl_t::slot_rec_t{};
            }
        }
    }
    return r;
}

std::vector<backend_ps4_t::ps4_slot_t> backend_ps4_t::ps4_breakpoints() const {
    return m_impl->list_slots(m_impl->bps);
}

std::vector<backend_ps4_t::ps4_slot_t> backend_ps4_t::ps4_watchpoints() const {
    return m_impl->list_slots(m_impl->wps);
}

io_result_t backend_ps4_t::ps4_bp_arm(uint64_t addr, uint32_t index, uint32_t& out_index,
                                      bool* reused) {
    return m_impl->arm(m_impl->bps, true, addr, 0, 0, index, out_index, reused);
}

io_result_t backend_ps4_t::ps4_bp_disarm(uint32_t index, uint64_t* out_addr) {
    return m_impl->disarm(m_impl->bps, true, index, out_addr);
}

io_result_t backend_ps4_t::ps4_bp_disarm_addr(uint64_t addr, uint32_t* out_index) {
    uint32_t idx = 0;
    if (!m_impl->find_armed(m_impl->bps, addr, idx)) return err_result(ps4::kErrNotArmed);
    if (out_index) *out_index = idx;
    return m_impl->disarm(m_impl->bps, true, idx, nullptr);
}

io_result_t backend_ps4_t::ps4_wp_arm(uint64_t addr, uint32_t len, uint32_t type,
                                      uint32_t index, uint32_t& out_index, bool* reused) {
    if (len != 1 && len != 2 && len != 4 && len != 8) return err_result(ps4::kErrBadArg);
    return m_impl->arm(m_impl->wps, false, addr, len, type, index, out_index, reused);
}

io_result_t backend_ps4_t::ps4_wp_disarm(uint32_t index, uint64_t* out_addr) {
    return m_impl->disarm(m_impl->wps, false, index, out_addr);
}

io_result_t backend_ps4_t::ps4_wp_disarm_addr(uint64_t addr, uint32_t* out_index) {
    uint32_t idx = 0;
    if (!m_impl->find_armed(m_impl->wps, addr, idx)) return err_result(ps4::kErrNotArmed);
    if (out_index) *out_index = idx;
    return m_impl->disarm(m_impl->wps, false, idx, nullptr);
}

namespace {

// a debug command that only answers a status word
io_result_t simple_debug_cmd(conn_t& c, int64_t budget, uint32_t cmd, const void* body,
                             uint32_t len) {
    cmd_lock_t lk(c, budget);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    if (!c.send_cmd(cmd, body, len)) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    r.ok = true;
    return r;
}

} // namespace

io_result_t backend_ps4_t::ps4_continue(uint32_t stop) {
    if (stop > ps4::kStopKill) return err_result(ps4::kErrBadArg);
    if (m_impl->dbg_pid.load() == 0) return err_result(ps4::kErrNotAttached);
    ps4::debug_continue_packet_t pkt{};
    pkt.stop = stop;
    // clear before the send: the stop event this resume provokes can arrive
    // before the reply is read, and its "held" must not be overwritten
    const bool was_held = stop == ps4::kStopResume && m_impl->dbg_held.exchange(false);
    auto r = simple_debug_cmd(*m_impl->conn, m_impl->cmd_budget_ms, ps4::CMD_DEBUG_CONTINUE,
                              &pkt, sizeof(pkt));
    if (!r.ok && was_held) m_impl->dbg_held.store(true);
    if (r.ok) {
        infra::event_bus::publish("debugger.state",
            nlohmann::json{{"attached", true}, {"pid", m_impl->dbg_pid.load()},
                           {"held", m_impl->dbg_held.load()}, {"stop", stop}});
    }
    return r;
}

io_result_t backend_ps4_t::ps4_step(uint32_t lwpid) {
    if (m_impl->dbg_pid.load() == 0) return err_result(ps4::kErrNotAttached);
    if (lwpid == 0)
        return simple_debug_cmd(*m_impl->conn, m_impl->cmd_budget_ms, ps4::CMD_DEBUG_STEP,
                                nullptr, 0);
    ps4::debug_lwpid_packet_t pkt{};
    pkt.lwpid = lwpid;
    return simple_debug_cmd(*m_impl->conn, m_impl->cmd_budget_ms, ps4::CMD_DEBUG_STEP_THREAD,
                            &pkt, sizeof(pkt));
}

io_result_t backend_ps4_t::ps4_suspend_thread(uint32_t lwpid) {
    if (m_impl->dbg_pid.load() == 0) return err_result(ps4::kErrNotAttached);
    ps4::debug_lwpid_packet_t pkt{};
    pkt.lwpid = lwpid;
    return simple_debug_cmd(*m_impl->conn, m_impl->cmd_budget_ms, ps4::CMD_DEBUG_SUSPEND,
                            &pkt, sizeof(pkt));
}

io_result_t backend_ps4_t::ps4_resume_thread(uint32_t lwpid) {
    if (m_impl->dbg_pid.load() == 0) return err_result(ps4::kErrNotAttached);
    ps4::debug_lwpid_packet_t pkt{};
    pkt.lwpid = lwpid;
    return simple_debug_cmd(*m_impl->conn, m_impl->cmd_budget_ms, ps4::CMD_DEBUG_RESUME,
                            &pkt, sizeof(pkt));
}

io_result_t backend_ps4_t::ps4_process_stop(uint32_t pid, uint32_t state) {
    if (state > ps4::kStopKill) return err_result(ps4::kErrBadArg);
    ps4::debug_process_stop_packet_t pkt{};
    pkt.pid   = pid;
    pkt.state = static_cast<uint8_t>(state);
    return simple_debug_cmd(*m_impl->conn, m_impl->cmd_budget_ms, ps4::CMD_DEBUG_PROCESS_STOP,
                            &pkt, sizeof(pkt));
}

io_result_t backend_ps4_t::ps4_get_dbregs(uint32_t lwpid, uint64_t dr[16]) {
    if (m_impl->dbg_pid.load() == 0) return err_result(ps4::kErrNotAttached);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    ps4::debug_lwpid_packet_t pkt{};
    pkt.lwpid = lwpid;
    if (!c.send_cmd(ps4::CMD_DEBUG_GETDBREGS, &pkt, sizeof(pkt))) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    if (!c.recv_all(dr, ps4::kDbregsSize)) return wire_fail(c);   // exactly 128 bytes
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_install(uint32_t pid, uint64_t& rpcstub) {
    {
        std::lock_guard lk(m_impl->stub_mu);
        if (auto it = m_impl->rpcstubs.find(pid); it != m_impl->rpcstubs.end()) {
            rpcstub = it->second;
            io_result_t r;
            r.ok = true;
            return r;
        }
    }
    auto& c = *m_impl->conn;
    uint64_t stub = 0;
    {
        cmd_lock_t lk(c, m_impl->cmd_budget_ms);
        if (!c.connected()) return err_result(ps4::kErrNotConnected);
        ps4::proc_intall_packet_t pkt{};
        pkt.pid = pid;
        if (!c.send_cmd(ps4::CMD_PROC_INTALL, &pkt, sizeof(pkt))) return wire_fail(c);
        io_result_t r;
        if (!expect_success(c, r)) return r;
        if (!c.recv_all(&stub, sizeof(stub))) return wire_fail(c);
        if (stub == 0) return err_result(ps4::kErrStatus);
    }
    rpcstub = stub;
    {
        std::lock_guard lk(m_impl->stub_mu);
        m_impl->rpcstubs[pid] = stub;
    }
    io_result_t r;
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_call(uint32_t pid, uint64_t rpcstub, uint64_t rip,
                                    const uint64_t args[6], uint64_t& out_rax) {
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    ps4::proc_call_packet_t pkt{};
    pkt.pid     = pid;
    pkt.rpcstub = rpcstub;
    pkt.rip     = rip;
    pkt.rdi = args[0]; pkt.rsi = args[1]; pkt.rdx = args[2];
    pkt.rcx = args[3]; pkt.r8  = args[4]; pkt.r9  = args[5];
    if (!c.send_cmd(ps4::CMD_PROC_CALL, &pkt, sizeof(pkt))) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    ps4::proc_call_response_t resp{};
    if (!c.recv_all(&resp, sizeof(resp))) return wire_fail(c);
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
        m_impl->ev_cv.wait_for(lk, std::chrono::milliseconds(timeout_ms > 0 ? timeout_ms : 0),
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

uint64_t backend_ps4_t::ps4_events_received() const noexcept {
    return m_impl->ev_received.load();
}

uint64_t backend_ps4_t::ps4_events_dropped() const noexcept {
    return m_impl->ev_dropped.load();
}

// ---------------------------------------------------------------------------
// console-side capabilities: auth, scan, on-device disasm, elf, console

namespace {

// read a scan result block stream: u64 len + len bytes, until the
// 0xFFFFFFFFFFFFFFFF sentinel. entries are {u32 offset, value bytes}.
// caller holds the command lock. A malformed block drops the connection
bool scan_read_blocks(conn_t& c, uint64_t base, uint32_t value_len,
                      std::vector<backend_ps4_t::ps4_scan_hit_t>& hits,
                      uint32_t* serr = nullptr, int /*timeout_ms*/ = 0) {
    std::vector<uint8_t> buf;
    for (;;) {
        uint64_t len = 0;
        if (!c.recv_all(&len, sizeof(len))) { if (serr) *serr = 1; return false; }
        if (len == 0xFFFFFFFFFFFFFFFFull) return true;
        const size_t entry = 4 + static_cast<size_t>(value_len);
        if (len > 0x100000 || len % entry != 0) {
            if (serr) *serr = 2;
            return c.fail(ps4::kErrProtocol, "scan result block of " + std::to_string(len) +
                                             " bytes (entry " + std::to_string(entry) + ")");
        }
        buf.resize(static_cast<size_t>(len));
        if (len && !c.recv_all(buf.data(), buf.size())) { if (serr) *serr = 3; return false; }
        for (size_t off = 0; off + entry <= buf.size(); off += entry) {
            uint32_t offset = 0;
            std::memcpy(&offset, buf.data() + off, 4);
            backend_ps4_t::ps4_scan_hit_t h;
            h.addr = base + offset;
            h.value.assign(buf.begin() + static_cast<ptrdiff_t>(off + 4),
                           buf.begin() + static_cast<ptrdiff_t>(off + entry));
            hits.push_back(std::move(h));
        }
    }
}

// bytes of seed value data the payload expects for (valtype, cmptype)
uint32_t scan_need(uint8_t vt, uint8_t ct, size_t data_size) {
    if (!ps4::scan_cmp_needs_value(ct)) return 0;
    const uint32_t fixed = ps4::scan_value_size(vt);
    if (!fixed) return static_cast<uint32_t>(data_size);
    return ct == ps4::kCmpBetween ? 2 * fixed : fixed;
}

// drain a u64 stream to its 0xFF..FF sentinel; keep at most cap entries
bool drain_u64_stream(conn_t& c, std::vector<uint64_t>& out, size_t cap, bool& truncated) {
    truncated = false;
    for (;;) {
        uint64_t v = 0;
        if (!c.recv_all(&v, sizeof(v))) return false;
        if (v == 0xFFFFFFFFFFFFFFFFull) return true;
        if (out.size() < cap) out.push_back(v);
        else truncated = true;
    }
}

// client-driven rescan stream shared by SCAN_COUNT and the non-resident
// Turbo COUNT: send prev as chunks of {u32 offset, [prev value]}, read the
// surviving blocks after each chunk, then the 0xFFFFFFFF end marker. err is
// 5 on a send failure, 6+n for a block read failure, 7 for the end marker.
// caller holds conn->mu and has already consumed the ack
bool scan_stream_count_chunks(conn_t& c, uint64_t base, uint8_t cmptype, uint32_t vlen,
                              const std::vector<backend_ps4_t::ps4_scan_hit_t>& prev,
                              std::vector<backend_ps4_t::ps4_scan_hit_t>& hits,
                              uint32_t& err, int /*timeout_ms*/ = 0) {
    const bool with_prev = ps4::scan_cmp_needs_previous(cmptype);
    const uint32_t chunk_cap = 0x20000;
    size_t i = 0;
    while (i < prev.size()) {
        std::vector<uint8_t> chunk;
        chunk.reserve(chunk_cap);
        while (i < prev.size()) {
            const uint32_t off = static_cast<uint32_t>(prev[i].addr - base);
            const size_t esz = 4 + (with_prev ? vlen : 0);
            if (chunk.size() + esz > chunk_cap) break;
            const size_t at = chunk.size();
            chunk.resize(at + esz, 0);
            std::memcpy(chunk.data() + at, &off, 4);
            if (with_prev) {
                const size_t n = std::min<size_t>(vlen, prev[i].value.size());
                if (n) std::memcpy(chunk.data() + at + 4, prev[i].value.data(), n);
            }
            ++i;
        }
        const uint32_t clen = static_cast<uint32_t>(chunk.size());
        if (!c.send_all(&clen, sizeof(clen)) || (clen && !c.send_all(chunk.data(), clen))) {
            err = 5; return false;
        }
        uint32_t serr = 0;
        if (!scan_read_blocks(c, base, vlen, hits, &serr)) { err = 6 + serr; return false; }
    }
    const uint32_t end = 0xFFFFFFFFu;
    if (!c.send_all(&end, sizeof(end))) { err = 7; return false; }
    return true;
}

// read u64 progress words until the sentinel (snapshot/resident passes)
bool turbo_read_progress(conn_t& c, uint64_t total,
                         const backend_ps4_t::ps4_progress_fn& progress, int /*timeout_ms*/) {
    for (;;) {
        uint64_t v = 0;
        if (!c.recv_all(&v, sizeof(v))) return false;
        if (v == ps4::kTurboSentinel) return true;
        if (progress) progress(v, total);
    }
}

bool send_turbo_segments(conn_t& c, const std::vector<backend_ps4_t::ps4_turbo_segment_t>& segs) {
    const uint32_t n = static_cast<uint32_t>(segs.size());
    if (!c.send_all(&n, sizeof(n))) return false;
    std::vector<ps4::turbo_snap_segment_t> wire(segs.size());
    for (size_t i = 0; i < segs.size(); ++i) {
        wire[i].address = segs[i].addr;
        wire[i].length  = segs[i].len;
    }
    return wire.empty() ||
           c.send_all(wire.data(), wire.size() * sizeof(ps4::turbo_snap_segment_t));
}

// value width for a turbo request: fixed types from the type, variable types
// (arrbytes/string) from the seed length
uint32_t turbo_value_len(uint8_t vt, size_t data_len) {
    const uint32_t v = ps4::scan_value_size(vt);
    return v ? v : static_cast<uint32_t>(data_len);
}

} // namespace

bool backend_ps4_t::ps4_auth(uint32_t flags, std::string& err) {
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) { err = "not connected"; return false; }
    bool ok = false;
    impl_t::auth_locked(c, ok, flags, err);
    m_impl->authed = ok;
    return ok;
}

bool backend_ps4_t::ps4_authed() const noexcept {
    return m_impl->authed.load();
}

io_result_t backend_ps4_t::ps4_console_info(ps4_console_info_t& out) {
    out = ps4_console_info_t{};
    io_result_t r;
    {
        auto& c = *m_impl->conn;
        cmd_lock_t lk(c, m_impl->cmd_budget_ms);
        if (!c.connected()) return err_result(ps4::kErrNotConnected);
        if (!c.send_cmd(ps4::CMD_CONSOLE_INFO, nullptr, 0)) return wire_fail(c);
        if (!expect_success(c, r)) return r;
    }
    out.alive     = true;
    out.endpoint  = endpoint();
    out.branding  = branding();
    out.caps      = server_caps();
    out.version   = server_version();
    out.fw        = fw_string();
    out.fw_bcd    = fw_version();
    {
        std::lock_guard lk(m_impl->info_mu);
        out.platform = m_impl->platform;
    }
    out.authed    = ps4_authed();
    out.debug_pid = ps4_debug_pid();
    out.drops     = drop_count();
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_scan_first(uint32_t pid, uint64_t addr, uint32_t len,
                                          uint8_t valtype, uint8_t cmptype, uint8_t alignment,
                                          const std::vector<uint8_t>& data,
                                          std::vector<ps4_scan_hit_t>& hits) {
    hits.clear();
    if (valtype > ps4::kValString || cmptype > ps4::kCmpUnknownLow) return err_result(ps4::kErrBadArg);
    const uint32_t fixed = ps4::scan_value_size(valtype);
    const uint32_t need = scan_need(valtype, cmptype, data.size());
    // variable-width types take their width from the seed data
    if (!fixed && need == 0) return err_result(ps4::kErrBadArg);
    if (data.size() < need || need > ps4::kMaxIoLen) return err_result(ps4::kErrBadArg);
    const uint32_t width = fixed ? fixed : need;

    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->long_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    ps4::proc_scan_start_packet_t pkt{};
    pkt.pid = pid; pkt.address = addr; pkt.length = len;
    pkt.valueType = valtype; pkt.compareType = cmptype;
    pkt.alignment = alignment; pkt.lenData = need;
    // the seed data goes out right behind the packet (as the payload reads
    // it), then the pre-read and post-read statuses come back
    if (!c.send_cmd(ps4::CMD_PROC_SCAN_START, &pkt, sizeof(pkt))) return wire_fail(c);
    if (need && !c.send_all(data.data(), need)) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;                  // pre-read status
    if (!expect_success(c, r)) return r;                  // post-read status
    if (!scan_read_blocks(c, addr, width, hits)) return wire_fail(c);
    if (!expect_success(c, r)) return r;                  // trailing status
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_scan_next(uint32_t pid, uint64_t base,
                                         uint8_t valtype, uint8_t cmptype,
                                         const std::vector<ps4_scan_hit_t>& prev,
                                         const std::vector<uint8_t>& data,
                                         std::vector<ps4_scan_hit_t>& hits) {
    hits.clear();
    if (valtype > ps4::kValString || cmptype > ps4::kCmpUnknownLow) return err_result(ps4::kErrBadArg);
    const uint32_t fixed = ps4::scan_value_size(valtype);
    const uint32_t need = scan_need(valtype, cmptype, data.size());
    // the payload derives a variable width from lenData; without seed data
    // it has no width at all and would misparse the entry stream
    if (!fixed && need == 0) return err_result(ps4::kErrBadArg);
    if (data.size() < need || need > ps4::kMaxIoLen) return err_result(ps4::kErrBadArg);
    const uint32_t width = fixed ? fixed : need;
    const bool with_prev = ps4::scan_cmp_needs_previous(cmptype);
    const size_t entry = 4 + (with_prev ? width : 0);
    if (entry > kScanChunkCap) return err_result(ps4::kErrBadArg);
    // validate every previous hit before a single byte goes out: the server
    // reads exactly `width` value bytes per entry
    for (const auto& h : prev) {
        if (h.addr < base || h.addr - base > 0xFFFFFFFFull) return err_result(ps4::kErrBadArg);
        if (with_prev && h.value.size() != width) return err_result(ps4::kErrBadArg);
    }

    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->long_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    ps4::proc_scan_count_packet_t pkt{};
    pkt.pid = pid; pkt.base_address = base;
    pkt.valueType = valtype; pkt.compareType = cmptype; pkt.lenData = need;
    io_result_t r;
    if (!c.send_cmd(ps4::CMD_PROC_SCAN_COUNT, &pkt, sizeof(pkt))) { r.error = 2; return r; }
    if (need && !c.send_all(data.data(), need)) { r.error = 3; return r; }
    uint32_t st = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 4; return r; }
    uint32_t serr = 0;
    if (!scan_stream_count_chunks(c, base, cmptype, width, prev, hits, serr)) {
        r.error = serr; return r;
    }
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 8; return r; }
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_scan_all(uint32_t pid, uint8_t valtype, uint8_t cmptype,
                                        const std::vector<uint8_t>& data,
                                        std::vector<uint64_t>& addrs, bool* truncated) {
    addrs.clear();
    if (truncated) *truncated = false;
    if (data.size() > ps4::kMaxIoLen) return err_result(ps4::kErrBadArg);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->long_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    ps4::proc_scan_packet_t pkt{};
    pkt.pid = pid; pkt.valueType = valtype; pkt.compareType = cmptype;
    pkt.lenData = static_cast<uint32_t>(data.size());
    if (!c.send_cmd(ps4::CMD_PROC_SCAN, &pkt, sizeof(pkt))) return wire_fail(c);
    if (!data.empty() && !c.send_all(data.data(), data.size())) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    if (!expect_success(c, r)) return r;
    bool trunc = false;
    if (!drain_u64_stream(c, addrs, kMaxScanAll, trunc)) return wire_fail(c);
    if (truncated) *truncated = trunc;
    r.ok = true;
    r.bytes = addrs.size();
    return r;
}

io_result_t backend_ps4_t::ps4_scan_aob(uint32_t pid, uint64_t addr, uint32_t len,
                                        const std::vector<uint8_t>& pattern,
                                        const std::vector<uint8_t>& mask,
                                        uint8_t max_matches, uint8_t stop_flag,
                                        uint64_t& out_addr) {
    out_addr = 0;
    if (pattern.empty() || pattern.size() != mask.size() || pattern.size() > 0x10000)
        return err_result(ps4::kErrBadArg);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->long_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    ps4::proc_scan_aob_packet_t pkt{};
    pkt.pid = pid; pkt.address = addr; pkt.length = len;
    pkt.max_matches = max_matches ? max_matches : 1;
    pkt.stop_flag = stop_flag;
    pkt.pattern_length = static_cast<uint32_t>(pattern.size());
    if (!c.send_cmd(ps4::CMD_PROC_SCAN_AOB, &pkt, sizeof(pkt))) return wire_fail(c);
    if (!c.send_all(pattern.data(), pattern.size()) ||
        !c.send_all(mask.data(), mask.size())) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    if (!expect_success(c, r)) return r;
    if (!c.recv_all(&out_addr, sizeof(out_addr))) return wire_fail(c);
    if (!expect_success(c, r)) return r;
    r.ok = true;
    return r;
}

// ---------------------------------------------------------------------------
// capability level, bulk write (0xBDAACC04) and Turbo Scan (0xBDAACC10-17)

namespace {
constexpr int kTurboTimeoutMs = 5 * 60 * 1000;   // a whole-process pass can be slow
}

std::string backend_ps4_t::ps4_capability_level() const {
    const std::string& b = m_impl->branding;
    const size_t nul = b.find('\0');
    if (nul == std::string::npos) return {};
    std::string lvl = b.substr(nul + 1);
    const size_t end = lvl.find('\0');
    if (end != std::string::npos) lvl.resize(end);
    return lvl;
}

io_result_t backend_ps4_t::ps4_write_multi(uint32_t pid,
                                           const std::vector<ps4_write_entry_t>& writes,
                                           bool want_status, std::vector<uint8_t>& status) {
    io_result_t r;
    status.clear();
    // the payload aborts the whole exchange on a cap violation, so refuse
    // locally instead of desyncing the stream half way through
    if (writes.size() > ps4::kWriteMultiMaxCount) { r.error = ERROR_INVALID_PARAMETER; return r; }
    size_t total = 0;
    for (const auto& w : writes) {
        if (w.bytes.size() > ps4::kWriteMultiMaxEntry) { r.error = ERROR_INVALID_PARAMETER; return r; }
        total += w.bytes.size();
    }
    if (writes.empty()) { r.ok = true; return r; }

    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    if (!c.connected()) { r.error = 1; return r; }
    ps4::proc_write_multi_packet_t pkt{};
    pkt.pid   = pid;
    pkt.count = static_cast<uint32_t>(writes.size());
    pkt.flags = want_status ? ps4::kWriteMultiFlagStatus : 0;
    if (!c.send_cmd(ps4::CMD_PROC_WRITE_MULTI, &pkt, sizeof(pkt))) { r.error = 2; return r; }
    uint32_t ack = 0;
    if (!c.recv_u32(ack) || ack != ps4::CMD_SUCCESS) { r.error = 3; return r; }

    // coalesce small entries into ~256 KiB sends
    std::vector<uint8_t> out;
    out.reserve(0x40000);
    for (const auto& w : writes) {
        ps4::proc_write_multi_entry_t e{};
        e.address = w.addr;
        e.length  = static_cast<uint32_t>(w.bytes.size());
        const auto* ep = reinterpret_cast<const uint8_t*>(&e);
        out.insert(out.end(), ep, ep + sizeof(e));
        out.insert(out.end(), w.bytes.begin(), w.bytes.end());
        if (out.size() >= 0x40000) {
            if (!c.send_all(out.data(), out.size())) { r.error = 4; return r; }
            out.clear();
        }
    }
    if (!out.empty() && !c.send_all(out.data(), out.size())) { r.error = 4; return r; }

    if (want_status) {
        status.resize(writes.size());
        if (!c.recv_all(status.data(), status.size(), kTurboTimeoutMs)) { r.error = 5; return r; }
    }
    uint32_t term = 0;
    if (!c.recv_u32(term, kTurboTimeoutMs)) { r.error = 6; return r; }
    if (term != ps4::CMD_SUCCESS) { r.error = 7; return r; }   // some entry failed (no status array)
    r.ok    = true;
    r.bytes = total;
    return r;
}

io_result_t backend_ps4_t::ps4_turbo_caps(ps4_turbo_caps_t& out) {
    io_result_t r;
    out = {};
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    if (!c.connected()) { r.error = 1; return r; }
    if (!c.send_cmd(ps4::CMD_TURBO_CAPS, nullptr, 0)) { r.error = 2; return r; }
    uint32_t st = 0;
    // an older payload has no handler and may say nothing at all: short wait
    if (!c.recv_u32(st, 3000)) { r.error = 3; return r; }
    if (st != ps4::CMD_SUCCESS) { r.error = 4; return r; }
    ps4::turbo_caps_response_t resp{};
    if (!c.recv_all(&resp, sizeof(resp))) { r.error = 5; return r; }
    out.version     = resp.version;
    out.engines     = resp.engines;
    out.max_threads = resp.max_threads;
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_turbo_start(const ps4_turbo_start_t& req, ps4_turbo_result_t& out,
                                           const ps4_progress_fn& progress) {
    io_result_t r;
    out = {};
    const bool snapshot  = (req.flags & ps4::kTsSnapshot) != 0;
    const bool resident  = (req.flags & ps4::kTsServerResident) != 0;
    const bool arrbytes  = req.valtype == ps4::kValArrBytes;
    const bool needs_val = ps4::scan_cmp_needs_value(req.cmptype);
    if (req.cmptype > ps4::kCmpUnknownLow) { r.error = ERROR_INVALID_PARAMETER; return r; }

    const uint32_t vlen = turbo_value_len(req.valtype, req.data.size());
    if (vlen == 0) { r.error = ERROR_INVALID_PARAMETER; return r; }
    if (needs_val) {
        const size_t want = (req.cmptype == ps4::kCmpBetween && ps4::scan_value_size(req.valtype))
                                ? 2u * vlen : vlen;
        if (req.data.size() != want) { r.error = ERROR_INVALID_PARAMETER; return r; }
    }
    if (snapshot && vlen > 8) { r.error = ERROR_INVALID_PARAMETER; return r; }
    std::vector<uint8_t> mask = req.mask;
    if (arrbytes && mask.empty()) mask.assign(vlen, 1);
    if (arrbytes && mask.size() != vlen) { r.error = ERROR_INVALID_PARAMETER; return r; }

    uint32_t flags = req.flags;
    const bool segmented = !req.segments.empty();
    if (segmented) {
        if (!snapshot && !resident) { r.error = ERROR_INVALID_PARAMETER; return r; }  // payload ignores them
        if (req.segments.size() > ps4::kTurboMaxSegments) { r.error = ERROR_INVALID_PARAMETER; return r; }
        flags |= ps4::kTsSnapshotSegments;
    } else {
        flags &= ~ps4::kTsSnapshotSegments;
    }

    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    if (!c.connected()) { r.error = 1; return r; }

    ps4::turbo_start_packet_t pkt{};
    pkt.pid         = req.pid;
    pkt.address     = segmented ? req.segments.front().addr : req.addr;
    pkt.length      = segmented ? req.segments.front().len : req.len;
    pkt.valueType   = req.valtype;
    pkt.compareType = req.cmptype;
    pkt.alignment   = req.alignment;
    // non-value compares still need a nonzero lenData unless snapshotting
    // (the payload rejects lenData == 0 there); it only reads it when needed
    pkt.lenData     = needs_val ? static_cast<uint32_t>(req.data.size()) : vlen;
    pkt.flags       = flags;
    if (!c.send_cmd(ps4::CMD_TURBO_START, &pkt, sizeof(pkt))) { r.error = 2; return r; }
    uint32_t st = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 3; return r; }   // auth / args
    if (needs_val && !c.send_all(req.data.data(), req.data.size())) { r.error = 4; return r; }
    if (arrbytes && !c.send_all(mask.data(), mask.size())) { r.error = 4; return r; }
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 5; return r; }   // buffers
    if (segmented && !send_turbo_segments(c, req.segments)) { r.error = 6; return r; }

    if (snapshot) {
        // plan, progress words, sentinel, summary, trailing status
        ps4::turbo_snap_plan_t plan{};
        if (!c.recv_all(&plan, sizeof(plan), kTurboTimeoutMs)) { r.error = 7; return r; }
        out.snapshot    = true;
        out.slot_count  = plan.slot_count;
        out.total_bytes = plan.total_bytes;
        if (!turbo_read_progress(c, plan.total_bytes, progress, kTurboTimeoutMs)) { r.error = 8; return r; }
        ps4::turbo_snap_summary_t sum{};
        if (!c.recv_all(&sum, sizeof(sum), kTurboTimeoutMs)) { r.error = 9; return r; }
        out.snapshot_ok = sum.snapshot_ok != 0;
        out.resident    = out.snapshot_ok;
        out.count       = sum.survivor_count;
        if (!c.recv_u32(st, kTurboTimeoutMs) || st != ps4::CMD_SUCCESS) { r.error = 10; return r; }
        r.ok = true;
        return r;
    }

    if (resident) {
        ps4::turbo_resident_summary_t sum{};
        if (!c.recv_all(&sum, sizeof(sum), kTurboTimeoutMs)) { r.error = 11; return r; }
        if (sum.resident_stored) {
            out.resident = true;
            out.count    = sum.count;
            if (!c.recv_u32(st, kTurboTimeoutMs) || st != ps4::CMD_SUCCESS) { r.error = 12; return r; }
            r.ok = true;
            return r;
        }
        if (segmented) {
            // resident store overflowed and segmented scans have no streamed
            // fallback: just the sentinel and the trailing status
            uint64_t sentinel = 0;
            if (!c.recv_all(&sentinel, sizeof(sentinel), kTurboTimeoutMs)) { r.error = 13; return r; }
            if (!c.recv_u32(st, kTurboTimeoutMs) || st != ps4::CMD_SUCCESS) { r.error = 12; return r; }
            r.error = 14;   // overflow: narrow the range or use a snapshot
            return r;
        }
        // not stored: falls back to the classic streamed runs below
    }

    uint32_t serr = 0;
    if (!scan_read_blocks(c, pkt.address, vlen, out.hits, &serr)) {
        r.error = 20 + serr; return r;
    }
    out.count = out.hits.size();
    if (!c.recv_u32(st, kTurboTimeoutMs) || st != ps4::CMD_SUCCESS) { r.error = 30; return r; }
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_turbo_count(uint32_t pid, uint64_t base, uint8_t valtype,
                                           uint8_t cmptype, uint32_t flags,
                                           const std::vector<uint8_t>& data,
                                           const std::vector<uint8_t>& mask_in,
                                           const std::vector<ps4_scan_hit_t>& prev,
                                           ps4_turbo_result_t& out,
                                           const ps4_progress_fn& progress) {
    io_result_t r;
    out = {};
    if (cmptype > ps4::kCmpUnknownLow) { r.error = ERROR_INVALID_PARAMETER; return r; }
    const bool resident  = (flags & ps4::kTsServerResident) != 0;
    const bool arrbytes  = valtype == ps4::kValArrBytes;
    const bool needs_val = ps4::scan_cmp_needs_value(cmptype);
    uint32_t vlen = ps4::scan_value_size(valtype);
    if (!vlen) {
        vlen = static_cast<uint32_t>(!data.empty() ? data.size()
                                     : (!prev.empty() ? prev.front().value.size() : 0));
    }
    if (vlen == 0 || vlen > 0x1000) { r.error = ERROR_INVALID_PARAMETER; return r; }
    if (needs_val) {
        const size_t want = (cmptype == ps4::kCmpBetween && ps4::scan_value_size(valtype))
                                ? 2u * vlen : vlen;
        if (data.size() != want) { r.error = ERROR_INVALID_PARAMETER; return r; }
    }
    std::vector<uint8_t> mask = mask_in;
    if (arrbytes && mask.empty()) mask.assign(vlen, 1);
    if (arrbytes && mask.size() != vlen) { r.error = ERROR_INVALID_PARAMETER; return r; }

    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    if (!c.connected()) { r.error = 1; return r; }
    ps4::turbo_count_packet_t pkt{};
    pkt.pid          = pid;
    pkt.base_address = base;
    pkt.valueType    = valtype;
    pkt.compareType  = cmptype;
    pkt.lenData      = needs_val ? static_cast<uint32_t>(data.size()) : vlen;
    pkt.flags        = flags;
    if (!c.send_cmd(ps4::CMD_TURBO_COUNT, &pkt, sizeof(pkt))) { r.error = 2; return r; }
    uint32_t st = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 3; return r; }
    if (needs_val && !c.send_all(data.data(), data.size())) { r.error = 4; return r; }
    if (arrbytes && !c.send_all(mask.data(), mask.size())) { r.error = 4; return r; }

    if (resident) {
        // list- or snapshot-resident: optional progress words, sentinel,
        // u64 survivor count, trailing status
        out.resident = true;
        if (!turbo_read_progress(c, 0, progress, kTurboTimeoutMs)) { r.error = 5; return r; }
        uint64_t n = 0;
        if (!c.recv_all(&n, sizeof(n), kTurboTimeoutMs)) { r.error = 6; return r; }
        out.count = n;
        if (!c.recv_u32(st, kTurboTimeoutMs) || st != ps4::CMD_SUCCESS) { r.error = 7; return r; }
        r.ok = true;
        return r;
    }

    uint32_t serr = 0;
    if (!scan_stream_count_chunks(c, base, cmptype, vlen, prev, out.hits, serr, kTurboTimeoutMs)) {
        r.error = 10 + serr; return r;
    }
    out.count = out.hits.size();
    if (!c.recv_u32(st, kTurboTimeoutMs) || st != ps4::CMD_SUCCESS) { r.error = 20; return r; }
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_turbo_get(uint32_t start, uint32_t count, uint32_t value_len,
                                         std::vector<ps4_turbo_record_t>& out) {
    io_result_t r;
    out.clear();
    if (value_len == 0 || value_len > 0x1000) { r.error = ERROR_INVALID_PARAMETER; return r; }
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    if (!c.connected()) { r.error = 1; return r; }
    ps4::turbo_get_packet_t pkt{};
    pkt.start_index = start;
    pkt.count       = count;
    if (!c.send_cmd(ps4::CMD_TURBO_GET, &pkt, sizeof(pkt))) { r.error = 2; return r; }
    uint32_t st = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 3; return r; }
    uint32_t hdr = 0;
    if (!c.recv_u32(hdr, kTurboTimeoutMs)) { r.error = 4; return r; }
    const uint32_t n = hdr & ~ps4::kTurboGetHasFirst;
    const bool has_first = (hdr & ps4::kTurboGetHasFirst) != 0;
    if (n > count) { r.error = 5; return r; }
    const size_t ent = 8 + static_cast<size_t>(value_len) * (has_first ? 3 : 2);
    out.reserve(n);
    std::vector<uint8_t> buf;
    uint32_t done = 0;
    while (done < n) {
        const uint32_t batch = std::min<uint32_t>(n - done, static_cast<uint32_t>(0x40000 / ent + 1));
        buf.resize(batch * ent);
        if (!c.recv_all(buf.data(), buf.size(), kTurboTimeoutMs)) { r.error = 6; return r; }
        for (uint32_t i = 0; i < batch; ++i) {
            const uint8_t* p = buf.data() + i * ent;
            ps4_turbo_record_t rec;
            std::memcpy(&rec.addr, p, 8);
            rec.current.assign(p + 8, p + 8 + value_len);
            rec.previous.assign(p + 8 + value_len, p + 8 + 2 * value_len);
            if (has_first) rec.first.assign(p + 8 + 2 * value_len, p + 8 + 3 * value_len);
            out.push_back(std::move(rec));
        }
        done += batch;
    }
    if (!c.recv_u32(st, kTurboTimeoutMs) || st != ps4::CMD_SUCCESS) { r.error = 7; return r; }
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_turbo_end() {
    io_result_t r;
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    if (!c.connected()) { r.error = 1; return r; }
    if (!c.send_cmd(ps4::CMD_TURBO_END, nullptr, 0)) { r.error = 2; return r; }
    uint32_t st = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 3; return r; }
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_turbo_config(uint32_t ram_thresh_mb, const std::string& spill_dir) {
    io_result_t r;
    if (spill_dir.size() > 63) { r.error = ERROR_INVALID_PARAMETER; return r; }   // payload cap
    std::vector<uint8_t> body(sizeof(ps4::turbo_config_packet_t) + spill_dir.size());
    ps4::turbo_config_packet_t pkt{};
    pkt.ram_thresh_mb  = ram_thresh_mb;
    pkt.spill_path_len = static_cast<uint32_t>(spill_dir.size());
    std::memcpy(body.data(), &pkt, sizeof(pkt));
    if (!spill_dir.empty())
        std::memcpy(body.data() + sizeof(pkt), spill_dir.data(), spill_dir.size());
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    if (!c.connected()) { r.error = 1; return r; }
    if (!c.send_cmd(ps4::CMD_TURBO_CONFIG, body.data(), static_cast<uint32_t>(body.size()))) {
        r.error = 2; return r;
    }
    uint32_t st = 0;
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 3; return r; }
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_turbo_regions(uint32_t pid, uint32_t max, uint32_t probe_bytes,
                                             std::vector<ps4_turbo_region_t>& out) {
    io_result_t r;
    out.clear();
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    if (!c.connected()) { r.error = 1; return r; }
    ps4::turbo_regions_packet_t pkt{};
    pkt.pid = pid; pkt.max = max; pkt.probe_bytes = probe_bytes;
    if (!c.send_cmd(ps4::CMD_TURBO_REGIONS, &pkt, sizeof(pkt))) { r.error = 2; return r; }
    uint32_t st = 0;
    // the payload times a read of every region before answering
    if (!c.recv_u32(st, kTurboTimeoutMs) || st != ps4::CMD_SUCCESS) { r.error = 3; return r; }
    uint32_t n = 0;
    if (!c.recv_u32(n) || n > 8192) { r.error = 4; return r; }
    std::vector<ps4::turbo_region_info_t> wire(n);
    if (n && !c.recv_all(wire.data(), n * sizeof(ps4::turbo_region_info_t))) { r.error = 5; return r; }
    if (!c.recv_u32(st) || st != ps4::CMD_SUCCESS) { r.error = 6; return r; }
    out.reserve(n);
    for (const auto& w : wire)
        out.push_back({w.start, w.end, w.prot, w.flags, w.mbps});
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_turbo_cancel(uint32_t pid, std::string& err) {
    io_result_t r;
    if (pid == 0) { r.error = ERROR_INVALID_PARAMETER; err = "pid must be nonzero"; return r; }
    // host/port are only written under conn->mu on connect, but the main
    // connection may be busy streaming the very scan we want to stop, so
    // read them without blocking on that mutex
    std::string host;
    uint16_t port = 0;
    {
        auto& m = *m_impl->conn;
        if (!m.connected()) { r.error = 1; err = "not connected"; return r; }
        host = m.host;
        port = m.port;
    }
    conn_t side;
    if (!side.open(host, port, err)) { r.error = 2; return r; }
    bool authed = false;
    if (!impl_t::auth_locked(side, authed, 0x3, err)) { side.close(); r.error = 3; return r; }
    const uint32_t body = pid;
    if (!side.send_cmd(ps4::CMD_TURBO_CANCEL, &body, sizeof(body))) {
        side.close(); r.error = 4; err = "cancel send failed"; return r;
    }
    uint32_t st = 0;
    const bool got = side.recv_u32(st);
    side.close();
    if (!got || st != ps4::CMD_SUCCESS) { r.error = 5; err = "cancel rejected"; return r; }
    r.ok = true;
    return r;
}

// ---------------------------------------------------------------------------
// NetVar1337 fork extensions: module list, one-shot region snapshot, and
// connection bookkeeping

uint64_t backend_ps4_t::ps4_connection_generation() const noexcept {
    return m_impl->conn->generation.load();
}

uint32_t backend_ps4_t::ps4_take_last_status() noexcept {
    return m_impl->conn->last_status.exchange(0);
}

int backend_ps4_t::ps4_fork_extensions() const noexcept {
    return m_impl->fork_ext;
}

io_result_t backend_ps4_t::ps4_modules(uint32_t pid, std::vector<module_info_t>& out) {
    io_result_t r;
    out.clear();
    if (m_impl->fork_ext == 0) { r.error = 100; return r; }   // known upstream payload
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    if (!c.connected()) { r.error = 1; return r; }
    ps4::proc_maps_packet_t pkt{};
    pkt.pid = pid;
    if (!c.send_cmd(ps4::CMD_PROC_MODULES, &pkt, sizeof(pkt))) { r.error = 2; return r; }
    uint32_t st = 0;
    if (!c.recv_u32(st)) { r.error = 3; return r; }
    if (st != ps4::CMD_SUCCESS) {
        // upstream answers an unknown command with plain CMD_ERROR (and then
        // drops us); the fork's own failures use CMD_ERR_PID / CMD_DATA_NULL
        if (m_impl->fork_ext == -1)
            m_impl->fork_ext = (st == ps4::CMD_ERROR) ? 0 : 1;
        r.error = m_impl->fork_ext == 0 ? 100 : 4;
        return r;
    }
    m_impl->fork_ext = 1;
    uint32_t num = 0;
    if (!c.recv_u32(num) || num > kMaxListEntries) { r.error = 5; return r; }
    std::vector<ps4::proc_module_entry_t> ents(num);
    if (num && !c.recv_all(ents.data(), num * sizeof(ps4::proc_module_entry_t))) {
        r.error = 6; return r;
    }
    out.reserve(num);
    for (const auto& e : ents) {
        module_info_t mi;
        mi.path = fixed_str(e.name, sizeof(e.name));
        mi.name = base_name(mi.path);
        mi.base = static_cast<uintptr_t>(e.base);
        mi.size = static_cast<uint32_t>(std::min<uint64_t>(e.size, 0xFFFFFFFFull));
        out.push_back(std::move(mi));
    }
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_snapshot(uint32_t pid, uint64_t addr, uint64_t len,
                                        const std::function<bool(const uint8_t*, size_t)>& sink) {
    io_result_t r;
    if (len == 0 || addr + len < addr) { r.error = ERROR_INVALID_PARAMETER; return r; }
    if (m_impl->fork_ext == 0) { r.error = 100; return r; }
    // the payload stops streaming (and drops the client) at the first page it
    // cannot read, so refuse ranges the vm map says are not fully readable
    std::vector<ps4::vm_map_entry_t> maps;
    uint32_t merr = 0;
    if (m_impl->maps_cached(pid, maps, merr) &&
        !impl_t::covered_by(maps, addr, len, ps4::kVmProtRead)) {
        r.error = 2;
        return r;
    }
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    if (!c.connected()) { r.error = 1; return r; }
    ps4::proc_snapshot_packet_t pkt{};
    pkt.pid = pid;
    pkt.address = addr;
    pkt.length = len;
    if (!c.send_cmd(ps4::CMD_PROC_SNAPSHOT, &pkt, sizeof(pkt))) { r.error = 3; return r; }
    uint32_t st = 0;
    if (!c.recv_u32(st)) { r.error = 4; return r; }
    if (st != ps4::CMD_SUCCESS) {
        if (m_impl->fork_ext == -1)
            m_impl->fork_ext = (st == ps4::CMD_ERROR) ? 0 : 1;
        r.error = m_impl->fork_ext == 0 ? 100 : 5;
        return r;
    }
    m_impl->fork_ext = 1;
    std::vector<uint8_t> buf(ps4::kSnapshotChunk);
    uint64_t left = len;
    while (left > 0) {
        const size_t n = static_cast<size_t>(std::min<uint64_t>(left, ps4::kSnapshotChunk));
        if (!c.recv_all(buf.data(), n)) {
            // short stream: the payload hit an unreadable page and closed the
            // connection; the next command reconnects
            r.error = 6;
            r.bytes = static_cast<size_t>(len - left);
            return r;
        }
        if (sink && !sink(buf.data(), n)) {
            // the caller gave up mid-stream: drain so the stream stays in sync
            left -= n;
            while (left > 0) {
                const size_t m = static_cast<size_t>(std::min<uint64_t>(left, ps4::kSnapshotChunk));
                if (!c.recv_all(buf.data(), m)) break;
                left -= m;
            }
            r.error = 7;
            r.bytes = static_cast<size_t>(len - left);
            return r;
        }
        left -= n;
    }
    r.ok = true;
    r.bytes = static_cast<size_t>(len);
    return r;
}

io_result_t backend_ps4_t::ps4_disasm_region(uint32_t pid, uint64_t addr, uint32_t len,
                                             uint32_t max_entries,
                                             std::vector<ps4_disasm_entry_t>& out,
                                             bool* truncated) {
    out.clear();
    if (truncated) *truncated = false;
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->long_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    ps4::proc_disasm_packet_t pkt{};
    pkt.pid = pid; pkt.address = addr; pkt.length = len;
    pkt.max_entries = max_entries ? max_entries : 4096;
    if (!c.send_cmd(ps4::CMD_PROC_DISASM_REGION, &pkt, sizeof(pkt))) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    // read to the sentinel no matter what: abandoning the loop early would
    // leave entry bytes in the socket for the next command to misread
    for (;;) {
        ps4::disasm_instr_entry_t e{};
        if (!c.recv_all(&e, sizeof(e))) return wire_fail(c);
        const bool sentinel = e.addr == 0xFFFFFFFFFFFFFFFFull && e.length == 0xFF;
        if (sentinel) break;
        if (out.size() >= pkt.max_entries) {
            if (truncated) *truncated = true;
            continue;   // drained, not kept
        }
        ps4_disasm_entry_t d;
        d.addr = e.addr; d.rip_rel_target = e.rip_rel_target; d.mem_disp = e.mem_disp;
        d.length = e.length; d.kind = e.kind; d.mem_base_reg = e.mem_base_reg;
        d.mem_index_reg = e.mem_index_reg; d.mem_scale = e.mem_scale;
        d.mnemonic_lo = e.mnemonic_lo;
        out.push_back(d);
    }
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_extract_xrefs(uint32_t pid, uint64_t addr, uint32_t len,
                                             uint32_t max_instrs,
                                             std::vector<uint64_t>& targets, bool* truncated) {
    targets.clear();
    if (truncated) *truncated = false;
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->long_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    ps4::proc_disasm_packet_t pkt{};
    pkt.pid = pid; pkt.address = addr; pkt.length = len;
    pkt.max_entries = max_instrs ? max_instrs : 10000000;
    if (!c.send_cmd(ps4::CMD_PROC_EXTRACT_CODE_XREFS, &pkt, sizeof(pkt))) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    bool trunc = false;
    if (!drain_u64_stream(c, targets, 0x1000000, trunc)) return wire_fail(c);
    if (truncated) *truncated = trunc;
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_find_xrefs_to(uint32_t pid, uint64_t addr, uint32_t len,
                                             uint64_t target, std::vector<uint64_t>& addrs,
                                             bool* truncated) {
    addrs.clear();
    if (truncated) *truncated = false;
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->long_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    ps4::proc_xrefs_to_packet_t pkt{};
    pkt.pid = pid; pkt.scan_address = addr; pkt.scan_length = len; pkt.target_address = target;
    if (!c.send_cmd(ps4::CMD_PROC_FIND_XREFS_TO, &pkt, sizeof(pkt))) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    bool trunc = false;
    if (!drain_u64_stream(c, addrs, 0x1000000, trunc)) return wire_fail(c);
    if (truncated) *truncated = trunc;
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_read_stack(uint32_t pid, uint64_t rbp, uint64_t rsp,
                                          uint32_t depth, std::vector<ps4_stack_frame_t>& frames) {
    frames.clear();
    std::vector<uint8_t> buf;
    {
        auto& c = *m_impl->conn;
        cmd_lock_t lk(c, m_impl->long_budget_ms);
        if (!c.connected()) return err_result(ps4::kErrNotConnected);
        ps4::proc_read_stack_packet_t pkt{};
        pkt.pid = pid; pkt.rbp = rbp; pkt.rsp = rsp;
        pkt.depth = depth ? depth : 1;
        if (!c.send_cmd(ps4::CMD_PROC_READ_STACK, &pkt, sizeof(pkt))) return wire_fail(c);
        io_result_t r;
        if (!expect_success(c, r)) return r;
        uint32_t bundle_len = 0;
        if (!c.recv_u32(bundle_len)) return wire_fail(c);
        if (bundle_len < 4 || bundle_len > 4u * 1024u * 1024u) {
            c.fail(ps4::kErrProtocol, "stack bundle of " + std::to_string(bundle_len) + " bytes");
            return wire_fail(c);
        }
        buf.resize(bundle_len);
        if (!c.recv_all(buf.data(), bundle_len)) return wire_fail(c);
    }
    // the bundle is fully consumed; parse errors below leave the stream in sync
    uint32_t n_frames = 0;
    std::memcpy(&n_frames, buf.data(), 4);
    size_t off = 4;
    for (uint32_t i = 0; i < n_frames && off + 44 <= buf.size(); ++i) {
        ps4_stack_frame_t f;
        std::memcpy(&f.rbp, buf.data() + off, 8);       off += 8;
        std::memcpy(&f.rsp, buf.data() + off, 8);       off += 8;
        std::memcpy(&f.saved_rbp, buf.data() + off, 8); off += 8;
        std::memcpy(&f.ret_addr, buf.data() + off, 8);  off += 8;
        uint32_t locals_len = 0, code_len = 0;
        std::memcpy(&f.flags, buf.data() + off, 4);     off += 4;
        std::memcpy(&locals_len, buf.data() + off, 4);  off += 4;
        std::memcpy(&code_len, buf.data() + off, 4);    off += 4;
        if (static_cast<uint64_t>(off) + locals_len + code_len > buf.size()) break;
        f.locals.assign(buf.begin() + static_cast<ptrdiff_t>(off),
                        buf.begin() + static_cast<ptrdiff_t>(off + locals_len));
        off += locals_len;
        f.code.assign(buf.begin() + static_cast<ptrdiff_t>(off),
                      buf.begin() + static_cast<ptrdiff_t>(off + code_len));
        off += code_len;
        frames.push_back(std::move(f));
    }
    io_result_t r;
    if (frames.size() != n_frames) {
        // truncated/corrupt bundle: keep what parsed, but say so
        r.error = ps4::kErrProtocol;
        r.bytes = frames.size();
        return r;
    }
    r.ok = true;
    r.bytes = frames.size();
    return r;
}

io_result_t backend_ps4_t::ps4_assemble(uint64_t base_addr, uint32_t syntax,
                                        const std::string& asm_text,
                                        std::vector<uint8_t>& out_bytes, uint32_t& insn_count,
                                        std::string& asm_err) {
    out_bytes.clear();
    insn_count = 0;
    asm_err.clear();
    if (asm_text.size() > 0x100000) return err_result(ps4::kErrBadArg);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    ps4::proc_assemble_packet_t pkt{};
    pkt.base_addr = base_addr;
    pkt.ks_opt_syntax = syntax;
    const uint32_t bodylen = sizeof(pkt) + static_cast<uint32_t>(asm_text.size());
    // header advertises packet + text; the text follows as part of the body
    ps4::packet_header_t hdr{ps4::kPacketMagic, ps4::CMD_PROC_ASSEMBLE, bodylen};
    if (!c.send_all(&hdr, sizeof(hdr)) || !c.send_all(&pkt, sizeof(pkt))) return wire_fail(c);
    if (!asm_text.empty() && !c.send_all(asm_text.data(), asm_text.size())) return wire_fail(c);
    uint32_t st = 0;
    if (!c.recv_u32(st)) return wire_fail(c);
    io_result_t r;
    if (st == ps4::CMD_SUCCESS) {
        ps4::proc_assemble_ok_t ok{};
        if (!c.recv_all(&ok, sizeof(ok))) return wire_fail(c);
        if (ok.byte_len > 0x10000) {
            c.fail(ps4::kErrProtocol, "assemble reply of " + std::to_string(ok.byte_len) + " bytes");
            return wire_fail(c);
        }
        out_bytes.resize(ok.byte_len);
        if (ok.byte_len && !c.recv_all(out_bytes.data(), ok.byte_len)) return wire_fail(c);
        insn_count = ok.insn_count;
        r.ok = true;
        return r;
    }
    if (st == ps4::CMD_ERROR) {
        ps4::proc_assemble_err_t e{};
        if (!c.recv_all(&e, sizeof(e))) return wire_fail(c);
        if (e.msg_len > 4096) {
            c.fail(ps4::kErrProtocol, "assembler error message of " + std::to_string(e.msg_len) + " bytes");
            return wire_fail(c);
        }
        asm_err.resize(e.msg_len);
        if (e.msg_len && !c.recv_all(asm_err.data(), e.msg_len)) return wire_fail(c);
        r.error = ps4::kErrAsm;   // assembler reported an error; message in asm_err
        return r;
    }
    r.error = ps4::status_to_err(st);
    if (r.error == ps4::kErrProtocol) c.fail(r.error, "assemble reply " + hex32(st));
    return r;
}

io_result_t backend_ps4_t::ps4_elf_load(uint32_t pid, const std::vector<uint8_t>& elf) {
    if (elf.empty() || elf.size() > ps4::kMaxIoLen) return err_result(ps4::kErrBadArg);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->long_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    ps4::proc_elf_packet_t pkt{};
    pkt.pid = pid; pkt.length = static_cast<uint32_t>(elf.size());
    if (!c.send_cmd(ps4::CMD_PROC_ELF, &pkt, sizeof(pkt))) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    if (!c.send_all(elf.data(), elf.size())) return wire_fail(c);
    if (!expect_success(c, r)) return r;
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_elf_rpc(uint32_t pid, const std::vector<uint8_t>& elf, uint64_t& entry) {
    entry = 0;
    if (elf.empty() || elf.size() > ps4::kMaxIoLen) return err_result(ps4::kErrBadArg);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->long_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    ps4::proc_elf_packet_t pkt{};
    pkt.pid = pid; pkt.length = static_cast<uint32_t>(elf.size());
    if (!c.send_cmd(ps4::CMD_PROC_ELF_RPC, &pkt, sizeof(pkt))) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    if (!c.send_all(elf.data(), elf.size())) return wire_fail(c);
    ps4::proc_elf_rpc_response_t resp{};
    if (!c.recv_all(&resp, sizeof(resp))) return wire_fail(c);
    entry = resp.entry;
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_console_notify(uint32_t message_type, const std::string& text) {
    if (text.size() > 1024) return err_result(ps4::kErrBadArg);
    std::string msg = text;
    if (msg.empty() || msg.back() != '\0') msg.push_back('\0');   // payload requires NUL
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    ps4::console_notify_packet_t pkt{};
    pkt.messageType = message_type ? message_type : ps4::kNotifyTypeGeneric;
    pkt.length = static_cast<uint32_t>(msg.size());
    if (!c.send_cmd(ps4::CMD_CONSOLE_NOTIFY, &pkt, sizeof(pkt))) return wire_fail(c);
    if (!c.send_all(msg.data(), msg.size())) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_console_print(const std::string& text) {
    if (text.empty() || text.size() > 4096) return err_result(ps4::kErrBadArg);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    const uint32_t len = static_cast<uint32_t>(text.size());
    if (!c.send_cmd(ps4::CMD_CONSOLE_PRINT, &len, sizeof(len))) return wire_fail(c);
    if (!c.send_all(text.data(), text.size())) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_foreground_app(ps4_app_info_t& out) {
    out = ps4_app_info_t{};
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    if (!c.send_cmd(ps4::CMD_CONSOLE_FOREGROUND_APP, nullptr, 0)) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    ps4::console_foreground_app_response_t resp{};
    if (!c.recv_all(&resp, sizeof(resp))) return wire_fail(c);
    out.pid       = resp.pid;
    out.titleid   = fixed_str(resp.titleid, sizeof(resp.titleid));
    out.contentid = fixed_str(resp.contentid, sizeof(resp.contentid));
    out.name      = fixed_str(resp.name, sizeof(resp.name));
    out.app_ver   = fixed_str(resp.app_ver, sizeof(resp.app_ver));
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_get_fpregs(uint32_t lwpid, uint8_t out[832]) {
    if (m_impl->dbg_pid.load() == 0) return err_result(ps4::kErrNotAttached);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    ps4::debug_lwpid_packet_t pkt{};
    pkt.lwpid = lwpid;
    if (!c.send_cmd(ps4::CMD_DEBUG_GETFPREGS, &pkt, sizeof(pkt))) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    if (!c.recv_all(out, ps4::kFpregsSize)) return wire_fail(c);
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_set_fpregs(uint32_t lwpid, const uint8_t* data, uint32_t len) {
    if (m_impl->dbg_pid.load() == 0) return err_result(ps4::kErrNotAttached);
    if (!data || len == 0 || len > 848) return err_result(ps4::kErrBadArg);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    ps4::debug_setregs_packet_t pkt{};
    pkt.lwpid = lwpid;
    pkt.length = len;
    if (!c.send_cmd(ps4::CMD_DEBUG_SETFPREGS, &pkt, sizeof(pkt))) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;   // pre-data status
    if (!c.send_all(data, len)) return wire_fail(c);
    if (!expect_success(c, r)) return r;   // post-data status
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_set_dbregs(uint32_t lwpid, const uint8_t dr[128]) {
    if (m_impl->dbg_pid.load() == 0) return err_result(ps4::kErrNotAttached);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    ps4::debug_setregs_packet_t pkt{};
    pkt.lwpid = lwpid;
    pkt.length = ps4::kDbregsSize;
    if (!c.send_cmd(ps4::CMD_DEBUG_SETDBREGS, &pkt, sizeof(pkt))) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    if (!c.send_all(dr, ps4::kDbregsSize)) return wire_fail(c);
    if (!expect_success(c, r)) return r;
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_get_fsgsbase(uint32_t lwpid, uint64_t& fs_base, uint64_t& gs_base) {
    fs_base = gs_base = 0;
    if (m_impl->dbg_pid.load() == 0) return err_result(ps4::kErrNotAttached);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    ps4::debug_lwpid_packet_t pkt{};
    pkt.lwpid = lwpid;
    if (!c.send_cmd(ps4::CMD_DEBUG_GETFSGSBASE, &pkt, sizeof(pkt))) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    uint8_t buf[16]{};
    if (!c.recv_all(buf, sizeof(buf))) return wire_fail(c);
    std::memcpy(&fs_base, buf, 8);
    std::memcpy(&gs_base, buf + 8, 8);
    r.ok = true;
    return r;
}

io_result_t backend_ps4_t::ps4_set_fsgsbase(uint32_t lwpid, uint64_t fs_base, uint64_t gs_base) {
    if (m_impl->dbg_pid.load() == 0) return err_result(ps4::kErrNotAttached);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps4::kErrNotConnected);
    ps4::debug_setregs_packet_t pkt{};
    pkt.lwpid = lwpid;
    pkt.length = 16;
    if (!c.send_cmd(ps4::CMD_DEBUG_SETFSGSBASE, &pkt, sizeof(pkt))) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    uint8_t buf[16]{};
    std::memcpy(buf, &fs_base, 8);
    std::memcpy(buf + 8, &gs_base, 8);
    if (!c.send_all(buf, sizeof(buf))) return wire_fail(c);
    if (!expect_success(c, r)) return r;
    r.ok = true;
    return r;
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
