// src/core/runtime/backend_ps5.cpp
// Remote PS5 backend over the ps5debug-NG wire protocol (TCP 744).
// Wire formats verified against the payload sources (common/include/protocol.h
// and PROTOCOL.md of ps5debug-NG v1.3.2): every request is a 12-byte header
// {magic, cmd, datalen} followed by datalen body bytes, all little-endian;
// replies start with a u32 status word unless noted.
//
// Failure model: every exchange runs under the connection mutex with a
// whole-command deadline on top of the per-chunk idle timeout. Any send/recv
// failure, timeout or malformed reply closes the socket (the stream can no
// longer be trusted), so connected() goes false and every later call fails
// fast instead of paying another timeout. reconnect() restores the session.

#include "core/runtime/backend_ps5.hpp"
#include "core/runtime/ps5_protocol.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "core/infra/clock.hpp"
#include "core/infra/diag.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <iterator>
#include <map>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

namespace slop::core::runtime {

namespace infra = slop::core::infra;

namespace {

constexpr int     kDefaultIoTimeoutMs = 10000;   // idle time per chunk
constexpr int64_t kDefaultCmdBudgetMs = 60000;   // whole command
constexpr int     kShortTimeoutMs     = 500;     // optional trailing status words
constexpr int     kConnectTimeoutMs   = 5000;
constexpr uint32_t kMaxListEntries    = 1u << 20;   // protocol sanity ceiling
constexpr int64_t kMapsCacheTtlMs     = 1500;
constexpr uint32_t kThreadInfoBatch   = 64;      // pipelined THREAD_INFO requests

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

std::string fixed_str(const char* s, size_t cap) {
    size_t n = 0;
    while (n < cap && s[n] != '\0') ++n;
    return std::string(s, n);
}

std::string base_name(const std::string& path) {
    const size_t slash = path.find_last_of("/\\");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

// ---------------------------------------------------------------------------
// conn_t: one TCP connection to the ps5debug-NG command server

class conn_t {
public:
    std::atomic<SOCKET> fd{INVALID_SOCKET};
    std::mutex mu;   // serializes whole command exchanges

    // guarded by mu: the exchange in progress
    int64_t  deadline_ms   = 0;     // steady clock; 0 = none
    int      io_timeout_ms = kDefaultIoTimeoutMs;
    uint32_t last_err      = 0;     // ps5::io_err_t of the last failure
    std::atomic<uint32_t> last_status{0};  // last error status word seen

    // invoked under mu when an I/O failure invalidates the socket
    std::function<void(uint32_t code, const std::string& why)> on_lost;

    // current endpoint; "" when never opened
    std::string host;
    uint16_t    port = 0;

    // bumped by every fresh connect(); handles remember the epoch they were
    // created in so a handle never reaches a different console
    std::atomic<uint64_t> epoch{0};

    bool connected() const noexcept {
        return fd.load(std::memory_order_acquire) != INVALID_SOCKET;
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
        if (s == INVALID_SOCKET) { last_err = ps5::kErrNotConnected; return false; }
        const char* p = static_cast<const char*>(buf);
        size_t left = len;
        while (left > 0) {
            const int budget = wait_budget_ms();
            if (budget < 0) return fail(ps5::kErrTimeout, "command deadline exceeded while sending");
            const int w = wait_sock(s, true, budget);
            if (w == 0) return fail(ps5::kErrTimeout, "console stopped accepting data (send timeout)");
            if (w < 0) return fail(ps5::kErrSendFailed, "select failed while sending (WSA " +
                                                         std::to_string(WSAGetLastError()) + ")");
            const int n = ::send(s, p, static_cast<int>(left > 0x10000 ? 0x10000 : left), 0);
            if (n <= 0) return fail(ps5::kErrSendFailed, "send failed (WSA " +
                                                         std::to_string(WSAGetLastError()) + ")");
            p    += n;
            left -= static_cast<size_t>(n);
        }
        return true;
    }

    bool recv_all(void* buf, size_t len) {
        const SOCKET s = fd.load(std::memory_order_acquire);
        if (s == INVALID_SOCKET) { last_err = ps5::kErrNotConnected; return false; }
        char* p = static_cast<char*>(buf);
        size_t left = len;
        while (left > 0) {
            const int budget = wait_budget_ms();
            if (budget < 0) return fail(ps5::kErrTimeout, "command deadline exceeded while receiving");
            const int w = wait_sock(s, false, budget);
            if (w == 0) return fail(ps5::kErrTimeout, "console did not answer within " +
                                                      std::to_string(budget) + " ms");
            if (w < 0) return fail(ps5::kErrRecvFailed, "select failed while receiving (WSA " +
                                                        std::to_string(WSAGetLastError()) + ")");
            const int n = ::recv(s, p, static_cast<int>(left > 0x10000 ? 0x10000 : left), 0);
            if (n == 0) return fail(ps5::kErrRecvFailed, "console closed the connection");
            if (n < 0) return fail(ps5::kErrRecvFailed, "recv failed (WSA " +
                                                        std::to_string(WSAGetLastError()) + ")");
            p    += n;
            left -= static_cast<size_t>(n);
        }
        return true;
    }

    bool recv_u32(uint32_t& v) {
        if (!recv_all(&v, sizeof(v))) return false;
        // remember error status words so callers can explain a failure
        if (ps5::status_name(v)[0] != '\0') last_status = v;
        return true;
    }

    // an optional trailing word: none when nothing arrives within timeout_ms
    // (stream still in sync), failed when a partial word or error broke it
    enum class opt_t { got, none, failed };
    opt_t recv_u32_optional(uint32_t& v, int timeout_ms) {
        const SOCKET s = fd.load(std::memory_order_acquire);
        if (s == INVALID_SOCKET) { last_err = ps5::kErrNotConnected; return opt_t::failed; }
        const int w = wait_sock(s, false, timeout_ms);
        if (w == 0) return opt_t::none;
        if (w < 0) { fail(ps5::kErrRecvFailed, "select failed"); return opt_t::failed; }
        return recv_u32(v) ? opt_t::got : opt_t::failed;
    }

    // send one request header + body; the caller then drives the reply
    bool send_cmd(uint32_t cmd, const void* body, uint32_t bodylen) {
        if (bodylen > ps5::kMaxDatalen) { last_err = ps5::kErrBadArg; return false; }
        ps5::packet_header_t hdr{};
        hdr.magic   = ps5::kPacketMagic;
        hdr.cmd     = cmd;
        hdr.datalen = bodylen;
        if (!send_all(&hdr, sizeof(hdr))) return false;
        if (bodylen > 0 && body) return send_all(body, bodylen);
        return true;
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
    r.error = c.last_err ? c.last_err : ps5::kErrNotConnected;
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
    if (st == ps5::CMD_SUCCESS) return true;
    r.error = ps5::status_to_err(st);
    if (r.error == ps5::kErrProtocol)
        c.fail(ps5::kErrProtocol, "expected a status word, got " + hex32(st) + " (stream desync)");
    return false;
}

// ---------------------------------------------------------------------------
// prot translation: callers pass Windows PAGE_* constants, ps5debug wants
// FreeBSD VM_PROT_* bits

uint32_t win_to_vm_prot(uint32_t page) {
    page &= ~(0x100u | 0x200u | 0x400u);   // drop PAGE_GUARD/NOCACHE/WRITECOMBINE
    switch (page) {
    case 0x01: return ps5::kVmProtNone;                     // PAGE_NOACCESS
    case 0x02: return ps5::kVmProtRead;                     // PAGE_READONLY
    case 0x04: return ps5::kVmProtRead | ps5::kVmProtWrite; // PAGE_READWRITE
    case 0x08: return ps5::kVmProtRead | ps5::kVmProtWrite; // PAGE_WRITECOPY
    case 0x10: return ps5::kVmProtExec;                     // PAGE_EXECUTE
    case 0x20: return ps5::kVmProtRead | ps5::kVmProtExec;  // PAGE_EXECUTE_READ
    case 0x40: return ps5::kVmProtAll;                      // PAGE_EXECUTE_READWRITE
    case 0x80: return ps5::kVmProtAll;                      // PAGE_EXECUTE_WRITECOPY
    default:   return ps5::kVmProtAll;
    }
}

uint32_t vm_to_win_prot(uint16_t vm) {
    static const uint32_t kTable[8] = { 0x01, 0x02, 0x04, 0x04, 0x10, 0x20, 0x40, 0x40 };
    return kTable[vm & 0x7];
}

void reg64_from_ctx(ps5::reg64_t& r, const thread_context_t& c) {
    r = {};
    r.r15 = c.r15; r.r14 = c.r14; r.r13 = c.r13; r.r12 = c.r12;
    r.r11 = c.r11; r.r10 = c.r10; r.r9  = c.r9;  r.r8  = c.r8;
    r.rdi = c.rdi; r.rsi = c.rsi; r.rbp = c.rbp; r.rbx = c.rbx;
    r.rdx = c.rdx; r.rcx = c.rcx; r.rax = c.rax;
    r.rip = c.rip; r.rsp = c.rsp; r.rflags = c.flags;
}

void ctx_from_reg64(thread_context_t& c, const ps5::reg64_t& r) {
    c = {};
    c.r15 = r.r15; c.r14 = r.r14; c.r13 = r.r13; c.r12 = r.r12;
    c.r11 = r.r11; c.r10 = r.r10; c.r9  = r.r9;  c.r8  = r.r8;
    c.rdi = r.rdi; c.rsi = r.rsi; c.rbp = r.rbp; c.rbx = r.rbx;
    c.rdx = r.rdx; c.rcx = r.rcx; c.rax = r.rax;
    c.rip = r.rip; c.rsp = r.rsp; c.flags = r.rflags;
}

ps5_segment_t segment_from_entry(const ps5::vm_map_entry_t& m) {
    ps5_segment_t s;
    s.start  = m.start;
    s.end    = m.end;
    s.offset = m.offset;
    s.prot   = m.prot;
    s.name   = fixed_str(m.name, sizeof(m.name));
    return s;
}

// ---------------------------------------------------------------------------
// event_listener_t: accepts the payload->client debug-event connection on 755.
// CMD_DEBUG_ATTACH fails payload-side unless it can connect back to us, so we
// listen and drain interrupt packets (0x4A0 bytes each) for the session life.

class event_listener_t {
public:
    ~event_listener_t() { stop(); }

    // set once before start() and never mutated afterwards; both run on the
    // listener thread. on_closed gets the attach id that was in flight when
    // the connection was accepted
    std::function<void(const uint8_t* pkt)> on_packet;
    std::function<void(uint64_t attach_id)> on_closed;
    std::atomic<uint64_t> current_attach{0};

    // Only the console we attached to may deliver stop events: port 755 is
    // bound on every interface because the payload connects back to us, so
    // without this any LAN host could forge a stop (fake RIP) or a SIGKILL.
    // 0 = no filter yet (before the first attach).
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

    bool start(uint16_t port, std::string& err) {
        // a stop() in flight closes the socket and joins the accept thread
        // without holding mu_ the whole time; starting in that window would
        // return true for a listener that no longer accepts
        for (int i = 0; i < 200 && stopping_.load(std::memory_order_acquire); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::lock_guard lk(mu_);
        if (running_ && !stop_ && listen_fd_.load() != INVALID_SOCKET) {
            if (port == port_) return true;
            err = "debug-event listener already bound to port " + std::to_string(port_);
            return false;
        }
        wsa();
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
                  std::to_string(e) + "); the payload always connects back to port 755, so "
                  "close whatever holds it and retry";
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

private:
    // drain one event connection on its own thread so a silent peer cannot
    // block accept() and starve the console's connect-back
    void drain(SOCKET c, uint64_t attach_id) {
        ps4_event_reassembler_t ra(ps5::kDebugEventSize);
        DWORD rt = 500;   // short recv timeout so stop_ is noticed with no traffic
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&rt), sizeof(rt));
        uint8_t buf[0x8000];
        bool peer_closed = false;
        while (!stop_) {
            const int n = ::recv(c, reinterpret_cast<char*>(buf), sizeof(buf), 0);
            if (n == 0) { peer_closed = true; break; }
            if (n < 0) {
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
    std::atomic<bool> stopping_{false};
    std::vector<std::thread> conns_;   // guarded by mu_
    uint16_t port_ = 0;
    std::thread th_;
    std::atomic<bool> stop_{false};
    std::atomic<bool> running_{false};
};

struct attach_state_t {
    uint32_t pid = 0;
    uint64_t epoch = 0;
    conn_t*  conn = nullptr;
    std::string name;
    std::string path;
};

} // namespace

namespace ps5 {

std::string io_error_str(uint32_t code) {
    switch (code) {
    case kErrNone:          return "ok";
    case kErrNotConnected:  return "not connected to a PS5 console (target.ps5_connect, or "
                                   "target.ps5_reconnect after a dropped connection)";
    case kErrSendFailed:    return "send to the console failed; the connection was dropped "
                                   "(target.ps5_reconnect restores it)";
    case kErrRecvFailed:    return "the console closed the connection or a receive failed; "
                                   "the connection was dropped (target.ps5_reconnect restores it)";
    case kErrTimeout:       return "the console did not answer in time (idle or whole-command "
                                   "deadline); the connection was dropped to keep the stream in "
                                   "sync (target.ps5_reconnect restores it)";
    case kErrStatus:        return "the payload rejected the command (CMD_ERROR): bad pid/address, "
                                   "process gone, or the operation is not allowed";
    case kErrProtocol:      return "malformed reply from the payload (stream desync); the "
                                   "connection was dropped";
    case kErrBadArg:        return "invalid argument (rejected before anything was sent)";
    case kErrUnmapped:      return "address range is not mapped (or lacks the needed protection) "
                                   "in the target process";
    case kErrNotAttached:   return "no ps5 debug session (debugger.ps5_attach first)";
    case kErrAlreadyDebug:  return "the payload is already debugging a process on this "
                                   "connection (CMD_ALREADY_DEBUG)";
    case kErrDataNull:      return "the payload reported CMD_DATA_NULL (missing data or an "
                                   "unsupported request)";
    case kErrTooMuchData:   return "the payload reported CMD_TOO_MUCH_DATA (request too large)";
    case kErrNoSlot:        return "no free slot (30 software breakpoints / 4 hardware "
                                   "watchpoints); clear one first";
    case kErrNotArmed:      return "that slot/address is not armed by this client";
    case kErrStaleHandle:   return "the target handle belongs to an earlier console connection; "
                                   "attach again";
    case kErrInvalidIndex:  return "the payload rejected the slot index (CMD_INVALID_INDEX)";
    case kErrListen:        return "cannot listen on the debug-event port 755 (the payload "
                                   "connects back there); is another program using it?";
    case kErrDetachFailed:  return "the payload refused to detach the previous debuggee; it is "
                                   "still being debugged";
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

} // namespace ps5

// ---------------------------------------------------------------------------
// backend impl

struct backend_ps5_t::impl_t {
    impl_t() {
        conn->on_lost = [this](uint32_t code, const std::string& why) { on_conn_lost(code, why); };
        listener.on_packet = [this](const uint8_t* pkt) { push_event(pkt); };
        listener.on_closed = [this](uint64_t id) { on_event_channel_closed(id); };
    }

    // tuning
    int      io_timeout_ms = kDefaultIoTimeoutMs;
    int64_t  cmd_budget_ms = kDefaultCmdBudgetMs;
    uint16_t event_port    = ps5::kDebugPort;

    std::shared_ptr<conn_t> conn = std::make_shared<conn_t>();

    // handshake facts + endpoint bookkeeping
    mutable std::mutex info_mu;
    std::string host;            // current endpoint ("" when not connected)
    uint16_t    port = 0;
    std::string last_host;       // remembered for reconnect
    uint16_t    last_port = 0;
    std::string branding, caps, version;
    uint16_t    fw = 0, platform = 0;
    bool        lost = false;
    std::string lost_reason;
    uint32_t    lost_dbg_pid = 0;    // debuggee the dropped connection had
    std::atomic<uint64_t> drops{0};

    // debug session. dbg_mu orders dbg_pid transitions against the listener's
    // channel-closed notification
    std::mutex dbg_mu;
    std::atomic<uint32_t> dbg_pid{0};
    uint64_t attach_counter = 0;     // ids handed to ATTACH attempts (dbg_mu)
    uint64_t live_attach = 0;        // id of the attach that is live (dbg_mu)
    event_listener_t listener;

    // debug event queue, fed by the port-755 listener thread
    std::mutex ev_mu;
    std::condition_variable ev_cv;
    std::deque<ps5_event_t> evq;
    std::atomic<uint64_t> ev_received{0};
    std::atomic<uint64_t> ev_dropped{0};

    // breakpoint / watchpoint slot records
    struct slot_rec_t {
        enum state_t : uint8_t { free_, reserved, armed };
        state_t  st = free_;
        uint64_t addr = 0;
        uint32_t len = 0, type = 0;
    };
    mutable std::mutex slot_mu;
    std::array<slot_rec_t, ps5::kMaxSwBreakpoints> bps{};
    std::array<slot_rec_t, ps5::kMaxWatchpoints>   wps{};
    bool     slots_stale = false;    // connection dropped, awaiting reconnect
    uint64_t slot_gen = 0;           // bumped whenever the records are wiped

    // live attach states (a handle from another backend, or one already
    // detached, is never dereferenced) and handles per pid, so dropping one
    // stale session never ends the debug session another handle relies on
    mutable std::mutex attach_mu;
    std::set<const void*> live_states;
    std::map<uint32_t, int> attach_refs;

    // maps cache so read-coverage checks don't hammer the console
    std::mutex cache_mu;
    uint32_t cache_pid = 0;
    int64_t  cache_at = 0;
    std::vector<ps5::vm_map_entry_t> cache;

    bool is_live(const void* p) const {
        std::lock_guard lk(attach_mu);
        return p && live_states.count(p) != 0;
    }

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
        {
            std::lock_guard lk(slot_mu);
            slots_stale = true;   // the payload dropped them with the connection
        }
        drops.fetch_add(1);
        invalidate_maps_cache();
        infra::diag::warn("ps5", "console connection lost (" + ps5::io_error_str(code) +
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

    // the debug session is over (detach, SIGKILL, channel closed): drop the
    // per-session records. keep_slots: the console connection died with the
    // session, so the records still describe what was armed and are re-armed
    // after a reconnect (only marked stale). Caller holds dbg_mu.
    void end_debug_session_locked(const std::string& why, bool keep_slots = false) {
        if (keep_slots) {
            std::lock_guard lk(slot_mu);
            slots_stale = true;
        } else {
            wipe_slots();
        }
        if (dbg_pid.exchange(0) != 0 && !why.empty())
            infra::diag::info("ps5", "debug session ended: " + why);
    }

    // ---- events -------------------------------------------------------
    void push_event(const uint8_t* pkt) {
        ps5_event_t e{};
        // the port-755 packet layout is identical to ps4debug's, so the PS4
        // decoder parses it
        if (!ps4_decode_event(pkt, ps5::kDebugEventSize, e)) return;
        ev_received.fetch_add(1);
        {
            std::lock_guard lk(ev_mu);
            if (evq.size() >= backend_ps5_t::kMaxQueuedEvents) {
                evq.pop_front();
                ev_dropped.fetch_add(1);
            }
            evq.push_back(std::move(e));
        }
        ev_cv.notify_one();
    }

    void on_event_channel_closed(uint64_t attach_id) {
        std::lock_guard lk(dbg_mu);
        // only the channel of the live attach with a live debuggee means "the
        // session is gone": failed attach attempts, earlier sessions and the
        // window a reconnect spends with dbg_pid == 0 close their channels too
        if (attach_id == 0 || attach_id != live_attach || dbg_pid.load() == 0) return;
        end_debug_session_locked("debug event channel closed by the payload");
    }

    void clear_events() {
        std::lock_guard lk(ev_mu);
        evq.clear();
    }

    // ---- maps ---------------------------------------------------------
    void invalidate_maps_cache() {
        std::lock_guard lk(cache_mu);
        cache_pid = 0;
        cache_at  = 0;
        cache.clear();
    }

    bool fetch_maps(uint32_t pid, std::vector<ps5::vm_map_entry_t>& out, uint32_t& err) {
        auto& c = *conn;
        cmd_lock_t lk(c, cmd_budget_ms);
        if (!c.connected()) { err = ps5::kErrNotConnected; return false; }
        ps5::proc_maps_packet_t pkt{};
        pkt.pid = pid;
        if (!c.send_cmd(ps5::CMD_PROC_MAPS, &pkt, sizeof(pkt))) { err = c.last_err; return false; }
        io_result_t r;
        if (!expect_success(c, r)) { err = r.error; return false; }
        uint32_t num = 0;
        if (!c.recv_u32(num)) { err = c.last_err; return false; }
        if (num > kMaxListEntries) {
            c.fail(ps5::kErrProtocol, "maps reply claims " + std::to_string(num) + " entries");
            err = ps5::kErrProtocol;
            return false;
        }
        out.resize(num);
        if (num > 0 && !c.recv_all(out.data(), num * sizeof(ps5::vm_map_entry_t))) {
            err = c.last_err;
            return false;
        }
        return true;
    }

    bool maps_cached(uint32_t pid, std::vector<ps5::vm_map_entry_t>& out, uint32_t& err) {
        {
            std::lock_guard lk(cache_mu);
            if (cache_pid == pid && cache_at != 0 &&
                infra::steady_ms() - cache_at < kMapsCacheTtlMs) {
                out = cache;
                return true;
            }
        }
        std::vector<ps5::vm_map_entry_t> fresh;
        if (!fetch_maps(pid, fresh, err)) return false;
        std::lock_guard lk(cache_mu);
        cache_pid = pid;
        cache_at  = infra::steady_ms();
        cache = fresh;
        out = std::move(fresh);
        return true;
    }

    static bool covered_by(const std::vector<ps5::vm_map_entry_t>& maps,
                           uint64_t addr, uint64_t len, uint16_t prot_bit) {
        if (len == 0) return true;
        const uint64_t end = addr + len;
        uint64_t cur = addr;
        int guard = 0;
        while (cur < end && guard++ < 1 << 20) {
            const ps5::vm_map_entry_t* hit = nullptr;
            for (const auto& m : maps) {
                if (m.start <= cur && cur < m.end) { hit = &m; break; }
            }
            if (!hit || (hit->prot & prot_bit) == 0) return false;
            cur = hit->end;
        }
        return cur >= end;
    }

    static const ps5::vm_map_entry_t* find_map(const std::vector<ps5::vm_map_entry_t>& maps,
                                               uint64_t addr) {
        for (const auto& m : maps)
            if (m.start <= addr && addr < m.end) return &m;
        return nullptr;
    }

    // ---- handshake ----------------------------------------------------
    // runs with conn->mu held
    bool handshake(conn_t& c, std::string& err) {
        std::string ver, brand;
        uint32_t len = 0;
        if (!c.send_cmd(ps5::CMD_VERSION, nullptr, 0)) { err = "no answer to CMD_VERSION"; return false; }
        if (!c.recv_u32(len) || len == 0 || len > 256) { err = "bad CMD_VERSION length"; return false; }
        ver.resize(len);
        if (!c.recv_all(ver.data(), len)) { err = "CMD_VERSION string short"; return false; }

        if (!c.send_cmd(ps5::CMD_BRANDING, nullptr, 0)) { err = "no answer to CMD_BRANDING"; return false; }
        if (!c.recv_u32(len) || len == 0 || len > 1024) { err = "bad CMD_BRANDING length"; return false; }
        brand.resize(len);
        if (!c.recv_all(brand.data(), len)) { err = "CMD_BRANDING string short"; return false; }

        uint16_t fw_bcd = 0;
        if (!c.send_cmd(ps5::CMD_FW_VERSION, nullptr, 0) || !c.recv_all(&fw_bcd, sizeof(fw_bcd))) {
            err = "no answer to CMD_FW_VERSION";
            return false;
        }
        uint16_t plat = 0;
        if (!c.send_cmd(ps5::CMD_PLATFORM_ID, nullptr, 0) || !c.recv_all(&plat, sizeof(plat))) {
            err = "no answer to CMD_PLATFORM_ID";
            return false;
        }
        if (plat != ps5::kPlatformPs5) {
            err = "the server reports platform id " + std::to_string(plat) +
                  ", not a PS5 (5); is this a ps4debug payload?";
            return false;
        }
        io_result_t r;
        if (!c.send_cmd(ps5::CMD_PROC_NOP, nullptr, 0) || !expect_success(c, r)) {
            err = "the server did not answer CMD_PROC_NOP";
            return false;
        }

        std::string caps_str;
        const size_t nul = brand.find('\0');
        std::string human = brand;
        if (nul != std::string::npos) {
            human = brand.substr(0, nul);
            caps_str = brand.substr(nul + 1);
            while (!caps_str.empty() && caps_str.back() == '\0') caps_str.pop_back();
        }
        std::lock_guard lk(info_mu);
        version  = ver;
        branding = human;
        caps     = caps_str;
        fw       = fw_bcd;
        platform = plat;
        return true;
    }

    // ---- debug attach -------------------------------------------------
    // lazy debug attach; the payload allows one debuggee per connection.
    // keep_slots: reconnect path, the records are re-armed afterwards
    uint32_t ensure_debug(uint32_t pid, std::string& detail, bool keep_slots = false) {
        auto& c = *conn;
        cmd_lock_t lk(c, cmd_budget_ms);
        if (!c.connected()) { detail = "not connected to a PS5 console"; return ps5::kErrNotConnected; }
        const uint32_t cur = dbg_pid.load();
        if (cur == pid) return 0;
        if (cur != 0) {
            // detach the previous debuggee and check the reply: if the payload
            // still debugs it, ATTACH would only say CMD_ALREADY_DEBUG
            if (!c.send_cmd(ps5::CMD_DEBUG_DETACH, nullptr, 0)) {
                detail = "detach of pid " + std::to_string(cur) + " failed: " +
                         ps5::io_error_str(c.last_err);
                return c.last_err;
            }
            io_result_t dr;
            if (!expect_success(c, dr)) {
                detail = "the payload refused to detach pid " + std::to_string(cur) +
                         "; it is still being debugged, so pid " + std::to_string(pid) +
                         " cannot be attached";
                return ps5::kErrDetachFailed;
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
            return ps5::kErrListen;
        }
        uint64_t id = 0;
        {
            std::lock_guard dl(dbg_mu);
            id = ++attach_counter;
        }
        listener.current_attach.store(id);
        ps5::debug_attach_packet_t pkt{};
        pkt.pid = pid;
        if (!c.send_cmd(ps5::CMD_DEBUG_ATTACH, &pkt, sizeof(pkt))) {
            detail = "CMD_DEBUG_ATTACH send failed: " + ps5::io_error_str(c.last_err);
            return c.last_err;
        }
        io_result_t ar;
        if (!expect_success(c, ar)) {
            if (ar.error == ps5::kErrAlreadyDebug)
                detail = "the payload reports CMD_ALREADY_DEBUG: this connection already has "
                         "a debuggee server-side (client thought: " +
                         (cur ? "pid " + std::to_string(cur) : std::string("none")) + ")";
            else
                detail = "the payload refused CMD_DEBUG_ATTACH for pid " + std::to_string(pid) +
                         " (process gone, not debuggable, or the payload could not connect "
                         "back to port " + std::to_string(event_port) + ")";
            return ar.error;
        }
        {
            std::lock_guard dl(dbg_mu);
            live_attach = id;
            dbg_pid = pid;
            if (!keep_slots) wipe_slots();
        }
        clear_events();   // fresh debug session: drop stale events
        return 0;
    }

    // ---- slot wire helpers --------------------------------------------
    io_result_t wire_set_bp(uint32_t index, bool enabled, uint64_t addr) {
        if (index >= ps5::kMaxSwBreakpoints) return err_result(ps5::kErrBadArg);
        if (dbg_pid.load() == 0) return err_result(ps5::kErrNotAttached);
        auto& c = *conn;
        cmd_lock_t lk(c, cmd_budget_ms);
        if (!c.connected()) return err_result(ps5::kErrNotConnected);
        ps5::debug_set_breakpoint_packet_t pkt{};
        pkt.index   = index;
        pkt.enabled = enabled ? 1 : 0;
        pkt.address = addr;
        if (!c.send_cmd(ps5::CMD_DEBUG_SET_BREAKPOINT, &pkt, sizeof(pkt))) return wire_fail(c);
        io_result_t r;
        if (!expect_success(c, r)) return r;
        r.ok = true;
        return r;
    }

    io_result_t wire_set_wp(uint32_t index, bool enabled, uint32_t len, uint32_t type,
                            uint64_t addr) {
        if (index >= ps5::kMaxWatchpoints) return err_result(ps5::kErrBadArg);
        if (len != 1 && len != 2 && len != 4 && len != 8) return err_result(ps5::kErrBadArg);
        if (dbg_pid.load() == 0) return err_result(ps5::kErrNotAttached);
        auto& c = *conn;
        cmd_lock_t lk(c, cmd_budget_ms);
        if (!c.connected()) return err_result(ps5::kErrNotConnected);
        ps5::debug_set_watchpoint_packet_t pkt{};
        pkt.index     = index;
        pkt.enabled   = enabled ? 1 : 0;
        pkt.length    = ps5::wp_dr7_length(len);
        pkt.breaktype = type;
        pkt.address   = addr;
        if (!c.send_cmd(ps5::CMD_DEBUG_SET_WATCHPOINT, &pkt, sizeof(pkt))) return wire_fail(c);
        io_result_t r;
        if (!expect_success(c, r)) return r;
        r.ok = true;
        return r;
    }

    template <size_t N>
    io_result_t arm(std::array<slot_rec_t, N>& tab, bool bp, uint64_t addr, uint32_t len,
                    uint32_t type, uint32_t index, uint32_t& out_index, bool* reused) {
        if (reused) *reused = false;
        if (dbg_pid.load() == 0) return err_result(ps5::kErrNotAttached);
        uint32_t idx = 0;
        slot_rec_t prev{};
        uint64_t gen = 0;
        {
            std::lock_guard lk(slot_mu);
            if (index == backend_ps5_t::kAutoSlot) {
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
                if (!found) return err_result(ps5::kErrNoSlot);
            } else {
                if (index >= N) return err_result(ps5::kErrBadArg);
                if (tab[index].st == slot_rec_t::reserved) return err_result(ps5::kErrNoSlot);
                idx = index;
                if (reused) *reused = tab[idx].st == slot_rec_t::armed && tab[idx].addr == addr;
            }
            if (tab[idx].st == slot_rec_t::reserved) return err_result(ps5::kErrNoSlot);
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
    io_result_t disarm(std::array<slot_rec_t, N>& tab, bool bp, uint32_t index,
                       uint64_t* out_addr) {
        slot_rec_t prev{};
        uint64_t gen = 0;
        {
            std::lock_guard lk(slot_mu);
            if (index >= N) return err_result(ps5::kErrBadArg);
            if (tab[index].st != slot_rec_t::armed) return err_result(ps5::kErrNotArmed);
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
    std::vector<backend_ps5_t::ps5_slot_t> list_slots(const std::array<slot_rec_t, N>& tab) const {
        std::lock_guard lk(slot_mu);
        std::vector<backend_ps5_t::ps5_slot_t> out;
        for (uint32_t i = 0; i < N; ++i) {
            if (tab[i].st != slot_rec_t::armed) continue;
            backend_ps5_t::ps5_slot_t s;
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
        if (!is_live(h.native)) { err = ps5::kErrBadArg; return nullptr; }
        auto* st = static_cast<attach_state_t*>(h.native);
        if (st->conn != conn.get()) { err = ps5::kErrBadArg; return nullptr; }
        if (st->epoch != conn->epoch.load()) { err = ps5::kErrStaleHandle; return nullptr; }
        if (!conn->connected()) { err = ps5::kErrNotConnected; return nullptr; }
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
        invalidate_maps_cache();
    }
};

// ---------------------------------------------------------------------------
// connection management

backend_ps5_t::backend_ps5_t() : m_impl(std::make_unique<impl_t>()) {}
backend_ps5_t::~backend_ps5_t() { disconnect(); }

void backend_ps5_t::set_timeouts(int io_timeout_ms, int64_t command_budget_ms) {
    auto& c = *m_impl->conn;
    std::lock_guard lk(c.mu);
    m_impl->io_timeout_ms = io_timeout_ms > 0 ? io_timeout_ms : kDefaultIoTimeoutMs;
    m_impl->cmd_budget_ms = command_budget_ms > 0 ? command_budget_ms : kDefaultCmdBudgetMs;
    c.io_timeout_ms = m_impl->io_timeout_ms;
}

void backend_ps5_t::set_event_port(uint16_t port) {
    m_impl->event_port = port ? port : ps5::kDebugPort;
}

bool backend_ps5_t::connect(const std::string& host, uint16_t port, std::string& err) {
    auto& c = *m_impl->conn;
    {
        std::lock_guard lk(m_impl->info_mu);
        if (c.connected() && m_impl->host == host && m_impl->port == port) return true;
    }
    disconnect();   // a different console (or a dropped one): start clean
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.open(host, port, err)) return false;
    c.last_status = 0;
    if (!m_impl->handshake(c, err)) {
        err = "handshake with " + host + ":" + std::to_string(port) +
              " failed (not a ps5debug-NG server?): " + err;
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

void backend_ps5_t::disconnect() {
    auto& c = *m_impl->conn;
    {
        cmd_lock_t lk(c, m_impl->cmd_budget_ms);
        if (c.connected() && m_impl->dbg_pid.load() != 0) {
            if (c.send_cmd(ps5::CMD_DEBUG_DETACH, nullptr, 0)) {
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
        m_impl->caps.clear();
        m_impl->version.clear();
        m_impl->fw = 0;
        m_impl->platform = 0;
    }
    m_impl->clear_lost();
}

bool backend_ps5_t::connected() const noexcept {
    return m_impl->conn->connected();
}

bool backend_ps5_t::lost() const noexcept {
    std::lock_guard lk(m_impl->info_mu);
    return m_impl->lost;
}

std::string backend_ps5_t::lost_reason() const {
    std::lock_guard lk(m_impl->info_mu);
    return m_impl->lost_reason;
}

uint64_t backend_ps5_t::drop_count() const noexcept {
    return m_impl->drops.load();
}

std::string backend_ps5_t::last_endpoint() const {
    std::lock_guard lk(m_impl->info_mu);
    if (m_impl->last_host.empty()) return {};
    return m_impl->last_host + ":" + std::to_string(m_impl->last_port);
}

bool backend_ps5_t::reconnect(std::string& err, reconnect_report_t* report) {
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
        err = "no previous console endpoint to reconnect to (use target.ps5_connect)";
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
        if (!m_impl->handshake(c, err)) {
            err = "handshake with " + host + ":" + std::to_string(port) + " failed: " + err;
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
    rep.handshake_ok = true;
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
        if (e != 0) rep.debug_error = detail.empty() ? ps5::io_error_str(e) : detail;
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

bool backend_ps5_t::ping() {
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return false;
    if (!c.send_cmd(ps5::CMD_PROC_NOP, nullptr, 0)) return false;
    io_result_t r;
    return expect_success(c, r);
}

std::string backend_ps5_t::endpoint() const {
    if (!connected()) return {};
    std::lock_guard lk(m_impl->info_mu);
    if (m_impl->host.empty()) return {};
    return m_impl->host + ":" + std::to_string(m_impl->port);
}

std::string backend_ps5_t::branding() const {
    std::lock_guard lk(m_impl->info_mu);
    return m_impl->branding;
}

std::string backend_ps5_t::server_caps() const {
    std::lock_guard lk(m_impl->info_mu);
    return m_impl->caps;
}

std::string backend_ps5_t::server_version() const {
    std::lock_guard lk(m_impl->info_mu);
    return m_impl->version;
}

uint16_t backend_ps5_t::fw_version() const noexcept {
    std::lock_guard lk(m_impl->info_mu);
    return m_impl->fw;
}

std::string backend_ps5_t::fw_string() const {
    const uint16_t fw = fw_version();
    // the payload reports major*100+minor (meta.c), so 900 is 9.00 and 1240 is
    // 12.40; 0 and 0xFFFF are the payload's "unknown" sentinels
    if (fw == 0 || fw == 0xFFFFu) return {};
    char b[16];
    std::snprintf(b, sizeof(b), "%u.%02u", static_cast<unsigned>(fw / 100u),
                  static_cast<unsigned>(fw % 100u));
    return b;
}

uint16_t backend_ps5_t::platform_id() const noexcept {
    std::lock_guard lk(m_impl->info_mu);
    return m_impl->platform;
}

// ---------------------------------------------------------------------------
// identity

backend_kind_t backend_ps5_t::kind() const noexcept {
    return backend_kind_t::ps5;
}

const char* backend_ps5_t::badge() const noexcept {
    return "PS5";
}

// ---------------------------------------------------------------------------
// attach / detach

target_handle_t backend_ps5_t::attach(uint32_t pid) {
    target_handle_t t;
    auto& c = *m_impl->conn;

    // validate the pid and pull name/path via CMD_PROC_INFO; fall back to the
    // process list when info is unavailable
    std::string name, path;
    {
        cmd_lock_t lk(c, m_impl->cmd_budget_ms);
        if (!c.connected()) return t;
        ps5::proc_info_packet_t pkt{};
        pkt.pid = pid;
        if (!c.send_cmd(ps5::CMD_PROC_INFO, &pkt, sizeof(pkt))) return t;
        io_result_t r;
        if (expect_success(c, r)) {
            ps5::proc_info_response_t resp{};
            if (!c.recv_all(&resp, sizeof(resp))) return t;
            name = fixed_str(resp.name, sizeof(resp.name));
            path = fixed_str(resp.path, sizeof(resp.path));
        } else if (!c.connected()) {
            return t;
        }
        if (name.empty()) {
            if (!c.send_cmd(ps5::CMD_PROC_LIST, nullptr, 0)) return t;
            if (!expect_success(c, r)) return t;
            uint32_t num = 0;
            if (!c.recv_u32(num)) return t;
            if (num > kMaxListEntries) {
                c.fail(ps5::kErrProtocol, "process list claims " + std::to_string(num) + " entries");
                return t;
            }
            // one recv for the whole list, then look for the pid
            std::vector<ps5::proc_list_entry_t> ents(num);
            if (num && !c.recv_all(ents.data(), num * sizeof(ps5::proc_list_entry_t))) return t;
            bool found = false;
            for (const auto& e : ents) {
                if (static_cast<uint32_t>(e.pid) == pid) {
                    name  = fixed_str(e.name, sizeof(e.name));
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
    st->conn  = m_impl->conn.get();
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

void backend_ps5_t::detach(target_handle_t& h) {
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
            ps5_debug_detach();
        delete st;
    }
    h = {};
}

bool backend_ps5_t::handle_info(const target_handle_t& h, process_info_t& out) {
    if (!m_impl->is_live(h.native)) return false;
    const auto* st = static_cast<const attach_state_t*>(h.native);
    out = process_info_t{};
    out.pid       = st->pid;
    out.name      = st->name;
    out.path      = st->path;
    out.arch      = arch_t::x64;          // PS5 userland is x86-64
    out.elevation = elevation_t::system;  // the payload runs inside SceShellCore
    return true;
}

// ---------------------------------------------------------------------------
// memory

io_result_t backend_ps5_t::read_memory(const target_handle_t& h, uintptr_t addr,
                                       void* buf, size_t len) {
    if (len == 0) { io_result_t r; r.ok = true; return r; }
    if (len > ps5::kMaxIoLen) return err_result(ps5::kErrBadArg);
    uint32_t herr = 0;
    auto* st = m_impl->state_of(h, herr);
    if (!st) return err_result(herr);

    // the payload zero-fills unreadable pages and still reports success, so
    // check coverage against the vm map first to keep the reader contract
    // honest (false = any part unreadable). A maps failure is not fatal.
    std::vector<ps5::vm_map_entry_t> maps;
    uint32_t merr = 0;
    if (m_impl->maps_cached(st->pid, maps, merr) &&
        !impl_t::covered_by(maps, addr, len, ps5::kVmProtRead))
        return err_result(ps5::kErrUnmapped);

    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps5::kErrNotConnected);
    ps5::proc_read_packet_t pkt{};
    pkt.pid     = st->pid;
    pkt.address = addr;
    pkt.length  = static_cast<uint32_t>(len);
    if (!c.send_cmd(ps5::CMD_PROC_READ, &pkt, sizeof(pkt))) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    // the payload then streams exactly `length` bytes (64 KiB chunks)
    if (!c.recv_all(buf, len)) return wire_fail(c);
    r.ok    = true;
    r.bytes = len;
    return r;
}

io_result_t backend_ps5_t::write_memory(const target_handle_t& h, uintptr_t addr,
                                        const void* buf, size_t len) {
    if (len == 0) { io_result_t r; r.ok = true; return r; }
    if (len > ps5::kMaxIoLen) return err_result(ps5::kErrBadArg);
    uint32_t herr = 0;
    auto* st = m_impl->state_of(h, herr);
    if (!st) return err_result(herr);

    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps5::kErrNotConnected);
    ps5::proc_write_packet_t pkt{};
    pkt.pid     = st->pid;
    pkt.address = addr;
    pkt.length  = static_cast<uint32_t>(len);
    if (!c.send_cmd(ps5::CMD_PROC_WRITE, &pkt, sizeof(pkt))) return wire_fail(c);
    // two-phase: the payload acks, we stream the bytes, it sends the terminal
    // status after the read-back verification
    io_result_t r;
    if (!expect_success(c, r)) return r;
    if (!c.send_all(buf, len)) return wire_fail(c);
    if (!expect_success(c, r)) return r;
    r.ok    = true;
    r.bytes = len;
    return r;
}

io_result_t backend_ps5_t::protect_memory(const target_handle_t& h, uintptr_t addr,
                                          size_t len, uint32_t new_prot, uint32_t* old_prot) {
    uint32_t herr = 0;
    auto* st = m_impl->state_of(h, herr);
    if (!st) return err_result(herr);
    if (len == 0 || len > 0xFFFFFFFFull) return err_result(ps5::kErrBadArg);
    if (old_prot) {
        std::vector<ps5::vm_map_entry_t> maps;
        uint32_t merr = 0;
        if (m_impl->maps_cached(st->pid, maps, merr)) {
            if (auto* m = impl_t::find_map(maps, addr))
                *old_prot = vm_to_win_prot(m->prot);
        }
    }

    auto& c = *m_impl->conn;
    io_result_t r;
    {
        cmd_lock_t lk(c, m_impl->cmd_budget_ms);
        if (!c.connected()) return err_result(ps5::kErrNotConnected);
        ps5::proc_protect_packet_t pkt{};
        pkt.pid     = st->pid;
        pkt.address = addr;
        pkt.length  = static_cast<uint32_t>(len);
        pkt.newprot = win_to_vm_prot(new_prot);
        if (!c.send_cmd(ps5::CMD_PROC_PROTECT, &pkt, sizeof(pkt))) return wire_fail(c);
        if (!expect_success(c, r)) return r;
    }
    r.ok = true;
    m_impl->invalidate_maps_cache();
    return r;
}

io_result_t backend_ps5_t::allocate_memory(const target_handle_t& h, uintptr_t addr,
                                           size_t len, uint32_t prot, uintptr_t* out_addr) {
    if (len == 0 || len > ps5::kMaxIoLen) return err_result(ps5::kErrBadArg);
    uint32_t herr = 0;
    auto* st = m_impl->state_of(h, herr);
    if (!st) return err_result(herr);

    auto& c = *m_impl->conn;
    io_result_t r;
    {
        cmd_lock_t lk(c, m_impl->cmd_budget_ms);
        if (!c.connected()) return err_result(ps5::kErrNotConnected);
        if (addr != 0) {
            ps5::proc_alloc_hinted_packet_t pkt{};
            pkt.pid    = st->pid;
            pkt.hint   = addr;
            pkt.length = static_cast<uint32_t>(len);
            if (!c.send_cmd(ps5::CMD_PROC_ALLOC_HINTED, &pkt, sizeof(pkt))) return wire_fail(c);
        } else {
            ps5::proc_alloc_packet_t pkt{};
            pkt.pid    = st->pid;
            pkt.length = static_cast<uint32_t>(len);
            if (!c.send_cmd(ps5::CMD_PROC_ALLOC, &pkt, sizeof(pkt))) return wire_fail(c);
        }
        if (!expect_success(c, r)) return r;
        ps5::proc_alloc_response_t resp{};
        if (!c.recv_all(&resp, sizeof(resp))) return wire_fail(c);
        if (resp.address == 0) return err_result(ps5::kErrStatus);
        const uint64_t out = resp.address;

        if (out_addr) *out_addr = static_cast<uintptr_t>(out);
        r.ok    = true;
        r.bytes = len;
        // the payload allocates RW; tighten to the requested protection
        if (prot != 0) {
            ps5::proc_protect_packet_t pp{};
            pp.pid     = st->pid;
            pp.address = out;
            pp.length  = static_cast<uint32_t>(len);
            pp.newprot = win_to_vm_prot(prot);
            if (c.send_cmd(ps5::CMD_PROC_PROTECT, &pp, sizeof(pp))) {
                io_result_t pr;
                expect_success(c, pr);
            }
        }
    }
    m_impl->invalidate_maps_cache();
    return r;
}

io_result_t backend_ps5_t::free_memory(const target_handle_t& h, uintptr_t addr) {
    uint32_t herr = 0;
    auto* st = m_impl->state_of(h, herr);
    if (!st) return err_result(herr);

    std::vector<ps5::vm_map_entry_t> maps;
    uint32_t merr = 0;
    if (!m_impl->maps_cached(st->pid, maps, merr)) return err_result(merr);
    auto* m = impl_t::find_map(maps, addr);
    if (!m) return err_result(ps5::kErrUnmapped);

    auto& c = *m_impl->conn;
    io_result_t r;
    {
        cmd_lock_t lk(c, m_impl->cmd_budget_ms);
        if (!c.connected()) return err_result(ps5::kErrNotConnected);
        ps5::proc_free_packet_t pkt{};
        pkt.pid     = st->pid;
        pkt.address = m->start;
        pkt.length  = static_cast<uint32_t>(m->end - m->start);
        if (!c.send_cmd(ps5::CMD_PROC_FREE, &pkt, sizeof(pkt))) return wire_fail(c);
        if (!expect_success(c, r)) return r;
    }
    r.ok = true;
    m_impl->invalidate_maps_cache();
    return r;
}

// ---------------------------------------------------------------------------
// enumeration

enum_result_t<process_info_t> backend_ps5_t::enum_processes() {
    enum_result_t<process_info_t> res;
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) { res.error = ps5::kErrNotConnected; return res; }
    if (!c.send_cmd(ps5::CMD_PROC_LIST, nullptr, 0)) { res.error = c.last_err; return res; }
    io_result_t r;
    if (!expect_success(c, r)) { res.error = r.error; return res; }
    uint32_t num = 0;
    if (!c.recv_u32(num)) { res.error = c.last_err; return res; }
    if (num > kMaxListEntries) {
        c.fail(ps5::kErrProtocol, "process list claims " + std::to_string(num) + " entries");
        res.error = ps5::kErrProtocol;
        return res;
    }
    // the whole list in one receive, not one select+recv per 36-byte entry
    std::vector<ps5::proc_list_entry_t> ents(num);
    if (num && !c.recv_all(ents.data(), num * sizeof(ps5::proc_list_entry_t))) {
        res.error = c.last_err;
        return res;
    }
    res.items.reserve(num);
    for (const auto& e : ents) {
        process_info_t p;
        p.pid       = static_cast<uint32_t>(e.pid);
        p.name      = fixed_str(e.name, sizeof(e.name));
        p.arch      = arch_t::x64;          // PS5 userland is x86-64
        p.elevation = elevation_t::system;  // the payload runs inside SceShellCore
        res.items.push_back(std::move(p));
    }
    res.ok = true;
    return res;
}

enum_result_t<ps5_segment_t> backend_ps5_t::ps5_maps(const target_handle_t& h) {
    enum_result_t<ps5_segment_t> res;
    uint32_t herr = 0;
    auto* st = m_impl->state_of(h, herr);
    if (!st) { res.error = herr; return res; }
    std::vector<ps5::vm_map_entry_t> maps;
    uint32_t err = 0;
    if (!m_impl->fetch_maps(st->pid, maps, err)) { res.error = err; return res; }
    res.items.reserve(maps.size());
    for (const auto& m : maps) res.items.push_back(segment_from_entry(m));
    res.ok = true;
    return res;
}

enum_result_t<ps5_module_t> backend_ps5_t::ps5_modules(const target_handle_t& h) {
    enum_result_t<ps5_module_t> res;
    auto maps = ps5_maps(h);
    if (!maps.ok) { res.error = maps.error; return res; }
    res.items = ps4_coalesce_modules(std::move(maps.items));
    res.ok = true;
    return res;
}

enum_result_t<module_info_t> backend_ps5_t::enum_modules(const target_handle_t& h) {
    enum_result_t<module_info_t> res;
    // ps5debug-NG has no server-side module list (no CMD_PROC_MODULES), so
    // group the vm map by backing name: base = lowest start, size = span
    std::vector<ps5::vm_map_entry_t> maps;
    uint32_t err = 0;
    if (!m_impl->fetch_maps(h.pid, maps, err)) { res.error = err ? err : ps5::kErrStatus; return res; }
    for (const auto& m : maps) {
        const std::string name = fixed_str(m.name, sizeof(m.name));
        if (name.empty()) continue;
        auto it = std::find_if(res.items.begin(), res.items.end(),
                               [&](const module_info_t& x) { return x.path == name; });
        if (it == res.items.end()) {
            module_info_t mi;
            mi.base = static_cast<uintptr_t>(m.start);
            mi.size = static_cast<uint32_t>(std::min<uint64_t>(m.end - m.start, 0xFFFFFFFFull));
            mi.name = base_name(name);
            mi.path = name;
            res.items.push_back(std::move(mi));
            continue;
        }
        const uint64_t lo = std::min<uint64_t>(it->base, m.start);
        const uint64_t hi = std::max<uint64_t>(it->base + it->size, m.end);
        it->base = static_cast<uintptr_t>(lo);
        it->size = static_cast<uint32_t>(std::min<uint64_t>(hi - lo, 0xFFFFFFFFull));
    }
    res.ok = true;
    return res;
}

enum_result_t<thread_info_t> backend_ps5_t::enum_threads(uint32_t pid) {
    enum_result_t<thread_info_t> res;
    std::string detail;
    if (const uint32_t e = m_impl->ensure_debug(pid, detail)) { res.error = e; return res; }
    std::vector<uint32_t> lwpids;
    io_result_t io = ps5_thread_list(lwpids);
    if (!io.ok) { res.error = io.error; return res; }
    res.items.reserve(lwpids.size());
    for (uint32_t lwpid : lwpids) {
        thread_info_t t;
        t.tid       = lwpid;
        t.owner_pid = pid;
        res.items.push_back(t);
    }
    // enrich with priority/name via CMD_DEBUG_THREAD_INFO: requests go out in
    // pipelined batches (one roundtrip per batch, small enough that the
    // replies never fill the socket buffers while we are still sending)
    auto& c = *m_impl->conn;
    for (size_t at = 0; at < res.items.size(); at += kThreadInfoBatch) {
        const size_t n = std::min<size_t>(kThreadInfoBatch, res.items.size() - at);
        std::vector<uint8_t> batch;
        batch.reserve(n * (sizeof(ps5::packet_header_t) + sizeof(ps5::debug_lwpid_packet_t)));
        for (size_t i = 0; i < n; ++i) {
            ps5::packet_header_t hdr{ps5::kPacketMagic, ps5::CMD_DEBUG_THREAD_INFO,
                                     sizeof(ps5::debug_lwpid_packet_t)};
            ps5::debug_lwpid_packet_t tp{res.items[at + i].tid};
            const auto* hp = reinterpret_cast<const uint8_t*>(&hdr);
            const auto* bp = reinterpret_cast<const uint8_t*>(&tp);
            batch.insert(batch.end(), hp, hp + sizeof(hdr));
            batch.insert(batch.end(), bp, bp + sizeof(tp));
        }
        {
            cmd_lock_t lk(c, m_impl->cmd_budget_ms);
            if (!c.connected()) { res.error = ps5::kErrNotConnected; return res; }
            if (!c.send_all(batch.data(), batch.size())) { res.error = c.last_err; return res; }
            for (size_t i = 0; i < n; ++i) {
                io_result_t tr;
                if (!expect_success(c, tr)) {
                    if (!c.connected()) { res.error = tr.error; return res; }
                    continue;   // that thread is gone; the info is best effort
                }
                ps5::debug_thread_info_response_t info{};
                if (!c.recv_all(&info, sizeof(info))) { res.error = c.last_err; return res; }
                res.items[at + i].priority = static_cast<int32_t>(info.priority);
                res.items[at + i].name = fixed_str(info.name, sizeof(info.name));
            }
        }
    }
    res.ok = true;
    return res;
}

enum_result_t<region_info_t> backend_ps5_t::enum_regions(const target_handle_t& h) {
    enum_result_t<region_info_t> res;
    std::vector<ps5_segment_t> segs;
    if (!h.native && h.pid != 0) {
        // unattached pid-only query
        std::vector<ps5::vm_map_entry_t> raw;
        uint32_t err = 0;
        if (!m_impl->fetch_maps(h.pid, raw, err)) { res.error = err; return res; }
        segs.reserve(raw.size());
        for (const auto& m : raw) segs.push_back(segment_from_entry(m));
    } else {
        auto maps = ps5_maps(h);
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

enum_result_t<handle_info_t> backend_ps5_t::enum_handles(uint32_t /*pid*/) {
    // no Win32-style handle table is exposed by ps5debug-NG
    enum_result_t<handle_info_t> res;
    res.ok = true;
    return res;
}

// ---------------------------------------------------------------------------
// thread context

io_result_t backend_ps5_t::get_thread_context(uint32_t tid, thread_context_t& ctx) {
    return ps5_get_regs(tid, ctx);
}

io_result_t backend_ps5_t::set_thread_context(uint32_t tid, const thread_context_t& ctx) {
    return ps5_set_regs(tid, ctx);
}

io_result_t backend_ps5_t::ps5_get_regs(uint32_t lwpid, thread_context_t& ctx) {
    if (m_impl->dbg_pid.load() == 0) return err_result(ps5::kErrNotAttached);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps5::kErrNotConnected);
    ps5::debug_lwpid_packet_t pkt{};
    pkt.lwpid = lwpid;
    if (!c.send_cmd(ps5::CMD_DEBUG_GETREGS, &pkt, sizeof(pkt))) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    ps5::reg64_t reg{};
    if (!c.recv_all(&reg, sizeof(reg))) return wire_fail(c);
    ctx_from_reg64(ctx, reg);
    r.ok = true;
    return r;
}

io_result_t backend_ps5_t::ps5_set_regs(uint32_t lwpid, const thread_context_t& ctx) {
    if (m_impl->dbg_pid.load() == 0) return err_result(ps5::kErrNotAttached);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps5::kErrNotConnected);
    ps5::debug_setregs_packet_t pkt{};
    pkt.lwpid  = lwpid;
    pkt.length = sizeof(ps5::reg64_t);
    if (!c.send_cmd(ps5::CMD_DEBUG_SETREGS, &pkt, sizeof(pkt))) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;   // ack, then the register blob
    ps5::reg64_t reg{};
    reg64_from_ctx(reg, ctx);
    if (!c.send_all(&reg, sizeof(reg))) return wire_fail(c);
    if (!expect_success(c, r)) return r;   // terminal status
    r.ok    = true;
    r.bytes = sizeof(reg);
    return r;
}

// ---------------------------------------------------------------------------
// query

arch_t backend_ps5_t::query_arch(const target_handle_t& /*h*/) {
    return arch_t::x64;
}

elevation_t backend_ps5_t::query_elevation() {
    // the payload runs inside SceShellCore, so every target is reachable
    return elevation_t::system;
}

// ---------------------------------------------------------------------------
// debug session

bool backend_ps5_t::ps5_debug_attach(uint32_t pid, std::string& err) {
    if (pid == 0) { err = "ps5_debug_attach: pid is 0"; return false; }
    std::string detail;
    const uint32_t e = m_impl->ensure_debug(pid, detail);
    if (e != 0) {
        err = detail.empty() ? ps5::io_error_str(e) : detail;
        return false;
    }
    return true;
}

bool backend_ps5_t::ps5_debug_detach() {
    if (m_impl->dbg_pid.load() == 0) return true;
    auto& c = *m_impl->conn;
    {
        cmd_lock_t lk(c, m_impl->cmd_budget_ms);
        if (c.connected()) {
            if (c.send_cmd(ps5::CMD_DEBUG_DETACH, nullptr, 0)) {
                io_result_t r;
                expect_success(c, r);
            }
        }
    }
    m_impl->listener.stop();
    std::lock_guard dl(m_impl->dbg_mu);
    m_impl->live_attach = 0;
    m_impl->end_debug_session_locked("detached");
    return true;
}

bool backend_ps5_t::ps5_debug_attached() const noexcept {
    return m_impl->dbg_pid.load() != 0;
}

uint32_t backend_ps5_t::ps5_debug_pid() const noexcept {
    return m_impl->dbg_pid.load();
}

io_result_t backend_ps5_t::ps5_set_breakpoint(uint32_t index, bool enabled, uintptr_t addr) {
    return m_impl->wire_set_bp(index, enabled, addr);
}

io_result_t backend_ps5_t::ps5_set_watchpoint(uint32_t index, bool enabled, uint32_t len,
                                              uint32_t type, uintptr_t addr) {
    return m_impl->wire_set_wp(index, enabled, len, type, addr);
}

io_result_t backend_ps5_t::ps5_continue(uint32_t stop) {
    if (m_impl->dbg_pid.load() == 0) return err_result(ps5::kErrNotAttached);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps5::kErrNotConnected);
    ps5::debug_continue_packet_t pkt{};
    pkt.stop = stop;
    if (!c.send_cmd(ps5::CMD_DEBUG_CONTINUE, &pkt, sizeof(pkt))) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    r.ok = true;
    return r;
}

io_result_t backend_ps5_t::ps5_step(uint32_t lwpid) {
    if (m_impl->dbg_pid.load() == 0) return err_result(ps5::kErrNotAttached);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps5::kErrNotConnected);
    if (lwpid == 0) {
        if (!c.send_cmd(ps5::CMD_DEBUG_STEP, nullptr, 0)) return wire_fail(c);
    } else {
        ps5::debug_lwpid_packet_t pkt{};
        pkt.lwpid = lwpid;
        if (!c.send_cmd(ps5::CMD_DEBUG_STEP_THREAD, &pkt, sizeof(pkt))) return wire_fail(c);
    }
    io_result_t r;
    if (!expect_success(c, r)) return r;
    r.ok = true;
    return r;
}

io_result_t backend_ps5_t::ps5_suspend_thread(uint32_t lwpid) {
    if (m_impl->dbg_pid.load() == 0) return err_result(ps5::kErrNotAttached);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps5::kErrNotConnected);
    ps5::debug_lwpid_packet_t pkt{};
    pkt.lwpid = lwpid;
    if (!c.send_cmd(ps5::CMD_DEBUG_SUSPEND, &pkt, sizeof(pkt))) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    r.ok = true;
    return r;
}

io_result_t backend_ps5_t::ps5_resume_thread(uint32_t lwpid) {
    if (m_impl->dbg_pid.load() == 0) return err_result(ps5::kErrNotAttached);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps5::kErrNotConnected);
    ps5::debug_lwpid_packet_t pkt{};
    pkt.lwpid = lwpid;
    if (!c.send_cmd(ps5::CMD_DEBUG_RESUME, &pkt, sizeof(pkt))) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    r.ok = true;
    return r;
}

io_result_t backend_ps5_t::ps5_thread_list(std::vector<uint32_t>& lwpids) {
    lwpids.clear();
    if (m_impl->dbg_pid.load() == 0) return err_result(ps5::kErrNotAttached);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps5::kErrNotConnected);
    if (!c.send_cmd(ps5::CMD_DEBUG_GET_THREAD_LIST, nullptr, 0)) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    uint32_t num = 0;
    if (!c.recv_u32(num)) return wire_fail(c);
    if (num > kMaxListEntries) {
        c.fail(ps5::kErrProtocol, "thread list claims " + std::to_string(num) + " entries");
        return err_result(ps5::kErrProtocol);
    }
    lwpids.resize(num);
    if (num && !c.recv_all(lwpids.data(), num * sizeof(uint32_t))) return wire_fail(c);
    r.ok    = true;
    r.bytes = num * sizeof(uint32_t);
    return r;
}

// ---------------------------------------------------------------------------
// client-side slot bookkeeping

std::vector<backend_ps5_t::ps5_slot_t> backend_ps5_t::ps5_breakpoints() const {
    return m_impl->list_slots(m_impl->bps);
}

std::vector<backend_ps5_t::ps5_slot_t> backend_ps5_t::ps5_watchpoints() const {
    return m_impl->list_slots(m_impl->wps);
}

io_result_t backend_ps5_t::ps5_bp_arm(uint64_t addr, uint32_t index, uint32_t& out_index,
                                      bool* reused) {
    return m_impl->arm(m_impl->bps, true, addr, 0, 0, index, out_index, reused);
}

io_result_t backend_ps5_t::ps5_bp_disarm(uint32_t index, uint64_t* out_addr) {
    return m_impl->disarm(m_impl->bps, true, index, out_addr);
}

io_result_t backend_ps5_t::ps5_bp_disarm_addr(uint64_t addr, uint32_t* out_index) {
    uint32_t idx = 0;
    if (!m_impl->find_armed(m_impl->bps, addr, idx)) return err_result(ps5::kErrNotArmed);
    if (out_index) *out_index = idx;
    return m_impl->disarm(m_impl->bps, true, idx, nullptr);
}

io_result_t backend_ps5_t::ps5_wp_arm(uint64_t addr, uint32_t len, uint32_t type,
                                      uint32_t index, uint32_t& out_index, bool* reused) {
    return m_impl->arm(m_impl->wps, false, addr, len, type, index, out_index, reused);
}

io_result_t backend_ps5_t::ps5_wp_disarm(uint32_t index, uint64_t* out_addr) {
    return m_impl->disarm(m_impl->wps, false, index, out_addr);
}

io_result_t backend_ps5_t::ps5_wp_disarm_addr(uint64_t addr, uint32_t* out_index) {
    uint32_t idx = 0;
    if (!m_impl->find_armed(m_impl->wps, addr, idx)) return err_result(ps5::kErrNotArmed);
    if (out_index) *out_index = idx;
    return m_impl->disarm(m_impl->wps, false, idx, nullptr);
}

// ---------------------------------------------------------------------------
// debug events

size_t backend_ps5_t::ps5_pending_events() {
    std::lock_guard lk(m_impl->ev_mu);
    return m_impl->evq.size();
}

bool backend_ps5_t::ps5_wait_event(ps5_event_t& out, int timeout_ms) {
    std::unique_lock lk(m_impl->ev_mu);
    if (m_impl->evq.empty()) {
        if (timeout_ms <= 0) return false;
        m_impl->ev_cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                               [this] { return !m_impl->evq.empty(); });
    }
    if (m_impl->evq.empty()) return false;
    out = std::move(m_impl->evq.front());
    m_impl->evq.pop_front();
    return true;
}

std::vector<ps5_event_t> backend_ps5_t::ps5_drain_events(size_t max, bool clear) {
    std::vector<ps5_event_t> out;
    std::lock_guard lk(m_impl->ev_mu);
    if (clear) {
        out.assign(std::make_move_iterator(m_impl->evq.begin()),
                   std::make_move_iterator(m_impl->evq.end()));
        m_impl->evq.clear();
        return out;
    }
    const size_t n = std::min(max, m_impl->evq.size());
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(std::move(m_impl->evq.front()));
        m_impl->evq.pop_front();
    }
    return out;
}

uint64_t backend_ps5_t::ps5_events_received() const noexcept {
    return m_impl->ev_received.load();
}

uint64_t backend_ps5_t::ps5_events_dropped() const noexcept {
    return m_impl->ev_dropped.load();
}

// ---------------------------------------------------------------------------
// console

io_result_t backend_ps5_t::ps5_console_info(ps5_console_info_t& out) {
    out = ps5_console_info_t{};
    auto& c = *m_impl->conn;
    io_result_t r;
    {
        cmd_lock_t lk(c, m_impl->cmd_budget_ms);
        if (!c.connected()) return err_result(ps5::kErrNotConnected);
        if (!c.send_cmd(ps5::CMD_CONSOLE_INFO, nullptr, 0)) return wire_fail(c);
        if (!expect_success(c, r)) return r;
    }
    out.alive = true;
    out.endpoint = endpoint();
    out.branding = branding();
    out.caps     = server_caps();
    out.version  = server_version();
    out.fw       = fw_string();
    out.fw_bcd   = fw_version();
    out.platform = platform_id();
    out.debug_pid = ps5_debug_pid();
    out.drops    = drop_count();
    r.ok = true;
    return r;
}

io_result_t backend_ps5_t::ps5_notify(const std::string& text) {
    if (text.size() > ps5::kMaxConsoleMsg) return err_result(ps5::kErrBadArg);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps5::kErrNotConnected);
    // the payload expects the text plus a trailing NUL in the data phase
    ps5::console_notify_packet_t pkt{};
    pkt.messageType = ps5::kNotifyTypeGeneric;
    pkt.length      = static_cast<uint32_t>(text.size() + 1);
    if (!c.send_cmd(ps5::CMD_CONSOLE_NOTIFY, &pkt, sizeof(pkt))) return wire_fail(c);
    if (!c.send_all(text.c_str(), text.size() + 1)) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    r.ok    = true;
    r.bytes = text.size();
    return r;
}

io_result_t backend_ps5_t::ps5_print(const std::string& text) {
    if (text.size() > ps5::kMaxConsoleMsg) return err_result(ps5::kErrBadArg);
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps5::kErrNotConnected);
    ps5::console_print_packet_t pkt{};
    pkt.length = static_cast<uint32_t>(text.size());
    if (!c.send_cmd(ps5::CMD_CONSOLE_PRINT, &pkt, sizeof(pkt))) return wire_fail(c);
    if (!text.empty() && !c.send_all(text.data(), text.size())) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    r.ok    = true;
    r.bytes = text.size();
    return r;
}

io_result_t backend_ps5_t::ps5_foreground_app(ps5_app_info_t& out) {
    out = ps5_app_info_t{};
    auto& c = *m_impl->conn;
    cmd_lock_t lk(c, m_impl->cmd_budget_ms);
    if (!c.connected()) return err_result(ps5::kErrNotConnected);
    if (!c.send_cmd(ps5::CMD_CONSOLE_FOREGROUND_APP, nullptr, 0)) return wire_fail(c);
    io_result_t r;
    if (!expect_success(c, r)) return r;
    ps5::console_foreground_app_response_t resp{};
    if (!c.recv_all(&resp, sizeof(resp))) return wire_fail(c);
    out.pid       = resp.pid;
    out.titleid   = fixed_str(resp.titleid, sizeof(resp.titleid));
    out.contentid = fixed_str(resp.contentid, sizeof(resp.contentid));
    out.name      = fixed_str(resp.name, sizeof(resp.name));
    out.app_ver   = fixed_str(resp.app_ver, sizeof(resp.app_ver));
    r.ok = true;
    return r;
}

} // namespace slop::core::runtime
