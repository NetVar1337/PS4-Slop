// src/core/network/http_proxy.cpp
// accept thread + one owned thread per connection; every socket a connection
// thread blocks on is registered so stop() can unblock and join it

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "core/network/http_proxy.hpp"

#include "core/network/mitm_pki.hpp"
#include "core/network/net_socket.hpp"
#include "core/network/parsers.hpp"
#include "core/network/tls_stream.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

namespace slop::core::network {

namespace {

constexpr size_t kMaxHead = 64 * 1024;          // request head we accept
constexpr size_t kMaxLogHead = 16 * 1024;       // head bytes kept per entry
constexpr size_t kMaxReplayBody = 64 * 1024;    // body bytes kept for replay
constexpr size_t kMaxResponseHead = 8 * 1024;
constexpr size_t kMaxEntries = 512;
constexpr size_t kMaxLogBytes = 16u << 20;
constexpr size_t kMaxReplayResponse = 1u << 20;
constexpr size_t kMaxCreds = 64;
constexpr int    kHalfCloseGraceMs = 15000;
constexpr int    kTlsHandshakeMs = 15000;

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch()).count();
}

int64_t mono_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch()).count();
}

size_t entry_bytes(const proxy_entry_t& e) {
    return sizeof(proxy_entry_t) + e.kind.size() + e.client.size() + e.method.size() +
           e.host.size() + e.port.size() + e.path.size() + e.sni.size() + e.tls.size() +
           e.error.size() + e.raw_request.size() + e.response_head.size();
}

bool ct_equal(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i)
        diff = static_cast<unsigned char>(diff | (static_cast<unsigned char>(a[i]) ^
                                                  static_cast<unsigned char>(b[i])));
    return diff == 0;
}

std::string simple_response(int code, const char* reason, const std::string& body,
                            const char* extra = "") {
    return "HTTP/1.1 " + std::to_string(code) + " " + reason +
           "\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: " +
           std::to_string(body.size()) + "\r\n" + extra + "\r\n" + body;
}

bool authorized(const parse::http_head_t& h, const std::string& token) {
    const std::string* v = h.get("proxy-authorization");
    if (!v) return false;
    const size_t sp = v->find(' ');
    if (sp == std::string::npos) return false;
    const std::string scheme = parse::lower(v->substr(0, sp));
    std::string cred = v->substr(sp + 1);
    while (!cred.empty() && cred.front() == ' ') cred.erase(cred.begin());
    if (scheme == "bearer") return ct_equal(cred, token);
    if (scheme == "basic") {
        const auto dec = parse::base64_decode(cred);
        if (!dec) return false;
        const size_t colon = dec->find(':');
        return colon != std::string::npos && ct_equal(dec->substr(colon + 1), token);
    }
    return false;
}

bool host_allowed(const proxy_options_t& opt, const std::string& host, const parse::ip_addr_t& ip) {
    if (opt.allow_hosts.empty()) return true;
    for (const auto& p : opt.allow_hosts)
        if (parse::host_pattern_match(p, host, &ip)) return true;
    return false;
}

std::string text_of(const std::vector<uint8_t>& v, size_t n) {
    return std::string(reinterpret_cast<const char*>(v.data()), std::min(n, v.size()));
}

} // namespace

// connection bookkeeping

namespace {

struct recorder_t;

struct conn_t {
    std::thread th;
    std::atomic<bool> done{false};
    std::mutex mu;
    std::vector<sock::socket_t> socks;

    void add(sock::socket_t s) {
        std::lock_guard lk(mu);
        socks.push_back(s);
    }
    void close(sock::socket_t s) {
        if (s == sock::kInvalid) return;
        std::lock_guard lk(mu);
        socks.erase(std::remove(socks.begin(), socks.end(), s), socks.end());
        sock::close(s);
    }
    void close_all() {
        std::lock_guard lk(mu);
        for (auto s : socks) sock::close(s);
        socks.clear();
    }
    void shutdown_all() {
        std::lock_guard lk(mu);
        for (auto s : socks) ::shutdown(static_cast<SOCKET>(s), SD_BOTH);
    }
};

struct endpoint_t {
    sock::socket_t s = sock::kInvalid;
    tls::stream_t* tls = nullptr;
    bool rd_open = true;

    int read(uint8_t* b, size_t cap) {
        if (tls) return tls->read(b, cap);
        const int r = ::recv(static_cast<SOCKET>(s), reinterpret_cast<char*>(b),
                             static_cast<int>(cap), 0);
        return r < 0 ? -1 : r;
    }
    bool write(const uint8_t* d, size_t n) {
        return tls ? tls->write(d, n) : sock::send_all(s, d, n);
    }
    bool pending() const { return tls && tls->pending(); }
    void shut_write() {
        if (tls) tls->close_notify();
        ::shutdown(static_cast<SOCKET>(s), SD_SEND);
    }
};

} // namespace

struct http_proxy_t::impl_t {
    mutable std::mutex mu;      // opt, mitm, creds, log
    proxy_options_t opt;
    std::shared_ptr<mitm::pki_t> mitm;
    std::map<std::string, std::shared_ptr<tls::server_cred_t>> creds;
    std::deque<proxy_entry_t> log;
    size_t log_bytes = 0;
    uint64_t next_id = 1;

    std::atomic<sock::socket_t> listen{sock::kInvalid};
    std::atomic<bool> quit{false};
    std::atomic<bool> running{false};
    std::atomic<uint16_t> port{0};
    std::thread accept_th;
    std::mutex conns_mu;
    std::list<std::unique_ptr<conn_t>> conns;

    std::atomic<uint64_t> total_conns{0}, rej_cap{0}, rej_auth{0}, rej_host{0}, rej_client{0};

    // log

    void trim_locked() {
        while (log.size() > 1 && (log.size() > kMaxEntries || log_bytes > kMaxLogBytes)) {
            log_bytes -= entry_bytes(log.front());
            log.pop_front();
        }
    }

    uint64_t record(proxy_entry_t e) {
        std::lock_guard lk(mu);
        e.id = next_id++;
        if (!e.at_ms) e.at_ms = now_ms();
        log_bytes += entry_bytes(e);
        log.push_back(std::move(e));
        const uint64_t id = log.back().id;
        trim_locked();
        return id;
    }

    proxy_entry_t* find_locked(uint64_t id) {
        auto it = std::lower_bound(log.begin(), log.end(), id,
                                   [](const proxy_entry_t& e, uint64_t v) { return e.id < v; });
        return it != log.end() && it->id == id ? &*it : nullptr;
    }

    template <class F>
    void update(uint64_t id, F&& f) {
        if (!id) return;
        std::lock_guard lk(mu);
        proxy_entry_t* e = find_locked(id);
        if (!e) return;
        log_bytes -= entry_bytes(*e);
        f(*e);
        log_bytes += entry_bytes(*e);
        trim_locked();
    }

    std::shared_ptr<tls::server_cred_t> cred_for(const std::string& host,
                                                 const std::shared_ptr<const _CERT_CONTEXT>& leaf,
                                                 std::string* err) {
        {
            std::lock_guard lk(mu);
            auto it = creds.find(host);
            if (it != creds.end()) return it->second;
        }
        auto c = tls::server_cred_t::create(leaf.get(), err);
        if (!c) return nullptr;
        std::lock_guard lk(mu);
        if (creds.size() >= kMaxCreds) creds.clear();
        creds[host] = c;
        return c;
    }

    void accept_loop();
    void handle(conn_t* c, sock::socket_t client);
    bool read_head(sock::socket_t s, std::vector<uint8_t>& buf, size_t* head_len, int timeout_ms);
    sock::socket_t connect_upstream(conn_t* c, const proxy_options_t& opt, const std::string& host,
                                    uint16_t port, const std::string& our_addr, int* status,
                                    std::string* err);
    void connect_flow(conn_t* c, sock::socket_t client, const parse::http_head_t& h,
                      proxy_entry_t base, const proxy_options_t& opt);
    void http_flow(conn_t* c, sock::socket_t client, const parse::http_head_t& h,
                   const std::string& head_text, const std::vector<uint8_t>& leftover,
                   proxy_entry_t base, const proxy_options_t& opt);
    void pump(endpoint_t& a, endpoint_t& b, recorder_t* rec, bool single,
              const std::vector<uint8_t>& initial, uint64_t* up, uint64_t* down, int idle_ms);
};

namespace {

// logs HTTP exchanges seen inside a connection (plain or decrypted)

struct recorder_t {
    http_proxy_t::impl_t& px;
    proxy_entry_t tmpl;
    parse::http_framer_t req{false};
    parse::http_framer_t resp{true};
    std::deque<uint64_t> awaiting;
    uint64_t cur_req = 0;
    bool capturing = false;
    std::vector<uint8_t> raw;
    size_t head_len = 0;
    size_t req_total = 0;
    bool trunc = false;
    uint64_t cur_resp = 0;
    size_t resp_total = 0;

    recorder_t(http_proxy_t::impl_t& p, proxy_entry_t t) : px(p), tmpl(std::move(t)) {}

    void begin(const std::string& head) {
        proxy_entry_t e = tmpl;
        e.at_ms = now_ms();
        if (auto h = parse::parse_http_head(head, false)) {
            e.method = parse::escape_nonprintable(h->method);
            e.path = parse::escape_nonprintable(h->target);
            if (e.kind == "https") {
                if (const std::string* host = h->get("host")) {
                    std::string hn;
                    uint16_t hp = 0;
                    if (sock::split_authority(*host, 443, &hn, &hp) && parse::valid_host(hn))
                        e.host = parse::lower(hn);
                }
            }
            resp.expect_response_to(h->method);
        }
        trunc = head.size() > kMaxLogHead;
        raw.assign(head.begin(), head.begin() + static_cast<std::ptrdiff_t>(std::min(head.size(), kMaxLogHead)));
        head_len = raw.size();
        req_total = head.size();
        e.raw_request = raw;
        e.req_bytes = req_total;
        e.request_truncated = true;          // until the message end is seen
        cur_req = px.record(std::move(e));
        awaiting.push_back(cur_req);
        capturing = true;
    }

    void take(const uint8_t* d, size_t n) {
        req_total += n;
        if (trunc || !n) return;
        if (raw.size() - head_len + n > kMaxReplayBody) {
            trunc = true;
            return;
        }
        raw.insert(raw.end(), d, d + n);
    }

    void finalize_req(bool complete) {
        if (!capturing) return;
        capturing = false;
        const bool t = trunc || !complete;
        px.update(cur_req, [&](proxy_entry_t& e) {
            e.raw_request = std::move(raw);
            e.req_bytes = req_total;
            e.request_truncated = t;
            e.replayable = !t;
        });
        raw.clear();
    }

    // returns the offset just past the first request that completed in this
    // chunk, or npos
    size_t c2s(const uint8_t* d, size_t n) {
        size_t first_end = std::string::npos;
        if (req.broken()) return first_end;
        std::vector<parse::http_framer_t::event_t> ev;
        req.feed(d, n, &ev);
        size_t pos = 0;
        for (const auto& e : ev) {
            if (e.kind == parse::http_framer_t::event_t::kind_t::head) {
                if (capturing) finalize_req(false);
                begin(e.head);
            } else {
                if (capturing) take(d + pos, e.at - pos);
                finalize_req(true);
                if (first_end == std::string::npos) first_end = e.at;
            }
            pos = e.at;
        }
        if (capturing && pos < n) take(d + pos, n - pos);
        if (req.broken() && capturing) finalize_req(false);
        return first_end;
    }

    void s2c(const uint8_t* d, size_t n) {
        if (resp.broken()) return;
        std::vector<parse::http_framer_t::event_t> ev;
        resp.feed(d, n, &ev);
        size_t pos = 0;
        for (const auto& e : ev) {
            if (e.kind == parse::http_framer_t::event_t::kind_t::head) {
                if (e.interim) { pos = e.at; continue; }
                cur_resp = 0;
                if (!awaiting.empty()) {
                    cur_resp = awaiting.front();
                    awaiting.pop_front();
                }
                resp_total = e.head.size();
                const auto h = parse::parse_http_head(e.head, true);
                const uint32_t status = h ? h->status : 0;
                const std::string& head = e.head;
                px.update(cur_resp, [&](proxy_entry_t& en) {
                    en.status = status;
                    en.response_head.assign(head.begin(),
                                            head.begin() + static_cast<std::ptrdiff_t>(
                                                               std::min(head.size(), kMaxResponseHead)));
                    en.resp_bytes = resp_total;
                });
            } else {
                resp_total += e.at - pos;
                const size_t total = resp_total;
                px.update(cur_resp, [&](proxy_entry_t& en) { en.resp_bytes = total; });
                cur_resp = 0;
            }
            pos = e.at;
        }
        if (cur_resp && pos < n) resp_total += n - pos;
    }

    void s2c_eof() {
        std::vector<parse::http_framer_t::event_t> ev;
        resp.finish(&ev);
        if (!cur_resp) return;
        const size_t total = resp_total;
        const bool completed = !ev.empty();
        px.update(cur_resp, [&](proxy_entry_t& en) {
            en.resp_bytes = total;
            if (!completed && en.error.empty())
                en.error = "connection closed before the response completed";
        });
        cur_resp = 0;
    }

    void finish() { finalize_req(false); }
};

} // namespace

// pump

void http_proxy_t::impl_t::pump(endpoint_t& a, endpoint_t& b, recorder_t* rec, bool single,
                                const std::vector<uint8_t>& initial, uint64_t* up,
                                uint64_t* down, int idle_ms) {
    bool a_read = true;
    auto fwd_up = [&](const uint8_t* d, size_t n) -> bool {
        size_t send_n = n;
        if (rec) {
            const size_t end = rec->c2s(d, n);
            if (single && end != std::string::npos) {
                send_n = end;
                a_read = false;           // one request per plain-HTTP connection
            }
        }
        *up += send_n;
        return send_n == 0 || b.write(d, send_n);
    };
    if (!initial.empty() && !fwd_up(initial.data(), initial.size())) return;

    std::vector<uint8_t> buf(16384);
    int64_t last = mono_ms();
    int64_t half_closed_at = 0;
    for (;;) {
        if (quit.load()) break;
        if (!b.rd_open && (single || !a_read)) break;
        if (!a_read && !b.rd_open) break;

        auto service_a = [&]() -> bool {
            const int n = a.read(buf.data(), buf.size());
            if (n > 0) return fwd_up(buf.data(), static_cast<size_t>(n));
            a_read = false;
            a.rd_open = false;
            if (!single) b.shut_write();
            return true;
        };
        auto service_b = [&]() -> bool {
            const int n = b.read(buf.data(), buf.size());
            if (n > 0) {
                if (rec) rec->s2c(buf.data(), static_cast<size_t>(n));
                *down += static_cast<size_t>(n);
                return a.write(buf.data(), static_cast<size_t>(n));
            }
            b.rd_open = false;
            if (rec) rec->s2c_eof();
            a.shut_write();
            return true;
        };

        bool ok = true;
        bool progressed = false;
        if (a_read && a.pending()) {
            ok = service_a();
            progressed = true;
        } else if (b.rd_open && b.pending()) {
            ok = service_b();
            progressed = true;
        } else {
            WSAPOLLFD fds[2]{};
            int nf = 0, ia = -1, ib = -1;
            if (a_read) { ia = nf; fds[nf++] = {static_cast<SOCKET>(a.s), POLLRDNORM, 0}; }
            if (b.rd_open) { ib = nf; fds[nf++] = {static_cast<SOCKET>(b.s), POLLRDNORM, 0}; }
            const int r = ::WSAPoll(fds, static_cast<ULONG>(nf), 250);
            if (r < 0) break;
            if (r > 0) {
                const SHORT ready = POLLRDNORM | POLLHUP | POLLERR;
                if (ia >= 0 && (fds[ia].revents & ready)) { ok = service_a(); progressed = true; }
                if (ok && ib >= 0 && (fds[ib].revents & ready)) { ok = service_b(); progressed = true; }
            }
        }
        if (!ok) break;
        const int64_t now = mono_ms();
        if (progressed) last = now;
        else if (now - last > idle_ms) break;
        if (!a_read || !b.rd_open) {
            if (!half_closed_at) half_closed_at = now;
            else if (!single && now - half_closed_at > kHalfCloseGraceMs) break;
        }
    }
    if (rec) rec->finish();
}

// accept

void http_proxy_t::impl_t::accept_loop() {
    while (!quit.load()) {
        const sock::socket_t l = listen.load();
        if (l == sock::kInvalid) break;
        WSAPOLLFD fd{static_cast<SOCKET>(l), POLLRDNORM, 0};
        const int r = ::WSAPoll(&fd, 1, 250);
        if (quit.load()) break;
        if (r <= 0) continue;
        const SOCKET c = ::accept(static_cast<SOCKET>(l), nullptr, nullptr);
        if (c == INVALID_SOCKET) continue;
        const sock::socket_t cs = static_cast<sock::socket_t>(c);

        // reap finished connection threads
        {
            std::lock_guard lk(conns_mu);
            for (auto it = conns.begin(); it != conns.end();) {
                if ((*it)->done.load()) {
                    if ((*it)->th.joinable()) (*it)->th.join();
                    it = conns.erase(it);
                } else {
                    ++it;
                }
            }
        }

        proxy_options_t o;
        {
            std::lock_guard lk(mu);
            o = opt;
        }
        const std::string peer = sock::peer_address(cs);
        if (!o.allow_clients.empty()) {
            const auto ip = parse::parse_ip(peer);
            bool ok = false;
            for (const auto& p : o.allow_clients)
                if (ip && parse::host_pattern_match(p, peer, &*ip)) ok = true;
            if (!ok) {
                ++rej_client;
                sock::close(cs);
                continue;
            }
        }
        size_t active = 0;
        {
            std::lock_guard lk(conns_mu);
            for (const auto& cc : conns)
                if (!cc->done.load()) ++active;
        }
        if (active >= o.max_connections) {
            ++rej_cap;
            const std::string msg = simple_response(503, "Service Unavailable",
                                                    "proxy connection limit reached\n");
            u_long nb = 1;
            ::ioctlsocket(c, FIONBIO, &nb);
            ::send(c, msg.data(), static_cast<int>(msg.size()), 0);
            sock::close(cs);
            continue;
        }
        ++total_conns;
        auto ctx = std::make_unique<conn_t>();
        conn_t* raw_ctx = ctx.get();
        raw_ctx->add(cs);
        std::lock_guard lk(conns_mu);
        conns.push_back(std::move(ctx));
        raw_ctx->th = std::thread([this, raw_ctx, cs] {
            handle(raw_ctx, cs);
            // done first: the client observes the close only after the slot is free
            raw_ctx->done.store(true);
            raw_ctx->close_all();
        });
    }
}

bool http_proxy_t::impl_t::read_head(sock::socket_t s, std::vector<uint8_t>& buf,
                                     size_t* head_len, int timeout_ms) {
    const int64_t deadline = mono_ms() + timeout_ms;
    size_t scan = 0;
    uint8_t chunk[4096];
    for (;;) {
        const size_t hit = parse::find_head_end(buf.data(), buf.size(), scan);
        if (hit != std::string::npos) {
            *head_len = hit;
            return true;
        }
        if (buf.size() > kMaxHead) return false;
        const int64_t left = deadline - mono_ms();
        if (left <= 0 || !sock::wait_readable(s, static_cast<int>(left), &quit)) return false;
        const int r = ::recv(static_cast<SOCKET>(s), reinterpret_cast<char*>(chunk), sizeof(chunk), 0);
        if (r <= 0) return false;
        scan = buf.size() >= 3 ? buf.size() - 3 : 0;
        buf.insert(buf.end(), chunk, chunk + r);
    }
}

sock::socket_t http_proxy_t::impl_t::connect_upstream(conn_t* c, const proxy_options_t& o,
                                                      const std::string& host, uint16_t p,
                                                      const std::string& our_addr, int* status,
                                                      std::string* err) {
    const auto addrs = sock::resolve(host, err);
    if (addrs.empty()) {
        *status = 502;
        return sock::kInvalid;
    }
    const auto bind_ip = parse::parse_ip(o.bind);
    const auto our_ip = parse::parse_ip(our_addr);
    bool any_allowed = false;
    for (const auto& ip : addrs) {
        if (!host_allowed(o, host, ip)) continue;
        any_allowed = true;
        const bool loop = p == port.load() &&
                          ((ip.family == 4 && ip.b[0] == 127) ||
                           (ip.family == 6 && ip == *parse::parse_ip("::1")) ||
                           (bind_ip && ip == *bind_ip) || (our_ip && ip == *our_ip));
        if (loop) {
            *status = 508;
            *err = "request would loop back into the proxy";
            return sock::kInvalid;
        }
        sock::socket_t s = sock::connect(ip, p, o.connect_timeout_ms, &quit, err);
        if (s != sock::kInvalid) {
            c->add(s);
            sock::set_timeouts(s, 30000, 30000);
            return s;
        }
    }
    if (!any_allowed) {
        ++rej_host;
        *status = 403;
        *err = "destination '" + host + "' is not in the proxy allowlist";
    } else {
        *status = 502;
    }
    return sock::kInvalid;
}

void http_proxy_t::impl_t::handle(conn_t* c, sock::socket_t client) {
    proxy_options_t o;
    {
        std::lock_guard lk(mu);
        o = opt;
    }
    sock::set_timeouts(client, o.header_timeout_ms, 30000);
    std::vector<uint8_t> buf;
    size_t head_len = 0;
    if (!read_head(client, buf, &head_len, o.header_timeout_ms)) return;   // slow / oversized / closed

    const std::string head_text = text_of(buf, head_len);
    proxy_entry_t base;
    base.at_ms = now_ms();
    base.client = sock::peer_address(client);
    const auto h = parse::parse_http_head(head_text, false);
    if (!h) {
        const std::string msg = simple_response(400, "Bad Request", "malformed request head\n");
        sock::send_all(client, reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
        return;
    }
    base.method = parse::escape_nonprintable(h->method);
    const bool is_connect = h->method == "CONNECT";
    base.kind = is_connect ? "connect" : "http";

    if (!o.token.empty() && !authorized(*h, o.token)) {
        ++rej_auth;
        const std::string msg = simple_response(
            407, "Proxy Authentication Required", "proxy token required\n",
            "Proxy-Authenticate: Basic realm=\"reverse-slop\"\r\n");
        sock::send_all(client, reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
        base.status = 407;
        base.path = parse::escape_nonprintable(h->target.substr(0, 512));
        base.error = "missing or wrong Proxy-Authorization";
        record(std::move(base));
        return;
    }
    if (is_connect) {
        connect_flow(c, client, *h, std::move(base), o);
    } else {
        const std::vector<uint8_t> leftover(buf.begin() + static_cast<std::ptrdiff_t>(head_len), buf.end());
        http_flow(c, client, *h, head_text, leftover, std::move(base), o);
    }
}

void http_proxy_t::impl_t::connect_flow(conn_t* c, sock::socket_t client,
                                        const parse::http_head_t& h, proxy_entry_t base,
                                        const proxy_options_t& o) {
    auto reply = [&](int code, const char* reason, const std::string& why) {
        const std::string msg = simple_response(code, reason, why + "\n");
        sock::send_all(client, reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
        base.status = static_cast<uint32_t>(code);
        base.error = why;
        record(base);
    };
    std::string host;
    uint16_t p = 0;
    if (!sock::split_authority(h.target, 443, &host, &p)) {
        base.host = parse::escape_nonprintable(h.target.substr(0, 256));
        return reply(400, "Bad Request", "CONNECT target must be host:port");
    }
    base.host = parse::escape_nonprintable(host);
    base.port = std::to_string(p);

    int status = 502;
    std::string err;
    const sock::socket_t remote =
        connect_upstream(c, o, host, p, sock::local_address(client), &status, &err);
    if (remote == sock::kInvalid)
        return reply(status, status == 403 ? "Forbidden" : status == 508 ? "Loop Detected" : "Bad Gateway", err);

    static constexpr char kOk[] = "HTTP/1.1 200 Connection established\r\n\r\n";
    if (!sock::send_all(client, reinterpret_cast<const uint8_t*>(kOk), sizeof(kOk) - 1)) return;
    base.status = 200;
    const uint64_t id = record(base);

    // the client sends its ClientHello only after the 200
    bool tls_hello = false;
    std::string sni;
    if (sock::wait_readable(client, o.header_timeout_ms, &quit)) {
        uint8_t peek[4096];
        const int r = ::recv(static_cast<SOCKET>(client), reinterpret_cast<char*>(peek),
                             sizeof(peek), MSG_PEEK);
        if (r > 0) {
            tls_hello = peek[0] == 0x16;
            sni = parse::extract_sni(peek, static_cast<size_t>(r));
        }
    }
    if (!sni.empty()) update(id, [&](proxy_entry_t& e) { e.sni = sni; });

    std::shared_ptr<mitm::pki_t> pki;
    {
        std::lock_guard lk(mu);
        pki = mitm;
    }
    uint64_t up = 0, down = 0;
    if (pki && tls_hello) {
        const std::string name = !sni.empty() ? sni
                                 : parse::valid_host(host) ? parse::lower(host) : std::string{};
        std::string why;
        auto leaf = name.empty() ? nullptr : pki->leaf_for(name, &why);
        auto cred = leaf ? cred_for(name, leaf, &why) : nullptr;
        if (cred) {
            auto ctls = tls::stream_t::accept(client, *cred, kTlsHandshakeMs, &why);
            if (!ctls) {
                update(id, [&](proxy_entry_t& e) {
                    e.error = "client TLS handshake failed (does the client trust the reverse-slop CA?): " + why;
                });
                return;
            }
            tls::client_options_t copt;
            copt.exclusive_roots = o.upstream_roots;
            auto utls = tls::stream_t::connect(remote, name, copt, kTlsHandshakeMs, &why);
            if (!utls) {
                const std::string msg = simple_response(502, "Bad Gateway", "upstream TLS failed: " + why + "\n");
                ctls->write(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
                ctls->close_notify();
                update(id, [&](proxy_entry_t& e) { e.error = "upstream TLS failed: " + why; });
                return;
            }
            const std::string proto = utls->protocol();
            update(id, [&](proxy_entry_t& e) {
                e.intercepted = true;
                e.tls = proto;
            });
            proxy_entry_t t;
            t.kind = "https";
            t.client = base.client;
            t.host = name;
            t.port = base.port;
            t.sni = sni;
            t.intercepted = true;
            t.tls = proto;
            t.tunnel_id = id;
            recorder_t rec(*this, std::move(t));
            endpoint_t a{client, ctls.get()}, b{remote, utls.get()};
            pump(a, b, &rec, false, {}, &up, &down, o.idle_timeout_ms);
            update(id, [&](proxy_entry_t& e) {
                e.req_bytes = up;
                e.resp_bytes = down;
            });
            return;
        }
        update(id, [&](proxy_entry_t& e) { e.error = "interception skipped: " + why; });
    }
    endpoint_t a{client, nullptr}, b{remote, nullptr};
    pump(a, b, nullptr, false, {}, &up, &down, o.idle_timeout_ms);
    update(id, [&](proxy_entry_t& e) {
        e.req_bytes = up;
        e.resp_bytes = down;
    });
}

void http_proxy_t::impl_t::http_flow(conn_t* c, sock::socket_t client, const parse::http_head_t& h,
                                     const std::string& head_text,
                                     const std::vector<uint8_t>& leftover, proxy_entry_t base,
                                     const proxy_options_t& o) {
    auto reply = [&](int code, const char* reason, const std::string& why) {
        const std::string msg = simple_response(code, reason, why + "\n");
        sock::send_all(client, reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
        base.status = static_cast<uint32_t>(code);
        base.error = why;
        record(base);
    };
    std::string authority, path;
    const std::string lt = parse::lower(h.target.substr(0, 8));
    if (lt.rfind("http://", 0) == 0) {
        const size_t slash = h.target.find('/', 7);
        authority = h.target.substr(7, slash == std::string::npos ? std::string::npos : slash - 7);
        path = slash == std::string::npos ? "/" : h.target.substr(slash);
    } else if (lt.rfind("https://", 0) == 0) {
        base.path = parse::escape_nonprintable(h.target.substr(0, 512));
        return reply(400, "Bad Request", "https:// targets must use CONNECT");
    } else if (!h.target.empty() && h.target[0] == '/') {
        const std::string* hh = h.get("host");
        if (!hh) return reply(400, "Bad Request", "origin-form request without a Host header");
        authority = *hh;
        path = h.target;
    } else {
        base.path = parse::escape_nonprintable(h.target.substr(0, 512));
        return reply(400, "Bad Request", "unsupported request target");
    }
    std::string host;
    uint16_t p = 80;
    if (!sock::split_authority(authority, 80, &host, &p)) {
        base.host = parse::escape_nonprintable(authority.substr(0, 256));
        return reply(400, "Bad Request", "bad host/port");
    }
    base.host = parse::escape_nonprintable(host);
    base.port = std::to_string(p);
    base.path = parse::escape_nonprintable(path);

    int status = 502;
    std::string err;
    const sock::socket_t remote =
        connect_upstream(c, o, host, p, sock::local_address(client), &status, &err);
    if (remote == sock::kInvalid)
        return reply(status, status == 403 ? "Forbidden" : status == 508 ? "Loop Detected" : "Bad Gateway", err);

    // origin-form request line, hop-by-hop / proxy headers dropped, one request per connection
    std::string out = h.method + " " + path + " HTTP/1.1\r\n";
    bool have_host = false;
    size_t pos = head_text.find("\r\n") + 2;
    while (pos < head_text.size()) {
        const size_t eol = head_text.find("\r\n", pos);
        if (eol == std::string::npos || eol == pos) break;
        const std::string line = head_text.substr(pos, eol - pos);
        pos = eol + 2;
        const std::string name = parse::lower(line.substr(0, line.find(':')));
        if (name == "proxy-authorization" || name == "proxy-connection" || name == "connection" ||
            name == "keep-alive" || name == "upgrade")
            continue;
        if (name == "host") have_host = true;
        out += line + "\r\n";
    }
    if (!have_host) out += "Host: " + authority + "\r\n";
    out += "Connection: close\r\n\r\n";
    std::vector<uint8_t> initial(out.begin(), out.end());
    initial.insert(initial.end(), leftover.begin(), leftover.end());

    proxy_entry_t t;
    t.kind = "http";
    t.client = base.client;
    t.host = base.host;
    t.port = base.port;
    recorder_t rec(*this, std::move(t));
    endpoint_t a{client, nullptr}, b{remote, nullptr};
    uint64_t up = 0, down = 0;
    pump(a, b, &rec, true, initial, &up, &down, o.idle_timeout_ms);
}

// public

http_proxy_t::http_proxy_t() : p_(std::make_unique<impl_t>()) {}

http_proxy_t::~http_proxy_t() { stop(); }

bool http_proxy_t::start(const proxy_options_t& o, std::string* error) {
    auto fail = [&](const std::string& why) {
        if (error) *error = why;
        return false;
    };
    if (p_->running.load())
        return fail("proxy already running on port " + std::to_string(p_->port.load()) +
                    " (stop it first to change options)");
    const auto bind_ip = parse::parse_ip(o.bind);
    if (!bind_ip) return fail("bind must be an IP literal, got '" + o.bind + "'");
    for (const auto& c : o.allow_clients)
        if (!parse::parse_cidr(c)) return fail("allow_clients entries must be IP/CIDR, got '" + c + "'");
    for (const auto& hpat : o.allow_hosts) {
        const bool wildcard = hpat.size() > 2 && hpat[0] == '*' && hpat[1] == '.' &&
                              parse::valid_host(hpat.substr(2));
        if (!wildcard && !parse::parse_cidr(hpat) && !parse::valid_host(hpat))
            return fail("bad allow_hosts pattern '" + hpat + "'");
    }
    const bool loopback = (bind_ip->family == 4 && bind_ip->b[0] == 127) ||
                          *bind_ip == *parse::parse_ip("::1");
    if (!loopback && o.token.empty() && o.allow_clients.empty())
        return fail("binding to " + o.bind + " exposes the proxy to the network: set proxy_token "
                    "or allow_clients (e.g. the console IP)");
    if (o.max_connections == 0) return fail("max_connections must be > 0");

    sock::ensure_wsa();
    const int af = bind_ip->family == 4 ? AF_INET : AF_INET6;
    SOCKET l = ::socket(af, SOCK_STREAM, IPPROTO_TCP);
    if (l == INVALID_SOCKET) return fail("socket() failed");
    BOOL excl = TRUE;
    ::setsockopt(l, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&excl), sizeof(excl));
    sockaddr_storage ss{};
    int len = 0;
    if (af == AF_INET) {
        auto* sin = reinterpret_cast<sockaddr_in*>(&ss);
        sin->sin_family = AF_INET;
        sin->sin_port = htons(o.port);
        std::memcpy(&sin->sin_addr, bind_ip->b.data(), 4);
        len = sizeof(sockaddr_in);
    } else {
        auto* sin6 = reinterpret_cast<sockaddr_in6*>(&ss);
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(o.port);
        std::memcpy(&sin6->sin6_addr, bind_ip->b.data(), 16);
        len = sizeof(sockaddr_in6);
    }
    if (::bind(l, reinterpret_cast<sockaddr*>(&ss), len) != 0 || ::listen(l, 64) != 0) {
        const int e = ::WSAGetLastError();
        ::closesocket(l);
        return fail("bind/listen on " + o.bind + ":" + std::to_string(o.port) + " failed (" +
                    std::to_string(e) + (e == WSAEADDRINUSE ? ", port busy)" : ")"));
    }
    uint16_t bound = 0;
    sock::local_address(static_cast<sock::socket_t>(l), &bound);
    {
        std::lock_guard lk(p_->mu);
        p_->opt = o;
        p_->opt.port = bound;
    }
    p_->port.store(bound);
    p_->listen.store(static_cast<sock::socket_t>(l));
    p_->quit.store(false);
    p_->running.store(true);
    p_->accept_th = std::thread([this] { p_->accept_loop(); });
    return true;
}

void http_proxy_t::stop() {
    if (!p_) return;
    p_->quit.store(true);
    const sock::socket_t l = p_->listen.exchange(sock::kInvalid);
    if (p_->accept_th.joinable()) p_->accept_th.join();
    sock::close(l);
    std::list<std::unique_ptr<conn_t>> conns;
    {
        std::lock_guard lk(p_->conns_mu);
        conns.swap(p_->conns);
    }
    for (auto& c : conns) c->shutdown_all();
    for (auto& c : conns)
        if (c->th.joinable()) c->th.join();
    p_->running.store(false);
    p_->port.store(0);
}

bool http_proxy_t::running() const { return p_->running.load(); }
uint16_t http_proxy_t::port() const { return p_->port.load(); }

proxy_options_t http_proxy_t::options() const {
    std::lock_guard lk(p_->mu);
    return p_->opt;
}

void http_proxy_t::set_mitm(std::shared_ptr<mitm::pki_t> pki) {
    std::lock_guard lk(p_->mu);
    p_->mitm = std::move(pki);
    p_->creds.clear();
}

bool http_proxy_t::mitm_enabled() const {
    std::lock_guard lk(p_->mu);
    return p_->mitm != nullptr;
}

std::vector<proxy_entry_t> http_proxy_t::recent(size_t max) const {
    std::lock_guard lk(p_->mu);
    std::vector<proxy_entry_t> out;
    const size_t start = p_->log.size() > max ? p_->log.size() - max : 0;
    for (size_t i = start; i < p_->log.size(); ++i) out.push_back(p_->log[i]);
    return out;
}

std::optional<proxy_entry_t> http_proxy_t::entry(uint64_t id) const {
    std::lock_guard lk(p_->mu);
    const proxy_entry_t* e = p_->find_locked(id);
    if (!e) return std::nullopt;
    return *e;
}

void http_proxy_t::clear_log() {
    std::lock_guard lk(p_->mu);
    p_->log.clear();
    p_->log_bytes = 0;
}

http_proxy_t::stats_t http_proxy_t::stats() const {
    stats_t s;
    {
        std::lock_guard lk(p_->conns_mu);
        for (const auto& c : p_->conns)
            if (!c->done.load()) ++s.active_connections;
    }
    s.total_connections = p_->total_conns.load();
    s.rejected_capacity = p_->rej_cap.load();
    s.rejected_auth = p_->rej_auth.load();
    s.rejected_host = p_->rej_host.load();
    s.rejected_client = p_->rej_client.load();
    std::lock_guard lk(p_->mu);
    s.log_entries = p_->log.size();
    s.log_bytes = p_->log_bytes;
    return s;
}

std::optional<replay_result_t> http_proxy_t::replay(uint64_t id, std::string* error, int timeout_ms) {
    auto fail = [&](const std::string& why) -> std::optional<replay_result_t> {
        if (error) *error = why;
        return std::nullopt;
    };
    const auto e = entry(id);
    if (!e) return fail("unknown entry id");
    if (e->kind != "http" && e->kind != "https")
        return fail("only http/https request entries are replayable (connect entries are tunnels)");
    if (!e->replayable)
        return fail(e->raw_request.empty() ? "entry has no captured request"
                                           : "request was not captured completely (body over 64 KiB, "
                                             "chunked past the cap, or the client aborted)");
    const proxy_options_t o = options();
    uint16_t p = 0;
    std::string h;
    if (!sock::split_authority(e->host + ":" + (e->port.empty() ? "80" : e->port), 80, &h, &p))
        return fail("logged host/port are invalid");
    std::string err;
    const auto addrs = sock::resolve(h, &err);
    if (addrs.empty()) return fail(err);
    sock::socket_t s = sock::kInvalid;
    std::atomic<bool> never{false};
    for (const auto& ip : addrs) {
        if (!host_allowed(o, h, ip)) continue;
        s = sock::connect(ip, p, o.connect_timeout_ms, &never, &err);
        if (s != sock::kInvalid) break;
    }
    if (s == sock::kInvalid) return fail(err.empty() ? "destination not in the proxy allowlist" : err);

    std::unique_ptr<tls::stream_t> t;
    if (e->kind == "https") {
        tls::client_options_t copt;
        copt.exclusive_roots = o.upstream_roots;
        t = tls::stream_t::connect(s, h, copt, kTlsHandshakeMs, &err);
        if (!t) {
            sock::close(s);
            return fail("TLS to " + h + " failed: " + err);
        }
    }
    sock::set_timeouts(s, timeout_ms, timeout_ms);
    endpoint_t ep{s, t.get()};
    if (!ep.write(e->raw_request.data(), e->raw_request.size())) {
        sock::close(s);
        return fail("sending the request failed");
    }

    replay_result_t out;
    parse::http_framer_t fr(true);
    fr.expect_response_to(e->method);
    const int64_t deadline = mono_ms() + timeout_ms;
    std::vector<uint8_t> buf(16384);
    std::vector<parse::http_framer_t::event_t> ev;
    for (;;) {
        if (fr.messages_completed() >= 1) { out.complete = true; break; }
        if (out.bytes.size() >= kMaxReplayResponse) {
            out.truncated = true;
            out.note = "response exceeds the 1 MiB replay cap";
            break;
        }
        const int64_t left = deadline - mono_ms();
        if (left <= 0 || (!ep.pending() && !sock::wait_readable(s, static_cast<int>(left), nullptr))) {
            out.truncated = true;
            out.note = "deadline reached before the response completed";
            break;
        }
        const int n = ep.read(buf.data(), std::min(buf.size(), kMaxReplayResponse - out.bytes.size()));
        if (n <= 0) {
            fr.finish(&ev);
            out.complete = fr.messages_completed() >= 1;
            if (!out.complete) {
                out.truncated = true;
                out.note = n == 0 ? "connection closed before the response completed"
                                  : "socket error while reading the response";
            }
            break;
        }
        out.bytes.insert(out.bytes.end(), buf.begin(), buf.begin() + n);
        fr.feed(buf.data(), static_cast<size_t>(n), &ev);
        if (fr.broken()) {
            out.note = "unframeable response (" + fr.error() + "); read until close";
        }
    }
    for (const auto& ev1 : ev)
        if (ev1.kind == parse::http_framer_t::event_t::kind_t::head && !ev1.interim) {
            if (auto hh = parse::parse_http_head(ev1.head, true)) out.status = hh->status;
            break;
        }
    if (t) t->close_notify();
    sock::close(s);
    return out;
}

} // namespace slop::core::network
