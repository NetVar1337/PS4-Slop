#pragma once

// HTTP/1.1 inspection proxy. Plain HTTP is forwarded one request per client
// connection (so every request is logged, authorized and allowlisted) and is
// replayable; CONNECT tunnels record the SNI and are relayed blindly unless
// TLS interception is enabled with a consented mitm::pki_t, in which case each
// HTTPS request inside the tunnel is logged and replayable too.
// Access control: optional Proxy-Authorization token, destination host
// allowlist, client address allowlist (required for non-loopback binds
// without a token), a concurrent-connection cap and header/idle timeouts.
// All connection threads are owned and joined by stop()

#include <atomic>
#include <cstdint>
#include <deque>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace slop::core::network {

namespace mitm { class pki_t; }

struct proxy_entry_t {
    uint64_t    id = 0;
    int64_t     at_ms = 0;
    std::string kind;              // "http" | "connect" | "https" (request inside an intercepted tunnel)
    std::string client;            // client address
    std::string method;
    std::string host;
    std::string port;
    std::string path;
    uint32_t    status = 0;        // upstream status, or the proxy's own 4xx/5xx answer (0 unknown)
    size_t      req_bytes = 0;
    size_t      resp_bytes = 0;
    std::string sni;               // connect only
    bool        intercepted = false;
    std::string tls;               // negotiated upstream protocol for intercepted traffic
    uint64_t    tunnel_id = 0;     // https: the connect entry carrying it
    std::string error;
    bool        replayable = false;
    bool        request_truncated = false;   // body over the replay cap, or not fully seen
    std::vector<uint8_t> raw_request;        // head (<= 16 KiB) + body (<= 64 KiB) as sent upstream
    std::vector<uint8_t> response_head;      // <= 8 KiB
};

struct proxy_options_t {
    uint16_t    port = 8888;               // 0 = ephemeral
    std::string bind = "127.0.0.1";        // IP literal; "0.0.0.0" / "::" for LAN clients (a console)
    std::string token;                     // when set, Proxy-Authorization Bearer <token> or Basic *:<token>
    std::vector<std::string> allow_hosts;  // destination patterns (host, *.suffix, IP, CIDR); empty = any
    std::vector<std::string> allow_clients;// client IP/CIDR patterns; empty = any (loopback binds only)
    void*       upstream_roots = nullptr;  // HCERTSTORE: exclusive trust roots for upstream TLS (tests)
    size_t      max_connections = 64;
    int         header_timeout_ms = 15000;
    int         idle_timeout_ms = 120000;
    int         connect_timeout_ms = 10000;
};

struct replay_result_t {
    std::vector<uint8_t> bytes;    // raw response (head + body as received)
    uint32_t    status = 0;
    bool        complete = false;  // framing (Content-Length / chunked / close) satisfied
    bool        truncated = false;
    std::string note;              // why it is incomplete
};

class http_proxy_t {
public:
    http_proxy_t();
    ~http_proxy_t();
    http_proxy_t(const http_proxy_t&) = delete;
    http_proxy_t& operator=(const http_proxy_t&) = delete;

    bool start(const proxy_options_t& opt, std::string* error);
    void stop();                                   // joins every proxy thread
    bool running() const;
    uint16_t port() const;
    proxy_options_t options() const;

    // non-null enables interception for new CONNECT tunnels (the caller has
    // obtained consent and created the CA); null returns to blind tunnels
    void set_mitm(std::shared_ptr<mitm::pki_t> pki);
    bool mitm_enabled() const;

    std::vector<proxy_entry_t> recent(size_t max = 128) const;
    std::optional<proxy_entry_t> entry(uint64_t id) const;
    void clear_log();

    // re-sends a logged http/https request and reads the response until its
    // framing completes, the peer closes, 1 MiB, or the deadline
    std::optional<replay_result_t> replay(uint64_t id, std::string* error, int timeout_ms = 15000);

    struct stats_t {
        size_t   active_connections = 0;
        uint64_t total_connections = 0;
        uint64_t rejected_capacity = 0, rejected_auth = 0, rejected_host = 0, rejected_client = 0;
        size_t   log_entries = 0, log_bytes = 0;
    };
    stats_t stats() const;

    struct impl_t;

private:
    std::unique_ptr<impl_t> p_;
};

} // namespace slop::core::network
