#pragma once

// src/core/network/tls_stream.hpp
// Schannel TLS over a connected blocking socket: server side for the MITM
// proxy (per-host leaf certificates from mitm_pki), client side for the proxy
// upstream, proxy replay and the pinned-address web client. Client streams
// validate the server chain and name themselves (system trust by default, an
// exclusive root store for tests)

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

struct _CERT_CONTEXT;

namespace slop::core::network::tls {

using socket_t = uintptr_t;   // SOCKET

// server credentials for one certificate (its private key must be reachable
// through CERT_KEY_PROV_INFO so LSA can use it)
class server_cred_t {
public:
    static std::shared_ptr<server_cred_t> create(const _CERT_CONTEXT* cert, std::string* error);
    ~server_cred_t();
    server_cred_t(const server_cred_t&) = delete;
    server_cred_t& operator=(const server_cred_t&) = delete;
    void* handle();                   // CredHandle*

private:
    server_cred_t();
    struct impl_t;
    std::unique_ptr<impl_t> p_;
};

struct client_options_t {
    void* exclusive_roots = nullptr;  // HCERTSTORE: trust only these roots; null = system trust
    bool  verify = true;              // chain + host name validation
};

class stream_t {
public:
    ~stream_t();
    stream_t(const stream_t&) = delete;
    stream_t& operator=(const stream_t&) = delete;

    // handshakes; the socket must be connected and blocking. timeout_ms bounds
    // each socket read during the handshake (and stays as SO_RCVTIMEO)
    static std::unique_ptr<stream_t> accept(socket_t s, server_cred_t& cred, int timeout_ms,
                                            std::string* error);
    static std::unique_ptr<stream_t> connect(socket_t s, const std::string& host,
                                             const client_options_t& opt, int timeout_ms,
                                             std::string* error);

    // > 0 plaintext bytes, 0 = peer closed (close_notify or EOF), < 0 = error
    int  read(uint8_t* buf, size_t cap);
    bool write(const uint8_t* d, size_t n);
    // decrypted bytes or a complete TLS record are buffered (read won't block)
    bool pending() const;
    // sends close_notify (best effort)
    void close_notify();
    std::string protocol() const;     // "TLS 1.2" | "TLS 1.3" | ...
    const std::string& last_error() const;

private:
    stream_t();
    struct impl_t;
    std::unique_ptr<impl_t> p_;
};

} // namespace slop::core::network::tls
