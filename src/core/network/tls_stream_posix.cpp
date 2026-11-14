// src/core/network/tls_stream_posix.cpp
// OpenSSL twin of tls_stream.cpp. The client side (web client, proxy
// upstream, proxy replay) is complete; the server side needs a certificate
// with a reachable private key, which the MITM proxy mints through CNG on
// Windows only, so accept() reports that instead of pretending.

#include "core/network/tls_stream.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <mutex>

namespace slop::core::network::tls {

namespace {

std::once_flag g_ssl_once;

void init_ssl() {
    std::call_once(g_ssl_once, [] {
        ::SSL_library_init();
        ::SSL_load_error_strings();
        ::OpenSSL_add_all_algorithms();
    });
}

std::string ssl_error_text() {
    const unsigned long e = ::ERR_get_error();
    if (e == 0) return "no OpenSSL error";
    char buf[256];
    ::ERR_error_string_n(e, buf, sizeof(buf));
    return buf;
}

} // namespace

struct server_cred_t::impl_t {};

server_cred_t::server_cred_t() : p_(std::make_unique<impl_t>()) {}
server_cred_t::~server_cred_t() = default;

std::shared_ptr<server_cred_t> server_cred_t::create(const _CERT_CONTEXT*, std::string* error) {
    if (error)
        *error = "server-side TLS needs a certificate with a reachable private key; the MITM "
                 "proxy mints those through CNG on Windows only";
    return nullptr;
}

void* server_cred_t::handle() { return nullptr; }

struct stream_t::impl_t {
    SSL*     ssl = nullptr;
    SSL_CTX* ctx = nullptr;
    int      fd  = -1;
    std::string last_error;

    ~impl_t() {
        if (ssl) ::SSL_free(ssl);
        if (ctx) ::SSL_CTX_free(ctx);
    }
};

stream_t::stream_t() : p_(std::make_unique<impl_t>()) {}
stream_t::~stream_t() = default;

std::unique_ptr<stream_t> stream_t::accept(socket_t, server_cred_t&, int, std::string* error) {
    if (error)
        *error = "server-side TLS is not implemented on this platform (no certificate store)";
    return nullptr;
}

std::unique_ptr<stream_t> stream_t::connect(socket_t s, const std::string& host,
                                            const client_options_t& opt, int timeout_ms,
                                            std::string* error) {
    init_ssl();
    auto out = std::unique_ptr<stream_t>(new stream_t());
    out->p_->fd = static_cast<int>(s);

    // system trust store; exclusive_roots is a Windows test hook and is
    // ignored here (tests that pin a root do not run on this platform)
    (void)opt.exclusive_roots;
    out->p_->ctx = ::SSL_CTX_new(::TLS_client_method());
    if (!out->p_->ctx) {
        if (error) *error = "SSL_CTX_new failed: " + ssl_error_text();
        return nullptr;
    }
    ::SSL_CTX_set_min_proto_version(out->p_->ctx, TLS1_2_VERSION);
    if (opt.verify) {
        ::SSL_CTX_set_verify(out->p_->ctx, SSL_VERIFY_PEER, nullptr);
        if (::SSL_CTX_set_default_verify_paths(out->p_->ctx) != 1) {
            if (error) *error = "no system trust store: " + ssl_error_text();
            return nullptr;
        }
    } else {
        ::SSL_CTX_set_verify(out->p_->ctx, SSL_VERIFY_NONE, nullptr);
    }

    out->p_->ssl = ::SSL_new(out->p_->ctx);
    if (!out->p_->ssl) {
        if (error) *error = "SSL_new failed: " + ssl_error_text();
        return nullptr;
    }
    if (timeout_ms > 0) {
        timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
        ::setsockopt(out->p_->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ::setsockopt(out->p_->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
    ::SSL_set_fd(out->p_->ssl, out->p_->fd);
    if (opt.verify) {
        ::SSL_set_hostflags(out->p_->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (::SSL_set1_host(out->p_->ssl, host.c_str()) != 1) {
            if (error) *error = "cannot pin the host name: " + host;
            return nullptr;
        }
    }
    ::SSL_set_tlsext_host_name(out->p_->ssl, host.c_str());
    if (::SSL_connect(out->p_->ssl) != 1) {
        out->p_->last_error = ssl_error_text();
        if (error) *error = out->p_->last_error;
        return nullptr;
    }
    return out;
}

int stream_t::read(uint8_t* buf, size_t cap) {
    if (!p_->ssl || cap == 0) return 0;
    const int n = ::SSL_read(p_->ssl, buf, static_cast<int>(std::min<size_t>(cap, 1 << 20)));
    if (n > 0) return n;
    const int err = ::SSL_get_error(p_->ssl, n);
    if (err == SSL_ERROR_ZERO_RETURN) return 0;
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return -1;
    p_->last_error = ssl_error_text();
    return -1;
}

bool stream_t::write(const uint8_t* d, size_t n) {
    if (!p_->ssl) return false;
    while (n > 0) {
        const int w = ::SSL_write(p_->ssl, d, static_cast<int>(std::min<size_t>(n, 1 << 20)));
        if (w <= 0) {
            p_->last_error = ssl_error_text();
            return false;
        }
        d += w;
        n -= static_cast<size_t>(w);
    }
    return true;
}


bool stream_t::pending() const {
    return p_->ssl && ::SSL_pending(p_->ssl) > 0;
}

void stream_t::close_notify() {
    if (p_->ssl) ::SSL_shutdown(p_->ssl);
}

std::string stream_t::protocol() const {
    if (!p_->ssl) return {};
    return ::SSL_get_version(p_->ssl);
}

const std::string& stream_t::last_error() const { return p_->last_error; }

} // namespace slop::core::network::tls
