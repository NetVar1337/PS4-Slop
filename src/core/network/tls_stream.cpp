// src/core/network/tls_stream.cpp

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <subauth.h>
#define SECURITY_WIN32
#include <security.h>
#include <sspi.h>
#define SCHANNEL_USE_BLACKLISTS
#include <schannel.h>

#include "core/network/tls_stream.hpp"

#include <algorithm>
#include <climits>
#include <cstdio>
#include <cstring>
#include <vector>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ws2_32.lib")

namespace slop::core::network::tls {

namespace {

std::string hr_text(SECURITY_STATUS ss) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%08lX", static_cast<unsigned long>(ss));
    return buf;
}

std::wstring widen(const std::string& s) {
    std::wstring w;
    w.reserve(s.size());
    for (char c : s) w.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
    return w;
}

bool send_all(SOCKET s, const uint8_t* p, size_t n) {
    while (n > 0) {
        const int w = ::send(s, reinterpret_cast<const char*>(p),
                             static_cast<int>(std::min<size_t>(n, 1 << 20)), 0);
        if (w <= 0) return false;
        p += w;
        n -= static_cast<size_t>(w);
    }
    return true;
}

void set_timeouts(SOCKET s, int ms) {
    const DWORD t = static_cast<DWORD>(ms);
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&t), sizeof(t));
    ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&t), sizeof(t));
}

// TLS 1.0-1.1 and SSL are never offered
constexpr DWORD kDisabledProtocols = SP_PROT_SSL2 | SP_PROT_SSL3 | SP_PROT_TLS1_0 | SP_PROT_TLS1_1;

// SCH_CREDENTIALS (TLS 1.3 capable) with a SCHANNEL_CRED fallback for older systems
SECURITY_STATUS acquire(bool server, PCCERT_CONTEXT cert, CredHandle* out) {
    TimeStamp expiry{};
    PCCERT_CONTEXT certs[1] = {cert};
    TLS_PARAMETERS tp{};
    tp.grbitDisabledProtocols = kDisabledProtocols;
    SCH_CREDENTIALS sc{};
    sc.dwVersion = SCH_CREDENTIALS_VERSION;
    sc.cCreds = cert ? 1 : 0;
    sc.paCred = cert ? certs : nullptr;
    sc.cTlsParameters = 1;
    sc.pTlsParameters = &tp;
    sc.dwFlags = server ? 0 : (SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS |
                               SCH_USE_STRONG_CRYPTO);
    SECURITY_STATUS ss = ::AcquireCredentialsHandleW(
        nullptr, const_cast<LPWSTR>(UNISP_NAME_W),
        server ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND, nullptr, &sc, nullptr, nullptr,
        out, &expiry);
    if (ss == SEC_E_OK) return ss;

    SCHANNEL_CRED legacy{};
    legacy.dwVersion = SCHANNEL_CRED_VERSION;
    legacy.cCreds = sc.cCreds;
    legacy.paCred = sc.paCred;
    legacy.grbitEnabledProtocols = server ? SP_PROT_TLS1_2_SERVER : SP_PROT_TLS1_2_CLIENT;
    legacy.dwFlags = sc.dwFlags;
    return ::AcquireCredentialsHandleW(nullptr, const_cast<LPWSTR>(UNISP_NAME_W),
                                       server ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND,
                                       nullptr, &legacy, nullptr, nullptr, out, &expiry);
}

} // namespace

// server credentials

struct server_cred_t::impl_t {
    CredHandle h{};
    bool valid = false;
    ~impl_t() {
        if (valid) ::FreeCredentialsHandle(&h);
    }
};

server_cred_t::server_cred_t() : p_(std::make_unique<impl_t>()) {}
server_cred_t::~server_cred_t() = default;
void* server_cred_t::handle() { return &p_->h; }

std::shared_ptr<server_cred_t> server_cred_t::create(const _CERT_CONTEXT* cert,
                                                     std::string* error) {
    std::shared_ptr<server_cred_t> c(new server_cred_t());
    const SECURITY_STATUS ss = acquire(true, cert, &c->p_->h);
    if (ss != SEC_E_OK) {
        if (error) *error = "server credentials rejected by Schannel (" + hr_text(ss) + ")";
        return nullptr;
    }
    c->p_->valid = true;
    return c;
}

// stream

struct stream_t::impl_t {
    SOCKET s = INVALID_SOCKET;
    bool server = false;
    CredHandle client_cred{};
    bool own_cred = false;
    CredHandle* cred = nullptr;
    CtxtHandle ctx{};
    bool has_ctx = false;
    std::wstring target;
    SecPkgContext_StreamSizes sizes{};
    std::vector<uint8_t> in;       // undecrypted bytes
    std::vector<uint8_t> plain;    // decrypted, not yet returned
    size_t plain_off = 0;
    bool closed = false;
    std::string error;
    // 16 KiB recv scratch, kept on the heap: a stack buffer of this size trips
    // MSVC /analyze C6262 (function uses 16396 bytes of stack)
    std::vector<uint8_t> recv_buf = std::vector<uint8_t>(16384);

    ~impl_t() {
        if (has_ctx) ::DeleteSecurityContext(&ctx);
        if (own_cred) ::FreeCredentialsHandle(&client_cred);
    }

    int recv_more() {
        const int r = ::recv(s, reinterpret_cast<char*>(recv_buf.data()),
                             static_cast<int>(recv_buf.size()), 0);
        if (r > 0) in.insert(in.end(), recv_buf.begin(), recv_buf.begin() + r);
        return r;
    }

    bool send_token(SecBuffer& b) {
        bool ok = true;
        if (b.cbBuffer && b.pvBuffer)
            ok = send_all(s, static_cast<const uint8_t*>(b.pvBuffer), b.cbBuffer);
        if (b.pvBuffer) ::FreeContextBuffer(b.pvBuffer);
        b.pvBuffer = nullptr;
        b.cbBuffer = 0;
        return ok;
    }

    SECURITY_STATUS step(SecBufferDesc* in_desc, SecBufferDesc* out_desc) {
        ULONG attrs = 0;
        if (server) {
            const ULONG flags = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                                ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR |
                                ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM;
            const SECURITY_STATUS ss = ::AcceptSecurityContext(
                cred, has_ctx ? &ctx : nullptr, in_desc, flags, 0, &ctx, out_desc, &attrs,
                nullptr);
            if (!has_ctx && (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED)) has_ctx = true;
            return ss;
        }
        const ULONG flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                            ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
                            ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
                            ISC_REQ_MANUAL_CRED_VALIDATION;
        const SECURITY_STATUS ss = ::InitializeSecurityContextW(
            cred, has_ctx ? &ctx : nullptr, target.empty() ? nullptr : target.data(), flags, 0,
            0, in_desc, 0, &ctx, out_desc, &attrs, nullptr);
        if (!has_ctx && (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED)) has_ctx = true;
        return ss;
    }

    // drives AcceptSecurityContext / InitializeSecurityContext until SEC_E_OK,
    // consuming `in`; bytes after the handshake stay in `in`
    bool handshake_loop(bool need_input_first) {
        bool need_read = need_input_first && in.empty();
        for (int rounds = 0; rounds < 64; ++rounds) {
            if (need_read) {
                const int r = recv_more();
                if (r <= 0) {
                    error = r == 0 ? "peer closed during the TLS handshake"
                                   : "socket error/timeout during the TLS handshake";
                    return false;
                }
            }
            SecBuffer ib[2] = {
                {static_cast<unsigned long>(in.size()), SECBUFFER_TOKEN, in.empty() ? nullptr : in.data()},
                {0, SECBUFFER_EMPTY, nullptr}};
            SecBufferDesc id{SECBUFFER_VERSION, 2, ib};
            SecBuffer ob[1] = {{0, SECBUFFER_TOKEN, nullptr}};
            SecBufferDesc od{SECBUFFER_VERSION, 1, ob};
            const bool have_input = !in.empty();
            SECURITY_STATUS ss = step(have_input ? &id : nullptr, &od);
            if (ss == SEC_E_INCOMPLETE_MESSAGE) {
                need_read = true;
                continue;
            }
            if (!send_token(ob[0])) {
                error = "socket send failed during the TLS handshake";
                return false;
            }
            if (ss == SEC_I_INCOMPLETE_CREDENTIALS) ss = SEC_I_CONTINUE_NEEDED;   // no client cert
            if (ss != SEC_E_OK && ss != SEC_I_CONTINUE_NEEDED) {
                error = "TLS handshake failed (" + hr_text(ss) + ")";
                return false;
            }
            if (have_input) {
                if (ib[1].BufferType == SECBUFFER_EXTRA && ib[1].cbBuffer <= in.size())
                    in.erase(in.begin(), in.end() - static_cast<std::ptrdiff_t>(ib[1].cbBuffer));
                else
                    in.clear();
            }
            if (ss == SEC_E_OK) return true;
            need_read = in.empty();
        }
        error = "TLS handshake did not converge";
        return false;
    }

    bool finish_setup() {
        const SECURITY_STATUS ss = ::QueryContextAttributesW(&ctx, SECPKG_ATTR_STREAM_SIZES, &sizes);
        if (ss != SEC_E_OK) {
            error = "stream sizes unavailable (" + hr_text(ss) + ")";
            return false;
        }
        return true;
    }

    bool verify_peer(const client_options_t& opt) {
        PCCERT_CONTEXT peer = nullptr;
        SECURITY_STATUS ss = ::QueryContextAttributesW(&ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &peer);
        if (ss != SEC_E_OK || !peer) {
            error = "server presented no certificate";
            return false;
        }
        HCERTCHAINENGINE engine = nullptr;
        if (opt.exclusive_roots) {
            CERT_CHAIN_ENGINE_CONFIG cfg{};
            cfg.cbSize = sizeof(cfg);
            cfg.hExclusiveRoot = static_cast<HCERTSTORE>(opt.exclusive_roots);
            if (!::CertCreateCertificateChainEngine(&cfg, &engine)) {
                ::CertFreeCertificateContext(peer);
                error = "cannot create the certificate chain engine";
                return false;
            }
        }
        LPSTR usages[] = {const_cast<LPSTR>(szOID_PKIX_KP_SERVER_AUTH)};
        CERT_CHAIN_PARA para{};
        para.cbSize = sizeof(para);
        para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
        para.RequestedUsage.Usage.cUsageIdentifier = 1;
        para.RequestedUsage.Usage.rgpszUsageIdentifier = usages;
        PCCERT_CHAIN_CONTEXT chain = nullptr;
        bool ok = ::CertGetCertificateChain(engine, peer, nullptr, peer->hCertStore, &para, 0,
                                            nullptr, &chain) != FALSE;
        if (!ok) {
            error = "certificate chain could not be built";
        } else {
            SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl{};
            ssl.cbSize = sizeof(ssl);
            ssl.dwAuthType = AUTHTYPE_SERVER;
            ssl.pwszServerName = target.data();
            CERT_CHAIN_POLICY_PARA pp{};
            pp.cbSize = sizeof(pp);
            pp.pvExtraPolicyPara = &ssl;
            CERT_CHAIN_POLICY_STATUS ps{};
            ps.cbSize = sizeof(ps);
            ok = ::CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain, &pp, &ps) &&
                 ps.dwError == 0;
            if (!ok) {
                char buf[96];
                std::snprintf(buf, sizeof(buf), "server certificate rejected (0x%08lX)",
                              static_cast<unsigned long>(ps.dwError));
                error = buf;
            }
            ::CertFreeCertificateChain(chain);
        }
        if (engine) ::CertFreeCertificateChainEngine(engine);
        ::CertFreeCertificateContext(peer);
        return ok;
    }

    bool record_complete() const {
        if (in.size() < 5) return false;
        const size_t len = (static_cast<size_t>(in[3]) << 8) | in[4];
        return in.size() >= 5 + len;
    }
};

stream_t::stream_t() : p_(std::make_unique<impl_t>()) {}
stream_t::~stream_t() = default;

std::unique_ptr<stream_t> stream_t::accept(socket_t s, server_cred_t& cred, int timeout_ms,
                                           std::string* error) {
    std::unique_ptr<stream_t> st(new stream_t());
    impl_t& p = *st->p_;
    p.s = static_cast<SOCKET>(s);
    p.server = true;
    p.cred = static_cast<CredHandle*>(cred.handle());
    set_timeouts(p.s, timeout_ms);
    if (!p.handshake_loop(true) || !p.finish_setup()) {
        if (error) *error = p.error;
        return nullptr;
    }
    return st;
}

std::unique_ptr<stream_t> stream_t::connect(socket_t s, const std::string& host,
                                            const client_options_t& opt, int timeout_ms,
                                            std::string* error) {
    std::unique_ptr<stream_t> st(new stream_t());
    impl_t& p = *st->p_;
    p.s = static_cast<SOCKET>(s);
    p.server = false;
    std::string h = host;
    if (h.size() >= 2 && h.front() == '[' && h.back() == ']') h = h.substr(1, h.size() - 2);
    p.target = widen(h);
    const SECURITY_STATUS ss = acquire(false, nullptr, &p.client_cred);
    if (ss != SEC_E_OK) {
        if (error) *error = "client credentials unavailable (" + hr_text(ss) + ")";
        return nullptr;
    }
    p.own_cred = true;
    p.cred = &p.client_cred;
    set_timeouts(p.s, timeout_ms);
    if (!p.handshake_loop(false) || !p.finish_setup() || (opt.verify && !p.verify_peer(opt))) {
        if (error) *error = p.error;
        return nullptr;
    }
    return st;
}

int stream_t::read(uint8_t* buf, size_t cap) {
    impl_t& p = *p_;
    for (;;) {
        if (p.plain_off < p.plain.size()) {
            const size_t n = std::min(cap, p.plain.size() - p.plain_off);
            std::memcpy(buf, p.plain.data() + p.plain_off, n);
            p.plain_off += n;
            if (p.plain_off == p.plain.size()) {
                p.plain.clear();
                p.plain_off = 0;
            }
            return static_cast<int>(std::min<size_t>(n, INT_MAX));
        }
        if (p.closed) return 0;
        if (!p.in.empty()) {
            SecBuffer b[4] = {{static_cast<unsigned long>(p.in.size()), SECBUFFER_DATA, p.in.data()},
                              {0, SECBUFFER_EMPTY, nullptr},
                              {0, SECBUFFER_EMPTY, nullptr},
                              {0, SECBUFFER_EMPTY, nullptr}};
            SecBufferDesc d{SECBUFFER_VERSION, 4, b};
            const SECURITY_STATUS ss = ::DecryptMessage(&p.ctx, &d, 0, nullptr);
            if (ss == SEC_E_OK || ss == SEC_I_RENEGOTIATE || ss == SEC_I_CONTEXT_EXPIRED) {
                std::vector<uint8_t> extra;
                for (auto& sb : b) {
                    if (sb.BufferType == SECBUFFER_DATA && sb.cbBuffer)
                        p.plain.insert(p.plain.end(), static_cast<uint8_t*>(sb.pvBuffer),
                                       static_cast<uint8_t*>(sb.pvBuffer) + sb.cbBuffer);
                    else if (sb.BufferType == SECBUFFER_EXTRA && sb.cbBuffer)
                        extra.assign(static_cast<uint8_t*>(sb.pvBuffer),
                                     static_cast<uint8_t*>(sb.pvBuffer) + sb.cbBuffer);
                }
                p.in = std::move(extra);
                if (ss == SEC_I_CONTEXT_EXPIRED) {
                    p.closed = true;
                } else if (ss == SEC_I_RENEGOTIATE) {
                    // TLS 1.3 post-handshake message (session ticket / key update):
                    // feed the remaining bytes back through the handshake call
                    if (!p.handshake_loop(false)) return -1;
                }
                continue;
            }
            if (ss != SEC_E_INCOMPLETE_MESSAGE) {
                p.error = "TLS decrypt failed (" + hr_text(ss) + ")";
                return -1;
            }
        }
        const int r = p.recv_more();
        if (r == 0) {
            p.closed = true;
            return 0;
        }
        if (r < 0) {
            p.error = "socket error/timeout";
            return -1;
        }
    }
}

bool stream_t::write(const uint8_t* d, size_t n) {
    impl_t& p = *p_;
    const size_t max_msg = p.sizes.cbMaximumMessage ? p.sizes.cbMaximumMessage : 16384;
    std::vector<uint8_t> buf(p.sizes.cbHeader + max_msg + p.sizes.cbTrailer);
    while (n > 0) {
        const size_t chunk = std::min(n, max_msg);
        std::memcpy(buf.data() + p.sizes.cbHeader, d, chunk);
        SecBuffer b[4] = {
            {p.sizes.cbHeader, SECBUFFER_STREAM_HEADER, buf.data()},
            {static_cast<unsigned long>(chunk), SECBUFFER_DATA, buf.data() + p.sizes.cbHeader},
            {p.sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, buf.data() + p.sizes.cbHeader + chunk},
            {0, SECBUFFER_EMPTY, nullptr}};
        SecBufferDesc desc{SECBUFFER_VERSION, 4, b};
        const SECURITY_STATUS ss = ::EncryptMessage(&p.ctx, 0, &desc, 0);
        if (ss != SEC_E_OK) {
            p.error = "TLS encrypt failed (" + hr_text(ss) + ")";
            return false;
        }
        if (!send_all(p.s, buf.data(), b[0].cbBuffer + b[1].cbBuffer + b[2].cbBuffer)) {
            p.error = "socket send failed";
            return false;
        }
        d += chunk;
        n -= chunk;
    }
    return true;
}

bool stream_t::pending() const {
    return p_->plain_off < p_->plain.size() || p_->record_complete();
}

void stream_t::close_notify() {
    impl_t& p = *p_;
    if (!p.has_ctx) return;
    DWORD type = SCHANNEL_SHUTDOWN;
    SecBuffer tb{sizeof(type), SECBUFFER_TOKEN, &type};
    SecBufferDesc td{SECBUFFER_VERSION, 1, &tb};
    if (::ApplyControlToken(&p.ctx, &td) != SEC_E_OK) return;
    SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc od{SECBUFFER_VERSION, 1, &ob};
    p.step(nullptr, &od);
    p.send_token(ob);
}

std::string stream_t::protocol() const {
    SecPkgContext_ConnectionInfo ci{};
    if (::QueryContextAttributesW(&p_->ctx, SECPKG_ATTR_CONNECTION_INFO, &ci) != SEC_E_OK)
        return "unknown";
    if (ci.dwProtocol & SP_PROT_TLS1_3) return "TLS 1.3";
    if (ci.dwProtocol & SP_PROT_TLS1_2) return "TLS 1.2";
    if (ci.dwProtocol & SP_PROT_TLS1_1) return "TLS 1.1";
    if (ci.dwProtocol & SP_PROT_TLS1_0) return "TLS 1.0";
    return "unknown";
}

const std::string& stream_t::last_error() const {
    return p_->error;
}

} // namespace slop::core::network::tls
