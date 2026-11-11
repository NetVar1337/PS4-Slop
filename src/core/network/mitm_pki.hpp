#pragma once

// src/core/network/mitm_pki.hpp
// local CA + per-host leaf certificates for the proxy's opt-in TLS
// interception. Keys are CNG keys (RSA-2048) in the Microsoft Software KSP;
// leaf certificates live in memory only. Trusting the CA (CurrentUser\ROOT)
// and removing that trust are separate, explicit operations; tests point the
// trust store at an in-memory store and destroy their keys afterwards

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

struct _CERT_CONTEXT;

namespace slop::core::network::mitm {

struct pki_options_t {
    // CNG key names are "<key_prefix>-ca" and "<key_prefix>-leaf"
    std::wstring key_prefix = L"reverse-slop-mitm";
    // directory holding ca.cer (DER) so the CA survives restarts; empty keeps
    // the CA in memory for this instance only (its key is then ephemeral)
    std::string dir;
    // HCERTSTORE used by install/uninstall/installed instead of
    // CurrentUser\ROOT (tests pass a CERT_STORE_PROV_MEMORY store)
    void* trust_store = nullptr;
    size_t max_cached_leaves = 256;
};

class pki_t {
public:
    explicit pki_t(pki_options_t opt);
    ~pki_t();
    pki_t(const pki_t&) = delete;
    pki_t& operator=(const pki_t&) = delete;

    // loads the persisted CA (dir/ca.cer + its CNG key, verified to match) or
    // creates a new one
    bool ensure_ca(std::string* error = nullptr);
    // loads a persisted CA without ever creating one; false when absent/invalid
    bool load_existing();
    bool has_ca() const;
    const _CERT_CONTEXT* ca_cert() const;      // borrowed; null until ensure_ca
    std::vector<uint8_t> ca_der() const;
    std::string ca_path() const;               // dir/ca.cer ("" in memory mode)
    std::string ca_thumbprint() const;         // SHA-1 hex, uppercase

    // leaf for `host` (DNS name or IP literal, validated; nothing touches the
    // filesystem). Serial: 128-bit random positive; valid now-1d .. now+397d;
    // SAN, serverAuth EKU, CA:false. Cached in memory (LRU)
    std::shared_ptr<const _CERT_CONTEXT> leaf_for(const std::string& host,
                                                  std::string* error = nullptr);
    size_t issued() const;

    // CA trust (CurrentUser\ROOT unless options.trust_store). Adding to the
    // real ROOT store makes Windows show its own confirmation dialog
    bool install_root(std::string* error = nullptr);
    bool root_installed() const;
    bool uninstall_root(std::string* error = nullptr);

    // removes trust, deletes both CNG keys and ca.cer, forgets all state
    bool destroy(std::string* error = nullptr);

private:
    struct impl_t;
    std::unique_ptr<impl_t> p_;
};

// removes what the previous PKI implementation left behind ("reverse-slop
// Local CA" in CurrentUser\MY and \ROOT, the "reverse-slop-ca-key" and
// "reverse-slop-host-*" CAPI containers, %LOCALAPPDATA%\reverse-slop\certs).
// Returns how many objects were removed
size_t remove_legacy_artifacts(std::string* error = nullptr);

} // namespace slop::core::network::mitm
