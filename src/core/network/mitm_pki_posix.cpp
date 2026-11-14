// src/core/network/mitm_pki_posix.cpp
// The MITM certificate authority is CNG/cert-store based on Windows. On POSIX
// there is no equivalent local key service wired up here, so every operation
// reports that instead of half-working: the proxy's TLS interception stays
// off and plain HTTP proxying keeps working.

#include "core/network/mitm_pki.hpp"

namespace slop::core::network::mitm {

namespace {

constexpr const char* kNoCa =
    "TLS interception needs a local CA; this build has no certificate store "
    "integration (Windows CNG only)";

} // namespace

struct pki_t::impl_t {};

pki_t::pki_t(pki_options_t) : p_(std::make_unique<impl_t>()) {}
pki_t::~pki_t() = default;

bool pki_t::ensure_ca(std::string* error) {
    if (error) *error = kNoCa;
    return false;
}

bool pki_t::load_existing() { return false; }

bool pki_t::has_ca() const { return false; }

const _CERT_CONTEXT* pki_t::ca_cert() const { return nullptr; }

std::vector<uint8_t> pki_t::ca_der() const { return {}; }

std::string pki_t::ca_path() const { return {}; }

std::string pki_t::ca_thumbprint() const { return {}; }

std::shared_ptr<const _CERT_CONTEXT> pki_t::leaf_for(const std::string&, std::string* error) {
    if (error) *error = kNoCa;
    return nullptr;
}

size_t pki_t::issued() const { return 0; }

bool pki_t::install_root(std::string* error) {
    if (error) *error = kNoCa;
    return false;
}

bool pki_t::root_installed() const { return false; }

bool pki_t::uninstall_root(std::string* error) {
    if (error) *error = kNoCa;
    return false;
}

bool pki_t::destroy(std::string* error) {
    if (error) *error = kNoCa;
    return false;
}

size_t remove_legacy_artifacts(std::string* error) {
    if (error) *error = kNoCa;
    return 0;
}

} // namespace slop::core::network::mitm
