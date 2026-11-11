// src/core/network/mitm_pki.cpp

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <bcrypt.h>

#include "core/network/mitm_pki.hpp"

#include "core/network/parsers.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

namespace slop::core::network::mitm {

namespace {

constexpr uint64_t kDay = 864000000000ull;            // 100 ns ticks
constexpr uint64_t kLeafDays = 397;                   // CA/B + Apple ceiling is 398
constexpr uint64_t kCaDays = 3650;

std::string gle_text(const char* what, DWORD e) {
    char buf[160];
    std::snprintf(buf, sizeof(buf), "%s (0x%08lX)", what, static_cast<unsigned long>(e));
    return buf;
}

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

FILETIME ft_add(FILETIME base, int64_t ticks) {
    ULARGE_INTEGER u;
    u.LowPart = base.dwLowDateTime;
    u.HighPart = base.dwHighDateTime;
    u.QuadPart = static_cast<uint64_t>(static_cast<int64_t>(u.QuadPart) + ticks);
    FILETIME out;
    out.dwLowDateTime = u.LowPart;
    out.dwHighDateTime = u.HighPart;
    return out;
}

std::vector<uint8_t> encode(LPCSTR type, const void* value) {
    DWORD cb = 0;
    if (!::CryptEncodeObjectEx(X509_ASN_ENCODING, type, value, 0, nullptr, nullptr, &cb)) return {};
    std::vector<uint8_t> out(cb);
    if (!::CryptEncodeObjectEx(X509_ASN_ENCODING, type, value, 0, nullptr, out.data(), &cb)) return {};
    out.resize(cb);
    return out;
}

// RDN sequence with UTF-8 strings (X509_UNICODE_NAME takes wide input)
std::vector<uint8_t> encode_name(const std::vector<std::pair<LPCSTR, std::wstring>>& parts) {
    std::vector<CERT_RDN_ATTR> attrs(parts.size());
    std::vector<CERT_RDN> rdns(parts.size());
    for (size_t i = 0; i < parts.size(); ++i) {
        attrs[i].pszObjId = const_cast<LPSTR>(parts[i].first);
        attrs[i].dwValueType = CERT_RDN_UTF8_STRING;
        attrs[i].Value.pbData = reinterpret_cast<BYTE*>(const_cast<wchar_t*>(parts[i].second.c_str()));
        attrs[i].Value.cbData = static_cast<DWORD>(parts[i].second.size() * sizeof(wchar_t));
        rdns[i].cRDNAttr = 1;
        rdns[i].rgRDNAttr = &attrs[i];
    }
    CERT_NAME_INFO ni{static_cast<DWORD>(rdns.size()), rdns.data()};
    return encode(X509_UNICODE_NAME, &ni);
}

// 128-bit positive serial. CRYPT_INTEGER_BLOB is little-endian (byte 0 is the
// least significant); CryptoAPI emits big-endian DER, so clearing the top bit
// of the last byte keeps the INTEGER positive and setting 0x40 keeps it 16 bytes
std::vector<uint8_t> random_serial() {
    std::vector<uint8_t> s(16);
    ::BCryptGenRandom(nullptr, s.data(), static_cast<ULONG>(s.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    s[15] = static_cast<uint8_t>((s[15] & 0x7F) | 0x40);
    return s;
}

struct ncrypt_key_t {
    NCRYPT_KEY_HANDLE h = 0;
    ncrypt_key_t() = default;
    ncrypt_key_t(const ncrypt_key_t&) = delete;
    ncrypt_key_t& operator=(const ncrypt_key_t&) = delete;
    ~ncrypt_key_t() { reset(); }
    void reset() {
        if (h) ::NCryptFreeObject(h);
        h = 0;
    }
};

struct ncrypt_prov_t {
    NCRYPT_PROV_HANDLE h = 0;
    ncrypt_prov_t() { ::NCryptOpenStorageProvider(&h, MS_KEY_STORAGE_PROVIDER, 0); }
    ~ncrypt_prov_t() {
        if (h) ::NCryptFreeObject(h);
    }
};

// opens the named persisted key, or creates it (name empty = ephemeral)
SECURITY_STATUS open_or_create_key(const std::wstring& name, bool create_new, ncrypt_key_t& out) {
    ncrypt_prov_t prov;
    if (!prov.h) return NTE_PROV_DLL_NOT_FOUND;
    out.reset();
    if (!name.empty() && !create_new &&
        ::NCryptOpenKey(prov.h, &out.h, name.c_str(), 0, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS)
        return ERROR_SUCCESS;
    SECURITY_STATUS ss = ::NCryptCreatePersistedKey(
        prov.h, &out.h, BCRYPT_RSA_ALGORITHM, name.empty() ? nullptr : name.c_str(), 0,
        name.empty() ? 0 : NCRYPT_OVERWRITE_KEY_FLAG);
    if (ss != ERROR_SUCCESS) return ss;
    DWORD bits = 2048;
    ::NCryptSetProperty(out.h, NCRYPT_LENGTH_PROPERTY, reinterpret_cast<PBYTE>(&bits), sizeof(bits), 0);
    DWORD usage = NCRYPT_ALLOW_ALL_USAGES;
    ::NCryptSetProperty(out.h, NCRYPT_KEY_USAGE_PROPERTY, reinterpret_cast<PBYTE>(&usage), sizeof(usage), 0);
    ss = ::NCryptFinalizeKey(out.h, NCRYPT_SILENT_FLAG);
    if (ss != ERROR_SUCCESS) out.reset();
    return ss;
}

void delete_key(const std::wstring& name) {
    ncrypt_prov_t prov;
    NCRYPT_KEY_HANDLE k = 0;
    if (prov.h && ::NCryptOpenKey(prov.h, &k, name.c_str(), 0, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS)
        ::NCryptDeleteKey(k, 0);   // frees the handle
}

std::vector<uint8_t> export_spki(NCRYPT_KEY_HANDLE k) {
    DWORD cb = 0;
    if (!::CryptExportPublicKeyInfo(k, 0, X509_ASN_ENCODING, nullptr, &cb)) return {};
    std::vector<uint8_t> buf(cb);
    if (!::CryptExportPublicKeyInfo(k, 0, X509_ASN_ENCODING,
                                    reinterpret_cast<CERT_PUBLIC_KEY_INFO*>(buf.data()), &cb))
        return {};
    return buf;
}

std::vector<uint8_t> key_id(const CERT_PUBLIC_KEY_INFO* spki) {
    std::vector<uint8_t> id(20);
    DWORD cb = static_cast<DWORD>(id.size());
    if (!::CryptHashPublicKeyInfo(0, CALG_SHA1, 0, X509_ASN_ENCODING,
                                  const_cast<CERT_PUBLIC_KEY_INFO*>(spki), id.data(), &cb))
        return {};
    id.resize(cb);
    return id;
}

struct cert_spec_t {
    std::vector<uint8_t> issuer, subject;
    const CERT_PUBLIC_KEY_INFO* spki = nullptr;
    FILETIME not_before{}, not_after{};
    std::vector<CERT_EXTENSION> exts;
};

std::vector<uint8_t> sign_cert(NCRYPT_KEY_HANDLE signer, const cert_spec_t& spec, DWORD* gle) {
    std::vector<uint8_t> serial = random_serial();
    CERT_INFO info{};
    info.dwVersion = CERT_V3;
    info.SerialNumber = {static_cast<DWORD>(serial.size()), serial.data()};
    info.SignatureAlgorithm.pszObjId = const_cast<LPSTR>(szOID_RSA_SHA256RSA);
    info.Issuer = {static_cast<DWORD>(spec.issuer.size()), const_cast<BYTE*>(spec.issuer.data())};
    info.Subject = {static_cast<DWORD>(spec.subject.size()), const_cast<BYTE*>(spec.subject.data())};
    info.NotBefore = spec.not_before;
    info.NotAfter = spec.not_after;
    info.SubjectPublicKeyInfo = *spec.spki;
    info.cExtension = static_cast<DWORD>(spec.exts.size());
    info.rgExtension = const_cast<CERT_EXTENSION*>(spec.exts.data());
    CRYPT_ALGORITHM_IDENTIFIER alg{};
    alg.pszObjId = const_cast<LPSTR>(szOID_RSA_SHA256RSA);
    DWORD cb = 0;
    if (!::CryptSignAndEncodeCertificate(signer, 0, X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED,
                                         &info, &alg, nullptr, nullptr, &cb)) {
        *gle = ::GetLastError();
        return {};
    }
    std::vector<uint8_t> der(cb);
    if (!::CryptSignAndEncodeCertificate(signer, 0, X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED,
                                         &info, &alg, nullptr, der.data(), &cb)) {
        *gle = ::GetLastError();
        return {};
    }
    der.resize(cb);
    return der;
}

CERT_EXTENSION ext(LPCSTR oid, bool critical, std::vector<uint8_t>& storage) {
    CERT_EXTENSION e{};
    e.pszObjId = const_cast<LPSTR>(oid);
    e.fCritical = critical ? TRUE : FALSE;
    e.Value = {static_cast<DWORD>(storage.size()), storage.data()};
    return e;
}

std::string hex_upper(const uint8_t* d, size_t n) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string s;
    for (size_t i = 0; i < n; ++i) {
        s.push_back(kHex[d[i] >> 4]);
        s.push_back(kHex[d[i] & 0xF]);
    }
    return s;
}

HCERTSTORE open_user_root(bool read_only) {
    return ::CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                           CERT_SYSTEM_STORE_CURRENT_USER |
                               (read_only ? CERT_STORE_READONLY_FLAG : 0),
                           L"ROOT");
}

using cert_ptr = std::shared_ptr<const CERT_CONTEXT>;

cert_ptr wrap(PCCERT_CONTEXT c) {
    return cert_ptr(c, [](const CERT_CONTEXT* p) { if (p) ::CertFreeCertificateContext(p); });
}

} // namespace

struct pki_t::impl_t {
    pki_options_t opt;
    mutable std::mutex mu;
    ncrypt_key_t ca_key;
    ncrypt_key_t leaf_key;
    std::vector<uint8_t> leaf_spki;
    cert_ptr ca;
    std::vector<uint8_t> ca_kid;
    struct leaf_entry_t { cert_ptr cert; uint64_t used = 0; };
    std::map<std::string, leaf_entry_t> leaves;
    uint64_t tick = 0;
    size_t issued = 0;

    std::wstring ca_key_name() const { return opt.key_prefix + L"-ca"; }
    std::wstring leaf_key_name() const { return opt.key_prefix + L"-leaf"; }
    std::string ca_file() const { return opt.dir.empty() ? std::string{} : opt.dir + "\\ca.cer"; }

    bool load_persisted() {
        const std::string path = ca_file();
        if (path.empty()) return false;
        std::ifstream f(path, std::ios::binary);
        if (!f) return false;
        std::vector<uint8_t> der((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        PCCERT_CONTEXT c = ::CertCreateCertificateContext(X509_ASN_ENCODING, der.data(),
                                                          static_cast<DWORD>(der.size()));
        if (!c) return false;
        cert_ptr cert = wrap(c);
        ncrypt_key_t k;
        if (open_or_create_key(ca_key_name(), false, k) != ERROR_SUCCESS) return false;
        std::vector<uint8_t> spki = export_spki(k.h);
        if (spki.empty() ||
            !::CertComparePublicKeyInfo(X509_ASN_ENCODING,
                                        const_cast<CERT_PUBLIC_KEY_INFO*>(&c->pCertInfo->SubjectPublicKeyInfo),
                                        reinterpret_cast<CERT_PUBLIC_KEY_INFO*>(spki.data())))
            return false;
        FILETIME now{};
        ::GetSystemTimeAsFileTime(&now);
        const FILETIME soon = ft_add(now, static_cast<int64_t>(30 * kDay));
        if (::CompareFileTime(&c->pCertInfo->NotAfter, &soon) < 0) return false;   // renew
        ca = std::move(cert);
        ca_key.h = k.h;
        k.h = 0;
        ca_kid = key_id(&ca->pCertInfo->SubjectPublicKeyInfo);
        return true;
    }

    bool create_ca(std::string* error) {
        const bool persist = !opt.dir.empty();
        SECURITY_STATUS ss = open_or_create_key(persist ? ca_key_name() : std::wstring{}, true, ca_key);
        if (ss != ERROR_SUCCESS) {
            if (error) *error = gle_text("CA key creation failed", static_cast<DWORD>(ss));
            return false;
        }
        std::vector<uint8_t> spki = export_spki(ca_key.h);
        if (spki.empty()) {
            if (error) *error = "CA public key export failed";
            return false;
        }
        const auto* pk = reinterpret_cast<const CERT_PUBLIC_KEY_INFO*>(spki.data());
        ca_kid = key_id(pk);

        SYSTEMTIME st{};
        ::GetSystemTime(&st);
        wchar_t cn[96];
        std::swprintf(cn, 96, L"reverse-slop MITM CA %04u-%02u-%02u %02u%02u%02u", st.wYear,
                      st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        cert_spec_t spec;
        spec.subject = encode_name({{szOID_COMMON_NAME, cn}, {szOID_ORGANIZATION_NAME, L"reverse-slop"}});
        spec.issuer = spec.subject;
        spec.spki = pk;
        FILETIME now{};
        ::GetSystemTimeAsFileTime(&now);
        spec.not_before = ft_add(now, -static_cast<int64_t>(kDay));
        spec.not_after = ft_add(now, static_cast<int64_t>(kCaDays * kDay));

        CERT_BASIC_CONSTRAINTS2_INFO bc{TRUE, TRUE, 0};
        auto bc_der = encode(X509_BASIC_CONSTRAINTS2, &bc);
        BYTE ku_bits = CERT_KEY_CERT_SIGN_KEY_USAGE | CERT_CRL_SIGN_KEY_USAGE |
                       CERT_DIGITAL_SIGNATURE_KEY_USAGE;
        CRYPT_BIT_BLOB ku{1, &ku_bits, 0};
        auto ku_der = encode(X509_KEY_USAGE, &ku);
        CRYPT_DATA_BLOB kid{static_cast<DWORD>(ca_kid.size()), ca_kid.data()};
        auto ski_der = encode(szOID_SUBJECT_KEY_IDENTIFIER, &kid);
        if (spec.subject.empty() || bc_der.empty() || ku_der.empty() || ski_der.empty()) {
            if (error) *error = "CA extension encoding failed";
            return false;
        }
        spec.exts = {ext(szOID_BASIC_CONSTRAINTS2, true, bc_der),
                     ext(szOID_KEY_USAGE, true, ku_der),
                     ext(szOID_SUBJECT_KEY_IDENTIFIER, false, ski_der)};
        DWORD gle = 0;
        const auto der = sign_cert(ca_key.h, spec, &gle);
        if (der.empty()) {
            if (error) *error = gle_text("CA signing failed", gle);
            return false;
        }
        PCCERT_CONTEXT c = ::CertCreateCertificateContext(X509_ASN_ENCODING, der.data(),
                                                          static_cast<DWORD>(der.size()));
        if (!c) {
            if (error) *error = gle_text("CA certificate decode failed", ::GetLastError());
            return false;
        }
        ca = wrap(c);
        if (persist) {
            std::error_code ec;
            std::filesystem::create_directories(opt.dir, ec);
            const std::string path = ca_file();
            const std::string tmp = path + ".tmp";
            {
                std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
                f.write(reinterpret_cast<const char*>(der.data()), static_cast<std::streamsize>(der.size()));
                if (!f) {
                    if (error) *error = "cannot write " + tmp;
                    return false;
                }
            }
            if (!::MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                if (error) *error = gle_text(("cannot replace " + path).c_str(), ::GetLastError());
                return false;
            }
        }
        leaves.clear();   // leaves of an older CA are useless now
        return true;
    }

    bool ensure_leaf_key(std::string* error) {
        if (leaf_key.h) return true;
        // persisted so LSA (Schannel) can open it for the server handshake
        const SECURITY_STATUS ss = open_or_create_key(leaf_key_name(), false, leaf_key);
        if (ss != ERROR_SUCCESS) {
            if (error) *error = gle_text("leaf key creation failed", static_cast<DWORD>(ss));
            return false;
        }
        leaf_spki = export_spki(leaf_key.h);
        if (leaf_spki.empty()) {
            leaf_key.reset();
            if (error) *error = "leaf public key export failed";
            return false;
        }
        return true;
    }

    cert_ptr issue(const std::string& host, std::string* error) {
        const auto ip = parse::parse_ip(host);
        cert_spec_t spec;
        const std::wstring whost = widen(host);
        spec.subject = encode_name({{szOID_COMMON_NAME, whost}, {szOID_ORGANIZATION_NAME, L"reverse-slop MITM"}});
        spec.issuer.assign(ca->pCertInfo->Subject.pbData,
                           ca->pCertInfo->Subject.pbData + ca->pCertInfo->Subject.cbData);
        spec.spki = reinterpret_cast<const CERT_PUBLIC_KEY_INFO*>(leaf_spki.data());
        FILETIME now{};
        ::GetSystemTimeAsFileTime(&now);
        spec.not_before = ft_add(now, -static_cast<int64_t>(kDay));
        spec.not_after = ft_add(now, static_cast<int64_t>(kLeafDays * kDay));

        CERT_ALT_NAME_ENTRY alt{};
        if (ip) {
            alt.dwAltNameChoice = CERT_ALT_NAME_IP_ADDRESS;
            alt.IPAddress = {ip->family == 4 ? 4u : 16u, const_cast<BYTE*>(ip->b.data())};
        } else {
            alt.dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
            alt.pwszDNSName = const_cast<LPWSTR>(whost.c_str());
        }
        CERT_ALT_NAME_INFO san{1, &alt};
        auto san_der = encode(X509_ALTERNATE_NAME, &san);
        LPSTR eku_oids[] = {const_cast<LPSTR>(szOID_PKIX_KP_SERVER_AUTH)};
        CERT_ENHKEY_USAGE eku{1, eku_oids};
        auto eku_der = encode(X509_ENHANCED_KEY_USAGE, &eku);
        CERT_BASIC_CONSTRAINTS2_INFO bc{FALSE, FALSE, 0};
        auto bc_der = encode(X509_BASIC_CONSTRAINTS2, &bc);
        BYTE ku_bits = CERT_DIGITAL_SIGNATURE_KEY_USAGE | CERT_KEY_ENCIPHERMENT_KEY_USAGE;
        CRYPT_BIT_BLOB ku{1, &ku_bits, 0};
        auto ku_der = encode(X509_KEY_USAGE, &ku);
        CERT_AUTHORITY_KEY_ID2_INFO aki{};
        aki.KeyId = {static_cast<DWORD>(ca_kid.size()), ca_kid.data()};
        auto aki_der = encode(X509_AUTHORITY_KEY_ID2, &aki);
        if (spec.subject.empty() || san_der.empty() || eku_der.empty() || bc_der.empty() ||
            ku_der.empty() || aki_der.empty()) {
            if (error) *error = "leaf extension encoding failed";
            return nullptr;
        }
        spec.exts = {ext(szOID_SUBJECT_ALT_NAME2, false, san_der),
                     ext(szOID_ENHANCED_KEY_USAGE, false, eku_der),
                     ext(szOID_BASIC_CONSTRAINTS2, true, bc_der),
                     ext(szOID_KEY_USAGE, true, ku_der),
                     ext(szOID_AUTHORITY_KEY_IDENTIFIER2, false, aki_der)};
        DWORD gle = 0;
        const auto der = sign_cert(ca_key.h, spec, &gle);
        if (der.empty()) {
            if (error) *error = gle_text("leaf signing failed", gle);
            return nullptr;
        }
        PCCERT_CONTEXT c = ::CertCreateCertificateContext(X509_ASN_ENCODING, der.data(),
                                                          static_cast<DWORD>(der.size()));
        if (!c) {
            if (error) *error = gle_text("leaf decode failed", ::GetLastError());
            return nullptr;
        }
        const std::wstring kname = leaf_key_name();
        CRYPT_KEY_PROV_INFO kpi{};
        kpi.pwszContainerName = const_cast<LPWSTR>(kname.c_str());
        kpi.pwszProvName = const_cast<LPWSTR>(MS_KEY_STORAGE_PROVIDER);
        kpi.dwProvType = 0;                                   // CNG
        kpi.dwKeySpec = 0;
        if (!::CertSetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, 0, &kpi)) {
            const DWORD e = ::GetLastError();
            ::CertFreeCertificateContext(c);
            if (error) *error = gle_text("cannot bind the leaf key", e);
            return nullptr;
        }
        ++issued;
        return wrap(c);
    }

    std::vector<uint8_t> thumb() const {
        std::vector<uint8_t> h(20);
        DWORD cb = static_cast<DWORD>(h.size());
        if (!ca || !::CertGetCertificateContextProperty(ca.get(), CERT_SHA1_HASH_PROP_ID, h.data(), &cb))
            return {};
        h.resize(cb);
        return h;
    }

    HCERTSTORE trust(bool read_only, bool* owned) const {
        if (opt.trust_store) {
            *owned = false;
            return static_cast<HCERTSTORE>(opt.trust_store);
        }
        *owned = true;
        return open_user_root(read_only);
    }

    PCCERT_CONTEXT find_trusted(HCERTSTORE store, PCCERT_CONTEXT prev) const {
        auto h = thumb();
        if (h.empty()) return nullptr;
        CRYPT_HASH_BLOB blob{static_cast<DWORD>(h.size()), h.data()};
        return ::CertFindCertificateInStore(store, X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH,
                                            &blob, prev);
    }
};

pki_t::pki_t(pki_options_t opt) : p_(std::make_unique<impl_t>()) {
    p_->opt = std::move(opt);
    if (p_->opt.max_cached_leaves == 0) p_->opt.max_cached_leaves = 1;
}

pki_t::~pki_t() = default;

bool pki_t::ensure_ca(std::string* error) {
    std::lock_guard lk(p_->mu);
    if (p_->ca) return true;
    if (p_->load_persisted()) return true;
    p_->ca.reset();
    p_->ca_key.reset();
    return p_->create_ca(error);
}

bool pki_t::load_existing() {
    std::lock_guard lk(p_->mu);
    if (p_->ca) return true;
    if (p_->load_persisted()) return true;
    p_->ca.reset();
    p_->ca_key.reset();
    return false;
}

bool pki_t::has_ca() const {
    std::lock_guard lk(p_->mu);
    return p_->ca != nullptr;
}

const _CERT_CONTEXT* pki_t::ca_cert() const {
    std::lock_guard lk(p_->mu);
    return p_->ca.get();
}

std::vector<uint8_t> pki_t::ca_der() const {
    std::lock_guard lk(p_->mu);
    if (!p_->ca) return {};
    return {p_->ca->pbCertEncoded, p_->ca->pbCertEncoded + p_->ca->cbCertEncoded};
}

std::string pki_t::ca_path() const {
    return p_->ca_file();
}

std::string pki_t::ca_thumbprint() const {
    std::lock_guard lk(p_->mu);
    const auto h = p_->thumb();
    return hex_upper(h.data(), h.size());
}

std::shared_ptr<const _CERT_CONTEXT> pki_t::leaf_for(const std::string& host_in,
                                                     std::string* error) {
    std::string host = parse::lower(host_in);
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']')
        host = host.substr(1, host.size() - 2);
    if (!parse::valid_host(host)) {
        if (error) *error = "refusing to issue a certificate for invalid host '" +
                            parse::escape_nonprintable(host_in) + "'";
        return nullptr;
    }
    if (const auto ip = parse::parse_ip(host)) host = parse::to_string(*ip);
    std::lock_guard lk(p_->mu);
    if (!p_->ca) {
        if (error) *error = "CA not initialized (call ensure_ca)";
        return nullptr;
    }
    auto it = p_->leaves.find(host);
    if (it != p_->leaves.end()) {
        it->second.used = ++p_->tick;
        return it->second.cert;
    }
    if (!p_->ensure_leaf_key(error)) return nullptr;
    auto cert = p_->issue(host, error);
    if (!cert) return nullptr;
    while (p_->leaves.size() >= p_->opt.max_cached_leaves) {
        auto victim = p_->leaves.begin();
        for (auto j = p_->leaves.begin(); j != p_->leaves.end(); ++j)
            if (j->second.used < victim->second.used) victim = j;
        p_->leaves.erase(victim);
    }
    p_->leaves[host] = {cert, ++p_->tick};
    return cert;
}

size_t pki_t::issued() const {
    std::lock_guard lk(p_->mu);
    return p_->issued;
}

bool pki_t::install_root(std::string* error) {
    std::lock_guard lk(p_->mu);
    if (!p_->ca) {
        if (error) *error = "CA not initialized";
        return false;
    }
    bool owned = false;
    HCERTSTORE store = p_->trust(false, &owned);
    if (!store) {
        if (error) *error = gle_text("cannot open the ROOT store", ::GetLastError());
        return false;
    }
    const BOOL ok = ::CertAddEncodedCertificateToStore(
        store, X509_ASN_ENCODING, p_->ca->pbCertEncoded, p_->ca->cbCertEncoded,
        CERT_STORE_ADD_REPLACE_EXISTING, nullptr);
    const DWORD e = ::GetLastError();
    if (owned) ::CertCloseStore(store, 0);
    if (!ok && error)
        *error = gle_text(e == ERROR_CANCELLED ? "trust installation declined by the user"
                                               : "trust installation failed", e);
    return ok != FALSE;
}

bool pki_t::root_installed() const {
    std::lock_guard lk(p_->mu);
    if (!p_->ca) return false;
    bool owned = false;
    HCERTSTORE store = p_->trust(true, &owned);
    if (!store) return false;
    PCCERT_CONTEXT c = p_->find_trusted(store, nullptr);
    const bool found = c != nullptr;
    if (c) ::CertFreeCertificateContext(c);
    if (owned) ::CertCloseStore(store, 0);
    return found;
}

bool pki_t::uninstall_root(std::string* error) {
    std::lock_guard lk(p_->mu);
    if (!p_->ca) return true;
    bool owned = false;
    HCERTSTORE store = p_->trust(false, &owned);
    if (!store) {
        if (error) *error = gle_text("cannot open the ROOT store", ::GetLastError());
        return false;
    }
    bool ok = true;
    while (PCCERT_CONTEXT c = p_->find_trusted(store, nullptr)) {
        if (!::CertDeleteCertificateFromStore(c)) {   // frees c either way
            const DWORD e = ::GetLastError();
            if (error) *error = gle_text(e == ERROR_CANCELLED ? "trust removal declined by the user"
                                                              : "trust removal failed", e);
            ok = false;
            break;
        }
    }
    if (owned) ::CertCloseStore(store, 0);
    return ok;
}

bool pki_t::destroy(std::string* error) {
    std::string err;
    bool ok = uninstall_root(&err);
    std::lock_guard lk(p_->mu);
    p_->leaves.clear();
    p_->leaf_key.reset();
    p_->ca_key.reset();
    p_->ca.reset();
    p_->leaf_spki.clear();
    delete_key(p_->leaf_key_name());
    if (!p_->opt.dir.empty()) {
        delete_key(p_->ca_key_name());
        std::error_code ec;
        std::filesystem::remove(p_->ca_file(), ec);
        if (ec) {
            ok = false;
            err += (err.empty() ? "" : "; ") + std::string("cannot delete ") + p_->ca_file();
        }
    }
    if (!ok && error) *error = err;
    return ok;
}

size_t remove_legacy_artifacts(std::string* error) {
    size_t removed = 0;
    std::string err;
    for (const wchar_t* name : {L"MY", L"ROOT"}) {
        HCERTSTORE store = ::CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                           CERT_SYSTEM_STORE_CURRENT_USER, name);
        if (!store) continue;
        for (;;) {
            PCCERT_CONTEXT hit = nullptr;
            PCCERT_CONTEXT it = nullptr;
            while ((it = ::CertEnumCertificatesInStore(store, it)) != nullptr) {
                char subj[256] = {};
                ::CertGetNameStringA(it, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, subj, sizeof(subj));
                if (std::string(subj) == "reverse-slop Local CA") {
                    hit = ::CertDuplicateCertificateContext(it);
                    ::CertFreeCertificateContext(it);
                    break;
                }
            }
            if (!hit) break;
            if (!::CertDeleteCertificateFromStore(hit)) {
                err = gle_text("legacy CA removal failed", ::GetLastError());
                break;
            }
            ++removed;
        }
        ::CertCloseStore(store, 0);
    }

    std::vector<std::string> containers;
    HCRYPTPROV enum_prov = 0;
    if (::CryptAcquireContextW(&enum_prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        char buf[1024];
        DWORD flags = CRYPT_FIRST;
        for (;;) {
            DWORD cb = sizeof(buf);
            if (!::CryptGetProvParam(enum_prov, PP_ENUMCONTAINERS, reinterpret_cast<BYTE*>(buf), &cb, flags))
                break;
            flags = 0;
            const std::string n(buf, strnlen(buf, sizeof(buf)));
            if (n == "reverse-slop-ca-key" || n.rfind("reverse-slop-host-", 0) == 0)
                containers.push_back(n);
        }
        ::CryptReleaseContext(enum_prov, 0);
    }
    for (const auto& n : containers) {
        HCRYPTPROV h = 0;
        if (::CryptAcquireContextA(&h, n.c_str(), nullptr, PROV_RSA_AES, CRYPT_DELETEKEYSET)) ++removed;
    }

    char base[MAX_PATH]{};
    if (::GetEnvironmentVariableA("LOCALAPPDATA", base, MAX_PATH)) {
        const std::filesystem::path dir = std::filesystem::path(base) / "reverse-slop" / "certs";
        std::error_code ec;
        if (std::filesystem::exists(dir, ec)) {
            const auto n = std::filesystem::remove_all(dir, ec);
            if (n != static_cast<std::uintmax_t>(-1)) removed += static_cast<size_t>(n);
        }
    }
    if (!err.empty() && error) *error = err;
    return removed;
}

} // namespace slop::core::network::mitm
