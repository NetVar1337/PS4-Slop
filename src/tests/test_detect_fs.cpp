// src/tests/test_detect_fs.cpp
// Deferred manager, fs utilities, the web client's egress guard over loopback
// origins, and the MITM PKI against in-memory trust stores

#include "harness.hpp"

#include "core/infra/deferred.hpp"
#include "core/network/web_fetch.hpp"
#include "core/network/mitm_pki.hpp"
#include "core/network/parsers.hpp"
#include "core/util/fs_tools.hpp"

#include <httplib.h>

#include <windows.h>
#include <wincrypt.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <thread>

namespace util = slop::core::util;
namespace infra = slop::core::infra;

TEST_CASE(deferred_manager_roundtrip) {
    auto& m = infra::deferred_manager_t::get();

    int executed_with = 0;
    REQUIRE(m.bind_executor("test_kind",
                            [&](const std::string& params,
                                std::string* result) {
                                executed_with =
                                    std::stoi(params);
                                *result = "\"ok\"";
                                return true;
                            }));
    // Duplicate bind rejected
    REQUIRE(!m.bind_executor("test_kind", [](const std::string&, std::string*) {
        return false;
    }));

    const uint64_t id = m.submit("test_kind", "77");
    REQUIRE_GT(id, 0ull);

    auto before = m.get(id);
    REQUIRE(before.has_value());
    REQUIRE_STR_EQ(before->status.c_str(), "pending");

    REQUIRE_EQ(m.execute_pending("test_kind"), 1u);
    REQUIRE_EQ(executed_with, 77);

    auto after = m.get(id);
    REQUIRE(after.has_value());
    REQUIRE_STR_EQ(after->status.c_str(), "done");
    REQUIRE(after->result_json.find("ok") != std::string::npos);

    REQUIRE(m.cancel(id) == false);   // already done
    m.clear();
}

namespace {
std::string temp_dir() {
    char p[MAX_PATH];
    std::snprintf(p, sizeof(p), "%s\\slop_fs_%u", std::getenv("TEMP"),
                  static_cast<unsigned>(::_getpid()));
    return p;
}
} // namespace

TEST_CASE(fs_tools_roundtrip_and_grep) {
    const std::string dir = temp_dir();
    util::create_directory(dir);
    REQUIRE(util::write_file(dir + "\\a.txt",
                             {'h', 'e', 'l', 'l', 'o'}, false));
    REQUIRE(util::write_file(dir + "\\b.log", {'w', 'o', 'r', 'l', 'd'},
                             false));

    auto items = util::list_directory(dir);
    REQUIRE_EQ(items.size(), 2u);

    std::vector<uint8_t> back;
    REQUIRE(util::read_file(dir + "\\a.txt", &back, 4096));
    REQUIRE_EQ(back.size(), 5u);

    auto found = util::search_files(dir, ".txt", 100);
    REQUIRE_EQ(found.size(), 1u);

    auto hits = util::grep_in_files(dir, "world", "", 10);
    REQUIRE_GE(hits.size(), 1u);
    REQUIRE(hits[0].path.find("b.log") != std::string::npos);

    REQUIRE(util::delete_path(dir + "\\a.txt"));
    REQUIRE(util::delete_path(dir + "\\b.log"));
    RemoveDirectoryA(dir.c_str());
}

namespace {

struct web_origin_t {
    httplib::Server srv;
    int port = 0;
    std::thread th;
    web_origin_t() {
        srv.Get("/probe", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("web-ok-1234", "text/plain");
        });
        srv.Get("/redir-local", [this](const httplib::Request&, httplib::Response& res) {
            res.set_redirect("http://127.0.0.1:" + std::to_string(port) + "/probe");
        });
        srv.Get("/redir-rel", [](const httplib::Request&, httplib::Response& res) {
            res.set_redirect("/probe");
        });
        srv.Post("/ct", [](const httplib::Request& req, httplib::Response& res) {
            res.set_content("ct=" + req.get_header_value("Content-Type") + ";body=" + req.body,
                            "text/plain");
        });
        srv.Get("/chunked", [](const httplib::Request&, httplib::Response& res) {
            res.set_chunked_content_provider("text/plain", [](size_t off, httplib::DataSink& sink) {
                if (off == 0) {
                    sink.write("part-one|", 9);
                    sink.write("part-two", 8);
                }
                sink.done();
                return true;
            });
        });
        srv.Get("/binary", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(std::string("\xFF\xFE\x00\x01", 4), "application/octet-stream");
        });
        port = srv.bind_to_any_port("127.0.0.1");
        th = std::thread([this] { srv.listen_after_bind(); });
        srv.wait_until_ready();
    }
    ~web_origin_t() {
        srv.stop();
        if (th.joinable()) th.join();
    }
    std::string url(const char* path) const {
        return "http://127.0.0.1:" + std::to_string(port) + path;
    }
};

} // namespace

TEST_CASE(network_web_egress_guard) {
    web_origin_t o;
    REQUIRE_GT(o.port, 0);
    std::string err;

    // default policy: loopback is refused before any connection is made
    util::egress_policy_t deny;
    REQUIRE(!util::http_get(o.url("/probe"), deny, 5000, &err).has_value());
    REQUIRE(err.find("blocked") != std::string::npos);
    REQUIRE(util::vet_destination("169.254.169.254", deny, &err).empty());
    REQUIRE(util::vet_destination("10.0.0.1", deny, &err).empty());
    REQUIRE(util::vet_destination("[::1]", deny, &err).empty());
    REQUIRE_EQ(util::vet_destination("8.8.8.8", deny, &err).size(), 1u);

    // web_allow_private opens it
    util::egress_policy_t open;
    open.allow_private = true;
    auto resp = util::http_get(o.url("/probe"), open, 5000, &err);
    REQUIRE(resp.has_value());
    REQUIRE_EQ(resp->status, 200u);
    REQUIRE(resp->body.find("web-ok-1234") != std::string::npos);
    REQUIRE_STR_EQ(resp->remote_addr, "127.0.0.1");

    // allowlisted host (by name) and by IP
    util::egress_policy_t by_name;
    by_name.allowlist = {"localhost"};
    resp = util::http_get("http://localhost:" + std::to_string(o.port) + "/probe", by_name, 5000, &err);
    REQUIRE(resp.has_value());
    REQUIRE(resp->body.find("web-ok-1234") != std::string::npos);
    util::egress_policy_t by_ip;
    by_ip.allowlist = {"127.0.0.0/8"};
    REQUIRE(util::http_get(o.url("/probe"), by_ip, 5000, &err).has_value());

    // redirects are re-checked: localhost is allowlisted, 127.0.0.1 is not
    REQUIRE(!util::http_get("http://localhost:" + std::to_string(o.port) + "/redir-local",
                            by_name, 5000, &err).has_value());
    REQUIRE(err.find("blocked") != std::string::npos);
    REQUIRE(err.find("after redirect") != std::string::npos);
    resp = util::http_get(o.url("/redir-local"), open, 5000, &err);
    REQUIRE(resp.has_value());
    REQUIRE_EQ(resp->redirects.size(), 1u);
    REQUIRE(resp->final_url.find("/probe") != std::string::npos);
    resp = util::http_get(o.url("/redir-rel"), open, 5000, &err);
    REQUIRE(resp.has_value());
    REQUIRE(resp->body.find("web-ok-1234") != std::string::npos);

    // POST carries the content type; chunked bodies are decoded
    resp = util::http_post(o.url("/ct"), "{\"a\":1}", "application/x-test", open, 5000, &err);
    REQUIRE(resp.has_value());
    REQUIRE(resp->body.find("ct=application/x-test;body={\"a\":1}") != std::string::npos);
    resp = util::http_get(o.url("/chunked"), open, 5000, &err);
    REQUIRE(resp.has_value());
    REQUIRE_STR_EQ(resp->body, "part-one|part-two");
    resp = util::http_get(o.url("/binary"), open, 5000, &err);
    REQUIRE(resp.has_value());
    REQUIRE_EQ(resp->body.size(), 4u);

    // body cap is reported
    util::http_request_t capped;
    capped.url = o.url("/probe");
    capped.max_body = 3;
    resp = util::http_request(capped, open, &err);
    REQUIRE(resp.has_value());
    REQUIRE(resp->body_truncated);
    REQUIRE_EQ(resp->body.size(), 3u);

    // malformed input
    REQUIRE(!util::http_get("ftp://x/", open, 1000, &err).has_value());
    REQUIRE(!util::http_get("http://user:pw@127.0.0.1/", open, 1000, &err).has_value());
    REQUIRE(!util::http_get("http://127.0.0.1:1/", open, 2000, &err).has_value());
    util::http_request_t inj;
    inj.method = "POST";
    inj.url = o.url("/ct");
    inj.content_type = "text/plain\r\nX-Evil: 1";
    REQUIRE(!util::http_request(inj, open, &err).has_value());
}

namespace {

struct mem_store_t {
    HCERTSTORE h = ::CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
    ~mem_store_t() { ::CertCloseStore(h, 0); }
};

uint64_t ft_ticks(const FILETIME& f) {
    return (static_cast<uint64_t>(f.dwHighDateTime) << 32) | f.dwLowDateTime;
}

} // namespace

TEST_CASE(network_pki_issuance_and_trust) {
    namespace mitm = slop::core::network::mitm;
    mem_store_t trust;
    mitm::pki_options_t opt;
    opt.key_prefix = L"reverse-slop-test-" + std::to_wstring(::GetCurrentProcessId()) + L"-pki";
    opt.trust_store = trust.h;          // never the real CurrentUser\ROOT
    opt.max_cached_leaves = 2;
    mitm::pki_t pki(opt);
    struct cleanup_t {
        mitm::pki_t& p;
        ~cleanup_t() { p.destroy(); }
    } cleanup{pki};

    std::string err;
    REQUIRE(!pki.leaf_for("target.local", &err));          // CA first
    REQUIRE(pki.ensure_ca(&err));
    REQUIRE(pki.has_ca());
    REQUIRE(pki.ca_path().empty());                         // memory mode writes nothing
    REQUIRE_EQ(pki.ca_thumbprint().size(), 40u);

    auto leaf = pki.leaf_for("Target.Local", &err);
    REQUIRE(leaf != nullptr);
    const CERT_INFO* info = leaf->pCertInfo;
    // 128-bit positive serial (CRYPT_INTEGER_BLOB is little-endian: [15] is the MSB)
    REQUIRE_EQ(info->SerialNumber.cbData, 16u);
    REQUIRE_LT(info->SerialNumber.pbData[15], 0x80);
    // validity: now-1d .. now+397d
    const uint64_t day = 864000000000ull;
    const uint64_t span = ft_ticks(info->NotAfter) - ft_ticks(info->NotBefore);
    REQUIRE_GE(span, 397 * day);
    REQUIRE_LE(span, 399 * day);
    // SAN dNSName is the (lowercased) host
    const CERT_EXTENSION* san = ::CertFindExtension(szOID_SUBJECT_ALT_NAME2, info->cExtension,
                                                    info->rgExtension);
    REQUIRE(san != nullptr);
    CERT_ALT_NAME_INFO* alt = nullptr;
    DWORD cb = 0;
    REQUIRE(::CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, san->Value.pbData,
                                  san->Value.cbData, CRYPT_DECODE_ALLOC_FLAG, nullptr, &alt, &cb));
    REQUIRE_EQ(alt->cAltEntry, 1u);
    REQUIRE_EQ(alt->rgAltEntry[0].dwAltNameChoice, static_cast<DWORD>(CERT_ALT_NAME_DNS_NAME));
    REQUIRE(std::wstring(alt->rgAltEntry[0].pwszDNSName) == L"target.local");
    ::LocalFree(alt);
    REQUIRE(::CertFindExtension(szOID_ENHANCED_KEY_USAGE, info->cExtension, info->rgExtension));

    // the leaf chains to the CA with SSL policy for that name
    {
        HCERTSTORE roots = ::CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
        const auto ca = pki.ca_der();
        ::CertAddEncodedCertificateToStore(roots, X509_ASN_ENCODING, ca.data(),
                                           static_cast<DWORD>(ca.size()), CERT_STORE_ADD_NEW, nullptr);
        CERT_CHAIN_ENGINE_CONFIG cfg{};
        cfg.cbSize = sizeof(cfg);
        cfg.hExclusiveRoot = roots;
        HCERTCHAINENGINE engine = nullptr;
        REQUIRE(::CertCreateCertificateChainEngine(&cfg, &engine));
        CERT_CHAIN_PARA para{};
        para.cbSize = sizeof(para);
        PCCERT_CHAIN_CONTEXT chain = nullptr;
        REQUIRE(::CertGetCertificateChain(engine, leaf.get(), nullptr, nullptr, &para, 0, nullptr, &chain));
        wchar_t name[] = L"target.local";
        SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl{};
        ssl.cbSize = sizeof(ssl);
        ssl.dwAuthType = AUTHTYPE_SERVER;
        ssl.pwszServerName = name;
        CERT_CHAIN_POLICY_PARA pp{};
        pp.cbSize = sizeof(pp);
        pp.pvExtraPolicyPara = &ssl;
        CERT_CHAIN_POLICY_STATUS ps{};
        ps.cbSize = sizeof(ps);
        REQUIRE(::CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain, &pp, &ps));
        REQUIRE_EQ(ps.dwError, 0u);
        ::CertFreeCertificateChain(chain);
        ::CertFreeCertificateChainEngine(engine);
        ::CertCloseStore(roots, 0);
    }

    // cached per host; IP literals get an IP SAN; bad names never reach a file/container name
    REQUIRE(pki.leaf_for("target.local", &err).get() == leaf.get());
    REQUIRE(pki.leaf_for("10.0.0.5", &err) != nullptr);
    for (const char* bad : {"..\\..\\evil", "../x", "a b", "", "x/y", "-lead.example"})
        REQUIRE(pki.leaf_for(bad, &err) == nullptr);
    REQUIRE_EQ(pki.issued(), 2u);
    // LRU cap of 2: a third host evicts the least recent, re-issuing it later
    REQUIRE(pki.leaf_for("third.example", &err) != nullptr);
    REQUIRE(pki.leaf_for("target.local", &err) != nullptr);
    REQUIRE_EQ(pki.issued(), 4u);

    // trust install / uninstall against the injected store only
    REQUIRE_FALSE(pki.root_installed());
    REQUIRE(pki.install_root(&err));
    REQUIRE(pki.root_installed());
    REQUIRE(pki.uninstall_root(&err));
    REQUIRE_FALSE(pki.root_installed());
    REQUIRE(pki.install_root(&err));
    REQUIRE(pki.destroy(&err));                             // removes trust too
    REQUIRE_FALSE(pki.has_ca());
    PCCERT_CONTEXT left = ::CertEnumCertificatesInStore(trust.h, nullptr);
    REQUIRE(left == nullptr);
}
