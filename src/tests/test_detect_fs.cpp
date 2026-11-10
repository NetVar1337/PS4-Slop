// src/tests/test_detect_fs.cpp
// Deferred manager, fs utilities, webfetch over a loopback origin, and PKI
// lifecycle (host-side suites that survived the PS4-only cut)

#include "harness.hpp"

#include "core/infra/deferred.hpp"
#include "core/network/web_fetch.hpp"
#include "core/network/mitm_pki.hpp"
#include "core/util/fs_tools.hpp"

#include <httplib.h>

#include <windows.h>

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

TEST_CASE(webfetch_hits_loopback_origin) {
    httplib::Server origin;
    origin.Get("/probe", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("web-ok-1234", "text/plain");
    });
    const int port = origin.bind_to_any_port("127.0.0.1");
    REQUIRE_GT(port, 0);
    std::thread t([&] { origin.listen_after_bind(); });

    auto resp = util::http_get("http://127.0.0.1:" + std::to_string(port) +
                                   "/probe");
    REQUIRE(resp.has_value());
    REQUIRE_EQ(resp->status, 200);
    REQUIRE(resp->body.find("web-ok-1234") != std::string::npos);

    origin.stop();
    t.join();
}

TEST_CASE(pki_ca_lifecycle) {
    // Generate is idempotent; issue requires it
    std::string err;
    REQUIRE(slop::core::network::mitm::generate_ca("reverse-slop Local CA",
                                                   &err));
    REQUIRE(err.empty());
    REQUIRE(slop::core::network::mitm::ca_exists());

    auto path = slop::core::network::mitm::issue_host_cert(
        "target.local", &err);
    if (!path.has_value()) std::printf("  [pki] err=%s", err.c_str());
    REQUIRE(path.has_value());
    REQUIRE(!err.empty() == false);

    std::vector<uint8_t> der;
    REQUIRE(util::read_file(*path, &der, 65536));
    REQUIRE_GT(der.size(), 256u);   // a real certificate blob

    // Root-store installation touches user trust state, exercised only via
    // explicit operator action through MCP, not in tests
}



