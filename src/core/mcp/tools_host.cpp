// src/core/mcp/tools_host.cpp
// tool: host — serve a payload directory over HTTP (afterglow-web style payload
// host): index page, per-file download under /files/<name>, and an
// auto-generated /manifest.json with sha256 per file. A non-loopback bind
// always requires a token (arg "token" or the host_token setting)

#include "core/mcp/tools_common.hpp"
#include "core/infra/paths.hpp"
#include "core/util/sha256.hpp"

#include <httplib.h>

#include <filesystem>

namespace slop::core::mcp::detail {

namespace {

namespace fs = std::filesystem;

constexpr uint64_t kMaxServeBytes = 64ull * 1024 * 1024;   // one file cap

struct host_state_t {
    std::mutex mu;
    std::unique_ptr<httplib::Server> srv;
    std::thread th;
    std::string bind = "127.0.0.1";
    int port = 0;
    std::string dir;
    std::string token;                 // enforced when non-empty
    std::atomic<bool> running{false};
};

host_state_t& host_state() {
    static host_state_t h;
    return h;
}

std::string sha256_file_hex(const fs::path& p, bool& ok) {
    ok = false;
    std::error_code ec;
    const auto size = fs::file_size(p, ec);
    if (ec || size > kMaxServeBytes) return {};
    std::ifstream f(p, std::ios::binary);
    if (!f) return {};
    std::vector<uint8_t> buf(static_cast<size_t>(size));
    if (!f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size())) &&
        buf.size() != 0)
        return {};
    ok = true;
    return util::sha256_hex(buf.data(), buf.size());
}

// joins rel under root and refuses anything that escapes it (absolute paths,
// drive letters, ".." segments)
bool safe_join(const std::string& root, const std::string& rel, fs::path& out) {
    if (rel.empty() || rel.front() == '/' || rel.front() == '\\' ||
        rel.find(':') != std::string::npos)
        return false;
    const fs::path base = fs::path(root).lexically_normal();
    const fs::path cand = (base / fs::path(rel)).lexically_normal();
    const std::string bs = base.generic_string();
    const std::string cs = cand.generic_string();
    if (cs.size() <= bs.size() || cs.compare(0, bs.size(), bs) != 0 ||
        cs[bs.size()] != '/')
        return false;
    out = cand;
    return true;
}

bool is_loopback_bind(const std::string& bind) {
    return bind == "localhost" || bind == "::1" ||
           bind.rfind("127.", 0) == 0;
}

const char* content_type_for(const fs::path& p) {
    const std::string e = p.extension().string();
    if (e == ".json") return "application/json";
    if (e == ".html" || e == ".htm") return "text/html; charset=utf-8";
    if (e == ".js") return "text/javascript; charset=utf-8";
    if (e == ".css") return "text/css; charset=utf-8";
    if (e == ".png") return "image/png";
    if (e == ".txt" || e == ".md") return "text/plain; charset=utf-8";
    return "application/octet-stream";   // .bin .elf .sprx .pkg ...
}

json build_manifest_locked(host_state_t& h) {
    json files = json::array();
    std::error_code ec;
    fs::recursive_directory_iterator it(h.dir, ec), end;
    while (!ec && it != end) {
        if (it->is_regular_file(ec)) {
            const auto rel = fs::relative(it->path(), h.dir, ec);
            if (!ec && !rel.empty()) {
                bool ok = false;
                const std::string digest = sha256_file_hex(it->path(), ok);
                const auto size = fs::file_size(it->path(), ec);
                if (ok && !ec)
                    files.push_back({{"name", rel.generic_string()},
                                     {"size", size},
                                     {"sha256", digest},
                                     {"url", "/files/" + rel.generic_string()}});
            }
        }
        it.increment(ec);
    }
    return {{"version", 1}, {"generator", "reverse-slop host"}, {"files", files}};
}

std::string index_html_locked(host_state_t& h) {
    const json man = build_manifest_locked(h);
    std::string s = "<!doctype html><html><head><meta charset=utf-8><title>reverse-slop "
                    "payload host</title><style>body{font:14px system-ui;background:#101014;"
                    "color:#ddd;margin:2em} a{color:#8ab4f8} li{margin:.3em 0}code{color:#9e9e9e}"
                    "</style></head><body><h1>payload host</h1><p>manifest: <a "
                    "href=/manifest.json>/manifest.json</a></p><ul>";
    for (const auto& f : man["files"])
        s += "<li><a href=\"" + f["url"].get<std::string>() + "\">" +
             f["name"].get<std::string>() + "</a> <code>" +
             std::to_string(f["size"].get<uint64_t>()) + " B sha256:" +
             f["sha256"].get<std::string>().substr(0, 16) + "…</code></li>";
    s += "</ul></body></html>";
    return s;
}

void register_handlers(host_state_t& h) {
    auto& srv = *h.srv;
    srv.set_exception_handler([](const httplib::Request&, httplib::Response& res,
                                 std::exception_ptr) {
        res.status = 500;
        res.set_content("internal error", "text/plain");
    });
    srv.set_pre_routing_handler(
        [&h](const httplib::Request& req, httplib::Response& res) {
            if (h.token.empty()) return httplib::Server::HandlerResponse::Unhandled;
            bool ok = false;
            if (req.has_header("Authorization"))
                ok = req.get_header_value("Authorization") == "Bearer " + h.token;
            if (!ok && req.has_param("token"))
                ok = req.get_param_value("token") == h.token;
            if (!ok) {
                res.status = 401;
                res.set_header("WWW-Authenticate", "Bearer");
                res.set_content("unauthorized", "text/plain");
                return httplib::Server::HandlerResponse::Handled;
            }
            return httplib::Server::HandlerResponse::Unhandled;
        });
    srv.Get("/", [&h](const httplib::Request&, httplib::Response& res) {
        std::lock_guard lk(h.mu);
        res.set_content(index_html_locked(h), "text/html; charset=utf-8");
    });
    srv.Get("/manifest.json", [&h](const httplib::Request&, httplib::Response& res) {
        std::lock_guard lk(h.mu);
        res.set_content(build_manifest_locked(h).dump(2), "application/json");
        res.set_header("Cache-Control", "no-store");
    });
    srv.Get("/files/(.*)", [&h](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard lk(h.mu);
        fs::path f;
        if (!safe_join(h.dir, req.matches[1], f)) {
            res.status = 400;
            res.set_content("bad path", "text/plain");
            return;
        }
        std::error_code ec;
        if (!fs::is_regular_file(f, ec) || fs::file_size(f, ec) > kMaxServeBytes) {
            res.status = 404;
            res.set_content("not found", "text/plain");
            return;
        }
        std::ifstream ifs(f, std::ios::binary);
        std::string data((std::istreambuf_iterator<char>(ifs)),
                         std::istreambuf_iterator<char>());
        res.set_content(std::move(data), content_type_for(f));
        res.set_header("Cache-Control", "no-store");
    });
}

} // namespace

json tool_host(const json& args) {
    const std::string action = require_action(args);
    auto& h = host_state();

    if (action == "status") {
        std::lock_guard lk(h.mu);
        json out = {{"running", h.running.load()},
                    {"bind", h.bind},
                    {"port", h.port},
                    {"dir", h.dir},
                    {"token_required", !h.token.empty()}};
        if (h.running.load()) {
            out["url"] = "http://" + h.bind + ":" + std::to_string(h.port) + "/";
            out["manifest_url"] = out["url"].get<std::string>() + "manifest.json";
        }
        return out;
    }

    if (action == "files" || action == "manifest") {
        std::lock_guard lk(h.mu);
        if (h.dir.empty()) fail("host." + action + ": the host is not started");
        return build_manifest_locked(h);
    }

    if (action == "start") {
        std::lock_guard lk(h.mu);
        if (h.running.load()) fail("host.start: already running on " + h.bind + ":" +
                                   std::to_string(h.port) + " (stop first)");
        const uint64_t p = args.contains("port") ? parse_addr(args, "port") : 8080;
        if (p == 0 || p > 0xFFFF) fail("host.start: bad port");
        const std::string bind = args.value("bind", "127.0.0.1");
        std::string dir = args.value("dir", std::string{});
        if (dir.empty()) {
            const std::string& ad = infra::paths::app_data();
            dir = ad.empty() ? "payloads" : ad + "\\payloads";
        }
        std::error_code ec;
        fs::create_directories(dir, ec);
        if (!fs::is_directory(dir, ec))
            fail("host.start: dir is not a directory: " + dir);
        std::string token = args.value("token", std::string{});
        if (token.empty()) token = infra::settings::get<std::string>("host_token", {});
        if (!is_loopback_bind(bind) && token.empty())
            fail("host.start: a non-loopback bind (" + bind + ") requires a token "
                 "(arg \"token\" or the host_token setting) so the payload dir is "
                 "not exposed unauthenticated; clients send Authorization: Bearer "
                 "<token> or ?token=<token>");
        h.srv = std::make_unique<httplib::Server>();
        // no port sharing with another process (httplib defaults to SO_REUSEADDR)
        h.srv->set_socket_options([](socket_t s) {
#ifdef _WIN32
        BOOL excl = TRUE;
        ::setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&excl), sizeof(excl));
#else
        int reuse = 1;
        ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#endif
        });
        register_handlers(h);
        const int sock = h.srv->bind_to_port(bind, static_cast<int>(p));
        if (sock < 0)
            fail("host.start: cannot bind " + bind + ":" + std::to_string(p) +
                 " (in use?)");
        h.bind = bind;
        h.port = static_cast<int>(p);
        h.dir  = fs::path(dir).lexically_normal().generic_string();
        h.token = token;
        httplib::Server* raw = h.srv.get();
        h.th = std::thread([raw] { raw->listen_after_bind(); });
        h.running = true;
        json out = {{"running", true}, {"bind", h.bind}, {"port", h.port},
                    {"dir", h.dir}, {"token_required", !h.token.empty()},
                    {"url", "http://" + h.bind + ":" + std::to_string(h.port) + "/"},
                    {"manifest_url", "http://" + h.bind + ":" + std::to_string(h.port) + "/manifest.json"}};
        if (!token.empty()) out["token"] = token;
        return out;
    }

    if (action == "stop") {
        std::lock_guard lk(h.mu);
        if (!h.running.load()) return {{"running", false}};
        if (h.srv) h.srv->stop();
        if (h.th.joinable()) h.th.join();
        h.srv.reset();
        h.running = false;
        return {{"running", false}};
    }

    if (action == "put") {
        // drop a payload file into the served dir (mutating: confirm-gated)
        if (!args.contains("name") || !args.at("name").is_string())
            fail("host.put requires string 'name' (relative path under the served dir)");
        const std::string name = args.at("name").get<std::string>();
        std::string data;
        if (args.contains("hex")) {
            const auto bytes = hex_decode(args.at("hex").get<std::string>());
            data.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        } else if (args.contains("text")) {
            data = args.at("text").get<std::string>();
        } else {
            fail("host.put requires 'hex' or 'text'");
        }
        std::lock_guard lk(h.mu);
        if (h.dir.empty()) fail("host.put: the host is not started");
        fs::path f;
        if (!safe_join(h.dir, name, f)) fail("host.put: bad name (path escapes the served dir)");
        fs::create_directories(f.parent_path());
        if (!infra::paths::write_file_atomic(f.generic_string(), data))
            fail("host.put: write failed: " + f.generic_string());
        bool ok = false;
        const std::string digest = sha256_file_hex(f, ok);
        return {{"written", true}, {"name", name}, {"size", data.size()},
                {"sha256", ok ? digest : ""}, {"url", "/files/" + name}};
    }

    fail("host: unknown action '" + action +
         "' (start|stop|status|files|manifest|put)");
}

} // namespace slop::core::mcp::detail
