// src/core/network/web_fetch.cpp

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "core/network/web_fetch.hpp"

#include "core/network/net_socket.hpp"
#include "core/network/parsers.hpp"
#include "core/network/tls_stream.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <memory>

namespace slop::core::util {

namespace parse = slop::core::network::parse;
namespace sock = slop::core::network::sock;
namespace tls = slop::core::network::tls;

namespace {

struct url_t {
    bool        https = false;
    std::string host;          // lowercase, no brackets
    uint16_t    port = 0;
    std::string authority;     // as sent in Host
    std::string target;        // origin-form path + query
};

int64_t mono_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch()).count();
}

bool parse_url(const std::string& u, url_t& out, std::string* error) {
    auto fail = [&](const std::string& why) {
        if (error) *error = why;
        return false;
    };
    const std::string lu = parse::lower(u.substr(0, 8));
    size_t skip = 0;
    if (lu.rfind("https://", 0) == 0) { out.https = true; skip = 8; }
    else if (lu.rfind("http://", 0) == 0) { out.https = false; skip = 7; }
    else return fail("URL must start with http:// or https://");
    std::string rest = u.substr(skip);
    if (const size_t frag = rest.find('#'); frag != std::string::npos) rest.resize(frag);
    const size_t end = rest.find_first_of("/?");
    out.authority = rest.substr(0, end);
    std::string target = end == std::string::npos ? "/" : rest.substr(end);
    if (!target.empty() && target[0] == '?') target = "/" + target;
    if (out.authority.find('@') != std::string::npos)
        return fail("credentials in URLs are not supported");
    std::string host;
    uint16_t port = 0;
    if (!sock::split_authority(out.authority, out.https ? 443 : 80, &host, &port))
        return fail("bad host or port in URL");
    host = parse::lower(host);
    if (!parse::valid_host(host)) return fail("invalid host '" + parse::escape_nonprintable(host) + "'");
    out.host = host;
    out.port = port;
    // percent-encode what may not appear raw in a request line
    static constexpr char kHex[] = "0123456789ABCDEF";
    out.target.clear();
    for (char ch : target) {
        const auto c = static_cast<unsigned char>(ch);
        if (c <= 0x20 || c >= 0x7F) {
            out.target += '%';
            out.target += kHex[c >> 4];
            out.target += kHex[c & 0xF];
        } else {
            out.target += ch;
        }
    }
    return true;
}

std::string resolve_location(const url_t& base, const std::string& loc) {
    const std::string l = parse::lower(loc.substr(0, 8));
    if (l.rfind("http://", 0) == 0 || l.rfind("https://", 0) == 0) return loc;
    const std::string origin = std::string(base.https ? "https://" : "http://") + base.authority;
    if (loc.rfind("//", 0) == 0) return std::string(base.https ? "https:" : "http:") + loc;
    if (!loc.empty() && loc[0] == '/') return origin + loc;
    std::string dir = base.target.substr(0, base.target.find('?'));
    dir = dir.substr(0, dir.rfind('/') + 1);
    return origin + (dir.empty() ? "/" : dir) + loc;
}

std::vector<parse::ip_addr_t> vet(const std::string& host, const egress_policy_t& policy,
                                  std::string* error) {
    const auto addrs = sock::resolve(host, error);
    if (addrs.empty()) return {};
    bool host_exempt = false;
    for (const auto& p : policy.allowlist)
        if (parse::host_pattern_match(p, host, nullptr)) host_exempt = true;
    std::vector<parse::ip_addr_t> out;
    for (const auto& ip : addrs) {
        bool ok = policy.allow_private || host_exempt || !parse::is_non_public(ip);
        for (const auto& p : policy.allowlist)
            if (!ok && parse::host_pattern_match(p, host, &ip)) ok = true;
        if (ok) out.push_back(ip);
    }
    if (out.empty() && error)
        *error = "blocked: '" + host + "' resolves to non-public address " +
                 parse::to_string(addrs.front()) +
                 " (loopback/link-local/private/reserved); enable web_allow_private or add the "
                 "host to web_allowlist";
    return out;
}

struct hop_result_t {
    uint32_t status = 0;
    std::string location;
    std::string content_type;
    std::string body;
    bool truncated = false;
    std::string remote;
};

bool do_hop(const url_t& url, const std::string& method, const std::string& body,
            const std::string& content_type, const egress_policy_t& policy, int64_t deadline,
            size_t max_body, hop_result_t& out, std::string* error) {
    auto fail = [&](const std::string& why) {
        if (error) *error = why;
        return false;
    };
    const auto addrs = vet(url.host, policy, error);
    if (addrs.empty()) return false;

    sock::socket_t s = sock::kInvalid;
    std::string err;
    for (const auto& ip : addrs) {
        const int64_t left = deadline - mono_ms();
        if (left <= 0) return fail("timed out connecting to " + url.host);
        s = sock::connect(ip, url.port, static_cast<int>(left), nullptr, &err);
        if (s != sock::kInvalid) {
            out.remote = parse::to_string(ip);
            break;
        }
    }
    if (s == sock::kInvalid) return fail(err);
    struct closer_t {
        sock::socket_t s;
        ~closer_t() { sock::close(s); }
    } closer{s};

    std::unique_ptr<tls::stream_t> t;
    if (url.https) {
        tls::client_options_t copt;
        copt.exclusive_roots = policy.exclusive_roots;
        const int64_t left = std::max<int64_t>(deadline - mono_ms(), 1);
        t = tls::stream_t::connect(s, url.host, copt, static_cast<int>(left), &err);
        if (!t) return fail("TLS to " + url.host + " failed: " + err);
    }
    const int64_t left = std::max<int64_t>(deadline - mono_ms(), 1);
    sock::set_timeouts(s, static_cast<int>(left), static_cast<int>(left));

    std::string req = method + " " + url.target + " HTTP/1.1\r\nHost: " + url.authority +
                      "\r\nUser-Agent: reverse-slop\r\nAccept: */*\r\n"
                      "Accept-Encoding: identity\r\nConnection: close\r\n";
    if (!body.empty() || method == "POST" || method == "PUT") {
        req += "Content-Type: " + (content_type.empty() ? std::string("application/octet-stream")
                                                        : content_type) + "\r\n";
        req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    }
    req += "\r\n";
    req += body;
    const bool sent = t ? t->write(reinterpret_cast<const uint8_t*>(req.data()), req.size())
                        : sock::send_all(s, reinterpret_cast<const uint8_t*>(req.data()), req.size());
    if (!sent) return fail("sending the request failed");

    parse::http_framer_t fr(true);
    fr.expect_response_to(method);
    std::vector<uint8_t> raw;
    std::vector<uint8_t> buf(32768);
    const size_t cap = max_body + 64 * 1024;          // head allowance
    bool capped = false;
    for (;;) {
        if (fr.messages_completed() >= 1) break;
        if (raw.size() >= cap) { capped = true; break; }
        const int64_t l = deadline - mono_ms();
        if (l <= 0) return fail("timed out waiting for the response from " + url.host);
        if (!(t && t->pending()) && !sock::wait_readable(s, static_cast<int>(l), nullptr))
            return fail("timed out waiting for the response from " + url.host);
        const size_t want = std::min(buf.size(), cap - raw.size());
        const int n = t ? t->read(buf.data(), want)
                        : ::recv(static_cast<SOCKET>(s), reinterpret_cast<char*>(buf.data()),
                                 static_cast<int>(want), 0);
        if (n < 0) return fail("connection error while reading the response");
        if (n == 0) {
            fr.finish();
            break;
        }
        raw.insert(raw.end(), buf.begin(), buf.begin() + n);
        fr.feed(buf.data(), static_cast<size_t>(n));
    }

    const size_t head_end = parse::find_head_end(raw.data(), raw.size());
    if (head_end == std::string::npos) return fail("no complete HTTP response head received");
    const auto head = parse::parse_http_head(
        std::string_view(reinterpret_cast<const char*>(raw.data()), head_end), true);
    if (!head) return fail("malformed HTTP response head");
    out.status = head->status;
    if (const std::string* ct = head->get("content-type")) out.content_type = *ct;
    if (const std::string* loc = head->get("location")) out.location = *loc;

    const uint8_t* b = raw.data() + head_end;
    const size_t bn = raw.size() - head_end;
    const std::string* te = head->get("transfer-encoding");
    const std::string* cl = head->get("content-length");
    std::vector<uint8_t> decoded;
    if (te && parse::lower(*te).find("chunked") != std::string::npos) {
        if (!parse::decode_chunked(b, bn, decoded) && !capped)
            return fail("malformed chunked response body");
        out.body.assign(decoded.begin(), decoded.end());
    } else if (cl) {
        const size_t want = static_cast<size_t>(std::strtoull(cl->c_str(), nullptr, 10));
        out.body.assign(reinterpret_cast<const char*>(b), std::min(bn, want));
    } else {
        out.body.assign(reinterpret_cast<const char*>(b), bn);
    }
    if (out.body.size() > max_body) {
        out.body.resize(max_body);
        capped = true;
    }
    out.truncated = capped;
    return true;
}

} // namespace

std::vector<std::string> vet_destination(const std::string& host, const egress_policy_t& policy,
                                         std::string* error) {
    std::vector<std::string> out;
    for (const auto& ip : vet(parse::lower(host), policy, error)) out.push_back(parse::to_string(ip));
    return out;
}

std::optional<http_response_t> http_request(const http_request_t& req,
                                            const egress_policy_t& policy, std::string* error) {
    auto fail = [&](const std::string& why) -> std::optional<http_response_t> {
        if (error) *error = why;
        return std::nullopt;
    };
    std::string method = req.method.empty() ? "GET" : req.method;
    for (char c : method)
        if (c < 'A' || c > 'Z') return fail("bad HTTP method '" + parse::escape_nonprintable(method) + "'");
    for (char c : req.content_type)
        if (c == '\r' || c == '\n') return fail("content_type must not contain line breaks");

    const int64_t deadline = mono_ms() + std::max(req.timeout_ms, 1);
    http_response_t res;
    std::string url_text = req.url;
    std::string body = req.body;
    for (int hop = 0;; ++hop) {
        url_t url;
        std::string err;
        if (!parse_url(url_text, url, &err)) return fail(err);
        hop_result_t hr;
        if (!do_hop(url, method, body, req.content_type, policy, deadline, req.max_body, hr, &err))
            return fail(hop ? err + " (after redirect to " + url_text + ")" : err);
        const bool redirect = (hr.status == 301 || hr.status == 302 || hr.status == 303 ||
                               hr.status == 307 || hr.status == 308) && !hr.location.empty();
        if (!redirect) {
            res.status = hr.status;
            res.content_type = std::move(hr.content_type);
            res.body = std::move(hr.body);
            res.body_truncated = hr.truncated;
            res.final_url = url_text;
            res.remote_addr = hr.remote;
            return res;
        }
        if (hop >= req.max_redirects)
            return fail("too many redirects (" + std::to_string(req.max_redirects) + ")");
        url_text = resolve_location(url, hr.location);
        res.redirects.push_back(url_text);
        if (hr.status == 303 || ((hr.status == 301 || hr.status == 302) && method == "POST")) {
            if (method != "HEAD") method = "GET";
            body.clear();
        }
    }
}

std::optional<http_response_t> http_get(const std::string& url, const egress_policy_t& policy,
                                        int timeout_ms, std::string* error) {
    http_request_t r;
    r.url = url;
    r.timeout_ms = timeout_ms;
    return http_request(r, policy, error);
}

std::optional<http_response_t> http_post(const std::string& url, const std::string& body,
                                         const std::string& content_type,
                                         const egress_policy_t& policy, int timeout_ms,
                                         std::string* error) {
    http_request_t r;
    r.method = "POST";
    r.url = url;
    r.body = body;
    r.content_type = content_type;
    r.timeout_ms = timeout_ms;
    return http_request(r, policy, error);
}

} // namespace slop::core::util
