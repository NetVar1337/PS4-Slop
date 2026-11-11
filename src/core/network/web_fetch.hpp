#pragma once

// src/core/network/web_fetch.hpp
// HTTP(S) client backing the MCP web tool. Each hop resolves the host once,
// refuses loopback / link-local / private / reserved destinations unless the
// policy allows them, and connects to exactly the vetted address (no
// re-resolution, so DNS rebinding cannot swap it). Redirects are followed
// manually and every hop is re-checked. TLS is Schannel with system trust

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace slop::core::util {

struct egress_policy_t {
    bool allow_private = false;            // settings: web_allow_private
    std::vector<std::string> allowlist;    // settings: web_allowlist (host, *.suffix, IP, CIDR)
    void* exclusive_roots = nullptr;       // HCERTSTORE trust override (tests)
};

struct http_response_t {
    uint32_t    status = 0;
    std::string content_type;
    std::string body;
    bool        body_truncated = false;    // body exceeded max_body
    std::string final_url;
    std::vector<std::string> redirects;    // URLs followed, in order
    std::string remote_addr;               // address actually connected to
};

struct http_request_t {
    std::string method = "GET";
    std::string url;
    std::string body;
    std::string content_type;
    int         timeout_ms = 15000;        // whole request, every hop
    size_t      max_body = 32u << 20;
    int         max_redirects = 5;
};

std::optional<http_response_t> http_request(const http_request_t& req,
                                            const egress_policy_t& policy,
                                            std::string* error = nullptr);

std::optional<http_response_t> http_get(const std::string& url, const egress_policy_t& policy,
                                        int timeout_ms = 15000, std::string* error = nullptr);
std::optional<http_response_t> http_post(const std::string& url, const std::string& body,
                                         const std::string& content_type,
                                         const egress_policy_t& policy, int timeout_ms = 15000,
                                         std::string* error = nullptr);

// the addresses of `host` that `policy` lets a request reach; empty with an
// explanatory *error when every address is blocked or resolution fails
std::vector<std::string> vet_destination(const std::string& host, const egress_policy_t& policy,
                                         std::string* error);

} // namespace slop::core::util
