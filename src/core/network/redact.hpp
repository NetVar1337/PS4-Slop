#pragma once

// src/core/network/redact.hpp
// secret redaction for captured HTTP/1.x traffic. Captured traffic is
// credentials by default: Authorization / Proxy-Authorization / Cookie /
// Set-Cookie and token-ish query values are masked before an entry is stored
// (proxy_redact_secrets, default on) and the masked form is never replayed.
// Pure string transforms, no globals

#include <string>
#include <string_view>

namespace slop::core::network::redact {

// masks the values of the secret headers and of token-ish query parameters in
// the request line. Everything after the blank line (the body) is untouched
std::string http_head(std::string_view head);

// removes those header lines and query parameters instead of masking them:
// what replay sends when the stored request is redacted
std::string strip_secrets(std::string_view head);

// masks token-ish query values in a path ("/x?token=1" -> "/x?token=<redacted>")
std::string query(std::string_view path);

} // namespace slop::core::network::redact
