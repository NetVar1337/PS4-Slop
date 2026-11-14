// src/core/network/redact.cpp

#include "core/network/redact.hpp"

#include <cctype>
#include <string>

namespace slop::core::network::redact {

namespace {

constexpr std::string_view kMask = "<redacted>";

// header names whose value is a credential or a session token
bool secret_header(std::string_view name) {
    static constexpr std::string_view kNames[] = {
        "authorization", "proxy-authorization", "cookie", "set-cookie",
        "x-api-key", "x-auth-token", "x-csrf-token",
    };
    for (std::string_view n : kNames)
        if (name == n) return true;
    return false;
}

// query parameter name that carries a token-ish value
bool secret_param(std::string_view name) {
    static constexpr std::string_view kNames[] = {
        "token", "key", "auth", "sig", "session", "password", "secret",
    };
    for (std::string_view n : kNames)
        if (name.find(n) != std::string_view::npos) return true;
    return false;
}

std::string lowered(std::string_view s) {
    std::string out(s);
    for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

// rewrites the query string of `path`; `strip` drops the parameter instead of
// masking its value
std::string rewrite_query(std::string_view path, bool strip) {
    const size_t q = path.find('?');
    if (q == std::string_view::npos) return std::string(path);
    std::string out(path.substr(0, q));
    size_t pos = q + 1;
    bool any = false;
    while (pos <= path.size()) {
        const size_t amp = path.find('&', pos);
        const size_t end = amp == std::string_view::npos ? path.size() : amp;
        const std::string pair(path.substr(pos, end - pos));
        const size_t eq = pair.find('=');
        const bool secret = eq != std::string::npos && secret_param(pair.substr(0, eq));
        if (!(secret && strip)) {
            out += any ? "&" : "?";
            out += secret ? pair.substr(0, eq + 1) + std::string(kMask) : pair;
            any = true;
        }
        if (amp == std::string_view::npos) break;
        pos = amp + 1;
    }
    return out;
}

// masks or drops the query of the request target on a request line
std::string rewrite_request_line(std::string_view line, bool strip) {
    const size_t first = line.find(' ');
    if (first == std::string_view::npos) return std::string(line);
    const size_t last = line.rfind(' ');
    if (last == first) return std::string(line);
    return std::string(line.substr(0, first + 1)) +
           rewrite_query(line.substr(first + 1, last - first - 1), strip) +
           std::string(line.substr(last));
}

std::string rewrite(std::string_view in, bool strip) {
    std::string out;
    out.reserve(in.size());
    size_t pos = 0;
    bool first_line = true;
    while (pos < in.size()) {
        const size_t eol = in.find("\r\n", pos);
        const size_t end = eol == std::string_view::npos ? in.size() : eol;
        const std::string_view line = in.substr(pos, end - pos);
        if (line.empty()) {                       // end of head: body stays verbatim
            out.append(in.substr(pos));
            return out;
        }
        if (first_line) {
            out += rewrite_request_line(line, strip);
            first_line = false;
        } else {
            const size_t colon = line.find(':');
            const bool secret =
                colon != std::string_view::npos && secret_header(lowered(line.substr(0, colon)));
            if (!secret)
                out += line;
            else if (!strip)
                out += std::string(line.substr(0, colon + 1)) + " " + std::string(kMask);
        }
        if (eol == std::string_view::npos) break;
        out += "\r\n";
        pos = eol + 2;
    }
    return out;
}

} // namespace

std::string http_head(std::string_view head) { return rewrite(head, false); }

std::string strip_secrets(std::string_view head) { return rewrite(head, true); }

std::string query(std::string_view path) { return rewrite_query(path, false); }

} // namespace slop::core::network::redact
