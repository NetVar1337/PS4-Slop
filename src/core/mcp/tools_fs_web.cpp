// src/core/mcp/tools_fs_web.cpp
// tools: fs and web

#include "core/mcp/tools_common.hpp"

namespace slop::core::mcp::detail {


namespace {

constexpr size_t kReadDefault = 64u << 10;   // fs.read_file default page
constexpr size_t kReadMax     = 1u << 20;    // per call, the response carries it twice at most

// valid utf-8 without NULs reads back as text, anything else as hex
bool looks_text(const std::vector<uint8_t>& b) {
    size_t i = 0;
    while (i < b.size()) {
        const uint8_t c = b[i];
        if (c == 0) return false;
        size_t n = c < 0x80 ? 1 : (c >> 5) == 0x6 ? 2 : (c >> 4) == 0xE ? 3 : (c >> 3) == 0x1E ? 4 : 0;
        if (n == 0) return false;
        // a sequence cut by the page end is fine, the next page continues it
        for (size_t k = 1; k < n && i + k < b.size(); ++k)
            if ((b[i + k] & 0xC0) != 0x80) return false;
        i += n;
    }
    return true;
}

} // namespace

// tool: fs (host filesystem; runs off the tool lock, walks honor cancellation)

json tool_fs(const json& args, const infra::cancel_token_t& cancel) {
    const std::string action = require_action(args);

    if (action == "read_file") {
        if (!args.contains("path")) fail("missing path");
        const std::string path = args.at("path").get<std::string>();
        const uint64_t offset = args.contains("offset") ? parse_addr(args, "offset") : 0;
        const size_t want = args.contains("max_bytes")
            ? static_cast<size_t>(std::min<uint64_t>(parse_addr(args, "max_bytes"), kReadMax))
            : kReadDefault;
        const std::string encoding = args.value("encoding", std::string{"auto"});
        if (encoding != "auto" && encoding != "text" && encoding != "hex")
            fail("fs.read_file: encoding must be auto|text|hex");
        std::vector<uint8_t> bytes;
        uint64_t total = 0;
        std::string err;
        if (!util::read_file(path, offset, &bytes, want, &total, &err)) fail(err);
        const uint64_t next = offset + bytes.size();
        json out = {{"path", path},
                    {"size", total},
                    {"offset", offset},
                    {"bytes", bytes.size()},
                    {"eof", next >= total}};
        if (next < total) out["next_offset"] = next;
        const bool as_text = encoding == "text" || (encoding == "auto" && looks_text(bytes));
        if (as_text) {
            out["encoding"] = "text";
            out["text"] = std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        } else {
            out["encoding"] = "hex";
            out["hex"] = to_hex(bytes.data(), bytes.size());
        }
        return out;
    }
    if (action == "write_file") {
        if (!args.contains("path")) fail("missing path");
        std::vector<uint8_t> bytes;
        if (args.contains("hex"))
            bytes = hex_decode(args.at("hex").get<std::string>());
        else if (args.contains("text")) {
            // bind once, two get calls make two different strings and thats ub
            const std::string text = args.at("text").get<std::string>();
            bytes.assign(text.begin(), text.end());
        }
        std::string err;
        if (!util::write_file(args.at("path").get<std::string>(), bytes,
                              args.value("append", false), &err))
            fail(err);
        return {{"written", bytes.size()}, {"path", args.at("path")}};
    }
    if (action == "list_directory") {
        if (!args.contains("path")) fail("missing path");
        std::string err;
        auto items = util::list_directory(
            args.at("path").get<std::string>(), &err);
        if (items.empty() && !err.empty()) fail(err);
        json arr = json::array();
        for (const auto& e : items)
            arr.push_back({{"name", e.name}, {"size", e.size},
                           {"directory", e.directory}, {"reparse", e.reparse}});
        json out = {{"entries", arr}, {"count", arr.size()}};
        if (!err.empty()) {
            out["truncated"] = true;
            out["warning"] = err;
        }
        return out;
    }
    if (action == "create_directory") {
        if (!args.contains("path")) fail("missing path");
        std::string err;
        if (!util::create_directory(args.at("path").get<std::string>(),
                                    &err))
            fail(err);
        return {{"created", true}};
    }
    if (action == "delete_path") {
        if (!args.contains("path")) fail("missing path");
        std::string err;
        if (!util::delete_path(args.at("path").get<std::string>(), &err))
            fail(err);
        return {{"deleted", true}};
    }
    if (action == "search_files") {
        if (!args.contains("root") || !args.contains("needle"))
            fail("missing root/needle");
        auto hits = util::search_files(
            args.at("root").get<std::string>(),
            args.at("needle").get<std::string>(),
            std::min<size_t>(args.value("limit", 200u), 2000u), cancel);
        json arr = json::array();
        for (const auto& h : hits)
            arr.push_back({{"path", h.path}, {"size", h.size},
                           {"directory", h.directory}});
        return {{"matches", arr}, {"count", arr.size()}, {"cancelled", cancel.cancelled()}};
    }
    if (action == "grep_in_files") {
        if (!args.contains("root") || !args.contains("needle"))
            fail("missing root/needle");
        auto hits = util::grep_in_files(
            args.at("root").get<std::string>(),
            args.at("needle").get<std::string>(),
            args.value("suffix", std::string{}),
            std::min<size_t>(args.value("limit", 200u), 2000u), cancel);
        json arr = json::array();
        for (const auto& h : hits)
            arr.push_back({{"path", h.path}, {"line", h.line},
                           {"text", h.text}});
        return {{"hits", arr}, {"count", arr.size()}, {"cancelled", cancel.cancelled()}};
    }

    fail("fs: unknown action (read_file|write_file|list_directory|"
         "create_directory|delete_path|search_files|grep_in_files)");
}


// tool: web

namespace {

bool valid_utf8(const std::string& s) {
    size_t i = 0;
    while (i < s.size()) {
        const auto c = static_cast<unsigned char>(s[i]);
        size_t n = c < 0x80 ? 1 : (c >> 5) == 0x6 ? 2 : (c >> 4) == 0xE ? 3 : (c >> 3) == 0x1E ? 4 : 0;
        if (n == 0 || i + n > s.size()) return false;
        for (size_t k = 1; k < n; ++k)
            if ((static_cast<unsigned char>(s[i + k]) & 0xC0) != 0x80) return false;
        i += n;
    }
    return true;
}

util::egress_policy_t web_policy() {
    util::egress_policy_t p;
    p.allow_private = infra::settings::get<bool>("web_allow_private", false);
    const json list = infra::settings::get_json("web_allowlist");
    if (list.is_array())
        for (const auto& e : list)
            if (e.is_string()) p.allowlist.push_back(e.get<std::string>());
    return p;
}


std::string base64(const std::string& in) {
    static constexpr char kAlpha[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    size_t i = 0;
    const auto byte = [&](size_t k) { return static_cast<uint32_t>(static_cast<unsigned char>(in[k])); };
    for (; i + 3 <= in.size(); i += 3) {
        const uint32_t v = (byte(i) << 16) | (byte(i + 1) << 8) | byte(i + 2);
        out += kAlpha[(v >> 18) & 63];
        out += kAlpha[(v >> 12) & 63];
        out += kAlpha[(v >> 6) & 63];
        out += kAlpha[v & 63];
    }
    if (i < in.size()) {
        uint32_t v = byte(i) << 16;
        if (i + 1 < in.size()) v |= byte(i + 1) << 8;
        out += kAlpha[(v >> 18) & 63];
        out += kAlpha[(v >> 12) & 63];
        out += i + 1 < in.size() ? kAlpha[(v >> 6) & 63] : '=';
        out += '=';
    }
    return out;
}
} // namespace

json tool_web(const json& args) {
    const std::string action = require_action(args);

    if (action == "fetch" || action == "post") {
        if (!args.contains("url") || !args.at("url").is_string()) fail("missing url");
        util::http_request_t req;
        req.url = args.at("url").get<std::string>();
        req.timeout_ms = static_cast<int>(std::clamp<uint64_t>(
            args.contains("timeout_ms") ? parse_addr(args, "timeout_ms") : 15000, 1000, 60000));
        if (action == "post") {
            if (!args.contains("body")) fail("missing body");
            const json& b = args.at("body");
            req.method = "POST";
            req.body = b.is_string() ? b.get<std::string>()
                                     : b.dump(-1, ' ', false, json::error_handler_t::replace);
            req.content_type = args.value("content_type", std::string{"application/json"});
        }
        const uint64_t offset = args.contains("offset") ? parse_addr(args, "offset") : 0;
        const size_t max_bytes = static_cast<size_t>(std::clamp<uint64_t>(
            args.contains("max_bytes") ? parse_addr(args, "max_bytes") : 65536, 1, 1u << 20));
        const std::string encoding = args.value("encoding", std::string{"auto"});
        if (encoding != "auto" && encoding != "text" && encoding != "base64")
            fail("encoding must be auto, text or base64");

        std::string err;
        auto resp = util::http_request(req, web_policy(), &err);
        if (!resp) fail(err);

        const std::string& body = resp->body;
        const size_t start = static_cast<size_t>(std::min<uint64_t>(offset, body.size()));
        size_t end = std::min(body.size(), start + max_bytes);
        const bool as_text = encoding == "text" || (encoding == "auto" && valid_utf8(body));
        if (as_text)   // never split a UTF-8 sequence across pages
            while (end > start && end < body.size() &&
                   (static_cast<unsigned char>(body[end]) & 0xC0) == 0x80)
                --end;
        const std::string slice = body.substr(start, end - start);
        json out = {{"status", resp->status},
                    {"content_type", resp->content_type},
                    {"total_bytes", body.size()},
                    {"offset", start},
                    {"returned", slice.size()},
                    {"next_offset", end < body.size() ? json(end) : json(nullptr)},
                    {"body_truncated", resp->body_truncated},
                    {"final_url", resp->final_url},
                    {"redirects", resp->redirects},
                    {"remote_addr", resp->remote_addr},
                    {"encoding", as_text ? "text" : "base64"}};
        if (as_text)
            out["text"] = slice;
        else
            out["base64"] = base64(slice);
        return out;
    }

    fail("web: unknown action (use fetch or post)");
}

} // namespace slop::core::mcp::detail
