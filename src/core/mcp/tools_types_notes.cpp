// src/core/mcp/tools_types_notes.cpp
// tools: types and notes

#include "core/mcp/tools_common.hpp"

#include "core/network/web_fetch.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>

namespace slop::core::mcp::detail {

namespace {

// tool: types

json struct_to_json(const re::type_catalog::struct_def_t& s) {
    json fields = json::array();
    for (const auto& f : s.fields)
        fields.push_back({{"name", f.name}, {"type", f.type},
                          {"offset", f.offset}, {"size", f.size},
                          {"array_count", f.array_count}});
    return {{"name", s.name}, {"size", s.size}, {"packed", s.packed},
            {"fields", fields}};
}

json enum_to_json(const re::type_catalog::enum_def_t& e) {
    json vals = json::array();
    for (const auto& [n, v] : e.values)
        vals.push_back({{"name", n}, {"value", v}});
    return {{"name", e.name}, {"underlying", e.underlying}, {"values", vals}};
}

// --- Git-shareable annotation files (notes.export / notes.import) ---
//
// symbols/<hash>.json holds everything an analyst would want reviewed: names,
// comments, bookmarks and the struct/enum catalog. Keys are zero padded so a
// lexicographic sort is a numeric VA sort, arrays are sorted and the dump is
// indented: two sessions that changed different addresses produce a diff with
// exactly those lines in it.

constexpr const char* kSymbolsFormat = "reverse-slop-symbols";

std::string va_key(uint64_t va) {
    char k[24];
    std::snprintf(k, sizeof(k), "%016llX", static_cast<unsigned long long>(va));
    return k;
}

struct notes_snapshot_t {
    uint64_t                        hash = 0;
    uint64_t                        base = 0;
    std::string                     image;
    std::map<uint64_t, std::string> names;
    std::map<uint64_t, std::string> comments;
    std::vector<uint64_t>           bookmarks;
    std::vector<re::type_catalog::struct_def_t> structs;
    std::vector<re::type_catalog::enum_def_t>   enums;
};

notes_snapshot_t snapshot_notes() {
    notes_snapshot_t s;
    {
        ds::binary_lock_t lk;
        auto& b = ds::get();
        s.hash = b.file_hash;
        s.base = b.base;
        s.image = b.name;
        s.names.insert(b.symbols.begin(), b.symbols.end());
        s.comments.insert(b.comments.begin(), b.comments.end());
        s.bookmarks = b.bookmarks;
    }
    s.structs = re::type_catalog::list_structs();   // sorted by name
    s.enums   = re::type_catalog::list_enums();
    return s;
}

json notes_doc(const notes_snapshot_t& s) {
    json names = json::object();
    for (const auto& [va, name] : s.names) names[va_key(va)] = name;
    json comments = json::object();
    for (const auto& [va, text] : s.comments) comments[va_key(va)] = text;
    std::vector<uint64_t> marks = s.bookmarks;
    std::sort(marks.begin(), marks.end());
    marks.erase(std::unique(marks.begin(), marks.end()), marks.end());
    json bookmarks = json::array();
    for (uint64_t va : marks) bookmarks.push_back(va_key(va));
    json structs = json::array();
    for (const auto& st : s.structs) structs.push_back(struct_to_json(st));
    json enums = json::array();
    for (const auto& e : s.enums) enums.push_back(enum_to_json(e));
    return {{"format", kSymbolsFormat},
            {"version", 1},
            {"image", {{"hash", va_key(s.hash)},
                       {"base", va_key(s.base)},
                       {"name", s.image}}},
            {"names", names},
            {"comments", comments},
            {"bookmarks", bookmarks},
            {"structs", structs},
            {"enums", enums}};
}

std::string notes_file_path(const std::string& dir, uint64_t hash) {
    return (std::filesystem::path(dir) / "symbols" / (va_key(hash) + ".json")).string();
}

std::optional<re::type_catalog::struct_def_t> struct_from_json(const json& j) {
    if (!j.is_object() || !j.contains("name") || !j.at("name").is_string()) return std::nullopt;
    re::type_catalog::struct_def_t s;
    s.name   = j.at("name").get<std::string>();
    s.packed = j.value("packed", false);
    if (j.contains("fields") && j.at("fields").is_array())
        for (const auto& f : j.at("fields")) {
            re::type_catalog::field_t fld;
            fld.name = f.value("name", std::string{});
            fld.type = f.value("type", std::string{});
            fld.offset = f.value("offset", 0ull);   // create_struct re-lays out
            fld.size = f.value("size", 0ull);
            fld.array_count = f.value("array_count", 0u);
            if (!fld.name.empty() && !fld.type.empty()) s.fields.push_back(std::move(fld));
        }
    return s;
}

std::optional<re::type_catalog::enum_def_t> enum_from_json(const json& j) {
    if (!j.is_object() || !j.contains("name") || !j.at("name").is_string()) return std::nullopt;
    re::type_catalog::enum_def_t e;
    e.name = j.at("name").get<std::string>();
    e.underlying = j.value("underlying", std::string{"u32"});
    if (j.contains("values") && j.at("values").is_array())
        for (const auto& v : j.at("values"))
            if (v.is_object() && v.contains("name") && v.at("name").is_string())
                e.values.emplace_back(v.at("name").get<std::string>(),
                                      v.value("value", static_cast<int64_t>(0)));
    return e;
}

// apply an annotation document to the session; shared by notes.import (a file
// an analyst committed) and notes.pull (the same file fetched from a shared
// symbol store). mode: ours = only fill gaps, theirs = the document wins,
// union = sets merge and local text stays.
json merge_notes_doc(const json& doc, const std::string& mode) {
    const bool theirs = mode == "theirs";
    size_t n_names = 0, n_comments = 0, n_marks = 0, n_structs = 0, n_enums = 0;
    auto for_each_entry = [&](const char* key, auto&& apply) {
        if (!doc.contains(key) || !doc.at(key).is_object()) return;
        for (auto it = doc.at(key).begin(); it != doc.at(key).end(); ++it) {
            if (!it.value().is_string()) continue;
            const uint64_t va = std::strtoull(it.key().c_str(), nullptr, 16);
            if (va) apply(va, it.value().get_ref<const std::string&>());
        }
    };
    for_each_entry("names", [&](uint64_t va, const std::string& name) {
        const std::string have = ds::symbol_name(va);
        if (have == name || (!theirs && !have.empty())) return;
        ds::set_symbol(va, name);
        ++n_names;
    });
    for_each_entry("comments", [&](uint64_t va, const std::string& text) {
        const std::string have = ds::comment_for(va);
        if (have == text || (!theirs && !have.empty())) return;
        ds::set_comment(va, text);
        ++n_comments;
    });
    if (doc.contains("bookmarks") && doc.at("bookmarks").is_array())
        for (const auto& v : doc.at("bookmarks")) {
            if (!v.is_string()) continue;
            const uint64_t va = std::strtoull(v.get_ref<const std::string&>().c_str(),
                                              nullptr, 16);
            if (va && !ds::is_bookmarked(va)) {
                ds::toggle_bookmark(va);
                ++n_marks;
            }
        }
    if (doc.contains("structs") && doc.at("structs").is_array())
        for (const auto& j : doc.at("structs")) {
            auto def = struct_from_json(j);
            if (!def) continue;
            const bool exists = re::type_catalog::get_struct(def->name).has_value();
            if (exists && !theirs) continue;
            if (exists) re::type_catalog::remove_struct(def->name);
            std::string err;
            if (re::type_catalog::create_struct(std::move(*def), &err)) ++n_structs;
        }
    if (doc.contains("enums") && doc.at("enums").is_array())
        for (const auto& j : doc.at("enums")) {
            auto def = enum_from_json(j);
            if (!def) continue;
            const bool exists = re::type_catalog::get_enum(def->name).has_value();
            if (exists && !theirs) continue;
            if (exists) re::type_catalog::remove_enum(def->name);
            std::string err;
            if (re::type_catalog::create_enum(std::move(*def), &err)) ++n_enums;
        }
    return {{"names", n_names},
            {"comments", n_comments},
            {"bookmarks", n_marks},
            {"structs", n_structs},
            {"enums", n_enums}};
}

} // namespace


json tool_types(const json& args) {
    namespace tc = re::type_catalog;
    const std::string action = require_action(args);

    // every mutation bumps the catalog generation; tell the UI so it can
    // refresh rendered types and decompiled functions
    const auto publish_types_changed = [] {
        slop::core::infra::event_bus::publish(
            "types.changed", {{"generation", tc::generation()}});
    };

    if (action == "create_struct" || action == "declare") {
        std::string decl_text;
        if (args.contains("decl") && args.at("decl").is_string())
            decl_text = args.at("decl").get<std::string>();
        else if (args.contains("name") && args.at("name").is_string())
            decl_text = "struct " + args.at("name").get<std::string>() + " {};";

        tc::decl_parse_result_t pr = tc::parse_decls(decl_text);
        if (!pr.error.empty()) fail(pr.error);
        size_t n = 0;
        std::string errs;
        for (auto& s : pr.structs)
            if (tc::create_struct(std::move(s), &errs)) ++n;
        for (auto& e : pr.enums)
            if (tc::create_enum(std::move(e), &errs)) ++n;
        if (n == 0) fail(errs.empty() ? "nothing declared" : errs);
        publish_types_changed();
        return {{"declared", n}};
    }

    if (action == "get_struct") {
        auto s = tc::get_struct(args.at("name").get<std::string>());
        if (!s) fail("unknown struct");
        return struct_to_json(*s);
    }
    if (action == "list_structs") {
        auto all = tc::list_structs(args.value("filter", std::string{}));
        json arr = json::array();
        for (const auto& s : all) arr.push_back(struct_to_json(s));
        return {{"structs", arr}, {"count", arr.size()}};
    }
    if (action == "add_member") {
        tc::field_t f;
        f.name  = args.at("field").get<std::string>();
        f.type  = args.at("type").get<std::string>();
        f.array_count = static_cast<uint32_t>(args.value("array_count", 0u));
        std::string err;
        if (!tc::add_member(args.at("name").get<std::string>(), f, &err)) fail(err);
        publish_types_changed();
        auto s = tc::get_struct(args.at("name").get<std::string>());
        return struct_to_json(*s);
    }
    if (action == "remove_struct") {
        const bool removed = tc::remove_struct(args.at("name").get<std::string>());
        if (removed) publish_types_changed();
        return {{"removed", removed}};
    }

    if (action == "create_enum") {
        tc::enum_def_t e;
        e.name = args.at("name").get<std::string>();
        e.underlying = args.value("underlying", std::string{"u32"});
        for (const auto& v : args.at("values")) {
            int64_t val = 0;
            const json& jv = v.contains("value") ? v.at("value") : json();
            if (jv.is_number_integer()) val = jv.get<int64_t>();
            else if (jv.is_string())    val = static_cast<int64_t>(std::stoull(jv.get<std::string>(), nullptr, 0));
            e.values.emplace_back(v.at("name").get<std::string>(), val);
        }
        std::string err;
        if (!tc::create_enum(std::move(e), &err)) fail(err);
        publish_types_changed();
        return {{"created", true}};
    }
    if (action == "get_enum") {
        auto e = tc::get_enum(args.at("name").get<std::string>());
        if (!e) fail("unknown enum");
        return enum_to_json(*e);
    }
    if (action == "list_enums") {
        auto all = tc::list_enums(args.value("filter", std::string{}));
        json arr = json::array();
        for (const auto& e : all) arr.push_back(enum_to_json(e));
        return {{"enums", arr}, {"count", arr.size()}};
    }
    if (action == "remove_enum") {
        const bool removed = tc::remove_enum(args.at("name").get<std::string>());
        if (removed) publish_types_changed();
        return {{"removed", removed}};
    }

    if (action == "format_at") {
        // pretty print typed memory like MYSTRUCT @ 140001234
        if (!args.contains("addr")) fail("missing addr");
        if (!args.contains("type") && !args.contains("struct"))
            fail("missing type (struct or enum name)");
        const std::string type_name =
            args.value("type", args.value("struct", std::string{}));
        const uint64_t base = parse_addr(args, "addr");
        const size_t   want =
            static_cast<size_t>(args.value("size", 256u)) & 0xFFFF;

        // sync the catalog into a hyperion type system per call, theyre small
        hype::TypeSystem ts;
        std::unordered_map<std::string, uint32_t> ids;
        for (const auto& e : tc::list_enums()) {
            const uint32_t id = ts.add_enum(e.name);
            for (const auto& [n, v] : e.values) ts.add_member(id, n, v);
            ids[e.name] = id;
        }
        for (const auto& s : tc::list_structs()) {
            const uint32_t id = ts.add_struct(s.name,
                static_cast<uint32_t>(s.size ? s.size : 1));
            ids[s.name] = id;
        }
        // second pass so struct to struct references resolve
        for (const auto& s : tc::list_structs()) {
            for (const auto& f : s.fields) {
                uint32_t tid = 0;
                auto it = ids.find(f.type);
                if (it != ids.end()) {
                    tid = it->second;
                } else {
                    // map catalog names to hyperion builtins
                    static const std::unordered_map<std::string, const char*> prim = {
                        {"u8", "u8"}, {"u16", "u16"}, {"u32", "u32"}, {"u64", "u64"},
                        {"i8", "i8"}, {"i16", "i16"}, {"i32", "i32"}, {"i64", "i64"},
                        {"f32", "float"}, {"f64", "double"},
                        {"ptr", "ptr64"}, {"char", "char"},
                    };
                    auto pit = prim.find(f.type);
                    const char* pname = pit != prim.end() ? pit->second : "u8";
                    if (const auto* td = ts.find_by_name(pname)) tid = td->id;
                }
                ts.add_field(ids[s.name], f.name, tid,
                             static_cast<uint32_t>(f.offset));
            }
        }
        const auto* td = ts.find_by_name(type_name);
        if (!td) fail("unknown type: " + type_name);

        // live target when asked, else the file image
        std::vector<uint8_t> buf(want);
        std::string source = "file";
        bool got = false;
        if (args.value("live", false)) {
            if (auto sess = process::active_session(); sess && sess->valid()) {
                auto io = sess->read(static_cast<uintptr_t>(base), buf.data(),
                                     buf.size());
                if (io.ok && io.bytes) {
                    buf.resize(io.bytes);
                    got = true;
                    source = "live";
                }
            }
            if (!got) fail("live read failed (target attached?)");
        } else {
            ds::binary_lock_t lk;
            auto& bin = ds::get();
            if (bin.ready) {
                if (auto off = bin.offset_of(base)) {
                    const size_t n = std::min(want, bin.file.size() - *off);
                    std::memcpy(buf.data(), bin.file.data() + *off, n);
                    buf.resize(n);
                    got = true;
                }
            }
            if (!got)
                fail("address not mapped in loaded image (load a binary or "
                     "pass live=true with a target attached)");
        }

        return {{"ok", true}, {"addr", base}, {"type", type_name},
                {"source", source},
                {"rendered", ts.format_at(base, td->id, buf.data(),
                                          buf.size())}};
    }

    if (action == "read_field") {
        auto s = tc::get_struct(args.at("struct").get<std::string>());
        if (!s) fail("unknown struct");
        const uint64_t base = parse_addr(args, "addr");

        // file image first, live memory when asked
        bool live = args.value("live", false);
        if (!live) {
            ds::binary_lock_t lk;
            auto& bin = ds::get();
            if (bin.ready) {
                auto off = bin.offset_of(base);
                if (off) {
                    auto v = tc::read_field(*s, args.at("field").get<std::string>(),
                                            0 /*offset already translated*/,
                                            bin.file.data() + *off,
                                            bin.file.size() - *off,
                                            nullptr, nullptr);
                    if (v.ok) return {{"ok", true}, {"hex", v.hex},
                                      {"uint", v.uint_val}, {"int", v.int_val},
                                      {"double", v.dbl_val}, {"source", "file"}};
                }
            }
        }
        auto sess = process::active_session();
        if (!live || !sess || !sess->valid())
            fail("no image data for that address (attach a target or use a mapped VA)");

        struct cb_ctx { runtime::session_t* s; } ctx{sess.get()};
        auto cb = [](uint64_t addr, void* dst, size_t len, void* user) -> bool {
            auto* c = static_cast<cb_ctx*>(user);
            auto io = c->s->read(static_cast<uintptr_t>(addr), dst, len);
            return io.ok && io.bytes == len;
        };
        auto v = tc::read_field(*s, args.at("field").get<std::string>(),
                                base, nullptr, 0, cb, &ctx);
        if (!v.ok) fail(v.error);
        return {{"ok", true}, {"hex", v.hex}, {"uint", v.uint_val},
                {"int", v.int_val}, {"double", v.dbl_val}, {"source", "target"}};
    }

    fail("types: unknown action (declare|create_struct|get_struct|list_structs|"
         "add_member|remove_struct|create_enum|get_enum|list_enums|remove_enum|"
         "read_field|format_at)");
}


// tool: notes

json tool_notes(const json& args) {
    const std::string action = require_action(args);
    if (!ds::has_binary()) fail("no image loaded in reverse-slop (see disasm.loaded)");

    if (action == "set_comment") {
        const uint64_t va = parse_addr(args, "addr");
        const std::string text = args.value("text", std::string{});
        ds::set_comment(va, text);          // saved, empty clears
        return {{"va", va}, {"cleared", text.empty()}};
    }
    if (action == "get_comment") {
        const uint64_t va = parse_addr(args, "addr");
        return {{"va", va}, {"comment", ds::comment_for(va)}};
    }
    if (action == "comments") {
        auto snaps = ds::comments_snapshot();
        std::sort(snaps.begin(), snaps.end());
        json arr = json::array();
        for (const auto& [va, text] : snaps)
            arr.push_back({{"va", va}, {"comment", text}});
        return {{"comments", arr}, {"count", arr.size()}};
    }
    if (action == "bookmark_toggle") {
        const uint64_t va = parse_addr(args, "addr");
        return {{"va", va}, {"bookmarked", ds::toggle_bookmark(va)}};
    }
    if (action == "bookmarks") {
        auto marks = ds::bookmarks_snapshot();
        std::sort(marks.begin(), marks.end());
        return {{"bookmarks", marks}, {"count", marks.size()}};
    }
    if (action == "export") {
        if (!args.contains("path") || !args.at("path").is_string())
            fail("missing path (folder to write symbols/<hash>.json into)");
        const notes_snapshot_t snap = snapshot_notes();
        const std::string file = notes_file_path(args.at("path").get<std::string>(), snap.hash);
        std::error_code ec;
        std::filesystem::create_directories(
            std::filesystem::path(file).parent_path(), ec);
        if (ec) fail("cannot create " + std::filesystem::path(file).parent_path().string() +
                     ": " + ec.message());
        std::ofstream f(file, std::ios::binary | std::ios::trunc);
        if (!f) fail("cannot write " + file);
        f << notes_doc(snap).dump(2) << "\n";
        f.close();
        if (!f) fail("write failed: " + file);
        return {{"path", file},
                {"hash", va_key(snap.hash)},
                {"names", snap.names.size()},
                {"comments", snap.comments.size()},
                {"bookmarks", snap.bookmarks.size()},
                {"structs", snap.structs.size()},
                {"enums", snap.enums.size()}};
    }
    if (action == "import") {
        if (!args.contains("path") || !args.at("path").is_string())
            fail("missing path (folder holding symbols/<hash>.json)");
        const std::string mode = args.value("merge", std::string{"ours"});
        if (mode != "ours" && mode != "theirs" && mode != "union")
            fail("merge must be ours|theirs|union");
        const notes_snapshot_t snap = snapshot_notes();
        const std::string file = notes_file_path(args.at("path").get<std::string>(), snap.hash);
        std::ifstream f(file, std::ios::binary);
        if (!f) fail("no annotation file for this image: " + file);
        const json doc = json::parse(f, nullptr, false);
        if (doc.is_discarded() || !doc.is_object()) fail("not a JSON object: " + file);
        if (doc.value("format", std::string{}) != kSymbolsFormat)
            fail("not a " + std::string(kSymbolsFormat) + " file: " + file);

        const json counts = merge_notes_doc(doc, mode);
        return {{"path", file},
                {"merge", mode},
                {"names", counts.at("names")},
                {"comments", counts.at("comments")},
                {"bookmarks", counts.at("bookmarks")},
                {"structs", counts.at("structs")},
                {"enums", counts.at("enums")}};
    }
    if (action == "push" || action == "pull") {
        // shared symbol server: any HTTP endpoint that serves the same
        // symbols/<hash>.json files (a static file server, a gist mirror, a
        // small team service). The egress policy of the `web` tool applies, so
        // a LAN server needs web_allow_private or a web_allowlist entry.
        if (!args.contains("url") || !args.at("url").is_string())
            fail("missing url (base of the shared symbol store)");
        std::string base = args.at("url").get<std::string>();
        while (!base.empty() && base.back() == '/') base.pop_back();
        const notes_snapshot_t snap = snapshot_notes();
        const std::string url = base + "/symbols/" + va_key(snap.hash) + ".json";

        util::egress_policy_t policy;
        policy.allow_private = infra::settings::get<bool>("web_allow_private", false);
        const json allow = infra::settings::get_json("web_allowlist");
        if (allow.is_array())
            for (const auto& e : allow)
                if (e.is_string()) policy.allowlist.push_back(e.get<std::string>());

        std::string err;
        if (action == "push") {
            const std::string body = notes_doc(snap).dump(2) + "\n";
            auto resp = util::http_post(url, body, "application/json", policy, 15000, &err);
            if (!resp) fail("push failed: " + err);
            if (resp->status < 200 || resp->status >= 300)
                fail("push rejected: HTTP " + std::to_string(resp->status));
            return {{"pushed", true},
                    {"url", url},
                    {"status", resp->status},
                    {"bytes", body.size()},
                    {"names", snap.names.size()},
                    {"comments", snap.comments.size()},
                    {"bookmarks", snap.bookmarks.size()}};
        }
        auto resp = util::http_get(url, policy, 15000, &err);
        if (!resp) fail("pull failed: " + err);
        if (resp->status == 404) fail("no annotations for this image yet: " + url);
        if (resp->status < 200 || resp->status >= 300)
            fail("pull rejected: HTTP " + std::to_string(resp->status));
        const json doc = json::parse(resp->body, nullptr, false);
        if (doc.is_discarded() || !doc.is_object()) fail("not a JSON object: " + url);
        if (doc.value("format", std::string{}) != kSymbolsFormat)
            fail("not a " + std::string(kSymbolsFormat) + " file: " + url);
        const std::string mode = args.value("merge", std::string{"ours"});
        if (mode != "ours" && mode != "theirs" && mode != "union")
            fail("merge must be ours|theirs|union");
        const json counts = merge_notes_doc(doc, mode);
        return {{"pulled", true},
                {"url", url},
                {"merge", mode},
                {"names", counts.at("names")},
                {"comments", counts.at("comments")},
                {"bookmarks", counts.at("bookmarks")},
                {"structs", counts.at("structs")},
                {"enums", counts.at("enums")}};
    }
    fail("notes: unknown action (set_comment|get_comment|comments|"
         "bookmark_toggle|bookmarks|export|import|push|pull)");
}

} // namespace slop::core::mcp::detail
