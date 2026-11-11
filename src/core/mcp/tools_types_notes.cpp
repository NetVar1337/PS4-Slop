// src/core/mcp/tools_types_notes.cpp
// tools: types and notes

#include "core/mcp/tools_common.hpp"

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

} // namespace


json tool_types(const json& args) {
    namespace tc = re::type_catalog;
    const std::string action = require_action(args);

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
        auto s = tc::get_struct(args.at("name").get<std::string>());
        return struct_to_json(*s);
    }
    if (action == "remove_struct")
        return {{"removed", tc::remove_struct(args.at("name").get<std::string>())}};

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
    if (action == "remove_enum")
        return {{"removed", tc::remove_enum(args.at("name").get<std::string>())}};

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
    fail("notes: unknown action (set_comment|get_comment|comments|"
         "bookmark_toggle|bookmarks)");
}

} // namespace slop::core::mcp::detail
