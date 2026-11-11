// src/core/mcp/tools_persist.cpp
// tool: persist (session / analysis database save and load)

#include "core/mcp/tools_common.hpp"

namespace slop::core::mcp::detail {

namespace {

// what an MCP client may push into the app database in one call
constexpr size_t kMaxSessionBytes = 16u << 20;   // save: serialized data
constexpr size_t kMaxValueBytes   = 1u << 20;    // kv_set: value
constexpr size_t kMaxNameBytes    = 256;         // save name / kv key

void check_name(const json& args, const char* key) {
    if (args.contains(key) && args.at(key).is_string() &&
        args.at(key).get_ref<const std::string&>().size() > kMaxNameBytes)
        fail(std::string(key) + " longer than " + std::to_string(kMaxNameBytes) + " bytes");
}

void check_payload(const std::string& what, size_t bytes, size_t cap) {
    if (bytes > cap)
        fail(what + " is " + std::to_string(bytes) + " bytes; the limit is " +
             std::to_string(cap) + " (store large artifacts as files via fs and save the path)");
}

} // namespace

// tool: persist

json tool_persist(const json& args) {
    const std::string action = require_action(args);

    // size checks come first: an oversized request never touches the store
    std::string payload;
    if (action == "save") {
        if (!args.contains("name") || !args.contains("data"))
            fail("missing name/data");
        check_name(args, "name");
        payload = args.at("data").dump(-1, ' ', false, json::error_handler_t::replace);
        check_payload("data", payload.size(), kMaxSessionBytes);
    } else if (action == "kv_set") {
        if (!args.contains("key") || !args.contains("value"))
            fail("missing key/value");
        check_name(args, "key");
        const json& v = args.at("value");
        payload = v.is_string() ? v.get<std::string>() : v.dump();
        check_payload("value", payload.size(), kMaxValueBytes);
    }

    // one store per process, opened on first use
    static persist::session_store_t store;
    static bool store_open = false;
    if (!store_open) {
        std::string err;
        if (!store.open(persist::default_store_path(), &err))
            fail("store open failed: " + err);
        store_open = true;
    }

    if (action == "save") {
        auto id = store.save_session(args.at("name").get<std::string>(), payload);
        if (!id) fail("save failed");
        return {{"saved", true}, {"id", *id}, {"bytes", payload.size()}};
    }
    if (action == "list") {
        json arr = json::array();
        for (const auto& m : store.list_sessions())
            arr.push_back({{"id", m.id}, {"name", m.name},
                           {"created_at", m.created_at}});
        return {{"sessions", arr}, {"count", arr.size()}};
    }
    if (action == "load") {
        auto row = store.load_session(parse_addr(args, "id"));
        if (!row) fail("unknown session id");
        json data = json::parse(row->data, nullptr, false);
        return {{"id", row->id}, {"name", row->name},
                {"created_at", row->created_at},
                {"data", data.is_discarded() ? json(row->data) : data}};
    }
    if (action == "delete") {
        if (!store.delete_session(parse_addr(args, "id")))
            fail("unknown session id");
        return {{"deleted", true}};
    }
    if (action == "kv_set") {
        if (!store.kv_set(args.at("key").get<std::string>(), payload))
            fail("kv_set failed");
        return {{"set", true}};
    }
    if (action == "kv_get") {
        auto v = store.kv_get(args.value("key", ""));
        if (!v) fail("no value for key");
        json parsed = json::parse(*v, nullptr, false);
        return {{"value", parsed.is_discarded() ? json(*v) : parsed}};
    }

    // hyperion project files (.hdb, see core/database/database.h): save
    // writes names, comments, functions, xrefs, types and applied types;
    // load validates the project and merges all of it into the live DB

    if (action == "hype_save") {
        if (!args.contains("dir") || !args.at("dir").is_string())
            fail("missing dir (project directory to write)");
        std::lock_guard lk(ds::state_mutex());
        auto& bin = ds::get();
        if (!bin.ready || !bin.hype || !bin.hype->ready())
            fail("no analyzed image loaded (see disasm.loaded)");
        hype::Database dbio;
        const std::string dir = args.at("dir").get<std::string>();
        std::string err;
        if (!dbio.save(dir, bin.hype->image(), bin.hype->db(), &err))
            fail("hype_save failed: " + err);
        const auto& db = bin.hype->db();
        return {{"ok", true}, {"dir", dir}, {"version", hype::Database::kVersion},
                {"names", db.names.size()},
                {"comments", db.comments.size()},
                {"functions", db.funcs.size()},
                {"xrefs", db.xrefs.size()},
                {"types", db.types.all().size()},
                {"applied_types", db.applied_types.size()}};
    }
    if (action == "hype_load") {
        if (!args.contains("dir") || !args.at("dir").is_string())
            fail("missing dir (project directory to read)");
        std::lock_guard lk(ds::state_mutex());
        auto& bin = ds::get();
        if (!bin.ready || !bin.hype || !bin.hype->ready())
            fail("no analyzed image loaded to merge into (see disasm.loaded)");
        const std::string dir = args.at("dir").get<std::string>();
        hype::PEImage  img{};
        hype::AnalysisDB loaded;
        hype::Database dbio;
        std::string err;
        if (!dbio.load(dir, img, loaded, &err)) fail("hype_load failed: " + err);
        json out = {{"ok", true}, {"dir", dir}};
        if (img.base != bin.hype->image().base)
            out["warning"] = "project base differs from the loaded image; VAs merged as saved";
        const auto st = hype::Database::merge(loaded, bin.hype->db_mut());
        out["merged_names"] = st.names;
        out["merged_comments"] = st.comments;
        out["merged_functions"] = st.functions;
        out["merged_xrefs"] = st.xrefs;
        out["merged_types"] = st.types;
        out["merged_applied_types"] = st.applied_types;
        return out;
    }

    fail("persist: unknown action (save|list|load|delete|kv_set|kv_get|"
         "hype_save|hype_load)");
}

} // namespace slop::core::mcp::detail
