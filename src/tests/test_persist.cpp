// src/tests/test_persist.cpp
// SQLite session store roundtrips against a temp database file, .hdb project
// save/load/merge + corruption handling, persist tool size caps

#include "harness.hpp"

#include "core/database/database.h"
#include "core/mcp/mcp_tools.hpp"
#include "core/persist/session_store.hpp"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <process.h>
#include <string>
#include <vector>

#include <windows.h>

using namespace slop::core::persist;
namespace fs = std::filesystem;

namespace {

std::string temp_db_path() {
    char path[MAX_PATH];
    std::snprintf(path, sizeof(path), "%s\\slop_sessions_%u.db",
                  std::getenv("TEMP"), static_cast<unsigned>(::_getpid()));
    return path;
}

fs::path temp_project(const char* tag) {
    fs::path p = fs::path(std::getenv("TEMP")) /
                 ("slop_hdb_" + std::string(tag) + "_" + std::to_string(::_getpid()));
    std::error_code ec;
    fs::remove_all(p, ec);
    return p;
}

void write_file(const fs::path& p, const std::vector<uint8_t>& bytes) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

template <class T> void put(std::vector<uint8_t>& b, T v) {
    const auto* p = reinterpret_cast<const uint8_t*>(&v);
    b.insert(b.end(), p, p + sizeof(T));
}

// a small analyzed-looking DB: 2 functions, names, a comment, xrefs, a
// struct referencing a builtin and an applied type
void fill_db(hype::AnalysisDB& db) {
    for (hype::va_t va : {0x401000ull, 0x401100ull}) {
        hype::Function f{};
        f.entry = va;
        f.name = va == 0x401000 ? "main" : hype::default_func_name(va);
        db.funcs[va] = std::move(f);
    }
    db.names[0x401000] = "main";
    db.names[0x403000] = "g_config";
    db.comments[0x401004] = "checks the license";
    db.add_xref({0x401010, 0x401100, hype::XrefType::CodeCall});
    db.add_xref({0x401020, 0x403000, hype::XrefType::DataRead});
    const uint32_t s = db.types.add_struct("Config", 16);
    db.types.add_field(s, "flags", db.types.find_by_name("u32")->id, 0);
    db.types.add_field(s, "next", db.types.find_by_name("ptr64")->id, 8);
    db.applied_types[0x403000] = s;
}

} // namespace

TEST_CASE(session_store_roundtrip) {
    const std::string path = temp_db_path();
    remove(path.c_str());

    {
        session_store_t db;
        std::string err;
        REQUIRE(db.open(path, &err));
        REQUIRE(err.empty());

        auto id = db.save_session("first", R"({"pid":1234,"bps":[]})", &err);
        REQUIRE(id.has_value());
        REQUIRE_GT(*id, 0u);

        id = db.save_session("second", R"({"pid":42})", &err);
        REQUIRE(id.has_value());

        auto rows = db.list_sessions();
        REQUIRE_EQ(rows.size(), 2u);
        REQUIRE_STR_EQ(rows[0].name.c_str(), "second");   // newest first

        auto loaded = db.load_session(rows[1].id);
        REQUIRE(loaded.has_value());
        REQUIRE_STR_EQ(loaded->data.c_str(), R"({"pid":1234,"bps":[]})");

        // kv table
        REQUIRE(db.kv_set("layout_main", "{\"dock\":\"left\"}"));
        auto v = db.kv_get("layout_main");
        REQUIRE(v.has_value());
        REQUIRE_STR_EQ(v->c_str(), "{\"dock\":\"left\"}");

        // overwrite
        REQUIRE(db.kv_set("layout_main", "v2"));
        v = db.kv_get("layout_main");
        REQUIRE(v.has_value());
        REQUIRE_STR_EQ(v->c_str(), "v2");
    }

    // Reopen: data persists
    {
        session_store_t db;
        REQUIRE(db.open(path));
        auto rows = db.list_sessions();
        REQUIRE_EQ(rows.size(), 2u);

        REQUIRE(db.delete_session(rows[0].id));
        REQUIRE(!db.delete_session(rows[0].id));   // already gone
        REQUIRE_EQ(db.list_sessions().size(), 1u);
    }
    remove(path.c_str());
}

TEST_CASE(session_store_unopen_is_safe) {
    session_store_t db;
    REQUIRE(!db.ok());
    REQUIRE_EQ(db.list_sessions().size(), 0u);
    REQUIRE(!db.load_session(1).has_value());
    REQUIRE(!db.delete_session(1));
    REQUIRE(!db.kv_set("k", "v"));
    REQUIRE(!db.kv_get("k").has_value());
}


TEST_CASE(persist_hdb_roundtrip_loads_every_section) {
    const fs::path dir = temp_project("rt");
    hype::PEImage img{};
    img.arch = hype::Arch::X64;
    img.format = hype::ImageFormat::ELF;
    img.base = 0x400000;
    img.entry = 0x401000;
    hype::AnalysisDB db;
    fill_db(db);

    hype::Database io;
    std::string err;
    REQUIRE(io.save(dir, img, db, &err));

    hype::PEImage li{};
    hype::AnalysisDB loaded;
    REQUIRE(io.load(dir, li, loaded, &err));
    REQUIRE(err.empty());
    REQUIRE(li.format == hype::ImageFormat::ELF);
    REQUIRE_EQ(li.base, 0x400000ull);
    REQUIRE_EQ(loaded.names.size(), 2u);
    REQUIRE_STR_EQ(loaded.comments[0x401004].c_str(), "checks the license");
    REQUIRE_EQ(loaded.funcs.size(), 2u);
    REQUIRE_STR_EQ(loaded.funcs[0x401000].name.c_str(), "main");
    REQUIRE_EQ(loaded.xrefs.size(), 2u);
    REQUIRE_EQ(loaded.xrefs_to[0x403000].size(), 1u);
    const hype::TypeDef* cfg = loaded.types.find_by_name("Config");
    REQUIRE(cfg != nullptr);
    REQUIRE_EQ(cfg->fields.size(), 2u);
    REQUIRE(loaded.types.get(cfg->fields[1].type_id) != nullptr);
    REQUIRE_STR_EQ(loaded.types.get(cfg->fields[1].type_id)->name.c_str(), "ptr64");
    REQUIRE_EQ(loaded.applied_types[0x403000], cfg->id);

    // merge into a live DB that already has one xref and its own types
    hype::AnalysisDB live;
    hype::Function f{};
    f.entry = 0x401100;
    f.name = hype::default_func_name(0x401100);
    live.funcs[0x401100] = f;
    live.add_xref({0x401010, 0x401100, hype::XrefType::CodeCall});
    live.types.add_struct("Other", 4);
    const auto st = hype::Database::merge(loaded, live);
    REQUIRE_EQ(st.names, 2u);
    REQUIRE_EQ(st.comments, 1u);
    REQUIRE_EQ(st.xrefs, 1u);                  // the duplicate call is skipped
    REQUIRE_EQ(live.xrefs.size(), 2u);
    REQUIRE_EQ(st.types, 1u);                  // Config; builtins map by name
    REQUIRE_EQ(st.applied_types, 1u);
    const hype::TypeDef* live_cfg = live.types.find_by_name("Config");
    REQUIRE(live_cfg != nullptr);
    REQUIRE_EQ(live.applied_types[0x403000], live_cfg->id);
    REQUIRE_STR_EQ(live.names[0x401000].c_str(), "main");
    REQUIRE(live.funcs.count(0x401000) == 0);  // unknown to the live DB: name only

    std::error_code ec;
    fs::remove_all(dir, ec);
}

TEST_CASE(persist_hdb_rejects_corrupt_projects) {
    const fs::path dir = temp_project("bad");
    hype::PEImage img{};
    img.arch = hype::Arch::X64;
    hype::AnalysisDB db;
    fill_db(db);
    hype::Database io;
    std::string err;
    REQUIRE(io.save(dir, img, db, &err));

    const auto try_load = [&](std::string& why) {
        hype::PEImage li{};
        hype::AnalysisDB out;
        why.clear();
        return io.load(dir, li, out, &why);
    };

    // a count claiming 4 billion names must fail before allocating
    {
        std::vector<uint8_t> names = {'N', 'A', 'M', 'S'};
        put<uint32_t>(names, 2);
        put<uint32_t>(names, 0xFFFFFFF0u);
        write_file(dir / "names.bin", names);
        REQUIRE(!try_load(err));
        REQUIRE(err.find("names.bin") != std::string::npos);
    }
    // a string length running past the end of the file
    {
        std::vector<uint8_t> names = {'N', 'A', 'M', 'S'};
        put<uint32_t>(names, 2);
        put<uint32_t>(names, 1);
        put<uint64_t>(names, 0x401000);
        put<uint32_t>(names, 0x7FFFFFFF);
        names.push_back('x');
        write_file(dir / "names.bin", names);
        REQUIRE(!try_load(err));
        REQUIRE(err.find("record 0") != std::string::npos);
    }
    // wrong section tag
    {
        std::vector<uint8_t> names = {'C', 'M', 'T', 'S'};
        put<uint32_t>(names, 2);
        put<uint32_t>(names, 0);
        write_file(dir / "names.bin", names);
        REQUIRE(!try_load(err));
        REQUIRE(err.find("tag") != std::string::npos);
    }
    // bad magic, then an unsupported version
    {
        std::vector<uint8_t> meta(36, 0);
        std::memcpy(meta.data(), "NOTAHDB", 8);
        write_file(dir / "meta.bin", meta);
        REQUIRE(!try_load(err));
        REQUIRE(err.find("magic") != std::string::npos);
        std::memcpy(meta.data(), "HYPEHDB", 8);
        const uint32_t v = 99;
        std::memcpy(meta.data() + 8, &v, 4);
        write_file(dir / "meta.bin", meta);
        REQUIRE(!try_load(err));
        REQUIRE(err.find("version 99") != std::string::npos);
    }
    std::error_code ec;
    fs::remove_all(dir, ec);
}

TEST_CASE(persist_hdb_reads_v1_projects) {
    // pre-versioning layout: 17-byte meta, untagged sections, u16 lengths
    const fs::path dir = temp_project("v1");
    fs::create_directories(dir);
    std::vector<uint8_t> meta;
    put<uint8_t>(meta, static_cast<uint8_t>(hype::Arch::X64));
    put<uint64_t>(meta, 0x140000000ull);
    put<uint64_t>(meta, 0x140001000ull);
    write_file(dir / "meta.bin", meta);
    std::vector<uint8_t> names;
    put<uint32_t>(names, 1);
    put<uint64_t>(names, 0x140001000ull);
    put<uint16_t>(names, 4);
    names.insert(names.end(), {'m', 'a', 'i', 'n'});
    write_file(dir / "names.bin", names);
    std::vector<uint8_t> empty_count;
    put<uint32_t>(empty_count, 0);
    write_file(dir / "comments.bin", empty_count);
    write_file(dir / "funcs.bin", empty_count);
    write_file(dir / "xrefs.bin", empty_count);
    std::vector<uint8_t> types = empty_count;   // 0 defs
    put<uint32_t>(types, 0);                    // 0 applied
    write_file(dir / "types.bin", types);

    hype::Database io;
    hype::PEImage li{};
    hype::AnalysisDB loaded;
    std::string err;
    REQUIRE(io.load(dir, li, loaded, &err));
    REQUIRE_EQ(li.base, 0x140000000ull);
    REQUIRE_STR_EQ(loaded.names[0x140001000ull].c_str(), "main");
    std::error_code ec;
    fs::remove_all(dir, ec);
}

TEST_CASE(persist_tool_rejects_oversized_payloads) {
    // the checks run before the store is opened, so nothing here touches
    // the user's session database
    bool is_error = false;
    nlohmann::json big = std::string(17u << 20, 'a');
    auto r = slop::core::mcp::call_tool(
        "persist", {{"action", "save"}, {"name", "huge"}, {"data", big}}, is_error);
    REQUIRE(is_error);
    REQUIRE(r.value("error", std::string{}).find("limit") != std::string::npos);

    r = slop::core::mcp::call_tool(
        "persist", {{"action", "kv_set"}, {"key", "k"}, {"value", std::string(2u << 20, 'v')}},
        is_error);
    REQUIRE(is_error);
    REQUIRE(r.value("error", std::string{}).find("limit") != std::string::npos);

    r = slop::core::mcp::call_tool(
        "persist", {{"action", "save"}, {"name", std::string(300, 'n')}, {"data", 1}}, is_error);
    REQUIRE(is_error);
    REQUIRE(r.value("error", std::string{}).find("name longer") != std::string::npos);
}
