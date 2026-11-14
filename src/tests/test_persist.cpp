// src/tests/test_persist.cpp
// SQLite session store roundtrips against a temp database file, .hdb project
// save/load/merge + corruption handling, persist tool size caps, schema
// migrations, the fs_root jail, DNS-pinned web egress, the persisted patch
// journal and the Git-shareable notes export/import

#include "harness.hpp"

#include "core/database/database.h"
#include "core/disasm/binary_state.hpp"
#include "core/infra/settings.hpp"
#include "core/mcp/mcp_tools.hpp"
#include "core/network/web_fetch.hpp"
#include "core/persist/session_store.hpp"
#include "core/util/fs_tools.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <process.h>
#include <string>
#include <thread>
#include <vector>

#include <windows.h>

using namespace slop::core::persist;
namespace fs = std::filesystem;
namespace util = slop::core::util;
namespace ds = slop::core::disasm::binary_state;
namespace settings = slop::core::infra::settings;

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

// === schema migrations ===

namespace {

// SQLite keeps PRAGMA user_version in the database header at byte 60, big
// endian. Poking it is how these tests build a store written by another build
// without linking sqlite into the test target
bool poke_user_version(const std::string& path, uint32_t v) {
    std::fstream f(path, std::ios::binary | std::ios::in | std::ios::out);
    if (!f) return false;
    f.seekp(60, std::ios::beg);
    const unsigned char b[4] = {
        static_cast<unsigned char>(v >> 24), static_cast<unsigned char>(v >> 16),
        static_cast<unsigned char>(v >> 8),  static_cast<unsigned char>(v)};
    f.write(reinterpret_cast<const char*>(b), 4);
    f.flush();
    return static_cast<bool>(f);
}

// LOCALAPPDATA is where the per-hash annotation stores live; pointing it at a
// scratch folder keeps these tests off the real user profile
struct env_guard_t {
    std::string name, prev;
    bool had = false;
    env_guard_t(const char* n, const std::string& value) : name(n) {
        char buf[32768];
        const DWORD len = GetEnvironmentVariableA(name.c_str(), buf,
                                                  static_cast<DWORD>(sizeof(buf)));
        had = len > 0 && len < sizeof(buf);
        if (had) prev.assign(buf, len);
        SetEnvironmentVariableA(name.c_str(), value.c_str());
    }
    ~env_guard_t() {
        SetEnvironmentVariableA(name.c_str(), had ? prev.c_str() : nullptr);
    }
};

void spit(const fs::path& p, const std::string& text) {
    fs::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f.write(text.data(), static_cast<std::streamsize>(text.size()));
}

std::string slurp(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(f),
                       std::istreambuf_iterator<char>());
}

} // namespace

TEST_CASE(persist_store_migrates_and_refuses_newer_schema) {
    const std::string path = temp_db_path();
    remove(path.c_str());

    // a fresh file lands on the current schema
    {
        session_store_t db;
        std::string err;
        REQUIRE(db.open(path, &err));
        REQUIRE(err.empty());
        REQUIRE_EQ(db.schema_version(), session_store_t::kSchemaVersion);
        REQUIRE(db.save_session("kept", R"({"a":1})", &err).has_value());
    }

    // a file from before versioning: same tables, user_version 0. It must be
    // adopted in place, data included, not recreated
    REQUIRE(poke_user_version(path, 0));
    {
        session_store_t db;
        std::string err;
        REQUIRE(db.open(path, &err));
        REQUIRE_EQ(db.schema_version(), 1);
        REQUIRE_EQ(db.list_sessions().size(), 1u);
        REQUIRE(db.kv_set("layout", "v1"));
    }

    // a file written by a newer build is refused with a clear reason instead
    // of being guessed at
    REQUIRE(poke_user_version(path, 99));
    {
        session_store_t db;
        std::string err;
        REQUIRE(!db.open(path, &err));
        REQUIRE(!db.ok());
        REQUIRE(err.find("newer") != std::string::npos);
        REQUIRE(err.find("99") != std::string::npos);
        REQUIRE(err.find("upgrade") != std::string::npos);
        REQUIRE_EQ(db.schema_version(), -1);
    }
    remove(path.c_str());
}

// === fs_root jail ===

TEST_CASE(persist_fs_jail_canonicalises_escape_forms) {
    const fs::path base = temp_project("jail");
    const fs::path jail = base / "jail";
    const fs::path outside = base / "outside";
    spit(jail / "sub" / "ok.txt", "inside\n");
    spit(outside / "secret.txt", "outside\n");

    std::string root;
    REQUIRE(util::canonical_path(jail.string(), &root));
    std::string c;

    // plain inside path
    REQUIRE(util::canonical_path((jail / "sub" / "ok.txt").string(), &c));
    REQUIRE(util::path_within(c, root));

    // `..` traversal out of the jail
    REQUIRE(util::canonical_path(
        (jail / "sub" / ".." / ".." / "outside" / "secret.txt").string(), &c));
    REQUIRE(!util::path_within(c, root));

    // NTFS alternate data streams judge the file, not the stream name
    REQUIRE(util::canonical_path((outside / "secret.txt:hidden").string(), &c));
    REQUIRE(!util::path_within(c, root));
    REQUIRE(util::canonical_path((jail / "sub" / "ok.txt:hidden").string(), &c));
    REQUIRE(util::path_within(c, root));   // same file, still inside

    // \\?\ prefix cannot smuggle a path past the jail
    REQUIRE(util::canonical_path("\\\\?\\" + (outside / "secret.txt").string(), &c));
    REQUIRE(!util::path_within(c, root));

    // 8.3 short names resolve to the long path they name
    {
        wchar_t short_path[MAX_PATH]{};
        const fs::path target = outside / "a_long_directory_name_for_short_names";
        fs::create_directories(target);
        const DWORD n = GetShortPathNameW(target.wstring().c_str(), short_path, MAX_PATH);
        std::string short_utf8;
        if (n > 0 && n < MAX_PATH) {
            const int len = WideCharToMultiByte(CP_UTF8, 0, short_path,
                                                static_cast<int>(n), nullptr, 0, nullptr, nullptr);
            if (len > 0) {
                short_utf8.resize(static_cast<size_t>(len));
                WideCharToMultiByte(CP_UTF8, 0, short_path, static_cast<int>(n),
                                    short_utf8.data(), len, nullptr, nullptr);
            }
        }
        if (!short_utf8.empty() && short_utf8 != target.string()) {
            REQUIRE(util::canonical_path(short_utf8, &c));
            REQUIRE(!util::path_within(c, root));
        }
    }

    // a junction inside the jail that points outside is judged by its target
    {
        const std::string cmd = "cmd /c mklink /J \"" + (jail / "link").string() +
                                "\" \"" + outside.string() + "\" >NUL 2>&1";
        const bool linked = std::system(cmd.c_str()) == 0 &&
                            fs::exists(jail / "link");
        if (linked) {
            REQUIRE(util::canonical_path((jail / "link" / "secret.txt").string(), &c));
            REQUIRE(!util::path_within(c, root));
            REQUIRE(util::canonical_path((jail / "link").string(), &c));
            REQUIRE(!util::path_within(c, root));
            ::RemoveDirectoryW((jail / "link").wstring().c_str());
        }
    }

    // UNC to a share that does not exist cannot be resolved, so it cannot be
    // smuggled in as "inside"
    {
        const std::string unc = "\\\\slop-jail-" + std::to_string(::_getpid()) +
                                "\\share\\x.txt";
        const bool resolved = util::canonical_path(unc, &c);
        REQUIRE(!resolved || !util::path_within(c, root));
    }

    // path_within is case-insensitive and separator aware
    REQUIRE(util::path_within(root, root));
    std::string upper = root;
    for (char& ch : upper)
        ch = static_cast<char>(toupper(static_cast<unsigned char>(ch)));
    REQUIRE(util::path_within(upper, root));
    REQUIRE(!util::path_within(root + "_sibling", root));

    std::error_code ec;
    fs::remove_all(base, ec);
}

TEST_CASE(persist_fs_tool_honours_fs_root) {
    const fs::path base = temp_project("fsroot");
    spit(base / "jail" / "ok.txt", "needle inside\n");
    spit(base / "outside" / "secret.txt", "needle outside\n");

    settings::set_file_for_testing((base / "settings.json").string());
    REQUIRE(settings::set("fs_root", nlohmann::json::array({(base / "jail").string()})));

    bool is_error = false;
    auto r = slop::core::mcp::call_tool(
        "fs", {{"action", "read_file"}, {"path", (base / "jail" / "ok.txt").string()}},
        is_error);
    REQUIRE(!is_error);
    REQUIRE(r.value("text", std::string{}).find("needle") != std::string::npos);

    // every action refuses a path outside the root, `..` included
    for (const char* action : {"read_file", "list_directory", "create_directory",
                               "delete_path"}) {
        r = slop::core::mcp::call_tool(
            "fs", {{"action", action},
                   {"path", (base / "outside" / "secret.txt").string()}},
            is_error);
        REQUIRE(is_error);
        REQUIRE(r.value("error", std::string{}).find("fs_root") != std::string::npos);
    }
    r = slop::core::mcp::call_tool(
        "fs", {{"action", "read_file"},
               {"path", (base / "jail" / ".." / "outside" / "secret.txt").string()}},
        is_error);
    REQUIRE(is_error);
    r = slop::core::mcp::call_tool(
        "fs", {{"action", "write_file"},
               {"path", (base / "outside" / "new.txt").string()},
               {"text", "x"}},
        is_error);
    REQUIRE(is_error);

    // walks are jailed at the root, so nothing outside can be listed or grepped
    r = slop::core::mcp::call_tool(
        "fs", {{"action", "search_files"}, {"root", (base / "outside").string()},
               {"needle", "secret"}},
        is_error);
    REQUIRE(is_error);
    r = slop::core::mcp::call_tool(
        "fs", {{"action", "grep_in_files"}, {"root", (base / "outside").string()},
               {"needle", "needle"}},
        is_error);
    REQUIRE(is_error);

    // the same walks inside the root work
    r = slop::core::mcp::call_tool(
        "fs", {{"action", "search_files"}, {"root", (base / "jail").string()},
               {"needle", "ok"}},
        is_error);
    REQUIRE(!is_error);
    REQUIRE_GE(r.value("count", 0u), 1u);
    r = slop::core::mcp::call_tool(
        "fs", {{"action", "grep_in_files"}, {"root", (base / "jail").string()},
               {"needle", "needle"}},
        is_error);
    REQUIRE(!is_error);
    REQUIRE_GE(r.value("count", 0u), 1u);

    // a malformed fs_root fails closed instead of silently dropping the jail
    REQUIRE(settings::set("fs_root", 42));
    r = slop::core::mcp::call_tool(
        "fs", {{"action", "read_file"}, {"path", (base / "jail" / "ok.txt").string()}},
        is_error);
    REQUIRE(is_error);
    REQUIRE(r.value("error", std::string{}).find("fs_root") != std::string::npos);

    // unset fs_root restores the historic behaviour
    REQUIRE(settings::set("fs_root", nullptr));
    r = slop::core::mcp::call_tool(
        "fs", {{"action", "read_file"}, {"path", (base / "outside" / "secret.txt").string()}},
        is_error);
    REQUIRE(!is_error);
    settings::set_file_for_testing({});

    std::error_code ec;
    fs::remove_all(base, ec);
}

// === web egress: DNS pinning ===

namespace {

// loopback origin with a redirect to a denied destination. The client must
// refuse the hop instead of resolving and connecting to it
struct web_origin_t {
    httplib::Server srv;
    int port = 0;
    std::thread th;

    web_origin_t() {
        srv.Get("/probe", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("pinned-ok", "text/plain");
        });
        srv.Get("/redir-meta", [](const httplib::Request&, httplib::Response& res) {
            res.set_redirect("http://169.254.169.254/latest/meta-data/");
        });
        srv.Get("/redir-private", [](const httplib::Request&, httplib::Response& res) {
            res.set_redirect("http://10.255.255.1/");
        });
        srv.Get("/redir-ok", [](const httplib::Request&, httplib::Response& res) {
            res.set_redirect("/probe");
        });
        srv.Get("/host", [](const httplib::Request& req, httplib::Response& res) {
            res.set_content("host=" + req.get_header_value("Host"), "text/plain");
        });
        port = srv.bind_to_any_port("127.0.0.1");
        th = std::thread([this] { srv.listen_after_bind(); });
        srv.wait_until_ready();
    }
    ~web_origin_t() {
        srv.stop();
        if (th.joinable()) th.join();
    }
    std::string url(const char* path) const {
        return "http://127.0.0.1:" + std::to_string(port) + path;
    }
};

} // namespace

TEST_CASE(persist_web_dns_pin_denies_redirect_to_private_target) {
    web_origin_t origin;
    REQUIRE_GT(origin.port, 0);
    std::string err;

    // only the origin's address is allowed: every hop is vetted separately
    util::egress_policy_t policy;
    policy.allowlist = {"127.0.0.1"};

    auto resp = util::http_get(origin.url("/probe"), policy, 5000, &err);
    REQUIRE(resp.has_value());
    REQUIRE_EQ(resp->status, 200u);
    // the request went to the vetted address, not to a re-resolved one
    REQUIRE_STR_EQ(resp->remote_addr, "127.0.0.1");
    REQUIRE_STR_EQ(resp->body, "pinned-ok");

    // a redirect into link-local metadata is refused before connecting
    REQUIRE(!util::http_get(origin.url("/redir-meta"), policy, 5000, &err).has_value());
    REQUIRE(err.find("blocked") != std::string::npos);
    REQUIRE(err.find("after redirect") != std::string::npos);
    // and so is one into RFC1918 space
    REQUIRE(!util::http_get(origin.url("/redir-private"), policy, 5000, &err).has_value());
    REQUIRE(err.find("blocked") != std::string::npos);

    // an allowed redirect hop still works
    resp = util::http_get(origin.url("/redir-ok"), policy, 5000, &err);
    REQUIRE(resp.has_value());
    REQUIRE_EQ(resp->redirects.size(), 1u);
    REQUIRE_STR_EQ(resp->body, "pinned-ok");

    // a name is resolved once and the connection made to that address while
    // the Host header keeps the name (SNI/Host handling with a pinned IP)
    util::egress_policy_t by_name;
    by_name.allowlist = {"localhost"};
    resp = util::http_get("http://localhost:" + std::to_string(origin.port) + "/host",
                          by_name, 5000, &err);
    REQUIRE(resp.has_value());
    REQUIRE_STR_EQ(resp->remote_addr, "127.0.0.1");
    REQUIRE_STR_EQ(resp->body, "host=localhost:" + std::to_string(origin.port));
    REQUIRE_GE(util::vet_destination("localhost", by_name, &err).size(), 1u);
}

// === persisted patch journal ===

TEST_CASE(persist_patch_journal_survives_reload) {
    const fs::path data = temp_project("patchstore");
    fs::create_directories(data);
    env_guard_t env("LOCALAPPDATA", data.string());

    REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH));
    uint64_t entry = 0;
    size_t off = 0;
    uint8_t original = 0;
    {
        ds::binary_lock_t lk;
        auto& bin = ds::get();
        entry = bin.base + bin.pe.entry_rva;
        auto o = bin.offset_of(entry);
        REQUIRE(o.has_value());
        off = *o;
        original = bin.file[off];
        REQUIRE(bin.patches.empty());   // fresh store
    }

    bool is_error = true;
    auto r = slop::core::mcp::call_tool(
        "patch", {{"action", "write_bytes"}, {"addr", entry}, {"hex", "9090"}},
        is_error);
    REQUIRE(!is_error);
    REQUIRE_GE(r.value("journal_total", 0u), 2u);
    ds::unload();

    // reload: the journal comes back from the per-hash store and the bytes are
    // already patched, so a session survives a restart
    REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH));
    {
        ds::binary_lock_t lk;
        auto& bin = ds::get();
        REQUIRE_GE(bin.patches.size(), 2u);
        REQUIRE_EQ(bin.file[off], 0x90);
        REQUIRE(bin.indexes_dirty);   // indexes were built from clean bytes
    }
    r = slop::core::mcp::call_tool("patch", {{"action", "journal"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GE(r.value("total", 0u), 2u);

    // revert_all still restores the originals and empties the journal
    r = slop::core::mcp::call_tool("patch", {{"action", "revert_all"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GE(r.value("bytes_changed", 0ull), 2ull);
    {
        ds::binary_lock_t lk;
        auto& bin = ds::get();
        REQUIRE(bin.patches.empty());
        REQUIRE_EQ(bin.file[off], original);
    }
    ds::unload();

    // the empty journal is what the store now holds
    REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH));
    {
        ds::binary_lock_t lk;
        REQUIRE(ds::get().patches.empty());
        REQUIRE_EQ(ds::get().file[off], original);
    }
    ds::unload();

    std::error_code ec;
    fs::remove_all(data, ec);
}

// === notes export / import (Git-friendly team annotations) ===

TEST_CASE(persist_notes_export_import_merge) {
    const fs::path data = temp_project("notestore");
    const fs::path share = temp_project("noteshare");
    fs::create_directories(data);
    fs::create_directories(share);
    env_guard_t env("LOCALAPPDATA", data.string());

    REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH));
    uint64_t entry = 0;
    {
        ds::binary_lock_t lk;
        auto& bin = ds::get();
        entry = bin.base + bin.pe.entry_rva;
    }

    bool is_error = true;
    auto r = slop::core::mcp::call_tool(
        "notes", {{"action", "set_comment"}, {"addr", entry}, {"text", "team comment"}},
        is_error);
    REQUIRE(!is_error);
    r = slop::core::mcp::call_tool(
        "notes", {{"action", "set_comment"}, {"addr", entry + 0x10},
                  {"text", "second"}},
        is_error);
    REQUIRE(!is_error);
    r = slop::core::mcp::call_tool(
        "types", {{"action", "declare"}, {"decl", "struct TeamRec { u32 a; u64 b; };"}},
        is_error);
    REQUIRE(!is_error);

    r = slop::core::mcp::call_tool("notes", {{"action", "export"}, {"path", share.string()}},
                                   is_error);
    REQUIRE(!is_error);
    const std::string file = r.value("path", std::string{});
    REQUIRE(fs::exists(file));
    REQUIRE(file.find("symbols") != std::string::npos);
    REQUIRE_EQ(r.value("comments", 0u), 2u);
    REQUIRE_GE(r.value("structs", 0u), 1u);

    const std::string first = slurp(file);
    REQUIRE(!first.empty());
    REQUIRE_EQ(first.back(), '\n');
    const auto doc = nlohmann::json::parse(first);
    REQUIRE_STR_EQ(doc.value("format", std::string{}).c_str(), "reverse-slop-symbols");
    REQUIRE(doc.contains("names"));
    REQUIRE(doc.contains("comments"));
    REQUIRE(doc.contains("bookmarks"));
    REQUIRE(doc.contains("structs"));
    REQUIRE(doc.contains("enums"));
    // zero padded VA keys: a lexicographic dump is a numeric VA order
    std::string prev_key;
    for (auto it = doc.at("comments").begin(); it != doc.at("comments").end(); ++it) {
        REQUIRE_EQ(it.key().size(), 16u);
        REQUIRE(it.key() > prev_key);
        prev_key = it.key();
    }

    // exporting the same state twice is byte identical (diff friendly)
    r = slop::core::mcp::call_tool("notes", {{"action", "export"}, {"path", share.string()}},
                                   is_error);
    REQUIRE(!is_error);
    REQUIRE_STR_EQ(slurp(file), first);

    // theirs: the file wins a conflict
    r = slop::core::mcp::call_tool(
        "notes", {{"action", "set_comment"}, {"addr", entry}, {"text", "local edit"}},
        is_error);
    REQUIRE(!is_error);
    r = slop::core::mcp::call_tool(
        "notes", {{"action", "import"}, {"path", share.string()}, {"merge", "theirs"}},
        is_error);
    REQUIRE(!is_error);
    REQUIRE_GE(r.value("comments", 0u), 1u);
    r = slop::core::mcp::call_tool("notes", {{"action", "get_comment"}, {"addr", entry}},
                                   is_error);
    REQUIRE_STR_EQ(r.value("comment", "").c_str(), "team comment");

    // ours (default): a local value survives, a cleared one is refilled
    r = slop::core::mcp::call_tool(
        "notes", {{"action", "set_comment"}, {"addr", entry}, {"text", "local wins"}},
        is_error);
    REQUIRE(!is_error);
    r = slop::core::mcp::call_tool(
        "notes", {{"action", "set_comment"}, {"addr", entry + 0x10}, {"text", ""}},
        is_error);
    REQUIRE(!is_error);
    r = slop::core::mcp::call_tool("notes", {{"action", "import"}, {"path", share.string()}},
                                   is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(r.value("comments", 0u), 1u);   // only the cleared one came back
    r = slop::core::mcp::call_tool("notes", {{"action", "get_comment"}, {"addr", entry}},
                                   is_error);
    REQUIRE_STR_EQ(r.value("comment", "").c_str(), "local wins");
    r = slop::core::mcp::call_tool("notes", {{"action", "get_comment"}, {"addr", entry + 0x10}},
                                   is_error);
    REQUIRE_STR_EQ(r.value("comment", "").c_str(), "second");

    // union merges bookmarks/structs without dropping local text
    r = slop::core::mcp::call_tool(
        "notes", {{"action", "bookmark_toggle"}, {"addr", entry}}, is_error);
    REQUIRE(!is_error);
    r = slop::core::mcp::call_tool(
        "notes", {{"action", "import"}, {"path", share.string()}, {"merge", "union"}},
        is_error);
    REQUIRE(!is_error);
    r = slop::core::mcp::call_tool("notes", {{"action", "get_comment"}, {"addr", entry}},
                                   is_error);
    REQUIRE_STR_EQ(r.value("comment", "").c_str(), "local wins");

    // a folder without the image's file is a clear error, not a silent no-op
    const fs::path empty_dir = temp_project("notesempty");
    fs::create_directories(empty_dir);
    r = slop::core::mcp::call_tool("notes", {{"action", "import"}, {"path", empty_dir.string()}},
                                   is_error);
    REQUIRE(is_error);
    REQUIRE(r.value("error", std::string{}).find("no annotation file") != std::string::npos);
    r = slop::core::mcp::call_tool("notes", {{"action", "export"}, {"path", share.string()},
                                             {"merge", "bogus"}},
                                   is_error);
    REQUIRE(!is_error);   // merge is ignored by export
    ds::unload();

    std::error_code ec;
    fs::remove_all(data, ec);
    fs::remove_all(share, ec);
    fs::remove_all(empty_dir, ec);
}
