// src/tests/test_mcp.cpp
// MCP protocol + tool-surface tests: real server on an ephemeral port, driven
// by a real HTTP client, initialize / tools/list / tools/call / health, plus
// error paths. Kernel-independent (user backend, no target required)

#include "harness.hpp"

#include "core/mcp/mcp_server.hpp"
#include "core/mcp/mcp_tools.hpp"
#include "core/disasm/binary_state.hpp"
#include "core/infra/diag.hpp"
#include "core/infra/event_bus.hpp"
#include "core/infra/paths.hpp"
#include "core/infra/settings.hpp"
#include "core/mcp/tools_common.hpp"
#include "core/network/net_socket.hpp"
#include "core/script/lua_engine.hpp"
#include "core/util/zip_reader.hpp"

#include <windows.h>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

using json = nlohmann::json;

struct server_fixture_t {
    server_fixture_t() : server_fixture_t(slop::core::mcp::server_config_t{}) {}
    explicit server_fixture_t(slop::core::mcp::server_config_t cfg) {
        cfg.port = 0;   // ephemeral
        REQUIRE(slop::core::mcp::start(cfg));
        port_ = slop::core::mcp::port();
        REQUIRE_GT(port_, 0);
        cli_ = std::make_unique<httplib::Client>("127.0.0.1", port_);
        cli_->set_connection_timeout(std::chrono::seconds(2));
#ifdef SLOP_ASAN
        // ASan analysis is ~4x slower; a 10 s read timeout trips on the
        // analysis-heavy tools before the server can answer.
        cli_->set_read_timeout(std::chrono::seconds(60));
        cli_->set_write_timeout(std::chrono::seconds(60));
#else
        cli_->set_read_timeout(std::chrono::seconds(10));
        cli_->set_write_timeout(std::chrono::seconds(10));
#endif
    }
    ~server_fixture_t() {
        // Close the client socket before joining server workers. Reversing
        // this order can leave stop() waiting on a worker that is itself
        // waiting for this still-live client connection to close
        if (cli_) {
            cli_->stop();
            cli_.reset();
        }
        slop::core::mcp::stop();
    }

    json rpc(const std::string& method, const json& params = json::object()) {
        json req = {{"jsonrpc", "2.0"}, {"id", 42}, {"method", method}};
        if (!params.is_null()) req["params"] = params;
        auto res = cli_->Post("/mcp", req.dump(), "application/json");
        REQUIRE(res);
        if (res->status != 200)
            std::printf("  [rpc %s] status=%d body=%.400s\n",
                        method.c_str(), res->status, res->body.c_str());
        REQUIRE_EQ(res->status, 200);
        return json::parse(res->body);
    }

    // /api helper (the UI channel; the only one allowed to reach `app`)
    json api(const std::string& tool, const std::string& action,
             const json& params = json::object()) {
        json req = {{"tool", tool}, {"action", action}};
        if (!params.empty()) req["params"] = params;
        auto res = cli_->Post("/api", req.dump(), "application/json");
        REQUIRE(res);
        return json::parse(res->body);
    }

    // tools/call helper then returns the parsed payload + error flag
    json call(const std::string& tool, const json& args, bool& is_error) {
        json res = rpc("tools/call", {{"name", tool}, {"arguments", args}});
        REQUIRE(res.contains("result"));
        is_error = res.at("result").value("isError", false);
        const auto& content = res.at("result").at("content");
        REQUIRE(!content.empty());
        return json::parse(content.at(0).at("text").get<std::string>());
    }

    uint16_t port() const { return port_; }

    uint16_t port_ = 0;
    std::unique_ptr<httplib::Client> cli_;
};

} // namespace

TEST_CASE(mcp_initialize_handshake) {
    server_fixture_t fx;
    json res = fx.rpc("initialize");
    REQUIRE(res.contains("result"));
    REQUIRE_STR_EQ(res.at("result").at("protocolVersion").get<std::string>(), "2025-06-18");
    REQUIRE_STR_EQ(res.at("result").at("serverInfo").at("name").get<std::string>(), "slopstation");
    REQUIRE(res.at("result").at("capabilities").contains("tools"));

    // Session context rides the handshake: the agent knows what the app has
    // attached / loaded without probing
    const json& st = res.at("result").at("state");
    REQUIRE(st.contains("backend"));
    REQUIRE(st.at("target").contains("attached"));
    REQUIRE(st.at("image").contains("ready"));
    REQUIRE(st.contains("debugger"));   // live debug sessions are visible up front

    // Server-level usage guidance: non-empty, and it points at the two
    // status actions an agent should open with
    const std::string instructions =
        res.at("result").at("instructions").get<std::string>();
    REQUIRE(!instructions.empty());
    REQUIRE(instructions.find("target.status") != std::string::npos);
    REQUIRE(instructions.find("disasm.loaded") != std::string::npos);
}

TEST_CASE(mcp_unknown_action_errors_enumerate_actions) {
    server_fixture_t fx;
    bool is_error = false;

    // A mistyped action must carry the valid set so the agent self-corrects
    // in one round trip instead of re-fetching tools/list
    json payload = fx.call("target", {{"action", "lst"}}, is_error);
    REQUIRE(is_error);
    const std::string err = payload.at("error").get<std::string>();
    REQUIRE(err.find("list") != std::string::npos);
    REQUIRE(err.find("attach") != std::string::npos);
    REQUIRE(err.find("dump_module") != std::string::npos);

    payload = fx.call("memory", {{"action", "reed"}}, is_error);
    REQUIRE(is_error);
    REQUIRE(payload.at("error").get<std::string>().find("scan") !=
            std::string::npos);

    payload = fx.call("disasm", {{"action", "fnuctions"}}, is_error);
    REQUIRE(is_error);
    REQUIRE(payload.at("error").get<std::string>().find("functions") !=
            std::string::npos);

    payload = fx.call("debugger", {{"action", "brk"}}, is_error);
    REQUIRE(is_error);
    REQUIRE(payload.at("error").get<std::string>().find("ps4_") !=
            std::string::npos);

    payload = fx.call("fs", {{"action", "sve"}}, is_error);
    REQUIRE(is_error);
    REQUIRE(payload.at("error").get<std::string>().find("write_file") !=
            std::string::npos);
}

TEST_CASE(mcp_ping_and_health) {
    server_fixture_t fx;
    json res = fx.rpc("ping");
    REQUIRE(res.contains("result"));

    auto health = fx.cli_->Get("/health");
    REQUIRE(health);
    REQUIRE_EQ(health->status, 200);
    json h = json::parse(health->body);
    REQUIRE_EQ(h.value("ok", false), true);
}

TEST_CASE(mcp_tools_list_consolidated) {
    server_fixture_t fx;
    json res = fx.rpc("tools/list");
    const auto& tools = res.at("result").at("tools");
    REQUIRE_EQ(tools.size(), 22u);

    bool seen_target = false, seen_memory = false, seen_disasm = false,
         seen_debugger = false,
         seen_emulate = false, seen_analyze = false,
         seen_network = false, seen_proxy = false,
         seen_persist = false, seen_re = false, seen_script = false,
         seen_decomp = false, seen_xray = false,
         seen_patch = false,
         seen_types = false, seen_notes = false, seen_devirt = false,
         seen_guide = false, seen_host = false, seen_gdb = false;
    for (const auto& t : tools) {
        const std::string n = t.at("name").get<std::string>();
        if (n == "target")   seen_target = true;
        if (n == "memory")   seen_memory = true;
        if (n == "disasm")   seen_disasm = true;
        if (n == "debugger") seen_debugger = true;
        if (n == "emulate")  seen_emulate = true;
        if (n == "analyze")  seen_analyze = true;
        if (n == "network")  seen_network = true;
        if (n == "proxy")    seen_proxy = true;
        if (n == "persist")  seen_persist = true;
        if (n == "re")       seen_re = true;
        if (n == "script")   seen_script = true;
        if (n == "decomp")   seen_decomp = true;
        if (n == "xray")     seen_xray = true;
        if (n == "patch")    seen_patch = true;
        if (n == "types")    seen_types = true;
        if (n == "notes")    seen_notes = true;
        if (n == "devirt")   seen_devirt = true;
        if (n == "guide")    seen_guide = true;
        if (n == "host")     seen_host = true;
        if (n == "gdb")      seen_gdb = true;
        REQUIRE(t.contains("inputSchema"));
        REQUIRE(t.contains("description"));
        REQUIRE(t.at("description").is_string());
        REQUIRE_GT(t.at("description").get<std::string>().size(), 120u);
        const auto& schema = t.at("inputSchema");
        REQUIRE_STR_EQ(schema.at("type").get<std::string>(), "object");
        REQUIRE(schema.at("properties").contains("action"));
        REQUIRE(schema.at("properties").at("action").contains("enum"));
        REQUIRE(!schema.at("properties").at("action").at("enum").empty());
        REQUIRE(std::find(schema.at("required").begin(), schema.at("required").end(), "action") !=
                schema.at("required").end());
    }
    REQUIRE(seen_target);
    REQUIRE(seen_memory);
    REQUIRE(seen_disasm);
    REQUIRE(seen_debugger);
    REQUIRE(seen_emulate);
    REQUIRE(seen_analyze);
    REQUIRE(seen_network);
    REQUIRE(seen_proxy);
    REQUIRE(seen_persist);
    REQUIRE(seen_re);
    REQUIRE(seen_script);
    REQUIRE(seen_decomp);
    REQUIRE(seen_xray);
    REQUIRE(seen_patch);
    REQUIRE(seen_types);
    REQUIRE(seen_notes);
    REQUIRE(seen_devirt);
    REQUIRE(seen_guide);
    REQUIRE(seen_host);
    REQUIRE(seen_gdb);
}
TEST_CASE(mcp_devirt_exposes_themida_sidecars) {
    server_fixture_t fx;
    bool is_error = false;
    const json payload = fx.call("devirt", {{"action", "themida_status"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_STR_EQ(payload.at("engine").get<std::string>(), "Magicmida");
    REQUIRE(payload.contains("x86_available"));
    REQUIRE(payload.contains("x64_available"));
    REQUIRE(payload.contains("x64_scyllahide_available"));

    json tools = json::array();
    slop::core::mcp::list_tools(tools);
    const auto it = std::find_if(tools.begin(), tools.end(), [](const json& tool) {
        return tool.at("name") == "devirt";
    });
    REQUIRE(it != tools.end());
    const auto& actions = it->at("inputSchema").at("properties").at("action").at("enum");
    REQUIRE(std::find(actions.begin(), actions.end(), "themida_start") != actions.end());
}

TEST_CASE(mcp_tool_descriptions_expose_workflow_context) {
    json tools = json::array();
    slop::core::mcp::list_tools(tools);

    const auto description = [&tools](const std::string& name) {
        const auto it = std::find_if(tools.begin(), tools.end(), [&name](const json& tool) {
            return tool.at("name").get<std::string>() == name;
        });
        REQUIRE(it != tools.end());
        return it->at("description").get<std::string>();
    };

    REQUIRE(description("target").find("ps4_auto") != std::string::npos);
    REQUIRE(description("memory").find("attached") != std::string::npos);
    REQUIRE(description("disasm").find("hype.ready") != std::string::npos);
    REQUIRE(description("debugger").find("ps4_wait") != std::string::npos);
    REQUIRE(description("network").find("capture_start") != std::string::npos);
    REQUIRE(description("guide").find("PS4") != std::string::npos);
    REQUIRE(description("patch").find("does not patch live target memory") != std::string::npos);
    REQUIRE(description("decomp").find("function-start addr") != std::string::npos);
}

TEST_CASE(mcp_unknown_method_and_tool) {
    server_fixture_t fx;
    json res = fx.rpc("bogus/method");
    REQUIRE(res.contains("error"));
    REQUIRE_EQ(res.at("error").at("code").get<int>(), -32601);

    bool is_error = false;
    json payload = fx.call("nope", json::object(), is_error);
    REQUIRE(is_error);
    REQUIRE(payload.contains("error"));
}

TEST_CASE(mcp_parse_error_is_400) {
    server_fixture_t fx;
    auto res = fx.cli_->Post("/mcp", "{not json", "application/json");
    REQUIRE(res);
    REQUIRE_EQ(res->status, 400);
    json body = json::parse(res->body);
    REQUIRE_EQ(body.at("error").at("code").get<int>(), -32700);
}

TEST_CASE(mcp_tool_errors_without_target) {
    server_fixture_t fx;

    bool is_error = true;
    json payload = fx.call("memory", {{"action", "read"}, {"addr", 0x41414141}}, is_error);
    REQUIRE(is_error);
    REQUIRE(payload.contains("error"));

    is_error = false;
    payload = fx.call("memory", {{"action", "frobnicate"}}, is_error);
    REQUIRE(is_error);

    is_error = false;
    payload = fx.call("debugger", {{"action", "regs"}}, is_error);
    REQUIRE(is_error);
}
TEST_CASE(mcp_target_status_shape) {
    server_fixture_t fx;
    bool is_error = true;
    json payload = fx.call("target", {{"action", "status"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("backend"));
    REQUIRE(payload.contains("attached"));
    REQUIRE_EQ(payload.value("attached", true), false);

    // Loaded-image state rides status too
    REQUIRE(payload.contains("image"));
    REQUIRE_EQ(payload.at("image").value("ready", true), false);

    // And it reflects the shared session the moment a binary is loaded
    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    payload = fx.call("target", {{"action", "status"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.at("image").value("ready", false), true);
    REQUIRE_GT(payload.at("image").value("functions", 0u), 0u);
    REQUIRE(!std::string(payload.at("image").value("name", "")).empty());
    slop::core::disasm::binary_state::unload();
}

TEST_CASE(mcp_ps4_send_payload_streams_the_file) {
    slop::core::network::sock::ensure_wsa();
    SOCKET srv = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(srv != INVALID_SOCKET);
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;
    REQUIRE(::bind(srv, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    REQUIRE(::listen(srv, 1) == 0);
    int alen = sizeof(addr);
    REQUIRE(::getsockname(srv, reinterpret_cast<sockaddr*>(&addr), &alen) == 0);
    const uint16_t port = ntohs(addr.sin_port);

    std::vector<uint8_t> got;
    std::thread reader([&] {
        SOCKET c = ::accept(srv, nullptr, nullptr);
        if (c == INVALID_SOCKET) return;
        char buf[8192];
        for (;;) {
            const int n = ::recv(c, buf, sizeof(buf), 0);
            if (n <= 0) break;
            got.insert(got.end(), buf, buf + n);
        }
        ::closesocket(c);
    });

    const auto path =
        std::filesystem::temp_directory_path() / "slop_payload_send_test.bin";
    std::vector<uint8_t> payload(64 * 1024);
    for (size_t i = 0; i < payload.size(); ++i)
        payload[i] = static_cast<uint8_t>((i * 31) & 0xFF);
    {
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(payload.data()),
                  static_cast<std::streamsize>(payload.size()));
    }

    server_fixture_t fx;
    bool is_error = true;
    json res = fx.call("target",
                       {{"action", "ps4_send_payload"},
                        {"host", "127.0.0.1"},
                        {"port", port},
                        {"path", path.string()}},
                       is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(res.value("bytes", 0ull), payload.size());
    reader.join();
    ::closesocket(srv);
    std::filesystem::remove(path);
    REQUIRE_EQ(got.size(), payload.size());
    REQUIRE(std::equal(got.begin(), got.end(), payload.begin()));
}

TEST_CASE(mcp_bad_action_rejected) {
    server_fixture_t fx;
    bool is_error = false;
    json payload = fx.call("target", {{"action", "explode"}}, is_error);
    REQUIRE(is_error);
    REQUIRE(payload.contains("error"));

    is_error = false;
    payload = fx.call("disasm", {}, is_error);
    REQUIRE(is_error);
}

TEST_CASE(mcp_server_stop_is_clean) {
    {
        server_fixture_t fx;
        json res = fx.rpc("ping");
        REQUIRE(res.contains("result"));
    }
    REQUIRE(!slop::core::mcp::running());
    // Restart on the same ephemeral flow must still work
    server_fixture_t fx2;
    json res = fx2.rpc("ping");
    REQUIRE(res.contains("result"));
}

// === loaded-file visibility (UI session shared with MCP) ===

namespace {

std::vector<uint8_t>& slop_target_bytes() {
    static std::vector<uint8_t> bytes = [] {
        std::ifstream f(SLOP_TARGET_EXE_PATH, std::ios::binary);
        return std::vector<uint8_t>(std::istreambuf_iterator<char>(f),
                                    std::istreambuf_iterator<char>{});
    }();
    return bytes;
}

} // namespace

TEST_CASE(mcp_disasm_loaded_reports_state) {
    server_fixture_t fx;
    bool is_error = true;

    // Nothing loaded yet: not an error, just ready=false + hint
    json payload = fx.call("disasm", {{"action", "loaded"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("ready", true), false);
    REQUIRE(payload.contains("hint"));
    // Target context rides along so one call shows both halves of the session
    REQUIRE(payload.contains("target"));
    REQUIRE_EQ(payload.at("target").value("attached", true), false);

    // Load the fixture through the shared core state, as the UI would
    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    payload = fx.call("disasm", {{"action", "loaded"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("ready", false), true);
    REQUIRE(payload.contains("path"));
    REQUIRE(payload.contains("base"));
    REQUIRE_GT(payload.value("functions", 0u), 0u);
    REQUIRE_GE(payload.value("sections", 0u), 3u);

    slop::core::disasm::binary_state::unload();
    payload = fx.call("disasm", {{"action", "loaded"}}, is_error);
    REQUIRE_EQ(payload.value("ready", true), false);
}

TEST_CASE(mcp_disasm_static_actions_use_loaded_binary) {
    server_fixture_t fx;
    bool is_error = false;

    // No path, nothing loaded -> actionable error
    json payload = fx.call("disasm", {{"action", "pe"}}, is_error);
    REQUIRE(is_error);

    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));

    // Every static action now works with zero arguments
    payload = fx.call("disasm", {{"action", "pe"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("ok", false), true);
    REQUIRE_GE(payload.at("sections").size(), 3u);

    payload = fx.call("disasm", {{"action", "functions"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GT(payload.value("total", 0u), 0u);
    REQUIRE(!payload.at("functions").empty());

    payload = fx.call("disasm", {{"action", "strings"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GT(payload.value("total_scanned", 0u), 0u);

    slop::core::disasm::binary_state::unload();

    // Explicit path still takes the private-cache route
    payload = fx.call("disasm", {{"action", "pe"}, {"path", SLOP_TARGET_EXE_PATH}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("ok", false), true);
}

TEST_CASE(mcp_disasm_symbols_roundtrip_and_file_disassemble) {
    server_fixture_t fx;
    bool is_error = true;

    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));

    json loaded = fx.call("disasm", {{"action", "loaded"}}, is_error);
    REQUIRE_EQ(loaded.value("ready", false), true);
    const uint64_t base     = loaded.at("base").get<uint64_t>();
    const uint64_t entry_va = loaded.value("entry_va", base);

    // Rename a function over MCP; it must come back through symbols list
    json res = fx.call("disasm", {{"action", "symbol_set"},
                                  {"addr", entry_va}, {"name", "ai_entry_point"}},
                       is_error);
    REQUIRE(!is_error);
    REQUIRE(res.value("cleared", true) == false);

    res = fx.call("disasm", {{"action", "symbols"}}, is_error);
    REQUIRE(!is_error);
    bool found = false;
    for (const auto& s : res.at("symbols")) {
        if (s.value("va", 0ull) == entry_va && s.value("name", "") == "ai_entry_point")
            found = true;
    }
    REQUIRE(found);

    // The rename must surface in functions output too (shared session)
    res = fx.call("disasm", {{"action", "functions"}, {"limit", 10000}}, is_error);
    REQUIRE(!is_error);
    found = false;
    for (const auto& f : res.at("functions")) {
        if (f.value("va", 0ull) == entry_va)
            found = f.value("symbol", "") == "ai_entry_point";
    }
    REQUIRE(found);

    // File-backed disassembly with NO attached target: entry point decodes
    res = fx.call("disasm", {{"action", "disassemble"}, {"addr", entry_va}, {"count", 8}},
                  is_error);
    REQUIRE(!is_error);
    REQUIRE_GT(res.value("count", 0u), 0u);
    REQUIRE(!res.at("instructions").empty());

    // Clearing via empty name
    res = fx.call("disasm", {{"action", "symbol_set"}, {"addr", entry_va}, {"name", ""}},
                  is_error);
    REQUIRE(!is_error);
    REQUIRE(res.value("cleared", false) == true);

    slop::core::disasm::binary_state::unload();
}

TEST_CASE(mcp_volt_regressions_arg_aliases_limits_assemble) {
    // Issues 1-5 + 14-15: base/addr aliases, apihash names, honored limits,
    // multi-instruction assemble, devirt guidance, predicate/iat counters.
    server_fixture_t fx;
    bool is_error = true;

    // assemble needs no image: "xor eax, eax; ret" is 31 C0 C3
    json res = fx.call("disasm", {{"action", "assemble"},
                                  {"text", "xor eax, eax; ret"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(res.value("length", 0u), 3u);
    REQUIRE_STR_EQ(res.value("bytes", "").c_str(), "31c0c3");

    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    json loaded = fx.call("disasm", {{"action", "loaded"}}, is_error);
    REQUIRE_EQ(loaded.value("ready", false), true);
    const uint64_t base = loaded.at("base").get<uint64_t>();
    const uint64_t entry_va = loaded.value("entry_va", base);

    // xray.entropy accepts base= alias + honors limit as window cap
    res = fx.call("xray", {{"action", "entropy"}, {"base", base},
                           {"size", 4096}, {"window_size", 256},
                           {"limit", 5}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(res.contains("overall_entropy"));
    REQUIRE_LE(res.at("windows").size(), 5u);
    REQUIRE(res.contains("total_windows"));

    // xray.pages honors limit
    res = fx.call("xray", {{"action", "pages"}, {"base", base},
                           {"size", 8192}, {"limit", 2}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_LE(res.at("pages").size(), 2u);
    REQUIRE(res.contains("total_pages"));

    // xray.apihash accepts plain API names (hashed with the algorithm)
    res = fx.call("xray", {{"action", "apihash"},
                           {"hashes", {"LoadLibraryA", "GetProcAddress"}}},
                  is_error);
    REQUIRE(!is_error);
    REQUIRE(res.contains("name_inputs"));
    REQUIRE_EQ(res.at("name_inputs").size(), 2u);

    // disasm.xrefs honors limit
    res = fx.call("disasm", {{"action", "xrefs"}, {"addr", entry_va},
                             {"limit", 5}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_LE(res.at("refs_to").size(), 5u);
    REQUIRE(res.contains("total"));

    // devirt.trace without handlers: structured guidance, not bare "missing"
    res = fx.call("devirt", {{"action", "trace"}, {"addr", entry_va}},
                  is_error);
    REQUIRE(is_error);
    REQUIRE(res.at("error").get<std::string>().find("handler_table") !=
            std::string::npos);

    // devirt.handlers accepts addr= as a table alias (clean entry has no
    // valid table, but the error must come from classification, not arg parse)
    res = fx.call("devirt", {{"action", "handlers"}, {"addr", base + 0x400}},
                  is_error);
    REQUIRE(is_error);
    const std::string herr = res.at("error").get<std::string>();
    REQUIRE(herr.find("missing numeric argument") == std::string::npos);

    // prove_predicates reports completed/failed/faulted denominators; it runs
    // the emulator, so it lives in its own case that the ASan lane excludes
    // (see mcp_devirt_prove_predicates_emulate below).

    // iat_audit default audits parsed IAT slots only (no 500k+ overcount)
    res = fx.call("devirt", {{"action", "iat_audit"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GT(res.value("named", 0u), 0u);
    REQUIRE_LE(res.value("slots_scanned", 1000000u),
               res.value("named", 0u) + res.value("unnamed_valid", 0u) +
                   res.value("invalid", 0u));

    slop::core::disasm::binary_state::unload();
}

TEST_CASE(mcp_devirt_prove_predicates_emulate) {
    // Seeded emulation: kept separate from the static volt regressions so the
    // ASan lane (SLOP_TEST_EXCLUDE=emulate) can skip it; Unicorn faults with
    // no ASan report.
    server_fixture_t fx;
    bool is_error = false;
    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    json loaded = fx.call("disasm", {{"action", "loaded"}}, is_error);
    REQUIRE_EQ(loaded.value("ready", false), true);
    const uint64_t base = loaded.at("base").get<uint64_t>();
    const uint64_t entry_va = loaded.value("entry_va", base);
    json res = fx.call("devirt", {{"action", "prove_predicates"},
                                  {"addr", entry_va}, {"runs", 2}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(res.contains("completed_runs"));
    REQUIRE(res.contains("failed_runs"));
    REQUIRE(res.contains("faulted_runs"));
    slop::core::disasm::binary_state::unload();
}

// === new memory / target / debugger surfaces ===

TEST_CASE(mcp_memory_new_actions_shape) {
    server_fixture_t fx;
    bool is_error = false;

    // All need a target; verify clean structured errors, not crashes
    json payload = fx.call("memory", {{"action", "pointerscan"}, {"target", 0x41414141}},
                           is_error);
    REQUIRE(is_error);

    payload = fx.call("memory", {{"action", "snapshot"}, {"addr", 0x41414141}}, is_error);
    REQUIRE(is_error);

    payload = fx.call("memory", {{"action", "diff"}, {"a", 1}, {"b", 2}}, is_error);
    REQUIRE(is_error);

    // Snapshot listing works without a target (empty store)
    payload = fx.call("memory", {{"action", "snapshots"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("count", -1), 0);

    payload = fx.call("memory", {{"action", "snapshot_free"}, {"all", true}}, is_error);
    REQUIRE(!is_error);
}

TEST_CASE(mcp_memory_ce_scan_state_and_validation) {
    server_fixture_t fx;
    bool is_error = false;

    json payload = fx.call("memory", {{"action", "scan_reset"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.value("reset", false));

    payload = fx.call("memory", {{"action", "scan_state"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_FALSE(payload.value("active", true));
    REQUIRE(payload.contains("region_scan_active"));
    REQUIRE(payload.contains("slots_tracked"));

    // Handler-level CE argument validation happens before the live scan, but
    // all scan/rescan actions still require an attached target
    payload = fx.call("memory",
                      {{"action", "scan"}, {"kind", "bogus"},
                       {"width", "u32"}, {"value", 1}}, is_error);
    REQUIRE(is_error);

    payload = fx.call("memory",
                      {{"action", "scan"}, {"kind", "exact"},
                       {"width", "u32"}, {"value", 1},
                       {"rounding", "bogus"}}, is_error);
    REQUIRE(is_error);
}

TEST_CASE(mcp_target_handles_needs_session) {
    server_fixture_t fx;
    bool is_error = false;
    json payload = fx.call("target", {{"action", "handles"}}, is_error);
    REQUIRE(is_error);   // no target attached in unit-test environment
    REQUIRE(payload.contains("error"));
}

TEST_CASE(mcp_target_attach_populates_shared_session) {
    server_fixture_t fx;
    bool is_error = true;
    slop::core::disasm::binary_state::unload();   // deterministic start

    // The user-mode backend can open our own process: full round trip with
    // no second host process needed
    json payload = fx.call("target",
                           {{"action", "attach"},
                            {"pid", static_cast<uint64_t>(GetCurrentProcessId())}},
                           is_error);
    if (is_error) return;   // locked-down environment: nothing further to assert

    REQUIRE_EQ(payload.value("attached", false), true);
    // Main module was readable from disk -> shared session auto-populated
    REQUIRE_EQ(payload.value("image_auto_loaded", false), true);
    REQUIRE(payload.contains("image"));
    REQUIRE_EQ(payload.at("image").value("ready", false), true);
    REQUIRE_GT(payload.at("image").value("functions", 0u), 0u);

    // Static tools now see it with zero arguments, no explicit 'path'
    payload = fx.call("disasm", {{"action", "functions"}, {"limit", 10}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(!payload.at("functions").empty());
    REQUIRE(!std::string(payload.value("image", "")).empty());

    // Never leak the session into later tests
    payload = fx.call("target", {{"action", "detach"}}, is_error);
    REQUIRE(!is_error);
    slop::core::disasm::binary_state::unload();
}
TEST_CASE(mcp_schemas_expose_new_actions) {
    server_fixture_t fx;
    json res = fx.rpc("tools/list");
    const auto& tools = res.at("result").at("tools");

    auto enum_of = [](const json& tools, const char* name) -> json {
        for (const auto& t : tools)
            if (t.at("name") == name)
                return t.at("inputSchema").at("properties").at("action").at("enum");
        return json::array();
    };

    const json mem = enum_of(tools, "memory");
    REQUIRE(std::find(mem.begin(), mem.end(), "pointerscan") != mem.end());
    REQUIRE(std::find(mem.begin(), mem.end(), "snapshot") != mem.end());
    REQUIRE(std::find(mem.begin(), mem.end(), "diff") != mem.end());
    REQUIRE(std::find(mem.begin(), mem.end(), "scan_state") != mem.end());
    REQUIRE(std::find(mem.begin(), mem.end(), "scan_reset") != mem.end());

    const json* mem_tool = nullptr;
    for (const auto& t : tools)
        if (t.at("name") == "memory") mem_tool = &t;
    REQUIRE(mem_tool != nullptr);
    if (mem_tool) {
        const auto& props = mem_tool->at("inputSchema").at("properties");
        const auto& kinds = props.at("kind").at("enum");
        const auto& widths = props.at("width").at("enum");
        const auto& rounding = props.at("rounding").at("enum");
        REQUIRE(std::find(kinds.begin(), kinds.end(), "between") != kinds.end());
        REQUIRE(std::find(kinds.begin(), kinds.end(), "increased_percent") != kinds.end());
        REQUIRE(std::find(kinds.begin(), kinds.end(), "decreased_percent") != kinds.end());
        REQUIRE(std::find(widths.begin(), widths.end(), "all") != widths.end());
        REQUIRE(std::find(rounding.begin(), rounding.end(), "truncated") != rounding.end());
        REQUIRE(props.contains("tail"));
        REQUIRE(props.contains("copy_on_write"));
        REQUIRE(props.contains("static_roots"));
        REQUIRE(props.contains("frontier_cap"));
    }

    const json tgt = enum_of(tools, "target");
    REQUIRE(std::find(tgt.begin(), tgt.end(), "handles") != tgt.end());

    // PS4 live-debug + host-side capture surfaces are declared
    const json dbg = enum_of(tools, "debugger");
    REQUIRE(std::find(dbg.begin(), dbg.end(), "ps4_attach") != dbg.end());
    REQUIRE(std::find(dbg.begin(), dbg.end(), "ps4_bp_set") != dbg.end());
    REQUIRE(std::find(dbg.begin(), dbg.end(), "ps4_wait") != dbg.end());
    REQUIRE(std::find(dbg.begin(), dbg.end(), "ps4_find_write") != dbg.end());

    const json net = enum_of(tools, "network");
    REQUIRE(std::find(net.begin(), net.end(), "capture_start") != net.end());
    REQUIRE(std::find(net.begin(), net.end(), "deep_inspect") != net.end());

    const json dis = enum_of(tools, "disasm");
    bool ok = false;
    ok |= std::find(dis.begin(), dis.end(), "loaded") != dis.end();
    ok |= std::find(dis.begin(), dis.end(), "symbols") != dis.end();
    ok |= std::find(dis.begin(), dis.end(), "symbol_set") != dis.end();
    REQUIRE(ok);
}

// === emulate + analyze over the wire ===

TEST_CASE(mcp_emulate_run_hex_payload) {
    server_fixture_t fx;
    bool is_error = true;

    // mov eax,2 / add eax,3 / ret
    json payload = fx.call("emulate",
                           {{"action", "run"},
                            {"hex", "B80200000083C003C3"}},
                           is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("ok", false), true);
    REQUIRE_STR_EQ(payload.value("stopped_reason", "").c_str(), "return");
    REQUIRE_EQ(payload.value("instructions", 0u), 3u);

    const auto& regs = payload.at("regs");
    REQUIRE(regs.is_object());
    bool saw_rax5 = false;
    for (auto it = regs.begin(); it != regs.end(); ++it)
        if (it.key() == "rax" && it.value() == 5) saw_rax5 = true;
    REQUIRE(saw_rax5);
}

TEST_CASE(mcp_emulate_taint_over_http) {
    server_fixture_t fx;
    bool is_error = true;

    // mov edx,[0x500000] / xor eax,eax / add eax,edx / mov [0x500200],eax / ret
    json payload = fx.call(
        "emulate",
        {{"action", "run"},
         {"hex", "8B14250000500031C001D089042500025000C3"},
         {"maps", json::array({json{{"addr", 0x500000},
                                    {"hex", std::string(0x600, 'A')}}})},
         {"taint", json::array({json{{"addr", 0x500000}, {"len", 4}}})},
         {"watch_addr", 0x500200},
         {"watch_len", 4}},
        is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.value("output_tainted", false) == true);
    REQUIRE(!payload.at("taint_events").empty());
}

TEST_CASE(mcp_emulate_rejects_bad_input) {
    server_fixture_t fx;
    bool is_error = false;
    json payload = fx.call("emulate", {{"action", "run"}}, is_error);
    REQUIRE(is_error);                       // no code source
    payload = fx.call("emulate", {{"action", "explode"}}, is_error);
    REQUIRE(is_error);                       // unknown action
}

TEST_CASE(mcp_emulate_file_addr_runs_past_the_slice_on_rebased_image) {
    // Entry stub is sub rsp / call __security_init_cookie / add rsp / jmp:
    // the old 64-byte window died on the first far branch. Rebased, the
    // file_addr lookup has to use the session base and the pages need base
    // relocations, so the run must match one at the preferred ImageBase
    namespace ds = slop::core::disasm::binary_state;
    server_fixture_t fx;
    auto run_entry = [&](uint64_t base_override, const json& extra) {
        REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH, base_override));
        uint64_t base = 0, entry = 0, preferred = 0, size = 0;
        {
            std::lock_guard lk(ds::state_mutex());
            base      = ds::get().base;
            entry     = base + ds::get().pe.entry_rva;
            preferred = ds::get().pe.image_base;
            size      = ds::get().pe.size_of_image;
        }
        json args = {{"action", "run"}, {"file_addr", entry}, {"count", 20000},
                     {"dump", json::array({json{{"addr", base}, {"len", 2}}})}};
        args.update(extra);
        bool is_error = true;
        json payload = fx.call("emulate", args, is_error);
        ds::unload();
        REQUIRE(!is_error);
        // an un-relocated pointer would send the run into the ImageBase copy
        if (base != preferred && payload.contains("fault")) {
            const uint64_t at = payload.at("fault").value("addr", 0ull);
            REQUIRE(at < preferred || at >= preferred + size);
        }
        return std::make_pair(base, payload);
    };

    constexpr uint64_t kBase = 0x7FF612340000ull;
    const auto [base, rebased] = run_entry(kBase, json::object());
    REQUIRE_EQ(base, kBase);
    REQUIRE_GT(rebased.value("instructions", 0u), 50u);
    REQUIRE_GT(rebased.value("paged_in", 0u), 0u);
    REQUIRE_GT(rebased.value("total_api_calls", 0u), 0u);
    const auto& calls = rebased.at("api_calls");
    REQUIRE(!calls.empty());
    REQUIRE(calls.at(0).value("name", "").find('!') != std::string::npos);
    REQUIRE_GE(calls.at(0).value("ip", 0ull), kBase);
    REQUIRE(rebased.at("regs").contains("gs_base"));
    // the headers page comes back through the image source
    REQUIRE_STR_EQ(rebased.at("memory").at(0).value("hex", "").c_str(), "4d5a");

    const auto [pref_base, preferred] = run_entry(0, json::object());
    REQUIRE(pref_base != kBase);
    REQUIRE_EQ(preferred.value("instructions", 0u), rebased.value("instructions", 1u));
    REQUIRE_EQ(preferred.value("total_api_calls", 0u), rebased.value("total_api_calls", 1u));
    REQUIRE_STR_EQ(preferred.value("stopped_reason", "").c_str(),
                   rebased.value("stopped_reason", "?").c_str());

    // per-import returns, unmatched keys reported back. The CRT's security
    // cookie init calls a critical-section import whose exact name depends on
    // the toolset (InitializeCriticalSectionAndSpinCount on older CRTs,
    // InitializeCriticalSectionEx on current ones), so take the name from the
    // image's own import table instead of hard-coding it
    std::string cs_init = "InitializeCriticalSectionEx";
    {
        REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH, kBase));
        {
            std::lock_guard lk(ds::state_mutex());
            for (const auto& dll : ds::get().pe.imports)
                for (const auto& fn : dll.functions)
                    if (!fn.by_ordinal &&
                        fn.name.find("InitializeCriticalSection") != std::string::npos)
                        cs_init = fn.name;
        }
        ds::unload();
    }
    const auto [b2, tuned] = run_entry(kBase, {{"api_returns",
        {{cs_init, 1}, {"nope.dll!Missing", -1}}}});
    REQUIRE_EQ(tuned.at("api_returns_unmatched").size(), 1u);
    REQUIRE_STR_EQ(tuned.at("api_returns_unmatched").at(0).get<std::string>().c_str(),
                   "nope.dll!missing");
    // with critical-section init succeeding the CRT goes on past its failure path
    REQUIRE_GT(tuned.value("total_api_calls", 0u), rebased.value("total_api_calls", 0u));

    // page_in=false keeps the old slice-only behavior
    const auto [b3, slice] = run_entry(kBase, {{"code_len", 16}, {"page_in", false},
                                               {"stub_imports", false}});
    REQUIRE(!slice.contains("paged_in"));
    REQUIRE(!slice.contains("api_calls"));
    REQUIRE(slice.contains("fault"));
}

TEST_CASE(mcp_emulate_runs_unlocked_and_honors_cancel) {
    using clock = std::chrono::steady_clock;
    auto ms_since = [](clock::time_point t) {
        return std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - t).count();
    };
    server_fixture_t fx;

    // jmp $ with a 20 s budget on its own connection, request id 777
    json emu_reply;
    std::atomic<bool> emu_done{false};
    std::thread runner([&] {
        httplib::Client cli("127.0.0.1", fx.port());
        cli.set_read_timeout(std::chrono::seconds(40));
        const json req = {
            {"jsonrpc", "2.0"}, {"id", 777}, {"method", "tools/call"},
            {"params", {{"name", "emulate"},
                        {"arguments", {{"action", "run"}, {"hex", "EBFE"},
                                       {"count", 1ull << 40}, {"timeout_ms", 20000}}}}}};
        if (auto res = cli.Post("/mcp", req.dump(), "application/json");
            res && res->status == 200)
            emu_reply = json::parse(res->body, nullptr, false);
        emu_done = true;
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Another tool must answer while the emulation is still running
    const json status_req = {{"jsonrpc", "2.0"}, {"id", 1}, {"method", "tools/call"},
                             {"params", {{"name", "target"},
                                         {"arguments", {{"action", "status"}}}}}};
    const auto status_t0 = clock::now();
    auto status_res = fx.cli_->Post("/mcp", status_req.dump(), "application/json");
    const auto status_ms = ms_since(status_t0);
    const bool status_ok = status_res && status_res->status == 200;
    const bool emu_running_during_status = !emu_done.load();

    // notifications/cancelled for id 777 must stop the run early; resend until
    // it lands so a slow registration on the runner thread cannot race the test
    const json cancel = {{"jsonrpc", "2.0"}, {"method", "notifications/cancelled"},
                         {"params", {{"requestId", 777}, {"reason", "test"}}}};
    const auto cancel_t0 = clock::now();
    while (!emu_done.load() && ms_since(cancel_t0) < 10000) {
        fx.cli_->Post("/mcp", cancel.dump(), "application/json");
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    runner.join();
    const auto cancel_ms = ms_since(cancel_t0);

    REQUIRE(status_ok);
    REQUIRE(emu_running_during_status);
    REQUIRE_LT(status_ms, 2000);
    REQUIRE(emu_reply.is_object() && emu_reply.contains("result"));
    const json payload = json::parse(
        emu_reply.at("result").at("content").at(0).at("text").get<std::string>());
    REQUIRE_STR_EQ(payload.value("stopped_reason", "").c_str(), "cancelled");
    REQUIRE_LT(cancel_ms, 5000);
}

TEST_CASE(mcp_analyze_packer_on_loaded_image) {
    server_fixture_t fx;
    bool is_error = false;

    // Nothing loaded: actionable error, not a crash
    json payload = fx.call("analyze", {{"action", "packer"}}, is_error);
    REQUIRE(is_error);

    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    payload = fx.call("analyze", {{"action", "packer"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("image"));
    REQUIRE_EQ(payload.value("packed", true), false);   // clean MSVC build
    REQUIRE(payload.value("confidence", 1.0) < 0.5);
    slop::core::disasm::binary_state::unload();

    payload = fx.call("analyze",
                      {{"action", "packer"}, {"path", SLOP_TARGET_EXE_PATH}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("sections"));
}

TEST_CASE(mcp_analyze_signatures_on_loaded_image) {
    server_fixture_t fx;
    bool is_error = false;

    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    json payload = fx.call("analyze", {{"action", "signatures"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("signatures"));
    REQUIRE(payload.contains("count"));

    // Explicit path route works too
    payload = fx.call("analyze",
                      {{"action", "signatures"}, {"path", SLOP_TARGET_EXE_PATH}},
                      is_error);
    REQUIRE(!is_error);
    slop::core::disasm::binary_state::unload();
}



// === network / proxy / persist / re / script surfaces ===

TEST_CASE(mcp_network_shape_host_side_store) {
    server_fixture_t fx;
    bool is_error = false;

    json payload = fx.call("network", {{"action", "status"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("capture_running"));
    REQUIRE(payload.contains("store_packets"));
    REQUIRE(payload.contains("proxy_running"));

    // Store-backed actions work with no capture running
    payload = fx.call("network", {{"action", "packets"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("count", -1), 0);

    payload = fx.call("network", {{"action", "streams"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("count", -1), 0);

    payload = fx.call("network",
                      {{"action", "stream_data"}, {"id", 999}}, is_error);
    REQUIRE(is_error);   // unknown stream

    payload = fx.call("network", {{"action", "dns"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("count"));

    payload = fx.call("network", {{"action", "stats"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("capture_active"));
    REQUIRE(payload.contains("store_packets"));

    payload = fx.call("network", {{"action", "reassemble_stream"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("packets", ~0u), 0u);

    payload = fx.call("network", {{"action", "connections"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("count", -1), 0);

    payload = fx.call("network", {{"action", "deep_inspect"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("count", -1), 0);

    payload = fx.call("network", {{"action", "frobnicate"}}, is_error);
    REQUIRE(is_error);
}

TEST_CASE(mcp_proxy_lifecycle_and_entries) {
    server_fixture_t fx;
    bool is_error = false;

    json payload = fx.call("proxy", {{"action", "start"}, {"port", 0}},
                           is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("running", false), true);
    const uint64_t port = payload.value("port", 0u);
    REQUIRE_GT(port, 0);

    payload = fx.call("proxy", {{"action", "entries"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("entries"));

    payload = fx.call("proxy", {{"action", "stop"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("running", true), false);
}

TEST_CASE(mcp_persist_roundtrip) {
    server_fixture_t fx;
    bool is_error = false;

    json payload = fx.call(
        "persist",
        {{"action", "save"}, {"name", "mcp_test_session"},
         {"data", json{{"pid", 4242}, {"note", "hello"}}}},
        is_error);
    REQUIRE(!is_error);
    const uint64_t id = payload.value("id", 0ull);
    REQUIRE_GT(id, 0ull);

    payload = fx.call("persist", {{"action", "list"}}, is_error);
    REQUIRE(!is_error);
    bool found = false;
    for (const auto& s : payload.at("sessions"))
        if (s.value("name", "") == "mcp_test_session") found = true;
    REQUIRE(found);

    payload = fx.call("persist", {{"action", "load"}, {"id", id}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_STR_EQ(payload.at("data").at("note").get<std::string>().c_str(),
                   "hello");

    payload = fx.call("persist", {{"action", "delete"}, {"id", id}},
                      is_error);
    REQUIRE(!is_error);

    payload = fx.call("persist", {{"action", "load"}, {"id", id}}, is_error);
    REQUIRE(is_error);   // deleted

    // kv helpers
    payload = fx.call("persist",
                      {{"action", "kv_set"}, {"key", "k"},
                       {"value", json{{"x", 1}}}},
                      is_error);
    REQUIRE(!is_error);
    payload = fx.call("persist", {{"action", "kv_get"}, {"key", "k"}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.at("value").at("x").get<int>(), 1);
}

TEST_CASE(mcp_re_actions_on_loaded_image) {
    server_fixture_t fx;
    bool is_error = false;

    // No image loaded: actionable error
    json payload = fx.call("re", {{"action", "rtti_scan"}}, is_error);
    REQUIRE(is_error);

    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));

    payload = fx.call("re", {{"action", "rtti_scan"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("classes"));

    payload = fx.call("re", {{"action", "danger"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("hits"));

    payload = fx.call("re",
                      {{"action", "libsig"},
                       {"sigset",
                        R"([{"name":"probe","pattern":"48 89 5C 24 ??","offset":0}])"}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("hits"));

    slop::core::disasm::binary_state::unload();
}

TEST_CASE(mcp_script_run_roundtrip) {
    server_fixture_t fx;
    bool is_error = false;

    json payload = fx.call(
        "script",
        {{"action", "run"}, {"code", "slop.log('answer', 6 * 7)"}},
        is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("ok", false), true);
    REQUIRE(payload.at("output").get<std::string>().find("answer\t42") !=
            std::string::npos);

    // Error path: script failure surfaces as structured output
    payload = fx.call("script",
                      {{"action", "run"}, {"code", "error('nope')"}},
                      is_error);
    REQUIRE(!is_error);   // tool succeeded; script failed inside
    REQUIRE_EQ(payload.value("ok", true), false);
    REQUIRE(payload.at("error").get<std::string>().find("nope") !=
            std::string::npos);

    payload = fx.call("script", {{"action", "explode"}}, is_error);
    REQUIRE(is_error);
}

TEST_CASE(mcp_script_unsafe_needs_per_run_consent) {
    namespace settings = slop::core::infra::settings;
    const std::string old_file = settings::file();
    const auto scratch = (std::filesystem::temp_directory_path() /
                          ("slop_test_mcp_script_unsafe_" +
                           std::to_string(GetCurrentProcessId()) + ".json")).string();
    settings::set_file_for_testing(scratch);
    server_fixture_t fx;
    bool is_error = false;

    // no per-run consent and no admin override: refused before any code runs
    json payload = fx.call("script",
                           {{"action", "run"}, {"code", "return io ~= nil"},
                            {"unsafe", true}},
                           is_error);
    REQUIRE(is_error);
    REQUIRE(payload.at("error").get<std::string>().find("confirm") !=
            std::string::npos);

    // consent opens the full stdlib for that one run
    payload = fx.call("script",
                      {{"action", "run"}, {"code", "return io ~= nil"},
                       {"unsafe", true}, {"confirm", true}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("ok", false), true);
    REQUIRE_EQ(payload.value("sandboxed", true), false);
    REQUIRE(payload.at("output").get<std::string>().find("return: true") !=
            std::string::npos);

    // the next run is sandboxed again: consent does not stick
    payload = fx.call("script", {{"action", "run"}, {"code", "return io ~= nil"}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("sandboxed", false), true);
    REQUIRE(payload.at("output").get<std::string>().find("return: false") !=
            std::string::npos);

    // script_unsafe stays the admin override
    REQUIRE(settings::set("script_unsafe", true));
    payload = fx.call("script",
                      {{"action", "run"}, {"code", "return io ~= nil"},
                       {"unsafe", true}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("sandboxed", true), false);

    settings::set_file_for_testing(old_file);
    std::error_code ec;
    std::filesystem::remove(scratch, ec);
}

TEST_CASE(mcp_script_api_lists_the_surface) {
    server_fixture_t fx;
    bool is_error = false;
    json payload = fx.call("script", {{"action", "api"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("count", size_t{0}),
               slop::core::script::api_entries().size());
    bool saw = false;
    for (const auto& f : payload.at("functions")) {
        REQUIRE(!f.value("signature", "").empty());
        REQUIRE(!f.value("doc", "").empty());
        if (f.value("name", "") == "slop.mem.read_hex") saw = true;
    }
    REQUIRE(saw);
}

TEST_CASE(mcp_script_snippets_roundtrip) {
    namespace fs = std::filesystem;
    namespace paths = slop::core::infra::paths;
    const auto dir = fs::temp_directory_path() /
                     ("slop_mcp_snippets_" + std::to_string(GetCurrentProcessId()));
    fs::remove_all(dir);
    paths::set_app_data_for_testing(dir.string());
    server_fixture_t fx;
    bool is_error = false;

    json payload = fx.call("script",
                           {{"action", "save"}, {"name", "find-value"},
                            {"code", "return 42"}},
                           is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("ok", false), true);

    payload = fx.call("script", {{"action", "list"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.at("snippets").size(), size_t{1});
    REQUIRE_EQ(payload.at("snippets")[0].value("name", ""),
               std::string("find-value"));

    payload = fx.call("script", {{"action", "load"}, {"name", "find-value"}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("code", ""), std::string("return 42"));

    payload = fx.call("script", {{"action", "delete"}, {"name", "find-value"}},
                      is_error);
    REQUIRE(!is_error);
    payload = fx.call("script", {{"action", "load"}, {"name", "find-value"}},
                      is_error);
    REQUIRE(is_error);

    // name validation refuses traversal and separators
    payload = fx.call("script",
                      {{"action", "save"}, {"name", "../escape"}, {"code", "x"}},
                      is_error);
    REQUIRE(is_error);
    REQUIRE(payload.at("error").get<std::string>().find("snippet name") !=
            std::string::npos);
    REQUIRE_FALSE(fs::exists(dir.parent_path() / "escape.lua"));

    // save without code and an unknown action both fail cleanly
    payload = fx.call("script", {{"action", "save"}, {"name", "empty"}}, is_error);
    REQUIRE(is_error);
    payload = fx.call("script", {{"action", "nope"}}, is_error);
    REQUIRE(is_error);

    paths::init();
    fs::remove_all(dir);
}

TEST_CASE(mcp_script_static_analysis_surface) {
    // the script loads the fixture from disk, which the sandbox refuses
    struct unsafe_guard_t {
        bool prev = slop::core::infra::settings::get<bool>("script_unsafe", false);
        unsafe_guard_t() { slop::core::infra::settings::set("script_unsafe", true); }
        ~unsafe_guard_t() { slop::core::infra::settings::set("script_unsafe", prev); }
    } unsafe_guard;
    server_fixture_t fx;
    bool is_error = false;

    // The script tool drives the shared static-analysis session: load the
    // fixture through Lua, walk functions, rename, and read the rename back
    // through the MCP disasm tool, proving the two surfaces interoperate
    const std::string code = std::string(R"(
        assert(slop.image.load(")") + SLOP_TARGET_EXE_PATH + R"("), "load failed")
        local fns = slop.disasm.functions()
        assert(#fns > 0, "no functions")
        slop.disasm.set_name(fns[1].va, "lua_entry")
        assert(slop.disasm.name(fns[1].va) == "lua_entry")
        local insn = slop.disasm.decode(slop.image.status().entry, 2)
        assert(#insn >= 1, "no decode")
        return #fns
    )";
    json payload = fx.call("script",
                           {{"action", "run"}, {"code", code},
                            {"timeout_ms", 30000}},
                           is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("ok", false), true);

    // The rename is visible to the MCP symbol surface (shared session)
    payload = fx.call("disasm", {{"action", "symbols"}}, is_error);
    REQUIRE(!is_error);
    const auto& syms = payload.at("symbols");
    bool saw = false;
    for (const auto& s : syms)
        if (s.value("name", "") == "lua_entry") saw = true;
    REQUIRE(saw);

    // Lua-side unload tears down the shared session for the MCP side too
    payload = fx.call("script",
                      {{"action", "run"}, {"code", "slop.image.unload()"}},
                      is_error);
    REQUIRE(!is_error);
    payload = fx.call("disasm", {{"action", "loaded"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("ready", true), false);
}

// === phase 11: xray / patch / types / notes + debugger extensions ===

TEST_CASE(mcp_xray_actions_over_loaded_image) {
    server_fixture_t fx;
    bool is_error = false;

    json payload = fx.call("xray", {{"action", "entropy"}}, is_error);
    REQUIRE(is_error);   // nothing loaded

    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    json loaded = fx.call("disasm", {{"action", "loaded"}}, is_error);
    const uint64_t entry = loaded.at("entry_va").get<uint64_t>();

    payload = fx.call("xray",
                      {{"action", "entropy"}, {"addr", entry},
                       {"size", 4096}, {"window_size", 256}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("overall_entropy"));
    {
        const std::string v = payload.value("verdict", "");
        REQUIRE(v == "normal" || v == "suspicious_high_entropy");
    }

    payload = fx.call("xray", {{"action", "cfg"}, {"addr", entry}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GE(payload.value("block_count", 0u), 1u);
    REQUIRE_GT(payload.value("cyclomatic_complexity", 0ull), 0ull);

    payload = fx.call("xray", {{"action", "complexity"}, {"addr", entry}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GT(payload.value("instruction_count", 0u), 0u);
    REQUIRE(payload.contains("complexity_rating"));

    payload = fx.call("xray", {{"action", "obfuscation"}, {"addr", entry}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_LE(payload.value("obfuscation_score_pct", 101), 100);

    payload = fx.call("xray", {{"action", "anti_analysis"}, {"addr", entry}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("detections"));

    payload = fx.call("xray", {{"action", "cff"}, {"addr", entry}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("flattened"));

    payload = fx.call("xray",
                      {{"action", "pages"}, {"addr", entry}, {"size", 8192}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_GT(payload.value("total_pages", 0u), 0u);
    REQUIRE(payload.contains("summary"));

    payload = fx.call("xray", {{"action", "gadgets"}, {"limit", 16}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GT(payload.value("count", 0u), 0u);

    payload = fx.call("xray",
                      {{"action", "apihash"},
                       {"hashes", json::array({0xDEADBEEF})},
                       {"algorithm", "ror13"}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("total_queried", 0u), 1u);
    REQUIRE_EQ(payload.value("resolved_count", -1), 0);

    payload = fx.call("xray", {{"action", "bogus"}}, is_error);
    REQUIRE(is_error);

    slop::core::disasm::binary_state::unload();
}

TEST_CASE(mcp_patch_journal_roundtrip) {
    server_fixture_t fx;
    bool is_error = true;
    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    json loaded = fx.call("disasm", {{"action", "loaded"}}, is_error);
    const uint64_t entry = loaded.at("entry_va").get<uint64_t>();

    // Dry run never lands bytes
    json payload = fx.call("patch",
                           {{"action", "resolve_opaque"}, {"addr", entry},
                            {"dry_run", true}},
                           is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("dry_run", false), true);

    // Real write through the journal, then revert
    payload = fx.call("patch",
                      {{"action", "write_bytes"}, {"addr", entry},
                       {"hex", "9090"}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_GE(payload.value("bytes_changed", 0ull), 2ull);

    payload = fx.call("patch", {{"action", "journal"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GE(payload.value("total", 0u), 2u);
    REQUIRE_EQ(payload.value("indexes_dirty", false), true);

    payload = fx.call("patch", {{"action", "revert_all"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GE(payload.value("bytes_changed", 0ull), 2ull);

    // Static actions still serve after mutation (lazy index rebuild path)
    payload = fx.call("disasm", {{"action", "functions"}, {"limit", 5}}, is_error);
    REQUIRE(!is_error);

    slop::core::disasm::binary_state::unload();

    // No image: structured error
    payload = fx.call("patch", {{"action", "write_bytes"}, {"addr", 1},
                                {"hex", "CC"}},
                      is_error);
    REQUIRE(is_error);
}

TEST_CASE(mcp_types_declare_and_read) {
    server_fixture_t fx;
    bool is_error = false;

    json payload = fx.call(
        "types",
        {{"action", "declare"},
         {"decl", "struct SlopRec packed { u32 magic; u64 counter; };"}
        },
        is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("declared", 0u), 1u);

    payload = fx.call("types", {{"action", "get_struct"}, {"name", "SlopRec"}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("size", 0ull), 12ull);   // packed u32+u64
    REQUIRE_EQ(payload.at("fields").at(1).value("offset", 0ull), 4ull);

    // Field read out of the live target (attached to ourselves by the attach
    // test pattern, here read from the loaded image's mapped header instead)
    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    json loaded = fx.call("disasm", {{"action", "loaded"}}, is_error);
    const uint64_t base = loaded.at("base").get<uint64_t>();
    payload = fx.call("types",
                      {{"action", "read_field"}, {"struct", "SlopRec"},
                       {"field", "magic"}, {"addr", base + 0x200}},
                      is_error);
    if (!is_error) {
        REQUIRE_EQ(payload.value("source", ""), "file");
        REQUIRE(payload.contains("uint"));
    } else {
        // Unmapped scratch VA in this image: structured failure is fine
        REQUIRE(payload.contains("error"));
    }
    slop::core::disasm::binary_state::unload();

    payload = fx.call(
        "types",
        {{"action", "create_enum"}, {"name", "SlopMode"},
         {"underlying", "u8"},
         {"values", json::array({json{{"name", "Off"}, {"value", 0}},
                                 json{{"name", "On"}, {"value", 1}}})}},
        is_error);
    REQUIRE(!is_error);
    payload = fx.call("types", {{"action", "get_enum"}, {"name", "SlopMode"}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.at("values").size(), 2u);
}

TEST_CASE(mcp_notes_comments_and_bookmarks) {
    server_fixture_t fx;
    bool is_error = true;
    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    json loaded = fx.call("disasm", {{"action", "loaded"}}, is_error);
    const uint64_t entry = loaded.at("entry_va").get<uint64_t>();

    json payload = fx.call("notes",
                           {{"action", "set_comment"}, {"addr", entry},
                            {"text", "ai says hi"}},
                           is_error);
    REQUIRE(!is_error);

    payload = fx.call("notes", {{"action", "get_comment"}, {"addr", entry}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_STR_EQ(payload.value("comment", "").c_str(), "ai says hi");

    payload = fx.call("notes", {{"action", "comments"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GE(payload.value("count", 0u), 1u);

    // Toggle flips state deterministically; the per-hash store may already
    // carry a bookmark from an earlier run, so don't assume the direction
    json t1 = fx.call("notes", {{"action", "bookmark_toggle"}, {"addr", entry}},
                      is_error);
    REQUIRE(!is_error);
    json t2 = fx.call("notes", {{"action", "bookmark_toggle"}, {"addr", entry}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_NE(t1.value("bookmarked", true), t2.value("bookmarked", false));

    payload = fx.call("notes", {{"action", "bookmarks"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("count"));

    // Clear comment via empty text
    payload = fx.call("notes",
                      {{"action", "set_comment"}, {"addr", entry},
                       {"text", ""}},
                      is_error);
    REQUIRE(!is_error);
    payload = fx.call("notes", {{"action", "get_comment"}, {"addr", entry}},
                      is_error);
    REQUIRE_STR_EQ(payload.value("comment", "x").c_str(), "");

    slop::core::disasm::binary_state::unload();

    payload = fx.call("notes", {{"action", "comments"}}, is_error);
    REQUIRE(is_error);   // needs a loaded image
}

TEST_CASE(mcp_devirt_and_full_pass_over_wire) {
    server_fixture_t fx;
    bool is_error = false;

    json payload = fx.call("devirt", {{"action", "identify"}, {"addr", 1}},
                           is_error);
    REQUIRE(is_error);   // nothing loaded

    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    json loaded = fx.call("disasm", {{"action", "loaded"}}, is_error);
    const uint64_t entry = loaded.at("entry_va").get<uint64_t>();
    const uint64_t base = loaded.at("base").get<uint64_t>();

    // Clean MSVC entry: not a VM, recovery reports none
    payload = fx.call("devirt", {{"action", "identify"}, {"addr", entry}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("likely_vm", true), false);
    REQUIRE(payload.contains("confidence_pct"));

    // recover_cfg / prove_predicates run the emulator; they live in
    // mcp_devirt_recover_cfg_prove_predicates_emulate so the ASan lane can
    // skip them (Unicorn faults with no ASan report).

    payload = fx.call("devirt", {{"action", "iat_audit"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GT(payload.value("named", 0u), 0u);   // real imports recognized

    // Handlers against a bogus table: structured error
    payload = fx.call("devirt",
                      {{"action", "handlers"},
                       {"table", base + 0x400}, {"entry_size", 8}},
                      is_error);
    REQUIRE(is_error);

    // patch.full_pass dry-run over the wire
    payload = fx.call("patch",
                      {{"action", "full_pass"}, {"addr", entry},
                       {"dry_run", true}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_GE(payload.value("pre_obfuscation_score", -1), 0);
    REQUIRE(payload.contains("steps"));

    slop::core::disasm::binary_state::unload();

    payload = fx.call("patch", {{"action", "rebuild"}, {"addr", 1}}, is_error);
    REQUIRE(is_error);   // image unloaded
}

TEST_CASE(mcp_devirt_recover_cfg_prove_predicates_emulate) {
    // Seeded emulation: separate so the ASan lane can skip it.
    server_fixture_t fx;
    bool is_error = false;
    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    json loaded = fx.call("disasm", {{"action", "loaded"}}, is_error);
    const uint64_t entry = loaded.at("entry_va").get<uint64_t>();

    json payload = fx.call("devirt",
                           {{"action", "recover_cfg"}, {"addr", entry},
                            {"runs", 2}},
                           is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("flattened", true), false);
    REQUIRE_STR_EQ(payload.value("mode", "").c_str(), "none");

    payload = fx.call("devirt",
                      {{"action", "prove_predicates"}, {"addr", entry},
                       {"runs", 2}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("predicates"));

    slop::core::disasm::binary_state::unload();
}

TEST_CASE(mcp_debugger_ps4_actions_refuse_without_console) {
    server_fixture_t fx;
    bool is_error = false;

    // Without a connected PS4 every ps4_* action refuses with a structured
    // error, and a local-debug action name points at the ps4_* set
    for (const char* action : {"ps4_attach", "ps4_bp_set", "ps4_continue",
                               "ps4_wait", "ps4_regs", "ps4_events",
                               "ps4_find_write"}) {
        json payload = fx.call("debugger",
                               {{"action", action}, {"addr", 0x41414141},
                                {"pid", 1234}}, is_error);
        REQUIRE(is_error);
        REQUIRE(payload.contains("error"));
    }

    json payload = fx.call("debugger", {{"action", "wait_halt"}}, is_error);
    REQUIRE(is_error);
    REQUIRE(payload.at("error").get<std::string>().find("ps4_") !=
            std::string::npos);

    payload = fx.call("debugger", {{"action", "status"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("ps4_connected", true), false);
    REQUIRE_EQ(payload.value("debug_attached", true), false);
    REQUIRE(payload.contains("backend"));

    payload = fx.call("memory",
                      {{"action", "live_crypto"},
                       {"begin", 0x41414141}, {"end", 0x41414241}},
                      is_error);
    REQUIRE(is_error);   // no target
}




// hyperion engine surface (decompiler + analyzer-backed actions)

namespace {

bool wait_hype_ready_mcp(int timeout_ms = 30000) {
    namespace ds = slop::core::disasm::binary_state;
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (ds::hype_ready()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return ds::hype_ready();
}

} // namespace

TEST_CASE(mcp_decomp_function_hyperion_engine) {
    namespace ds = slop::core::disasm::binary_state;
    REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH));
    REQUIRE(wait_hype_ready_mcp());

    server_fixture_t fx;
    bool is_error = false;

    // Locate a real function through the hyperion-enriched listing
    json loaded = fx.call("disasm", {{"action", "loaded"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(loaded.contains("hype"));
    REQUIRE_EQ(loaded.at("hype").value("ready", false), true);
    REQUIRE_GT(loaded.at("hype").value("functions", 0), 0);

    json fns = fx.call("disasm",
                       {{"action", "functions"}, {"limit", 64}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(fns.at("functions").size() > 0);
    // Every row carries its provenance (index vs hyperion analyzer DB)
    for (const auto& f : fns.at("functions")) {
        REQUIRE(f.contains("source"));
        const std::string src = f.value("source", "");
        REQUIRE(src == "index" || src == "hyperion");
    }
    const uint64_t some_fn =
        fns.at("functions").at(0).at("va").get<uint64_t>();

    json payload = fx.call("decomp", {{"action", "function"},
                                      {"addr", some_fn}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("engine", ""), "hyperion");
    REQUIRE(payload.contains("signature"));
    REQUIRE(payload.at("lines").size() > 0);
    REQUIRE(payload.contains("function_va"));
    REQUIRE(payload.contains("vars"));

    // Unknown address -> structured error, fast unmapped-VA reject
    // (must never wedge the engine on addresses outside the image)
    payload = fx.call("decomp", {{"action", "function"},
                                 {"addr", 0x1BADBEEFull}}, is_error);
    REQUIRE(is_error);
    REQUIRE(payload.contains("error"));
    REQUIRE(payload.at("error").get<std::string>().find("not mapped") !=
            std::string::npos);

    ds::unload();
}

TEST_CASE(mcp_disasm_hyperion_blocks_vtables_globals) {
    namespace ds = slop::core::disasm::binary_state;
    REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH));
    REQUIRE(wait_hype_ready_mcp());

    server_fixture_t fx;
    bool is_error = false;

    // blocks: function containing the image entry point
    namespace dsm = slop::core::disasm;
    auto& b = ds::get();
    const uint64_t entry = b.base + b.pe.entry_rva;

    json blocks = fx.call("disasm", {{"action", "blocks"}, {"addr", entry}},
                          is_error);
    REQUIRE(!is_error);
    REQUIRE(blocks.contains("blocks"));
    REQUIRE(blocks.at("blocks").size() > 0);
    REQUIRE(blocks.at("blocks").at(0).contains("succs"));
    REQUIRE(blocks.contains("entry"));

    // globals + vtables respond with count fields (may be empty on a small
    // fixture, but must be well-formed and non-error)
    json globals = fx.call("disasm", {{"action", "globals"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(globals.contains("count"));
    json vts = fx.call("disasm", {{"action", "vtables"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(vts.contains("count"));

    // xrefs now carry hyperion kind names
    json fns = fx.call("disasm",
                       {{"action", "functions"}, {"limit", 64}}, is_error);
    const uint64_t some_fn =
        fns.at("functions").at(0).at("va").get<uint64_t>();
    json xr = fx.call("disasm", {{"action", "xrefs"}, {"addr", some_fn}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE(xr.contains("refs_to"));

    ds::unload();
}

TEST_CASE(mcp_analyze_diff_self_identical) {
    server_fixture_t fx;
    bool is_error = false;

    json payload = fx.call("analyze",
                           {{"action", "diff"},
                            {"path_a", SLOP_TARGET_EXE_PATH},
                            {"path_b", SLOP_TARGET_EXE_PATH}},
                           is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("totals"));
    REQUIRE_GT(payload.at("totals").value("identical", -1), 0);
    // Self-diff reports no changed functions
    REQUIRE_EQ(payload.value("count", 1), 0);
}

TEST_CASE(mcp_types_format_at_renders_struct) {
    namespace ds = slop::core::disasm::binary_state;
    REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH));

    server_fixture_t fx;
    bool is_error = false;

    // Declare a small struct, then render it over the entry-point bytes
    json decl = fx.call("types",
                        {{"action", "declare"},
                         {"decl", "struct HypeHdr { u32 magic; u32 size; u64 stamp; };"}},
                        is_error);
    REQUIRE(!is_error);

    auto& b = ds::get();
    const uint64_t entry = b.base + b.pe.entry_rva;
    json payload = fx.call("types",
                           {{"action", "format_at"},
                            {"addr", entry}, {"type", "HypeHdr"}},
                           is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("source", ""), "file");
    REQUIRE(payload.at("rendered").get<std::string>().find("HypeHdr") !=
            std::string::npos);

    ds::unload();
}

TEST_CASE(mcp_persist_hype_project_roundtrip) {
    namespace ds = slop::core::disasm::binary_state;
    REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH));
    REQUIRE(wait_hype_ready_mcp());

    server_fixture_t fx;
    bool is_error = false;

    // Rename a function over MCP, save the .hdb, merge-load it back
    json fns = fx.call("disasm",
                       {{"action", "functions"}, {"limit", 8}}, is_error);
    const uint64_t some_fn =
        fns.at("functions").at(0).at("va").get<uint64_t>();
    REQUIRE(!fx.call("disasm",
                     {{"action", "symbol_set"}, {"addr", some_fn},
                      {"name", "hype_roundtrip_fn"}},
                     is_error)
                 .is_null());

    const std::string dir = std::string(std::getenv("TEMP") ? std::getenv("TEMP")
                                                            : ".") +
                            "\\slop_hype_test_proj";
    json saved = fx.call("persist", {{"action", "hype_save"}, {"dir", dir}},
                         is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(saved.value("ok", false), true);

    json loaded = fx.call("persist", {{"action", "hype_load"}, {"dir", dir}},
                          is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(loaded.value("ok", false), true);
    REQUIRE_GT(loaded.value("merged_names", 0), 0);

    ds::unload();
}

TEST_CASE(mcp_hype_reanalysis_after_patch) {
    namespace ds = slop::core::disasm::binary_state;
    REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH));
    REQUIRE(wait_hype_ready_mcp());

    server_fixture_t fx;
    bool is_error = false;

    // Any mapped byte write goes through the imgpatch journal and dirties
    // the indexes; the next functions/xrefs/strings call rebuilds them and
    // kicks a hyperion re-analysis over the patched bytes
    auto& b = ds::get();
    const uint64_t entry = b.base + b.pe.entry_rva;

    json w = fx.call("patch",
                     {{"action", "write_bytes"}, {"addr", entry},
                      {"hex", "90"}},
                     is_error);
    REQUIRE(!is_error);

    // Trigger the lazy rebuild + reanalyze
    json fns = fx.call("disasm",
                       {{"action", "functions"}, {"limit", 16}}, is_error);
    REQUIRE(!is_error);

    // Re-analysis started synchronously inside the handler: not ready now..
    REQUIRE_FALSE(ds::hype_ready());
    // ...and completes again
    REQUIRE(wait_hype_ready_mcp());

    // Decompiler still works over the patched image
    json decomp = fx.call("decomp", {{"action", "function"},
                                     {"addr", entry}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(decomp.value("engine", ""), "hyperion");

    ds::unload();
}

TEST_CASE(mcp_disasm_load_unload_shared_session) {
    namespace ds = slop::core::disasm::binary_state;
    ds::unload();

    server_fixture_t fx;
    bool is_error = false;

    // Load straight into the shared session, same path the UI's
    // "open file..." takes, hyperion analysis included
    json payload = fx.call("disasm",
                           {{"action", "load"},
                            {"path", SLOP_TARGET_EXE_PATH}},
                           is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("ok", false), true);
    REQUIRE_EQ(payload.value("ready", false), true);
    REQUIRE(payload.contains("hype"));
    REQUIRE(wait_hype_ready_mcp());

    // The decompiler runs against the shared session's engine
    auto& b = ds::get();
    const uint64_t entry = b.base + b.pe.entry_rva;
    payload = fx.call("decomp", {{"action", "function"},
                                 {"addr", entry}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("engine", ""), "hyperion");

    // Unload tears it all down
    payload = fx.call("disasm", {{"action", "unload"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_FALSE(ds::has_binary());
}

// === transport: auth, host/origin guard, cors, sessions, notifications, sse ===

namespace {

const std::string kTok   = std::string(64, 'a');
const std::string kExtra = std::string(64, 'b');

json rpc_body(const std::string& method, const json& id = 1, const json& params = json::object()) {
    json r = {{"jsonrpc", "2.0"}, {"method", method}, {"params", params}};
    if (!id.is_null()) r["id"] = id;
    return r;
}

httplib::Headers bearer(const std::string& t) { return {{"Authorization", "Bearer " + t}}; }

slop::core::mcp::server_config_t token_cfg() {
    slop::core::mcp::server_config_t cfg;
    cfg.token = kTok;
    cfg.extra_tokens = {kExtra};
    return cfg;
}

// scratch settings file so app.* settings actions never touch the real profile
struct scratch_settings_t {
    std::filesystem::path dir;
    std::string old_profile, old_appdata;
    scratch_settings_t() {
        dir = std::filesystem::temp_directory_path() /
              ("slop_mcp_settings_" + std::to_string(::GetCurrentProcessId()));
        std::filesystem::create_directories(dir);
        slop::core::infra::settings::set_file_for_testing((dir / "settings.json").string());
        slop::core::infra::settings::load();
        // rotate_token refreshes onboarded client configs: sandbox them too
        char buf[32768];
        DWORD n = ::GetEnvironmentVariableA("USERPROFILE", buf, sizeof(buf));
        if (n > 0 && n < sizeof(buf)) old_profile.assign(buf, n);
        n = ::GetEnvironmentVariableA("APPDATA", buf, sizeof(buf));
        if (n > 0 && n < sizeof(buf)) old_appdata.assign(buf, n);
        ::SetEnvironmentVariableA("USERPROFILE", (dir / "profile").string().c_str());
        ::SetEnvironmentVariableA("APPDATA", (dir / "appdata").string().c_str());
    }
    ~scratch_settings_t() {
        ::SetEnvironmentVariableA("USERPROFILE", old_profile.empty() ? nullptr : old_profile.c_str());
        ::SetEnvironmentVariableA("APPDATA", old_appdata.empty() ? nullptr : old_appdata.c_str());
        slop::core::infra::settings::set_file_for_testing({});
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

} // namespace

TEST_CASE(mcp_auth_rejects_missing_or_bad_tokens_with_rpc_shape) {
    server_fixture_t fx(token_cfg());
    const std::string body = rpc_body("ping").dump();

    auto none = fx.cli_->Post("/mcp", body, "application/json");
    REQUIRE(none);
    REQUIRE_EQ(none->status, 401);
    REQUIRE_STR_EQ(none->get_header_value("WWW-Authenticate").c_str(), "Bearer");
    const json err = json::parse(none->body);
    REQUIRE_STR_EQ(err.at("jsonrpc").get<std::string>().c_str(), "2.0");
    REQUIRE_EQ(err.at("error").at("code").get<int>(), -32001);

    auto bad = fx.cli_->Post("/mcp", bearer(std::string(64, 'c')), body, "application/json");
    REQUIRE(bad);
    REQUIRE_EQ(bad->status, 401);
    auto prefix = fx.cli_->Post("/mcp", bearer(kTok.substr(0, 63)), body, "application/json");
    REQUIRE(prefix);
    REQUIRE_EQ(prefix->status, 401);

    auto good = fx.cli_->Post("/mcp", bearer(kTok), body, "application/json");
    REQUIRE(good);
    REQUIRE_EQ(good->status, 200);
    auto extra = fx.cli_->Post("/mcp", bearer(kExtra), body, "application/json");
    REQUIRE(extra);
    REQUIRE_EQ(extra->status, 200);

    // /api keeps the ui's {ok,error} shape
    const json api = {{"tool", "app"}, {"action", "status"}};
    auto api_bad = fx.cli_->Post("/api", api.dump(), "application/json");
    REQUIRE(api_bad);
    REQUIRE_EQ(api_bad->status, 401);
    REQUIRE(!json::parse(api_bad->body).value("ok", true));
    // the stream routes are gated too
    auto stream = fx.cli_->Get("/mcp");
    REQUIRE(stream);
    REQUIRE_EQ(stream->status, 401);
    // health stays open for the startup probe
    auto health = fx.cli_->Get("/health");
    REQUIRE(health);
    REQUIRE_EQ(health->status, 200);
}

TEST_CASE(mcp_host_and_origin_guard_and_cors) {
    server_fixture_t fx;
    const std::string body = rpc_body("ping").dump();

    // dns rebinding: a foreign Host never reaches a handler
    auto rebind = fx.cli_->Post("/mcp", {{"Host", "evil.example:" + std::to_string(fx.port())}},
                                body, "application/json");
    REQUIRE(rebind);
    REQUIRE_EQ(rebind->status, 403);
    auto local = fx.cli_->Post("/mcp", {{"Host", "localhost:" + std::to_string(fx.port())}},
                               body, "application/json");
    REQUIRE(local);
    REQUIRE_EQ(local->status, 200);
    REQUIRE(slop::core::mcp::host_allowed("[::1]:" + std::to_string(fx.port()), fx.port()));
    REQUIRE(!slop::core::mcp::host_allowed("127.0.0.1:1", fx.port()));
    REQUIRE(!slop::core::mcp::host_allowed("127.0.0.1.evil.example", fx.port()));

    // a web page cannot drive /mcp
    auto foreign = fx.cli_->Post("/mcp", {{"Origin", "https://evil.example"}}, body,
                                 "text/plain");
    REQUIRE(foreign);
    REQUIRE_EQ(foreign->status, 403);

    // the webview gets cors on every route, including the startup /health probe
    const httplib::Headers tauri = {{"Origin", "http://tauri.localhost"}};
    auto health = fx.cli_->Get("/health", tauri);
    REQUIRE(health);
    REQUIRE_EQ(health->status, 200);
    REQUIRE_STR_EQ(health->get_header_value("Access-Control-Allow-Origin").c_str(),
                   "http://tauri.localhost");
    auto pre = fx.cli_->Options("/mcp", {{"Origin", "http://localhost:1420"},
                                         {"Access-Control-Request-Method", "POST"}});
    REQUIRE(pre);
    REQUIRE_EQ(pre->status, 204);
    REQUIRE(pre->get_header_value("Access-Control-Allow-Headers").find("Authorization") !=
            std::string::npos);
    REQUIRE(pre->get_header_value("Access-Control-Expose-Headers").find("Mcp-Session-Id") !=
            std::string::npos);
    auto pre_bad = fx.cli_->Options("/api", {{"Origin", "https://evil.example"}});
    REQUIRE(pre_bad);
    REQUIRE_EQ(pre_bad->status, 403);
}

TEST_CASE(mcp_notifications_never_get_replies) {
    server_fixture_t fx;
    auto single = fx.cli_->Post("/mcp", rpc_body("notifications/whatever", nullptr).dump(),
                                "application/json");
    REQUIRE(single);
    REQUIRE_EQ(single->status, 202);
    REQUIRE(single->body.empty());

    const json batch_only = json::array({rpc_body("notifications/initialized", nullptr),
                                         rpc_body("bogus/notification", nullptr)});
    auto only = fx.cli_->Post("/mcp", batch_only.dump(), "application/json");
    REQUIRE(only);
    REQUIRE_EQ(only->status, 202);

    const json mixed = json::array({rpc_body("ping", 7), rpc_body("bogus/notification", nullptr),
                                    rpc_body("bogus/method", 8)});
    auto res = fx.cli_->Post("/mcp", mixed.dump(), "application/json");
    REQUIRE(res);
    REQUIRE_EQ(res->status, 200);
    const json arr = json::parse(res->body);
    REQUIRE(arr.is_array());
    REQUIRE_EQ(arr.size(), 2u);
    REQUIRE_EQ(arr.at(0).at("id").get<int>(), 7);
    REQUIRE_EQ(arr.at(1).at("error").at("code").get<int>(), -32601);

    auto empty = fx.cli_->Post("/mcp", "[]", "application/json");
    REQUIRE(empty);
    REQUIRE_EQ(empty->status, 400);
}

TEST_CASE(mcp_initialize_negotiates_version_and_issues_sessions) {
    server_fixture_t fx;
    auto old = fx.cli_->Post("/mcp",
                             rpc_body("initialize", 1, {{"protocolVersion", "2024-11-05"}}).dump(),
                             "application/json");
    REQUIRE(old);
    REQUIRE_EQ(old->status, 200);
    REQUIRE_STR_EQ(json::parse(old->body).at("result").at("protocolVersion")
                       .get<std::string>().c_str(), "2024-11-05");
    const std::string sid = old->get_header_value("Mcp-Session-Id");
    REQUIRE_EQ(sid.size(), 64u);

    auto future_ver = fx.cli_->Post("/mcp",
                                    rpc_body("initialize", 2, {{"protocolVersion", "2099-01-01"}}).dump(),
                                    "application/json");
    REQUIRE(future_ver);
    REQUIRE_STR_EQ(json::parse(future_ver->body).at("result").at("protocolVersion")
                       .get<std::string>().c_str(), "2025-06-18");
    REQUIRE_NE(future_ver->get_header_value("Mcp-Session-Id"), sid);

    // a known session is accepted, an unknown one must re-initialize
    auto ok = fx.cli_->Post("/mcp", {{"Mcp-Session-Id", sid}}, rpc_body("ping").dump(),
                            "application/json");
    REQUIRE(ok);
    REQUIRE_EQ(ok->status, 200);
    auto unknown = fx.cli_->Post("/mcp", {{"Mcp-Session-Id", "forged"}}, rpc_body("ping").dump(),
                                 "application/json");
    REQUIRE(unknown);
    REQUIRE_EQ(unknown->status, 404);

    auto del = fx.cli_->Delete("/mcp", {{"Mcp-Session-Id", sid}});
    REQUIRE(del);
    REQUIRE_EQ(del->status, 204);
    auto gone = fx.cli_->Post("/mcp", {{"Mcp-Session-Id", sid}}, rpc_body("ping").dump(),
                              "application/json");
    REQUIRE(gone);
    REQUIRE_EQ(gone->status, 404);
}

TEST_CASE(mcp_cancel_is_scoped_to_the_issuing_session_emulate) {
    server_fixture_t fx;
    auto init_a = fx.cli_->Post("/mcp", rpc_body("initialize").dump(), "application/json");
    auto init_b = fx.cli_->Post("/mcp", rpc_body("initialize").dump(), "application/json");
    REQUIRE(init_a && init_b);
    const std::string sa = init_a->get_header_value("Mcp-Session-Id");
    const std::string sb = init_b->get_header_value("Mcp-Session-Id");

    json reply;
    std::thread runner([&] {
        httplib::Client cli("127.0.0.1", fx.port());
        cli.set_read_timeout(std::chrono::seconds(20));
        const json req = rpc_body("tools/call", 99,
                                  {{"name", "emulate"},
                                   {"arguments", {{"action", "run"}, {"hex", "EBFE"},
                                                  {"count", 1ull << 40}, {"timeout_ms", 1500}}}});
        if (auto r = cli.Post("/mcp", {{"Mcp-Session-Id", sa}}, req.dump(), "application/json"))
            reply = json::parse(r->body, nullptr, false);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    const json cancel = rpc_body("notifications/cancelled", nullptr, {{"requestId", 99}});
    // session b cannot cancel session a's request 99
    for (int i = 0; i < 3; ++i)
        fx.cli_->Post("/mcp", {{"Mcp-Session-Id", sb}}, cancel.dump(), "application/json");
    runner.join();
    REQUIRE(reply.is_object());
    const json payload =
        json::parse(reply.at("result").at("content").at(0).at("text").get<std::string>());
    REQUIRE(payload.value("stopped_reason", "") != "cancelled");
}

TEST_CASE(mcp_tools_carry_annotations_closed_schemas_and_structured_content) {
    server_fixture_t fx;
    const json list = fx.rpc("tools/list");
    for (const auto& t : list.at("result").at("tools")) {
        REQUIRE(t.contains("annotations"));
        REQUIRE(t.at("annotations").contains("readOnlyHint"));
        REQUIRE(t.at("annotations").at("readOnlyHint") == t.at("read_only"));
        REQUIRE(t.at("inputSchema").at("additionalProperties") == false);
        REQUIRE(t.contains("outputSchema"));
        for (const auto& [k, p] : t.at("inputSchema").at("properties").items())
            REQUIRE(p.contains("description"));
        if (t.at("name") == "memory") {
            const auto& addr = t.at("inputSchema").at("properties").at("addr").at("type");
            REQUIRE(addr.is_array());   // integer or "0x..." string
        }
    }
    const json call = fx.rpc("tools/call", {{"name", "target"}, {"arguments", {{"action", "status"}}}});
    const json& result = call.at("result");
    REQUIRE(result.contains("structuredContent"));
    REQUIRE(result.at("structuredContent").is_object());
    REQUIRE(result.at("structuredContent") ==
            json::parse(result.at("content").at(0).at("text").get<std::string>()));
}

TEST_CASE(mcp_events_ticket_is_single_use) {
    server_fixture_t fx(token_cfg());
    const json req = {{"tool", "app"}, {"action", "events_ticket"}};
    auto res = fx.cli_->Post("/api", bearer(kTok), req.dump(), "application/json");
    REQUIRE(res);
    REQUIRE_EQ(res->status, 200);
    const std::string ticket = json::parse(res->body).at("data").at("ticket").get<std::string>();
    REQUIRE_EQ(ticket.size(), 64u);

    auto open_stream = [&](const std::string& path) {
        httplib::Client cli("127.0.0.1", fx.port());
        cli.set_read_timeout(std::chrono::seconds(5));
        std::string got;
        auto r = cli.Get(path, [&](const char* data, size_t len) {
            got.append(data, len);
            return got.find("event: hello") == std::string::npos;   // stop after hello
        });
        return std::make_pair(r ? r->status : (got.empty() ? -1 : 200), got);
    };
    const auto first = open_stream("/events?ticket=" + ticket);
    REQUIRE(first.second.find("event: hello") != std::string::npos);
    const auto reuse = open_stream("/events?ticket=" + ticket);
    REQUIRE_EQ(reuse.first, 401);
    const auto legacy = open_stream("/events?token=" + kTok);
    REQUIRE_EQ(legacy.first, 401);   // the query-string token is gone
}

TEST_CASE(mcp_stream_cap_keeps_workers_free) {
    slop::core::mcp::server_config_t cfg;
    cfg.max_streams = 1;
    server_fixture_t fx(cfg);
    std::atomic<bool> stop_first{false};
    std::atomic<bool> first_open{false};
    std::thread holder([&] {
        httplib::Client cli("127.0.0.1", fx.port());
        cli.set_read_timeout(std::chrono::seconds(10));
        cli.Get("/events", [&](const char*, size_t) {
            first_open = true;
            return !stop_first.load();
        });
    });
    for (int i = 0; i < 200 && !first_open.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    REQUIRE(first_open.load());
    REQUIRE_EQ(slop::core::mcp::active_streams(), 1u);
    auto second = fx.cli_->Get("/events");
    REQUIRE(second);
    REQUIRE_EQ(second->status, 503);
    // plain requests still flow while the stream is parked
    REQUIRE(fx.rpc("ping").contains("result"));
    stop_first = true;
    slop::core::infra::event_bus::publish("test.nudge", json::object());
    holder.join();
    for (int i = 0; i < 300 && slop::core::mcp::active_streams() != 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    REQUIRE_EQ(slop::core::mcp::active_streams(), 0u);
}

TEST_CASE(mcp_app_settings_api_redacts_and_validates) {
    scratch_settings_t scratch;
    server_fixture_t fx;

    // `app` is UI plumbing: reachable on /api, rejected on the agent transport
    json denied = fx.rpc("tools/call", {{"name", "app"},
                                        {"arguments", {{"action", "settings_get"}}}});
    REQUIRE(denied.contains("error"));
    REQUIRE(denied.at("error").at("message").get<std::string>().find("UI-only") !=
            std::string::npos);

    json got = fx.api("app", "settings_get").at("data");
    REQUIRE_STR_EQ(got.at("mcp_token").get<std::string>().c_str(), "set");

    REQUIRE(!fx.api("app", "settings_set", {{"key", "mcp_token"}, {"value", "x"}})
                 .value("ok", true));
    REQUIRE(!fx.api("app", "settings_set", {{"key", "mcp_port"}, {"value", 70000}})
                 .value("ok", true));
    json set = fx.api("app", "settings_set", {{"key", "script_unsafe"}, {"value", true}})
                   .at("data");
    REQUIRE(set.value("ok", false));
    REQUIRE(slop::core::infra::settings::get<bool>("script_unsafe", false));
    set = fx.api("app", "settings_set", {{"key", "mcp_port"}, {"value", 9100}}).at("data");
    REQUIRE(set.value("restart_required", false));
}

TEST_CASE(mcp_app_diag_bundle_redacts_and_zips) {
    scratch_settings_t scratch;
    server_fixture_t fx;
    slop::core::infra::diag::info("test", "bundle marker line");
    slop::core::infra::event_bus::output("output marker line");

    const auto dir = std::filesystem::temp_directory_path() /
                     ("slop_diag_" + std::to_string(::GetCurrentProcessId()));
    std::filesystem::create_directories(dir);
    const auto zip_path = dir / "diag.zip";
    std::error_code ec;
    std::filesystem::remove(zip_path, ec);

    json res = fx.api("app", "diag_bundle", {{"path", zip_path.string()}});
    REQUIRE(res.value("ok", false));
    const json data = res.at("data");
    CHECK(data.value("bytes", 0) > 0);

    std::ifstream f(zip_path, std::ios::binary);
    REQUIRE(f.is_open());
    const std::string bytes((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
    slop::core::util::zip::archive_t ar;
    std::string err;
    REQUIRE(ar.open(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size(), &err));
    for (const char* name : {"versions.json", "settings.json", "ps4_status.json",
                             "diag.log", "output.log", "bundle.json"})
        CHECK(ar.find(name) != nullptr);

    // settings are redacted: the bearer token never reaches the archive
    const auto* entry = ar.find("settings.json");
    REQUIRE(entry != nullptr);
    std::vector<uint8_t> out;
    REQUIRE(ar.extract(*entry, out, &err));
    const std::string settings_text(out.begin(), out.end());
    CHECK(json::parse(settings_text).value("mcp_token", "") == "set");
    const std::string token = slop::core::infra::settings::mcp_token();
    REQUIRE(!token.empty());
    CHECK(settings_text.find(token) == std::string::npos);
    CHECK(bytes.find(token) == std::string::npos);

    // the log tail carries the marker line
    entry = ar.find("diag.log");
    REQUIRE(entry != nullptr);
    out.clear();
    REQUIRE(ar.extract(*entry, out, &err));
    CHECK(std::string(out.begin(), out.end()).find("bundle marker line") != std::string::npos);

    // a bundle needs a destination
    json bad = fx.api("app", "diag_bundle", json::object());
    CHECK(!bad.value("ok", true));
    std::filesystem::remove_all(dir, ec);
}

TEST_CASE(mcp_rotate_token_applies_live) {
    scratch_settings_t scratch;
    slop::core::mcp::server_config_t cfg;
    cfg.token = slop::core::infra::settings::mcp_token();
    cfg.extra_tokens = {kExtra};
    server_fixture_t fx(cfg);
    const std::string old_tok = cfg.token;
    const json req = {{"tool", "app"}, {"action", "rotate_token"}};

    // the per-launch supervisor token (extra) is the UI's token, so it rotates;
    // its own bearer keeps working and the new bearer is returned once
    auto sup = fx.cli_->Post("/api", bearer(kExtra), req.dump(), "application/json");
    REQUIRE(sup);
    const json sup_out = json::parse(sup->body).at("data");
    REQUIRE(sup_out.value("rotated", false));
    REQUIRE(!sup_out.value("caller_must_switch", true));
    const std::string mid = slop::core::infra::settings::mcp_token();
    REQUIRE_STR_EQ(sup_out.at("token").get<std::string>().c_str(), mid.c_str());
    REQUIRE_NE(mid, old_tok);
    auto sup_again = fx.cli_->Post("/mcp", bearer(kExtra), rpc_body("ping").dump(), "application/json");
    REQUIRE_EQ(sup_again->status, 200);
    auto stale = fx.cli_->Post("/mcp", bearer(old_tok), rpc_body("ping").dump(), "application/json");
    REQUIRE(stale);
    REQUIRE_EQ(stale->status, 401);

    // the primary holder gets the new token back and the old one dies
    auto prim = fx.cli_->Post("/api", bearer(mid), req.dump(), "application/json");
    REQUIRE(prim);
    const json prim_out = json::parse(prim->body).at("data");
    REQUIRE(prim_out.value("caller_must_switch", false));
    const std::string fresh = prim_out.at("token").get<std::string>();
    REQUIRE_STR_EQ(fresh.c_str(), slop::core::infra::settings::mcp_token().c_str());
    auto ok = fx.cli_->Post("/mcp", bearer(fresh), rpc_body("ping").dump(), "application/json");
    REQUIRE(ok);
    REQUIRE_EQ(ok->status, 200);

    // register_token needs the primary token
    const json reg = {{"tool", "app"}, {"action", "register_token"},
                      {"params", {{"token", std::string(64, 'd')}}}};
    auto denied = fx.cli_->Post("/api", bearer(kExtra), reg.dump(), "application/json");
    REQUIRE(!json::parse(denied->body).value("ok", true));
    auto granted = fx.cli_->Post("/api", bearer(fresh), reg.dump(), "application/json");
    REQUIRE(json::parse(granted->body).value("ok", false));
    auto with_new = fx.cli_->Post("/mcp", bearer(std::string(64, 'd')), rpc_body("ping").dump(),
                                  "application/json");
    REQUIRE_EQ(with_new->status, 200);
}

TEST_CASE(mcp_fs_read_file_pages) {
    server_fixture_t fx;
    const auto dir = std::filesystem::temp_directory_path() /
                     ("slop_mcp_fs_" + std::to_string(::GetCurrentProcessId()));
    std::filesystem::create_directories(dir);
    const std::string file = (dir / "page.txt").string();
    { std::ofstream(file, std::ios::binary) << "hello paged world"; }
    bool is_error = true;
    json a = fx.call("fs", {{"action", "read_file"}, {"path", file}, {"max_bytes", 6}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(a.at("size").get<uint64_t>(), 17u);
    REQUIRE_STR_EQ(a.at("text").get<std::string>().c_str(), "hello ");
    REQUIRE_EQ(a.at("next_offset").get<uint64_t>(), 6u);
    json b = fx.call("fs", {{"action", "read_file"}, {"path", file}, {"offset", "0x6"},
                            {"max_bytes", 64}, {"encoding", "hex"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(b.value("eof", false));
    REQUIRE_STR_EQ(b.at("hex").get<std::string>().c_str(), "706167656420776f726c64");
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

TEST_CASE(mcp_stop_is_bounded_when_a_tool_ignores_cancel) {
    using clock = std::chrono::steady_clock;
    auto* fx = new server_fixture_t;
    const uint16_t p = fx->port();
    // hold the tool lock so a locked tool call parks inside a server worker
    std::unique_lock held(slop::core::mcp::detail::tool_mutex());
    std::thread caller([p] {
        httplib::Client cli("127.0.0.1", p);
        cli.set_read_timeout(std::chrono::seconds(30));
        cli.Post("/mcp", rpc_body("tools/call", 5, {{"name", "target"},
                                                    {"arguments", {{"action", "status"}}}}).dump(),
                 "application/json");
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    fx->cli_->stop();
    fx->cli_.reset();
    const auto t0 = clock::now();
    slop::core::mcp::stop();
    const auto ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - t0).count();
    REQUIRE_LT(ms, 9000);
    REQUIRE(!slop::core::mcp::running());
    held.unlock();
    caller.join();
    delete fx;   // stop() already ran; the destructor's stop is a no-op
    // the background join finished and a new server binds fine
    server_fixture_t again;
    REQUIRE(again.rpc("ping").contains("result"));
}

namespace {

struct mcp_scratch_dir_t {
    std::filesystem::path dir;
    mcp_scratch_dir_t() {
        dir = std::filesystem::temp_directory_path() /
              ("slop_mcp_" + std::to_string(::GetCurrentProcessId()) + "_" +
               std::to_string(slop::core::infra::steady_ms()) + "_" +
               std::to_string(reinterpret_cast<uintptr_t>(this) & 0xFFFF));
        std::filesystem::create_directories(dir);
    }
    ~mcp_scratch_dir_t() {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
    std::string str(const char* leaf = nullptr) const {
        return leaf ? (dir / leaf).string() : dir.string();
    }
};

std::string mcp_slurp(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());
}

uint16_t free_tcp_port() {
    WSADATA d;
    ::WSAStartup(MAKEWORD(2, 2), &d);
    const SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) return 0;
    sockaddr_in bound{};
    int len = sizeof(bound);
    ::getsockname(s, reinterpret_cast<sockaddr*>(&bound), &len);
    const uint16_t port = ntohs(bound.sin_port);
    ::closesocket(s);
    return port;
}

} // namespace

TEST_CASE(mcp_audit_log_and_confirm_gate) {
    namespace settings = slop::core::infra::settings;
    mcp_scratch_dir_t tmp;
    settings::set_file_for_testing(tmp.str("settings.json"));
    settings::load();
    settings::set("mcp_audit_enabled", true);
    settings::set("mcp_audit_path", tmp.str("audit.jsonl"));

    server_fixture_t fx;
    bool is_error = false;
    // read-only call dispatches and is audited
    json res = fx.call("target", {{"action", "status"}}, is_error);
    REQUIRE(!is_error);
    // gate on: a mutating ps4_* action without confirm is refused
    settings::set("mcp_require_confirm", true);
    res = fx.call("debugger", {{"action", "ps4_bp_set"}, {"addr", 0x1000}}, is_error);
    REQUIRE(is_error);
    REQUIRE(res.at("error").get<std::string>().find("confirm") != std::string::npos);
    // with confirm it dispatches (and fails only because no console is connected)
    res = fx.call("debugger",
                  {{"action", "ps4_bp_set"}, {"addr", 0x1000}, {"confirm", true}},
                  is_error);
    REQUIRE(is_error);
    REQUIRE(res.at("error").get<std::string>().find("confirm") == std::string::npos);
    // gate off: the same call dispatches without confirm
    settings::set("mcp_require_confirm", false);
    res = fx.call("debugger", {{"action", "ps4_bp_set"}, {"addr", 0x1000}}, is_error);
    REQUIRE(is_error);
    REQUIRE(res.at("error").get<std::string>().find("confirm") == std::string::npos);

    // the audit log holds one JSONL line per call with tool/action/ok
    const std::string log = mcp_slurp(tmp.dir / "audit.jsonl");
    REQUIRE(!log.empty());
    int lines = 0;
    bool saw_refusal = false, saw_status = false;
    std::istringstream ss(log);
    for (std::string line; std::getline(ss, line);) {
        if (line.empty()) continue;
        ++lines;
        const json j = json::parse(line);
        REQUIRE(j.contains("ts_ms"));
        REQUIRE(j.contains("tool"));
        REQUIRE(j.contains("ok"));
        if (j.at("tool") == "debugger" && j.at("action") == "ps4_bp_set" &&
            j.at("ok") == false && j.at("error").get<std::string>().find("confirm") !=
                                     std::string::npos)
            saw_refusal = true;
        if (j.at("tool") == "target" && j.at("action") == "status" && j.at("ok") == true)
            saw_status = true;
    }
    REQUIRE_EQ(lines, 4);
    REQUIRE(saw_refusal);
    REQUIRE(saw_status);
    settings::set_file_for_testing({});
}

TEST_CASE(mcp_ps4_discover_probe_answers_without_console) {
    server_fixture_t fx;
    bool is_error = false;
    json res = fx.call("target", {{"action", "ps4_discover"}, {"timeout_ms", 300}},
                       is_error);
    REQUIRE(!is_error);
    REQUIRE(res.contains("found"));
    REQUIRE_GE(res.at("found").get<int>(), 0);
    REQUIRE(res.contains("consoles"));
    REQUIRE(res.contains("probe"));
}

TEST_CASE(mcp_host_serves_payload_dir_with_sha256_manifest) {
    namespace settings = slop::core::infra::settings;
    mcp_scratch_dir_t tmp;
    settings::set_file_for_testing(tmp.str("settings.json"));
    settings::load();
    settings::set("mcp_audit_enabled", false);

    const std::filesystem::path payloads = tmp.dir / "payloads";
    std::filesystem::create_directories(payloads);
    const std::string content = "hello ps4 payload \x01\x02\x03";
    {
        std::ofstream f(payloads / "hello.bin", std::ios::binary);
        f.write(content.data(), static_cast<std::streamsize>(content.size()));
    }

    server_fixture_t fx;
    bool is_error = false;
    const uint16_t port = free_tcp_port();
    REQUIRE_GT(port, 0);
    json res = fx.call("host", {{"action", "start"},
                                {"port", port},
                                {"bind", "127.0.0.1"},
                                {"dir", payloads.string()}},
                       is_error);
    REQUIRE(!is_error);
    REQUIRE(res.at("running").get<bool>());
    REQUIRE_EQ(res.at("port").get<int>(), static_cast<int>(port));

    httplib::Client cli("127.0.0.1", port);
    cli.set_connection_timeout(std::chrono::seconds(3));
    cli.set_read_timeout(std::chrono::seconds(5));
    auto m = cli.Get("/manifest.json");
    REQUIRE(m);
    REQUIRE_EQ(m->status, 200);
    const json man = json::parse(m->body);
    REQUIRE_EQ(man.at("files").size(), 1u);
    REQUIRE_STR_EQ(man.at("files").at(0).at("name").get<std::string>().c_str(),
                   "hello.bin");
    REQUIRE_EQ(man.at("files").at(0).at("size").get<uint64_t>(), content.size());
    const std::string sha = man.at("files").at(0).at("sha256").get<std::string>();
    REQUIRE_EQ(sha.size(), 64u);

    auto f = cli.Get("/files/hello.bin");
    REQUIRE(f);
    REQUIRE_EQ(f->status, 200);
    REQUIRE(f->body == content);

    auto idx = cli.Get("/");
    REQUIRE(idx);
    REQUIRE_EQ(idx->status, 200);
    REQUIRE(idx->body.find("hello.bin") != std::string::npos);

    // put is confirm-gated while mcp_require_confirm is on
    settings::set("mcp_require_confirm", true);
    res = fx.call("host", {{"action", "put"}, {"name", "note.txt"}, {"text", "hi"}},
                  is_error);
    REQUIRE(is_error);
    REQUIRE(res.at("error").get<std::string>().find("confirm") != std::string::npos);
    settings::set("mcp_require_confirm", false);

    // put drops a file into the served dir and reports its sha256
    res = fx.call("host", {{"action", "put"}, {"name", "note.txt"}, {"text", "hi"}},
                  is_error);
    REQUIRE(!is_error);
    REQUIRE(res.at("written").get<bool>());
    REQUIRE_EQ(res.at("sha256").get<std::string>().size(), 64u);
    // path traversal via put is refused
    res = fx.call("host", {{"action", "put"}, {"name", "../evil.bin"}, {"text", "x"}},
                  is_error);
    REQUIRE(is_error);

    m = cli.Get("/manifest.json");
    REQUIRE(m);
    REQUIRE_EQ(json::parse(m->body).at("files").size(), 2u);

    res = fx.call("host", {{"action", "stop"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(!res.at("running").get<bool>());
    settings::set_file_for_testing({});
}

TEST_CASE(mcp_gdb_tool_and_broker_status) {
    namespace settings = slop::core::infra::settings;
    mcp_scratch_dir_t tmp;
    settings::set_file_for_testing(tmp.str("settings.json"));
    settings::load();
    settings::set("mcp_audit_enabled", false);

    server_fixture_t fx;
    bool is_error = false;

    // status with the bridge down: the MCP server itself is a broker client
    json res = fx.call("gdb", {{"action", "status"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(!res.at("running").get<bool>());
    REQUIRE(res.at("console").at("connected") == false);
    bool saw_mcp = false;
    for (const auto& c : res.at("broker_clients"))
        if (c.at("name") == "mcp") saw_mcp = true;
    REQUIRE(saw_mcp);

    const uint16_t port = free_tcp_port();
    REQUIRE_GT(port, 0);

    // start is confirm-gated while mcp_require_confirm is on
    settings::set("mcp_require_confirm", true);
    res = fx.call("gdb", {{"action", "start"}, {"port", port}}, is_error);
    REQUIRE(is_error);
    REQUIRE(res.at("error").get<std::string>().find("confirm") != std::string::npos);
    settings::set("mcp_require_confirm", false);

    // non-loopback bind is refused (the bridge exposes the console session)
    res = fx.call("gdb", {{"action", "start"}, {"port", port}, {"bind", "0.0.0.0"}},
                  is_error);
    REQUIRE(is_error);
    REQUIRE(res.at("error").get<std::string>().find("loopback") != std::string::npos);

    // start on loopback works even without a console attached
    res = fx.call("gdb", {{"action", "start"}, {"port", port}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(res.at("running").get<bool>());
    REQUIRE_EQ(res.at("port").get<int>(), static_cast<int>(port));

    // a raw RSP client can handshake without any console session
    {
        WSADATA d;
        ::WSAStartup(MAKEWORD(2, 2), &d);
        const SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        REQUIRE(s != INVALID_SOCKET);
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
        REQUIRE(::connect(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0);
        DWORD to = 3000;
        ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&to),
                     sizeof(to));
        const std::string cmd = "qSupported";
        uint8_t sum = 0;
        for (char ch : cmd) sum = static_cast<uint8_t>(sum + static_cast<uint8_t>(ch));
        char pkt[64];
        std::snprintf(pkt, sizeof(pkt), "$%s#%02x", cmd.c_str(), sum);
        REQUIRE(::send(s, pkt, static_cast<int>(std::strlen(pkt)), 0) != SOCKET_ERROR);
        std::string reply;
        char ch;
        for (;;) {              // skip acks until the frame starts
            if (::recv(s, &ch, 1, 0) != 1) break;
            if (ch == '$') break;
        }
        for (;;) {
            if (::recv(s, &ch, 1, 0) != 1) break;
            if (ch == '#') { char cc[2]; ::recv(s, cc, 2, 0); break; }
            reply += ch;
        }
        REQUIRE(reply.rfind("PacketSize=4000", 0) == 0);

        // while connected, status shows the RSP client and the gdb broker entry
        res = fx.call("gdb", {{"action", "status"}}, is_error);
        REQUIRE(!is_error);
        REQUIRE(res.at("running").get<bool>());
        REQUIRE_GE(res.at("rsp_clients").get<int>(), 1);
        bool saw_gdb = false;
        for (const auto& c : res.at("broker_clients"))
            if (c.at("name").get<std::string>().rfind("gdb:", 0) == 0) saw_gdb = true;
        REQUIRE(saw_gdb);
        ::closesocket(s);
    }

    res = fx.call("gdb", {{"action", "stop"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(!res.at("running").get<bool>());
    res = fx.call("gdb", {{"action", "status"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(!res.at("running").get<bool>());
    settings::set_file_for_testing({});
}

// === versioned api surface, openapi, rate limits, progress, resources/prompts ===

TEST_CASE(mcp_api_v1_prefix_and_deprecated_alias) {
    server_fixture_t fx;
    // guide.list is pure static data, so both paths must answer byte-identically
    const json req = {{"tool", "guide"}, {"action", "list"}};

    auto v1 = fx.cli_->Post("/api/v1", req.dump(), "application/json");
    REQUIRE(v1);
    REQUIRE_EQ(v1->status, 200);
    REQUIRE(json::parse(v1->body).value("ok", false));
    REQUIRE(v1->get_header_value("Deprecation").empty());

    // the old path answers the same body, flagged deprecated
    auto alias = fx.cli_->Post("/api", req.dump(), "application/json");
    REQUIRE(alias);
    REQUIRE_EQ(alias->status, 200);
    REQUIRE_STR_EQ(alias->get_header_value("Deprecation").c_str(), "true");
    REQUIRE(alias->body == v1->body);

    // the event stream moved with it; both paths deliver the hello event
    const auto ticket = [&] {
        const json t = {{"tool", "app"}, {"action", "events_ticket"}};
        auto res = fx.cli_->Post("/api/v1", t.dump(), "application/json");
        REQUIRE(res);
        return json::parse(res->body).at("data").at("ticket").get<std::string>();
    };
    const auto hello_seen = [&](const std::string& path) {
        std::string got;
        httplib::Client cli("127.0.0.1", fx.port());
        cli.set_read_timeout(std::chrono::seconds(5));
        // the receiver cancels once hello lands, so the result carries no response
        cli.Get(path, [&](const char* data, size_t len) {
            got.append(data, len);
            return got.find("event: hello") == std::string::npos;
        });
        return got.find("event: hello") != std::string::npos;
    };
    REQUIRE(hello_seen("/api/v1/events?ticket=" + ticket()));
    REQUIRE(hello_seen("/events?ticket=" + ticket()));
}

TEST_CASE(mcp_openapi_descriptor_matches_tools_list) {
    server_fixture_t fx;
    auto res = fx.cli_->Get("/api/v1/openapi.json");
    REQUIRE(res);
    REQUIRE_EQ(res->status, 200);
    const json doc = json::parse(res->body);
    REQUIRE_STR_EQ(doc.at("openapi").get<std::string>().c_str(), "3.1.0");
    REQUIRE(doc.at("paths").contains("/api/v1"));
    REQUIRE(doc.at("components").at("schemas").contains("ApiCall"));

    const json tools = fx.rpc("tools/list").at("result").at("tools");
    REQUIRE_EQ(tools.size(), 22u);
    for (const auto& t : tools) {
        const std::string n = t.at("name").get<std::string>();
        REQUIRE(doc.at("components").at("schemas").contains(n));
        // the descriptor carries the exact input schema the mcp clients see
        REQUIRE(doc.at("components").at("schemas").at(n) == t.at("inputSchema"));
        const auto& tool_enum = doc.at("components").at("schemas").at("ApiCall")
                                    .at("properties").at("tool").at("enum");
        REQUIRE(std::find(tool_enum.begin(), tool_enum.end(), n) != tool_enum.end());
    }
}

TEST_CASE(mcp_rate_limit_trips_with_retry_after) {
    scratch_settings_t scratch;
    REQUIRE(slop::core::infra::settings::set(
        "mcp_rate_limits", {{"guide", {{"rate", 0.5}, {"burst", 2}}}}));
    server_fixture_t fx;
    const json call = {{"jsonrpc", "2.0"},
                       {"id", 9},
                       {"method", "tools/call"},
                       {"params", {{"name", "guide"}, {"arguments", {{"action", "list"}}}}}};

    for (int i = 0; i < 2; ++i) {
        auto ok = fx.cli_->Post("/mcp", call.dump(), "application/json");
        REQUIRE(ok);
        REQUIRE_EQ(ok->status, 200);
        REQUIRE(!json::parse(ok->body).at("result").value("isError", true));
    }

    auto limited = fx.cli_->Post("/mcp", call.dump(), "application/json");
    REQUIRE(limited);
    REQUIRE_EQ(limited->status, 429);
    REQUIRE(!limited->get_header_value("Retry-After").empty());
    const json err = json::parse(limited->body).at("error");
    REQUIRE_EQ(err.at("code").get<int>(), -32002);
    REQUIRE_GT(err.at("data").at("retry_after_ms").get<int64_t>(), 0);
    REQUIRE(err.at("message").get<std::string>().find("rate limit") != std::string::npos);

    // the ui channel is exempt: opening a view must never spend the agent budget
    for (int i = 0; i < 5; ++i) REQUIRE(fx.api("guide", "list").value("ok", false));
}

TEST_CASE(mcp_progress_notifications_reach_the_stream) {
    server_fixture_t fx;
    std::mutex mu;
    std::string got;
    std::atomic<bool> open{false};
    std::thread reader([&] {
        httplib::Client cli("127.0.0.1", fx.port());
        cli.set_read_timeout(std::chrono::seconds(10));
        cli.Get("/mcp", [&](const char* data, size_t len) {
            std::lock_guard lk(mu);
            got.append(data, len);
            if (got.find("event: endpoint") != std::string::npos) open = true;
            return got.find("guide.list done") == std::string::npos;
        });
    });
    for (int i = 0; i < 300 && !open.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    REQUIRE(open.load());

    const json req = {{"jsonrpc", "2.0"},
                      {"id", 11},
                      {"method", "tools/call"},
                      {"params",
                       {{"name", "guide"},
                        {"arguments", {{"action", "list"}}},
                        {"_meta", {{"progressToken", "tok-1"}}}}}};
    auto res = fx.cli_->Post("/mcp", req.dump(), "application/json");
    REQUIRE(res);
    REQUIRE_EQ(res->status, 200);
    reader.join();

    std::vector<double> seen;
    {
        std::lock_guard lk(mu);
        REQUIRE(got.find("notifications/progress") != std::string::npos);
        REQUIRE(got.find("\"progressToken\":\"tok-1\"") != std::string::npos);
        size_t at = 0;
        while ((at = got.find("data: ", at)) != std::string::npos) {
            at += 6;
            const size_t end = got.find('\n', at);
            const json msg = json::parse(got.substr(at, end - at), nullptr, false);
            if (msg.is_discarded() || !msg.is_object()) continue;
            if (msg.value("method", std::string{}) != "notifications/progress") continue;
            const auto& p = msg.at("params");
            REQUIRE_STR_EQ(p.at("progressToken").get<std::string>().c_str(), "tok-1");
            REQUIRE(p.contains("message"));
            seen.push_back(p.at("progress").get<double>());
        }
    }
    REQUIRE_GE(seen.size(), 2u);
    REQUIRE_EQ(seen.front(), 0.0);
    REQUIRE_EQ(seen.back(), 1.0);
    for (size_t i = 1; i < seen.size(); ++i) REQUIRE_GE(seen[i], seen[i - 1]);
}

TEST_CASE(mcp_resources_and_prompts_roundtrip) {
    server_fixture_t fx;

    const json init = fx.rpc("initialize", {{"protocolVersion", "2025-06-18"},
                                            {"capabilities", json::object()}});
    const auto& caps = init.at("result").at("capabilities");
    REQUIRE(caps.contains("tools"));
    REQUIRE(caps.contains("resources"));
    REQUIRE(caps.contains("prompts"));

    const json resources = fx.rpc("resources/list").at("result").at("resources");
    REQUIRE_GE(resources.size(), 3u);
    bool has_target = false, has_image = false, has_guide = false;
    for (const auto& r : resources) {
        REQUIRE(r.contains("uri"));
        REQUIRE(r.contains("mimeType"));
        const std::string uri = r.at("uri").get<std::string>();
        if (uri == "slop://state/target") has_target = true;
        if (uri == "slop://state/image") has_image = true;
        if (uri.rfind("slop://guide/", 0) == 0) has_guide = true;
    }
    REQUIRE(has_target);
    REQUIRE(has_image);
    REQUIRE(has_guide);

    const auto text_of = [](const json& read) {
        return json::parse(read.at("result").at("contents").at(0).at("text").get<std::string>());
    };
    const json playbook = text_of(fx.rpc("resources/read", {{"uri", "slop://guide/ps4_setup"}}));
    REQUIRE_STR_EQ(playbook.at("topic").get<std::string>().c_str(), "ps4_setup");
    REQUIRE(!playbook.at("steps").empty());
    const json target = text_of(fx.rpc("resources/read", {{"uri", "slop://state/target"}}));
    REQUIRE(target.contains("target"));
    const json image = text_of(fx.rpc("resources/read", {{"uri", "slop://state/image"}}));
    REQUIRE(image.contains("image"));
    REQUIRE(fx.rpc("resources/read", {{"uri", "slop://nope"}}).contains("error"));

    const json prompts = fx.rpc("prompts/list").at("result").at("prompts");
    REQUIRE_GE(prompts.size(), 5u);
    bool named = false;
    for (const auto& p : prompts) {
        REQUIRE(p.contains("name"));
        REQUIRE(p.contains("description"));
        if (p.at("name") == "ps4_setup") named = true;
    }
    REQUIRE(named);
    const json got = fx.rpc("prompts/get", {{"name", "ps4_setup"}}).at("result");
    REQUIRE_STR_EQ(got.at("messages").at(0).at("role").get<std::string>().c_str(), "user");
    const std::string prompt_text =
        got.at("messages").at(0).at("content").at("text").get<std::string>();
    REQUIRE(prompt_text.find("ps4_auto") != std::string::npos);
    REQUIRE(fx.rpc("prompts/get", {{"name", "nope"}}).contains("error"));
}

TEST_CASE(mcp_annotations_match_mutating_classification) {
    server_fixture_t fx;
    const json tools = fx.rpc("tools/list").at("result").at("tools");
    REQUIRE_GE(tools.size(), 20u);
    for (const auto& t : tools) {
        const std::string name = t.at("name").get<std::string>();
        REQUIRE(t.contains("annotations"));
        const auto& a = t.at("annotations");
        for (const char* k : {"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"})
            REQUIRE(a.at(k).is_boolean());
        REQUIRE(a.at("title").is_string());

        bool mutating = false;
        for (const auto& act : t.at("inputSchema").at("properties").at("action").at("enum"))
            mutating = mutating ||
                       slop::core::mcp::action_mutating(name, act.get<std::string>());
        if (mutating) REQUIRE_FALSE(a.at("readOnlyHint").get<bool>());
        // a destructive tool is never advertised as read-only
        if (a.at("destructiveHint").get<bool>()) REQUIRE_FALSE(a.at("readOnlyHint").get<bool>());
        // read-only tools are idempotent; writers make no such promise
        if (a.at("readOnlyHint").get<bool>()) REQUIRE(a.at("idempotentHint").get<bool>());
    }
}

TEST_CASE(mcp_explicit_port_is_honored) {
    // --port reaches the bind: ask for a known free port and get exactly it
    const auto free_port = [] {
        uint16_t p = 0;
        SOCKET s = ::socket(AF_INET, SOCK_STREAM, 0);
        if (s == INVALID_SOCKET) return p;
        sockaddr_in a{};
        a.sin_family      = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port        = 0;
        if (::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0) {
            int len = sizeof(a);
            if (::getsockname(s, reinterpret_cast<sockaddr*>(&a), &len) == 0)
                p = ntohs(a.sin_port);
        }
        ::closesocket(s);
        return p;
    };
    uint16_t want = 0;
    bool started  = false;
    for (int attempt = 0; attempt < 5 && !started; ++attempt) {
        want = free_port();
        REQUIRE_GT(want, 0);
        slop::core::mcp::server_config_t cfg;
        cfg.port = want;
        started  = slop::core::mcp::start(cfg);
    }
    REQUIRE(started);
    REQUIRE_EQ(slop::core::mcp::port(), want);
    slop::core::mcp::stop();
}
