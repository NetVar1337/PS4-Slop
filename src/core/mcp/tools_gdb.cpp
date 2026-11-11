// src/core/mcp/tools_gdb.cpp
// tool: gdb — control the GDB Remote Serial Protocol bridge (gdb_rsp) that
// lets GDB/LLDB/Binary Ninja share the console debug session with the UI and
// the MCP tools. Memory/register writes over RSP (M/G/P) are refused unless
// the bridge was started with allow_writes=true.

#include "core/mcp/tools_common.hpp"
#include "core/runtime/broker.hpp"
#include "core/runtime/gdb_rsp.hpp"

namespace slop::core::mcp::detail {

json tool_gdb(const json& args) {
    const std::string action = require_action(args);
    auto& srv = runtime::gdb_rsp();

    if (action == "status") {
        json out = {{"running", srv.running()},
                    {"port", srv.port()},
                    {"allow_writes", srv.allow_writes()},
                    {"rsp_clients", srv.client_count()}};
        if (srv.running())
            out["hint"] = "connect with: gdb -ex 'target remote 127.0.0.1:" +
                          std::to_string(srv.port()) + "' (needs debugger.ps4_attach first)";
        json clients = json::array();
        for (const auto& [name, since] : runtime::broker_clients())
            clients.push_back({{"name", name}, {"since_ms", since}});
        out["broker_clients"] = clients;
        auto* p = runtime::registry_ps4();
        out["console"] = p && p->connected()
            ? json{{"connected", true}, {"endpoint", p->endpoint()},
                   {"debug_attached", p->ps4_debug_attached()},
                   {"debug_pid", p->ps4_debug_pid()}}
            : json{{"connected", false}};
        return out;
    }

    if (action == "start") {
        if (srv.running())
            fail("gdb.start: already running on port " + std::to_string(srv.port()) +
                 " (stop first)");
        const uint64_t port = args.contains("port") ? parse_addr(args, "port")
                                                    : 2331;
        if (port == 0 || port > 0xFFFF) fail("gdb.start: bad port");
        const std::string bind = args.value("bind", "127.0.0.1");
        const bool allow_writes = args.value("allow_writes", false);
        if (bind != "127.0.0.1" && bind != "localhost" && bind != "::1")
            fail("gdb.start: non-loopback bind is refused; the bridge exposes the "
                 "console debug session, keep it on loopback (use an SSH tunnel "
                 "for remote GDB)");
        std::string err;
        if (!srv.start(bind, static_cast<uint16_t>(port), allow_writes, err))
            fail("gdb.start failed: " + err);
        return {{"running", true},
                {"port", srv.port()},
                {"bind", bind},
                {"allow_writes", allow_writes},
                {"hint", "gdb -ex 'target remote 127.0.0.1:" + std::to_string(srv.port()) +
                             "' — the console needs debugger.ps4_attach {pid} first"}};
    }

    if (action == "stop") {
        srv.stop();
        return {{"running", false}};
    }

    fail("gdb: unknown action '" + action + "' (start|stop|status)");
}

} // namespace slop::core::mcp::detail
