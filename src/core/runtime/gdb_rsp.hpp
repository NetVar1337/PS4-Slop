#pragma once

// src/core/runtime/gdb_rsp.hpp
// GDB Remote Serial Protocol bridge over the shared PS4 debug session.
// Ported from PS4-MCP's rsp.rs/broker: a TCP listener that speaks RSP so GDB,
// LLDB or Binary Ninja can attach to the console debug session that the UI
// and the MCP tools are already using. All console operations take
// broker_gate(), so a GDB client, an MCP agent and the UI serialize on the
// one console connection instead of racing. Memory/register writes (M/G/P)
// are refused unless the server was started with allow_writes=true.

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

namespace slop::core::runtime {

class backend_ps4_t;

class gdb_rsp_server_t {
public:
    gdb_rsp_server_t();
    ~gdb_rsp_server_t();

    gdb_rsp_server_t(const gdb_rsp_server_t&) = delete;
    gdb_rsp_server_t& operator=(const gdb_rsp_server_t&) = delete;

    // binds 0.0.0.0:port? No: 127.0.0.1 by default is not enough for a console
    // on the LAN, but the bridge talks to the PC-side backend, not the
    // console, so loopback is the safe default; pass bind explicitly.
    bool start(const std::string& bind, uint16_t port, bool allow_writes,
               std::string& err, backend_ps4_t* test_backend = nullptr);
    void stop();

    bool     running() const noexcept;
    uint16_t port() const noexcept;
    bool     allow_writes() const noexcept;
    size_t   client_count() const noexcept;   // live RSP connections

private:
    struct impl_t;
    std::unique_ptr<impl_t> p_;
};

// process-wide bridge driven by the MCP "gdb" tool
gdb_rsp_server_t& gdb_rsp();

} // namespace slop::core::runtime
