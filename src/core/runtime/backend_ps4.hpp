#pragma once

// src/core/runtime/backend_ps4.hpp
// Remote PS4 backend: speaks the ps4debug-NG wire protocol (TCP 744) to a
// console running the ps4debug-NG payload, so memory/enumeration actions work
// on the console exactly like on a local process

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "core/runtime/backend.hpp"

namespace slop::core::runtime {

// one server->client debug event (ps4debug-NG port-755 packet, 0x4A0 bytes)
struct ps4_event_t {
    uint32_t         lwpid = 0;
    uint32_t         status = 0;    // raw wait4 status
    int              signal = 0;    // (status >> 8) & 0xFF
    char             thread_name[41]{};
    thread_context_t ctx{};
    uint64_t         dr[16]{};
};

class backend_ps4_t final : public backend_t {
public:
    backend_ps4_t();
    ~backend_ps4_t() override;

    backend_ps4_t(const backend_ps4_t&) = delete;
    backend_ps4_t& operator=(const backend_ps4_t&) = delete;

    // connection management (outside the backend_t interface)
    bool        connect(const std::string& host, uint16_t port, std::string& err);
    void        disconnect();
    bool        connected() const noexcept;
    bool        ping();   // CMD_PROC_NOP roundtrip, liveness probe
    std::string endpoint() const;   // "host:port" or "" when not connected
    std::string branding() const;   // server branding string or ""
    uint16_t    fw_version() const noexcept;  // BCD (e.g. 0x1100 = 11.00), 0 if unknown

    // Identity
    backend_kind_t kind() const noexcept override;
    const char*    badge() const noexcept override;

    // Attach / Detach
    target_handle_t attach(uint32_t pid) override;
    void            detach(target_handle_t& h) override;

    // Memory
    io_result_t read_memory(const target_handle_t& h, uintptr_t addr, void* buf, size_t len) override;
    io_result_t write_memory(const target_handle_t& h, uintptr_t addr, const void* buf, size_t len) override;
    io_result_t protect_memory(const target_handle_t& h, uintptr_t addr, size_t len, uint32_t new_prot, uint32_t* old_prot) override;
    io_result_t allocate_memory(const target_handle_t& h, uintptr_t addr, size_t len, uint32_t prot, uintptr_t* out_addr) override;
    io_result_t free_memory(const target_handle_t& h, uintptr_t addr) override;

    // Enumeration
    enum_result_t<process_info_t> enum_processes() override;
    enum_result_t<module_info_t>  enum_modules(const target_handle_t& h) override;
    enum_result_t<thread_info_t>  enum_threads(uint32_t pid) override;
    enum_result_t<region_info_t>  enum_regions(const target_handle_t& h) override;
    enum_result_t<handle_info_t>  enum_handles(uint32_t pid) override;

    // Thread context
    io_result_t get_thread_context(uint32_t tid, thread_context_t& ctx) override;
    io_result_t set_thread_context(uint32_t tid, const thread_context_t& ctx) override;

    // Query
    arch_t      query_arch(const target_handle_t& h) override;
    elevation_t query_elevation() override;

    // ---- live debug session (ps4debug-NG remote debugger) -----------------
    // These drive CMD_DEBUG_* on the same connection; ps4_debug_attach also
    // starts the port-755 event listener that feeds ps4_wait_event/drain.
    bool        ps4_debug_attach(uint32_t pid, std::string& err);
    bool        ps4_debug_detach();
    bool        ps4_debug_attached() const noexcept;
    uint32_t    ps4_debug_pid() const noexcept;

    io_result_t ps4_set_breakpoint(uint32_t index, bool enabled, uintptr_t addr);
    io_result_t ps4_set_watchpoint(uint32_t index, bool enabled, uint32_t len,
                                   uint32_t type, uintptr_t addr);
    io_result_t ps4_continue(uint32_t stop);   // ps4::kStopResume/Stop/Kill
    io_result_t ps4_step(uint32_t lwpid);      // 0 = all threads
    io_result_t ps4_suspend_thread(uint32_t lwpid);
    io_result_t ps4_resume_thread(uint32_t lwpid);
    io_result_t ps4_process_stop(uint32_t pid, uint32_t state);
    io_result_t ps4_get_dbregs(uint32_t lwpid, uint64_t dr[16]);

    // remote function call through the payload's rpc stub (CMD_PROC_INTALL /
    // CMD_PROC_CALL); args are rdi, rsi, rdx, rcx, r8, r9
    io_result_t ps4_install(uint32_t pid, uint64_t& rpcstub);
    io_result_t ps4_call(uint32_t pid, uint64_t rpcstub, uint64_t rip,
                         const uint64_t args[6], uint64_t& out_rax);

    // debug event stream (port 755)
    size_t                   ps4_pending_events();
    bool                     ps4_wait_event(ps4_event_t& out, int timeout_ms);
    std::vector<ps4_event_t> ps4_drain_events(size_t max, bool clear);

private:
    struct impl_t;
    std::unique_ptr<impl_t> m_impl;
};

} // namespace slop::core::runtime
