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

    // ---- console-side capabilities (ps4debug-NG) ---------------------------

    // CMD_PROC_AUTH challenge-response (the payload's keystream is four LFSRs
    // seeded 200/300/400/500 - see debugger/source/proc.c auth_lfsr_next).
    // Run automatically on connect; bit 1 (0x2) unlocks the scan family.
    bool ps4_auth(uint32_t flags, std::string& err);
    bool ps4_authed() const noexcept;

    // one scan hit: absolute address plus the raw value bytes found there
    struct ps4_scan_hit_t {
        uint64_t              addr = 0;
        std::vector<uint8_t>  value;
    };
    // SCAN_START: seed scan of [addr, addr+len). compare/data per the
    // kVal*/kCmp* constants in ps4_protocol.hpp; data carries lenData bytes
    // (two values for kCmpBetween). Fills hits; ok=false on wire/protocol error
    io_result_t ps4_scan_first(uint32_t pid, uint64_t addr, uint32_t len,
                               uint8_t valtype, uint8_t cmptype, uint8_t alignment,
                               const std::vector<uint8_t>& data,
                               std::vector<ps4_scan_hit_t>& hits);
    // SCAN_COUNT: narrow previous hits (offsets relative to base) with a new
    // comparison. prev entries carry the value bytes when the compare type
    // needs the previous value
    io_result_t ps4_scan_next(uint32_t pid, uint64_t base,
                              uint8_t valtype, uint8_t cmptype,
                              const std::vector<ps4_scan_hit_t>& prev,
                              const std::vector<uint8_t>& data,
                              std::vector<ps4_scan_hit_t>& hits);
    // legacy whole-memory single-pass scan (CMD_PROC_SCAN)
    io_result_t ps4_scan_all(uint32_t pid, uint8_t valtype, uint8_t cmptype,
                             const std::vector<uint8_t>& data,
                             std::vector<uint64_t>& addrs);
    // array-of-bytes scan over [addr, addr+len); mask byte 1 = exact, 0 = wildcard.
    // Returns the max_matches-th match (0 if none / invalidated)
    io_result_t ps4_scan_aob(uint32_t pid, uint64_t addr, uint32_t len,
                             const std::vector<uint8_t>& pattern,
                             const std::vector<uint8_t>& mask,
                             uint8_t max_matches, uint8_t stop_flag,
                             uint64_t& out_addr);

    // one on-device decoded instruction (CMD_PROC_DISASM_REGION)
    struct ps4_disasm_entry_t {
        uint64_t addr = 0;
        uint64_t rip_rel_target = 0;
        int64_t  mem_disp = 0;
        uint8_t  length = 0;
        uint8_t  kind = 0;          // ps4::disasm_instr_entry_t kind bits
        uint8_t  mem_base_reg = 0;
        uint8_t  mem_index_reg = 0;
        uint8_t  mem_scale = 0;
        uint8_t  mnemonic_lo = 0;
    };
    io_result_t ps4_disasm_region(uint32_t pid, uint64_t addr, uint32_t len,
                                  uint32_t max_entries,
                                  std::vector<ps4_disasm_entry_t>& out);
    // RIP-relative branch/call targets inside [addr, addr+len)
    io_result_t ps4_extract_xrefs(uint32_t pid, uint64_t addr, uint32_t len,
                                  uint32_t max_instrs, std::vector<uint64_t>& targets);
    // addresses inside [addr, addr+len) that branch/call target
    io_result_t ps4_find_xrefs_to(uint32_t pid, uint64_t addr, uint32_t len,
                                  uint64_t target, std::vector<uint64_t>& addrs);

    // one server-side stack frame from CMD_PROC_READ_STACK
    struct ps4_stack_frame_t {
        uint64_t rbp = 0, rsp = 0, saved_rbp = 0, ret_addr = 0;
        uint32_t flags = 0;                 // bit0: frame locals omitted
        std::vector<uint8_t> locals;        // rsp..rbp bytes when present
        std::vector<uint8_t> code;          // window around ret_addr
    };
    io_result_t ps4_read_stack(uint32_t pid, uint64_t rbp, uint64_t rsp,
                               uint32_t depth, std::vector<ps4_stack_frame_t>& frames);

    // on-device Keystone assemble (0xBDAA0024); syntax 0 = default (Intel)
    io_result_t ps4_assemble(uint64_t base_addr, uint32_t syntax,
                             const std::string& asm_text,
                             std::vector<uint8_t>& out_bytes, uint32_t& insn_count,
                             std::string& asm_err);

    // upload an ELF to the console process: load+run (entry jump) or RPC
    // (returns entry address without jumping)
    io_result_t ps4_elf_load(uint32_t pid, const std::vector<uint8_t>& elf);
    io_result_t ps4_elf_rpc(uint32_t pid, const std::vector<uint8_t>& elf, uint64_t& entry);

    // console feedback: on-screen notification / kernel log print /
    // foreground game metadata
    io_result_t ps4_console_notify(uint32_t message_type, const std::string& text);
    io_result_t ps4_console_print(const std::string& text);
    struct ps4_app_info_t {
        uint32_t pid = 0;
        std::string titleid, contentid, name, app_ver;
    };
    io_result_t ps4_foreground_app(ps4_app_info_t& out);

    // extra register sets while a debug session is attached
    io_result_t ps4_get_fpregs(uint32_t lwpid, uint8_t out[832]);
    io_result_t ps4_set_fpregs(uint32_t lwpid, const uint8_t* data, uint32_t len);
    io_result_t ps4_set_dbregs(uint32_t lwpid, const uint8_t dr[128]);
    io_result_t ps4_get_fsgsbase(uint32_t lwpid, uint64_t& fs_base, uint64_t& gs_base);
    io_result_t ps4_set_fsgsbase(uint32_t lwpid, uint64_t fs_base, uint64_t gs_base);

private:
    struct impl_t;
    std::unique_ptr<impl_t> m_impl;
};

} // namespace slop::core::runtime
