#pragma once

// src/core/runtime/backend_ps5.hpp
// Remote PS5 backend: speaks the ps5debug-NG wire protocol (TCP 744) to a
// console running the payload, so memory/enumeration actions work on the
// console exactly like on a local process.
//
// ps5debug-NG descends from ps4debug, so the vm_map entry layout and the
// port-755 stop packet are byte-identical to ps4debug-NG's: the segment /
// module grouping and the stop-event decoder are shared with the PS4 backend
// instead of duplicated.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "core/runtime/backend.hpp"
#include "core/runtime/backend_ps4.hpp"

namespace slop::core::runtime {

// one stop event (payload->client port-755 packet); same layout as PS4's
using ps5_event_t = ps4_event_t;

// one vm_map entry / one module (adjacent same-named maps coalesced)
using ps5_segment_t = ps4_segment_t;
using ps5_module_t  = ps4_module_t;

class backend_ps5_t final : public backend_t {
public:
    backend_ps5_t();
    ~backend_ps5_t() override;

    backend_ps5_t(const backend_ps5_t&) = delete;
    backend_ps5_t& operator=(const backend_ps5_t&) = delete;

    // ---- connection management (outside the backend_t interface) ----------
    // connect() is a fresh logical connection: handles from an earlier
    // connection become stale, client-side slot state is cleared
    bool        connect(const std::string& host, uint16_t port, std::string& err);
    void        disconnect();
    bool        connected() const noexcept;
    bool        ping();   // CMD_PROC_NOP roundtrip, liveness probe
    std::string endpoint() const;        // "host:port" or "" when not connected
    std::string branding() const;        // server branding string or ""
    std::string server_caps() const;     // capability tail of the branding blob
    std::string server_version() const;  // CMD_VERSION string or ""
    uint16_t    fw_version() const noexcept;   // 900 = 9.00, 0 if unknown
    std::string fw_string() const;             // "9.00" or "" if unknown
    uint16_t    platform_id() const noexcept;  // CMD_PLATFORM_ID tag (5 = PS5)

    // any send/recv failure (error, peer close, timeout, desync) closes the
    // socket so connected() goes false and callers fail fast. lost() then
    // reports the dropped connection until reconnect()/connect()/disconnect()
    bool        lost() const noexcept;
    std::string lost_reason() const;
    uint64_t    drop_count() const noexcept;   // connections lost so far
    std::string last_endpoint() const;         // remembered for reconnect

    // re-open the remembered endpoint, re-run the handshake, then restore the
    // debug session the dropped connection had (the payload keeps debug state
    // per connection) and every breakpoint/watchpoint slot this client armed.
    // Existing target handles stay valid.
    struct reconnect_report_t {
        bool        handshake_ok = false;
        uint32_t    debug_pid = 0;          // pid re-attached (0 = none wanted)
        bool        debug_restored = false;
        std::string debug_error;
        uint32_t    bp_rearmed = 0, bp_failed = 0;
        uint32_t    wp_rearmed = 0, wp_failed = 0;
    };
    bool reconnect(std::string& err, reconnect_report_t* report = nullptr);

    // ---- identity
    backend_kind_t kind() const noexcept override;
    const char*    badge() const noexcept override;

    // ---- attach / detach
    target_handle_t attach(uint32_t pid) override;
    void            detach(target_handle_t& h) override;

    // ---- memory
    io_result_t read_memory(const target_handle_t& h, uintptr_t addr, void* buf, size_t len) override;
    io_result_t write_memory(const target_handle_t& h, uintptr_t addr, const void* buf, size_t len) override;
    io_result_t protect_memory(const target_handle_t& h, uintptr_t addr, size_t len, uint32_t new_prot, uint32_t* old_prot) override;
    io_result_t allocate_memory(const target_handle_t& h, uintptr_t addr, size_t len, uint32_t prot, uintptr_t* out_addr) override;
    io_result_t free_memory(const target_handle_t& h, uintptr_t addr) override;

    // ---- enumeration
    enum_result_t<process_info_t> enum_processes() override;
    // one record per module (segments coalesced, see ps4_coalesce_modules)
    enum_result_t<module_info_t>  enum_modules(const target_handle_t& h) override;
    // needs a debug session: the payload only lists lwpids while attached
    enum_result_t<thread_info_t>  enum_threads(uint32_t pid) override;
    enum_result_t<region_info_t>  enum_regions(const target_handle_t& h) override;
    enum_result_t<handle_info_t>  enum_handles(uint32_t pid) override;

    // modules with their individual segments (for whole-module dumps)
    enum_result_t<ps5_module_t>   ps5_modules(const target_handle_t& h);
    // raw maps of the handle's process
    enum_result_t<ps5_segment_t>  ps5_maps(const target_handle_t& h);

    // ---- thread context (needs a debug session)
    io_result_t get_thread_context(uint32_t tid, thread_context_t& ctx) override;
    io_result_t set_thread_context(uint32_t tid, const thread_context_t& ctx) override;

    // ---- query
    arch_t      query_arch(const target_handle_t& h) override;
    elevation_t query_elevation() override;
    bool        handle_info(const target_handle_t& h, process_info_t& out) override;

    // ---- live debug session (ps5debug-NG remote debugger) -----------------
    // ps5_debug_attach also starts the port-755 event listener that feeds
    // ps5_wait_event/ps5_drain_events
    bool        ps5_debug_attach(uint32_t pid, std::string& err);
    bool        ps5_debug_detach();
    bool        ps5_debug_attached() const noexcept;
    uint32_t    ps5_debug_pid() const noexcept;

    io_result_t ps5_set_breakpoint(uint32_t index, bool enabled, uintptr_t addr);
    io_result_t ps5_set_watchpoint(uint32_t index, bool enabled, uint32_t len,
                                   uint32_t type, uintptr_t addr);
    io_result_t ps5_continue(uint32_t stop);   // ps5::kStopResume/Stop/Kill
    io_result_t ps5_step(uint32_t lwpid);      // 0 = all threads
    io_result_t ps5_suspend_thread(uint32_t lwpid);
    io_result_t ps5_resume_thread(uint32_t lwpid);
    io_result_t ps5_get_regs(uint32_t lwpid, thread_context_t& ctx);
    io_result_t ps5_set_regs(uint32_t lwpid, const thread_context_t& ctx);
    io_result_t ps5_thread_list(std::vector<uint32_t>& lwpids);

    // ---- client-side breakpoint/watchpoint slot bookkeeping ---------------
    // The payload cannot list its slots, so this client records what it
    // armed. Records are cleared when the debug session ends (detach, attach
    // to another pid, connect, disconnect); a dropped connection keeps them
    // (armed=false) so reconnect() can re-arm them.
    static constexpr uint32_t kAutoSlot = 0xFFFFFFFFu;
    struct ps5_slot_t {
        uint32_t index = 0;
        uint64_t addr  = 0;
        uint32_t len   = 0;     // watchpoints only
        uint32_t type  = 0;     // watchpoints only (ps5::kWp*)
        bool     armed = false; // false while the connection is down
    };
    std::vector<ps5_slot_t> ps5_breakpoints() const;
    std::vector<ps5_slot_t> ps5_watchpoints() const;
    // index == kAutoSlot: reuse the slot already armed at addr, else the first
    // free one. reused says whether addr was already armed by us
    io_result_t ps5_bp_arm(uint64_t addr, uint32_t index, uint32_t& out_index,
                           bool* reused = nullptr);
    io_result_t ps5_bp_disarm(uint32_t index, uint64_t* out_addr = nullptr);
    io_result_t ps5_bp_disarm_addr(uint64_t addr, uint32_t* out_index = nullptr);
    io_result_t ps5_wp_arm(uint64_t addr, uint32_t len, uint32_t type, uint32_t index,
                           uint32_t& out_index, bool* reused = nullptr);
    io_result_t ps5_wp_disarm(uint32_t index, uint64_t* out_addr = nullptr);
    io_result_t ps5_wp_disarm_addr(uint64_t addr, uint32_t* out_index = nullptr);

    // debug event stream (port 755)
    size_t                   ps5_pending_events();
    bool                     ps5_wait_event(ps5_event_t& out, int timeout_ms);
    std::vector<ps5_event_t> ps5_drain_events(size_t max, bool clear);
    uint64_t                 ps5_events_received() const noexcept;  // packets decoded
    uint64_t                 ps5_events_dropped() const noexcept;   // lost to the queue cap
    static constexpr size_t  kMaxQueuedEvents = 4096;

    // ---- console-side capabilities ----------------------------------------

    // CMD_CONSOLE_INFO roundtrip (the payload answers a bare CMD_SUCCESS)
    // plus everything the handshake learned about the console
    struct ps5_console_info_t {
        bool        alive = false;      // CMD_CONSOLE_INFO answered
        std::string endpoint, branding, caps, version, fw;
        uint16_t    fw_bcd = 0;
        uint16_t    platform = 0;       // CMD_PLATFORM_ID tag (5 = PS5)
        uint32_t    debug_pid = 0;
        uint64_t    drops = 0;
    };
    io_result_t ps5_console_info(ps5_console_info_t& out);

    // console feedback: on-screen notification / kernel log print /
    // foreground game metadata
    io_result_t ps5_notify(const std::string& text);
    io_result_t ps5_print(const std::string& text);
    struct ps5_app_info_t {
        uint32_t pid = 0;
        std::string titleid, contentid, name, app_ver;
    };
    io_result_t ps5_foreground_app(ps5_app_info_t& out);

    // ---- tuning (tests use these to exercise deadlines quickly) -----------
    // per-chunk idle timeout and whole-command budget, milliseconds
    void set_timeouts(int io_timeout_ms, int64_t command_budget_ms);
    // port the debug-event listener binds (the payload always connects back
    // to 755; only tests override this)
    void set_event_port(uint16_t port);

private:
    struct impl_t;
    std::unique_ptr<impl_t> m_impl;
};

} // namespace slop::core::runtime
