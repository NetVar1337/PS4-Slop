#pragma once

// src/core/runtime/backend_ps4.hpp
// Remote PS4 backend: speaks the ps4debug-NG wire protocol (TCP 744) to a
// console running the ps4debug-NG payload, so memory/enumeration actions work
// on the console exactly like on a local process

#include <cstddef>
#include <cstdint>
#include <functional>
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

// decode one raw 0x4A0 packet (false when n is short)
bool ps4_decode_event(const uint8_t* pkt, size_t n, ps4_event_t& out);

// TCP can split or coalesce the fixed-size port-755 packets; this rebuilds
// whole packets from an arbitrary byte stream. Consumed bytes are compacted
// once per feed (not once per packet).
class ps4_event_reassembler_t {
public:
    explicit ps4_event_reassembler_t(size_t packet_size);
    // returns the number of complete packets delivered to on_packet
    size_t feed(const uint8_t* data, size_t n,
                const std::function<void(const uint8_t* pkt)>& on_packet);
    size_t buffered() const noexcept { return buf_.size(); }
    void   reset() noexcept { buf_.clear(); }

private:
    size_t packet_size_;
    std::vector<uint8_t> buf_;
};

// one vm_map entry, as received from CMD_PROC_MAPS
struct ps4_segment_t {
    uint64_t    start  = 0;
    uint64_t    end    = 0;
    uint64_t    offset = 0;
    uint16_t    prot   = 0;    // FreeBSD VM_PROT_* bits (1 r, 2 w, 4 x)
    std::string name;
};

// one module: adjacent same-named map entries (text, relro, data, ...)
// coalesced into one record spanning [base, end)
struct ps4_module_t {
    std::string name;          // base name ("eboot.bin")
    std::string path;          // map name as the console reports it
    uint64_t    base = 0;
    uint64_t    end  = 0;
    std::vector<ps4_segment_t> segments;
};

// group maps into modules: entries are sorted by start; consecutive entries
// with the same non-empty name form one module (unnamed anonymous mappings in
// between do not break the run, a different name does)
std::vector<ps4_module_t> ps4_coalesce_modules(std::vector<ps4_segment_t> maps);

class backend_ps4_t final : public backend_t {
public:
    backend_ps4_t();
    ~backend_ps4_t() override;

    backend_ps4_t(const backend_ps4_t&) = delete;
    backend_ps4_t& operator=(const backend_ps4_t&) = delete;

    // ---- connection management (outside the backend_t interface) ----------
    // connect() is a fresh logical connection: handles from an earlier
    // connection become stale, client-side slot/stub state is cleared
    bool        connect(const std::string& host, uint16_t port, std::string& err);
    void        disconnect();
    bool        connected() const noexcept;
    bool        ping();   // CMD_PROC_NOP roundtrip, liveness probe
    std::string endpoint() const;   // "host:port" or "" when not connected
    std::string branding() const;   // server branding string or ""
    std::string server_caps() const;    // capability tail of the branding blob
    std::string server_version() const; // CMD_VERSION string or ""
    uint16_t    fw_version() const noexcept;  // major*100+minor (e.g. 1400 = 14.00), 0 if unknown
    std::string fw_string() const;            // "14.00" or "" if unknown

    // any send/recv failure (error, peer close, timeout, desync) closes the
    // socket so connected() goes false and callers fail fast. lost() then
    // reports the dropped connection until reconnect()/connect()/disconnect()
    bool        lost() const noexcept;
    std::string lost_reason() const;
    uint64_t    drop_count() const noexcept;     // connections lost so far
    std::string last_endpoint() const;           // remembered for reconnect

    // re-open the remembered endpoint, re-run the handshake and auth, then
    // restore what the dropped connection had: the debug session (the payload
    // keeps debug state per connection) and every breakpoint/watchpoint slot
    // this client armed. Existing target handles stay valid.
    struct reconnect_report_t {
        bool        authed = false;
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
    // threads with priority/name; the per-thread info requests are pipelined
    // in small batches (one roundtrip per batch, not per thread)
    enum_result_t<thread_info_t>  enum_threads(uint32_t pid) override;
    enum_result_t<region_info_t>  enum_regions(const target_handle_t& h) override;
    enum_result_t<handle_info_t>  enum_handles(uint32_t pid) override;

    // modules with their individual segments (for whole-module dumps)
    enum_result_t<ps4_module_t>   ps4_modules(const target_handle_t& h);
    // raw maps of the handle's process
    enum_result_t<ps4_segment_t>  ps4_maps(const target_handle_t& h);

    // ---- thread context
    io_result_t get_thread_context(uint32_t tid, thread_context_t& ctx) override;
    io_result_t set_thread_context(uint32_t tid, const thread_context_t& ctx) override;

    // ---- query
    arch_t      query_arch(const target_handle_t& h) override;
    elevation_t query_elevation() override;
    bool        handle_info(const target_handle_t& h, process_info_t& out) override;

    // ---- live debug session (ps4debug-NG remote debugger) -----------------
    // These drive CMD_DEBUG_* on the same connection; ps4_debug_attach also
    // starts the port-755 event listener that feeds ps4_wait_event/drain.
    bool        ps4_debug_attach(uint32_t pid, std::string& err);
    bool        ps4_debug_detach();
    bool        ps4_debug_attached() const noexcept;
    bool        ps4_debug_held() const noexcept;   // a stop event is holding the debuggee
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

    // ---- client-side breakpoint/watchpoint slot bookkeeping ---------------
    // The payload cannot list its slots, so this client records what it
    // armed. Records are cleared when the debug session ends (detach, SIGKILL,
    // event channel closed by the payload, attach to another pid, connect,
    // disconnect); a dropped connection keeps them (armed=false) so
    // reconnect() can re-arm them. Slots are reserved under a small lock and
    // the wire call runs without it.
    static constexpr uint32_t kAutoSlot = 0xFFFFFFFFu;
    struct ps4_slot_t {
        uint32_t index = 0;
        uint64_t addr  = 0;
        uint32_t len   = 0;     // watchpoints only
        uint32_t type  = 0;     // watchpoints only (ps4::kWp*)
        bool     armed = false; // false while the connection is down
    };
    std::vector<ps4_slot_t> ps4_breakpoints() const;
    std::vector<ps4_slot_t> ps4_watchpoints() const;
    // index == kAutoSlot: reuse the slot already armed at addr, else the first
    // free one. reused says whether addr was already armed by us
    io_result_t ps4_bp_arm(uint64_t addr, uint32_t index, uint32_t& out_index,
                           bool* reused = nullptr);
    io_result_t ps4_bp_disarm(uint32_t index, uint64_t* out_addr = nullptr);
    io_result_t ps4_bp_disarm_addr(uint64_t addr, uint32_t* out_index = nullptr);
    io_result_t ps4_wp_arm(uint64_t addr, uint32_t len, uint32_t type, uint32_t index,
                           uint32_t& out_index, bool* reused = nullptr);
    io_result_t ps4_wp_disarm(uint32_t index, uint64_t* out_addr = nullptr);
    io_result_t ps4_wp_disarm_addr(uint64_t addr, uint32_t* out_index = nullptr);

    // remote function call through the payload's rpc stub (CMD_PROC_INTALL /
    // CMD_PROC_CALL); args are rdi, rsi, rdx, rcx, r8, r9. ps4_install caches
    // the stub per pid (cleared on connect/disconnect)
    io_result_t ps4_install(uint32_t pid, uint64_t& rpcstub);
    io_result_t ps4_call(uint32_t pid, uint64_t rpcstub, uint64_t rip,
                         const uint64_t args[6], uint64_t& out_rax);

    // debug event stream (port 755)
    size_t                   ps4_pending_events();
    bool                     ps4_wait_event(ps4_event_t& out, int timeout_ms);
    std::vector<ps4_event_t> ps4_drain_events(size_t max, bool clear);
    uint64_t                 ps4_events_received() const noexcept;  // packets decoded
    uint64_t                 ps4_events_dropped() const noexcept;   // lost to the queue cap
    static constexpr size_t  kMaxQueuedEvents = 4096;

    // ---- console-side capabilities (ps4debug-NG) ---------------------------

    // CMD_PROC_AUTH challenge-response (the payload's keystream is four LFSRs
    // seeded 200/300/400/500 - see debugger/source/proc.c auth_lfsr_next).
    // Run automatically on connect; bit 1 (0x2) unlocks the scan family.
    bool ps4_auth(uint32_t flags, std::string& err);
    bool ps4_authed() const noexcept;

    // CMD_CONSOLE_INFO roundtrip (the payload answers a bare CMD_SUCCESS)
    // plus everything the handshake learned about the console
    struct ps4_console_info_t {
        bool        alive = false;      // CMD_CONSOLE_INFO answered
        std::string endpoint, branding, caps, version, fw;
        uint16_t    fw_bcd = 0;
        uint16_t    platform = 0;       // CMD_PLATFORM_ID tag (4 = PS4)
        bool        authed = false;
        uint32_t    debug_pid = 0;
        uint64_t    drops = 0;
    };
    io_result_t ps4_console_info(ps4_console_info_t& out);

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
    // needs the previous value; every such value must be exactly the value
    // width (fixed width, or data.size() for arrbytes/string) and every hit
    // must lie in [base, base + 4 GiB) or the call fails before sending
    io_result_t ps4_scan_next(uint32_t pid, uint64_t base,
                              uint8_t valtype, uint8_t cmptype,
                              const std::vector<ps4_scan_hit_t>& prev,
                              const std::vector<uint8_t>& data,
                              std::vector<ps4_scan_hit_t>& hits);
    // max previous-hit bytes per SCAN_COUNT chunk (protocol chunk cap)
    static constexpr uint32_t kScanChunkCap = 0x20000;
    // legacy whole-memory single-pass scan (CMD_PROC_SCAN). Past kMaxScanAll
    // addresses the rest of the stream is drained (connection stays in sync)
    // and *truncated is set
    static constexpr size_t kMaxScanAll = 0x1000000;
    io_result_t ps4_scan_all(uint32_t pid, uint8_t valtype, uint8_t cmptype,
                             const std::vector<uint8_t>& data,
                             std::vector<uint64_t>& addrs, bool* truncated = nullptr);
    // array-of-bytes scan over [addr, addr+len); mask byte 1 = exact, 0 = wildcard.
    // Returns the max_matches-th match (0 if none / invalidated)
    io_result_t ps4_scan_aob(uint32_t pid, uint64_t addr, uint32_t len,
                             const std::vector<uint8_t>& pattern,
                             const std::vector<uint8_t>& mask,
                             uint8_t max_matches, uint8_t stop_flag,
                             uint64_t& out_addr);

    // capability level string the payload appends after a NUL in its
    // branding ("1.0" adds bulk write, "1.1" verified writes); "" when absent
    std::string ps4_capability_level() const;

    // ---- bulk write (0xBDAACC04) ------------------------------------------
    struct ps4_write_entry_t {
        uint64_t             addr = 0;
        std::vector<uint8_t> bytes;
    };
    // apply up to 0xFFFF writes in one exchange. With want_status the server
    // returns one status byte per entry (ps4::kWriteStatus*) and ok reflects
    // the transport only; without it, ok=false if any entry failed.
    // Non-atomic: failed entries do not stop the rest
    io_result_t ps4_write_multi(uint32_t pid, const std::vector<ps4_write_entry_t>& writes,
                                bool want_status, std::vector<uint8_t>& status);

    // ---- Turbo Scan (0xBDAACC10-17) ----------------------------------------
    struct ps4_turbo_caps_t {
        uint32_t version = 0;
        uint32_t engines = 0;       // ps4::kTse* bits
        uint32_t max_threads = 0;
    };
    // false (error set) when the payload predates Turbo Scan
    io_result_t ps4_turbo_caps(ps4_turbo_caps_t& out);

    struct ps4_turbo_segment_t {
        uint64_t addr = 0;
        uint32_t len = 0;
    };
    struct ps4_turbo_start_t {
        uint32_t pid = 0;
        uint64_t addr = 0;          // single range when segments is empty
        uint32_t len = 0;
        uint8_t  valtype = 0;
        uint8_t  cmptype = 0;
        uint8_t  alignment = 0;
        uint32_t flags = 0;         // ps4::kTs* bits
        std::vector<uint8_t> data;  // seed value(s); two values for between
        std::vector<uint8_t> mask;  // arrbytes only: 1 = compare, 0 = wildcard
        std::vector<ps4_turbo_segment_t> segments;  // sets kTsSnapshotSegments
    };
    struct ps4_turbo_result_t {
        bool     resident = false;      // survivors kept on the console (fetch with get)
        bool     snapshot = false;      // phase-B snapshot session
        bool     snapshot_ok = false;
        uint64_t count = 0;             // survivor count
        uint64_t slot_count = 0;        // snapshot plan
        uint64_t total_bytes = 0;
        std::vector<ps4_scan_hit_t> hits;  // streamed (non-resident) results
    };
    // progress callback for snapshot passes: (bytes_or_slots_done, total)
    using ps4_progress_fn = std::function<void(uint64_t, uint64_t)>;
    io_result_t ps4_turbo_start(const ps4_turbo_start_t& req, ps4_turbo_result_t& out,
                                const ps4_progress_fn& progress = {});

    // narrow. Resident/snapshot sessions narrow server-side and return just a
    // count; otherwise prev (with values when the compare needs them) is
    // streamed and the surviving hits come back
    io_result_t ps4_turbo_count(uint32_t pid, uint64_t base, uint8_t valtype,
                                uint8_t cmptype, uint32_t flags,
                                const std::vector<uint8_t>& data,
                                const std::vector<uint8_t>& mask,
                                const std::vector<ps4_scan_hit_t>& prev,
                                ps4_turbo_result_t& out,
                                const ps4_progress_fn& progress = {});

    struct ps4_turbo_record_t {
        uint64_t             addr = 0;
        std::vector<uint8_t> current, previous, first;  // first empty unless kept
    };
    // fetch resident survivors [start, start+count); value_len is the
    // session's value width
    io_result_t ps4_turbo_get(uint32_t start, uint32_t count, uint32_t value_len,
                              std::vector<ps4_turbo_record_t>& out);
    io_result_t ps4_turbo_end();
    io_result_t ps4_turbo_config(uint32_t ram_thresh_mb, const std::string& spill_dir);

    struct ps4_turbo_region_t {
        uint64_t start = 0, end = 0;
        uint32_t prot = 0, flags = 0, mbps = 0;
    };
    io_result_t ps4_turbo_regions(uint32_t pid, uint32_t max, uint32_t probe_bytes,
                                  std::vector<ps4_turbo_region_t>& out);
    // opens a short-lived second connection (the first is busy streaming)
    // and arms the payload's cancel flag for pid
    io_result_t ps4_turbo_cancel(uint32_t pid, std::string& err);

    // ---- NetVar1337 fork extensions + connection bookkeeping ----------------
    // bumped whenever the backend transparently reopened the command
    // connection after the payload dropped it (which tears down the debug
    // session and the Turbo Scan session on the console)
    uint64_t ps4_connection_generation() const noexcept;
    // last error status word the console sent (ps4::CMD_ERR_* etc.), then clear
    uint32_t ps4_take_last_status() noexcept;
    // fork extensions (CMD_PROC_MODULES / CMD_PROC_SNAPSHOT): -1 not probed
    // yet, 0 upstream payload, 1 present
    int ps4_fork_extensions() const noexcept;
    // CMD_PROC_MODULES: one entry per backing file, base/size spanning all of
    // its maps. error 100 = payload lacks the extension
    io_result_t ps4_modules(uint32_t pid, std::vector<module_info_t>& out);
    // CMD_PROC_SNAPSHOT: stream [addr, addr+len) in one round trip, any size;
    // sink gets 64 KiB pieces (return false to stop). error 2 = range not
    // fully readable, 100 = payload lacks the extension
    io_result_t ps4_snapshot(uint32_t pid, uint64_t addr, uint64_t len,
                             const std::function<bool(const uint8_t*, size_t)>& sink);

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
    // entries past max_entries are drained to the sentinel and dropped
    // (*truncated = true), the command stream never desyncs
    io_result_t ps4_disasm_region(uint32_t pid, uint64_t addr, uint32_t len,
                                  uint32_t max_entries,
                                  std::vector<ps4_disasm_entry_t>& out,
                                  bool* truncated = nullptr);
    // RIP-relative branch/call targets inside [addr, addr+len)
    io_result_t ps4_extract_xrefs(uint32_t pid, uint64_t addr, uint32_t len,
                                  uint32_t max_instrs, std::vector<uint64_t>& targets,
                                  bool* truncated = nullptr);
    // addresses inside [addr, addr+len) that branch/call target
    io_result_t ps4_find_xrefs_to(uint32_t pid, uint64_t addr, uint32_t len,
                                  uint64_t target, std::vector<uint64_t>& addrs,
                                  bool* truncated = nullptr);

    // one server-side stack frame from CMD_PROC_READ_STACK
    struct ps4_stack_frame_t {
        uint64_t rbp = 0, rsp = 0, saved_rbp = 0, ret_addr = 0;
        uint32_t flags = 0;                 // bit0: frame locals omitted
        std::vector<uint8_t> locals;        // rsp..rbp bytes when present
        std::vector<uint8_t> code;          // window around ret_addr
    };
    // ok=false (kErrProtocol) when the bundle holds fewer frames than it
    // claims; the frames that did parse are still returned
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

    // ---- tuning (tests use these to exercise deadlines quickly) -----------
    // per-chunk idle timeout and whole-command budget, milliseconds
    void set_timeouts(int io_timeout_ms, int64_t command_budget_ms,
                      int64_t long_command_budget_ms);
    // port the debug-event listener binds (the payload always connects back
    // to 755; only tests override this)
    void set_event_port(uint16_t port);

private:
    struct impl_t;
    std::unique_ptr<impl_t> m_impl;
};

} // namespace slop::core::runtime
