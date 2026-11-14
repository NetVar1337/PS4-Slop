#pragma once

// one shot emulation over unicorn, map regions, seed registers, run with
// budget timeout and stop address, collect trace and taint, callers
// materialize the bytes so this stays source agnostic.
// two architectures: x86-64 (PE / ELF / PS4 SELF, win64 or sysv abi) and
// aarch64 (Mach-O / iOS). the abi picks the x86 environment: win64 (rcx,rdx,
// r8,r9 args, TEB/PEB behind gs) or sysv (rdi,rsi,rdx,rcx,r8,r9 args,
// FreeBSD/PS4 TCB behind fs). aarch64 uses the AAPCS64 registers (x0..x7
// args, x30 link register). syscall instructions are hooked and logged on
// x86-64; an Orbis handler can serve them instead of a fixed return value.
// persistent sessions keep one engine alive across calls, with bounded
// snapshot/restore of registers + dirty pages, and a dynamic backward slicer
// over a recorded trace.

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "core/emu/orbis.hpp"
#include "core/emu/taint.hpp"
#include "core/infra/cancel.hpp"

namespace slop::core::emu {

inline constexpr size_t kPageSize = 0x1000;

// Demand paging: asked for a 4 KiB page the code touches that nothing mapped.
// Fill out[kPageSize] and return true to map it and retry the access, false
// to let it fault. Runs on the emulation thread, off every tool lock
using page_source_t = std::function<bool(uint64_t page, uint8_t* out)>;

struct emu_mem_region_t {
    uint64_t             addr = 0;
    std::vector<uint8_t> bytes;
};

struct import_slot_t {
    uint64_t    slot = 0;      // IAT slot va, patched to point at a stub
    std::string name;          // "dll!func" or "dll!#ordinal"
    bool        has_ret = false;   // ret replaces api_ret for this import
    uint64_t    ret = 0;
};

// stub page holds one RET per import
inline constexpr size_t kMaxImports = 16384;

enum class abi_t : uint8_t {
    win64,   // Windows x64: TEB/PEB at gs, api args rcx,rdx,r8,r9
    sysv,    // SysV AMD64 (FreeBSD/PS4 ELF): TCB at fs, args rdi,rsi,rdx,rcx,r8,r9
};

const char* abi_name(abi_t a) noexcept;

enum class arch_t : uint8_t { x86_64, arm64 };

const char* arch_name(arch_t a) noexcept;

// syscall number -> name, null for unknown numbers
using syscall_namer_t = const char* (*)(uint64_t num);

struct run_request_t {
    std::vector<uint8_t> code;                 // required, non-empty
    uint64_t code_base       = 0x400000;
    bool     entry_absolute  = false;          // false: entry is offset into code
    uint64_t entry           = 0;

    arch_t   arch            = arch_t::x86_64;

    uint64_t stack_base      = 0x002FF000;
    size_t   stack_size      = 0x100000;
    bool     sp_set          = false;          // override initial RSP/SP
    uint64_t sp              = 0;

    // x86-64: "rax".."r15", "rip", "rflags", "fs_base", "gs_base"
    // aarch64: "x0".."x28", "x29"/"fp", "x30"/"lr", "sp", "pc", "nzcv"
    std::map<std::string, uint64_t> regs;
    std::vector<emu_mem_region_t>   maps;      // extra data mappings

    // Pages nothing mapped come from here on first touch, so calls, jumps
    // and loads outside the code slice keep running. The pages the code
    // slice only partly covers are completed from it too
    page_source_t page_in;
    size_t        page_in_max = 4096;          // demand pages per run (16 MiB)

    // IAT/GOT slots redirected to stubs: a call through one is logged in
    // api_calls and returns api_ret in rax/x0 instead of faulting
    std::vector<import_slot_t> imports;        // <= kMaxImports
    uint64_t api_ret = 0;

    // win64: a zeroed TEB/PEB is mapped at gs base (self, PEB, stack bounds,
    // ids) unless regs sets gs_base or the pages are taken; this fills
    // PEB.ImageBaseAddress
    uint64_t image_base = 0;

    abi_t abi = abi_t::win64;

    // syscall hook: the instruction does not enter a kernel, it is logged in
    // syscalls (rax = number, args rdi,rsi,rdx,r10,r8,r9) and returns
    // syscall_returns[number] or syscall_ret in rax with CF clear (FreeBSD
    // success); rcx/r11 get the return rip / rflags like the real instruction
    uint64_t syscall_ret = 0;
    std::map<uint64_t, uint64_t> syscall_returns;
    syscall_namer_t syscall_name = nullptr;    // names the log entries when set

    // Orbis syscall emulation (x86-64 sysv only): numbers without an entry in
    // syscall_returns are served by the built-in handler, which maps memory,
    // captures write() and answers ENOSYS for the rest
    bool          orbis_syscalls = false;
    orbis_state_t orbis;

    // Memory read back after the run. Pages the run never touched come
    // from page_in, so a dump of an untouched global still has its bytes
    struct dump_range_t { uint64_t addr = 0; size_t len = 0; };
    std::vector<dump_range_t> dumps;

    uint64_t until_addr        = 0;            // stop-before address (0 = none)
    uint64_t max_instructions  = 100000;
    uint32_t timeout_ms        = 5000;         // clamped to kMaxTimeoutMs
    infra::cancel_token_t cancel;              // polled per instruction, stops with "cancelled"

    bool     trace             = false;
    size_t   trace_max         = 4096;

    // Record the per-instruction bytes and the memory reads, the raw material
    // of a dynamic backward slice. Costs a memory-read hook per access
    bool     record_slice      = false;

    // Taint: mark input ranges inside any mapped region before running
    struct taint_source_t { uint64_t addr = 0; size_t len = 0; };
    std::vector<taint_source_t> taint_sources;
    // Output window reported through output_tainted
    uint64_t watch_addr = 0;
    size_t   watch_len  = 0;
};

struct run_result_t {
    bool        ok = false;
    std::string error;
    // return|until|count|timeout|cancelled|invalid_mem_*|invalid_insn|
    // cpu_exception|exit
    std::string stopped_reason;

    uint64_t instructions = 0;
    std::map<std::string, uint64_t> regs;

    // bytes/size are only filled when the run recorded slice data
    struct trace_entry_t {
        uint64_t ip = 0;
        std::string text;
        uint8_t  size = 0;
        uint8_t  bytes[16] = {};
    };
    std::vector<trace_entry_t> trace;

    // value holds the low 8 bytes of the store; truncated marks stores wider
    // than 8 bytes (vector/string stores) whose upper bytes are not logged
    struct write_entry_t {
        uint64_t ip = 0; uint64_t addr = 0; size_t len = 0; uint64_t value = 0;
        bool truncated = false;
        size_t seq = 0;   // trace index of the instruction that stored
    };
    std::vector<write_entry_t> writes;     // capped at 2048 entries
    size_t total_writes = 0;

    // Memory reads, only recorded for a slice run
    struct read_entry_t {
        uint64_t ip = 0; uint64_t addr = 0; size_t len = 0;
        size_t seq = 0;   // trace index of the instruction that loaded
    };
    std::vector<read_entry_t> reads;       // capped at 4096 entries
    size_t total_reads = 0;

    // ip is the call (or jmp) through the slot, ret the address it returns to
    struct api_call_t {
        uint64_t    ip = 0;
        uint64_t    ret = 0;
        std::string name;
        uint64_t    args[6] = {};          // abi argument registers at entry
        uint8_t     arg_count = 0;         // 4 win64, 6 sysv/aapcs64
    };
    std::vector<api_call_t> api_calls;     // capped at 1024 entries
    size_t total_api_calls = 0;

    struct syscall_t {
        uint64_t    ip = 0;                // the syscall instruction
        uint64_t    num = 0;               // rax at entry
        std::string name;                  // from syscall_name, empty when unknown
        uint64_t    args[6] = {};          // rdi, rsi, rdx, r10, r8, r9
        uint64_t    ret = 0;               // rax handed back
        bool        enosys = false;        // answered by the Orbis handler as ENOSYS
    };
    std::vector<syscall_t> syscalls;       // capped at 1024 entries
    size_t total_syscalls = 0;

    // Orbis capture: bytes written to fd 1/2 by the emulated code
    std::vector<uint8_t> stdout_data;
    size_t   syscall_enosys = 0;
    bool     exited      = false;
    uint64_t exit_code   = 0;

    size_t paged_in          = 0;          // demand pages mapped from page_in
    bool   page_in_exhausted = false;      // a fault was left standing at page_in_max
    bool   teb_mapped        = false;      // win64 TEB/PEB at gs
    bool   tls_mapped        = false;      // sysv TCB at fs

    std::vector<emu_mem_region_t> memory;  // one per dump, cut at the first unreadable page

    struct fault_t { uint64_t ip = 0; uint64_t addr = 0; std::string access; };
    std::optional<fault_t> fault;

    // Taint results (empty when no sources were marked)
    std::vector<taint_range_t> taint_ranges;
    std::vector<taint_event_t> taint_events;
    bool output_tainted = false;
};

// Budget ceiling for one run. MCP clients commonly abort requests at 60 s,
// so a run plus result serialization has to finish well inside that window.
inline constexpr uint32_t kMaxTimeoutMs = 30000;

run_result_t emulate_run(const run_request_t& req);

// === dynamic backward slicing =============================================
// Walk a recorded trace backwards from `at` and keep the instructions that
// (transitively) produced the target value. Registers are tracked exactly;
// memory dependencies use the recorded read/write addresses, so the slice is
// dynamic: it follows the addresses this run actually touched.
struct slice_request_t {
    std::string reg;        // target register ("rax".."r15", "rip", "rflags")
    uint64_t    addr = 0;   // target memory range when reg is empty
    size_t      len  = 0;
    uint64_t    at   = 0;   // slice at this instruction ip (0 = end of trace)
};

struct slice_result_t {
    bool        ok = false;
    std::string error;
    std::vector<size_t> indices;   // indices into run.trace, program order
    std::vector<run_result_t::trace_entry_t> insns;
};

slice_result_t emulate_slice(const run_result_t& run, const slice_request_t& slice);

// === persistent sessions ===================================================
// One live engine that keeps its mappings, registers and dirty-page tracking
// across calls. snapshots are bounded (kMaxSnapshotPages) and COW-style: only
// the pages written since the engine started are captured, restore writes
// them back and reloads the registers.
inline constexpr size_t kMaxSnapshotPages = 4096;   // 16 MiB per snapshot
inline constexpr size_t kMaxSnapshots     = 8;

class emulation_session_t {
public:
    // null + err on a bad request (same validation as emulate_run)
    static std::unique_ptr<emulation_session_t> create(const run_request_t& req,
                                                       std::string* err);
    ~emulation_session_t();
    emulation_session_t(const emulation_session_t&)            = delete;
    emulation_session_t& operator=(const emulation_session_t&) = delete;

    // Execute up to `count` instructions (0 = the request's budget) and
    // append to the accumulated result
    bool step(uint64_t count, uint32_t timeout_ms, infra::cancel_token_t cancel,
              std::string* err);
    bool snapshot(std::string* err);
    bool restore(std::string* err);

    const run_result_t& state() const;
    size_t snapshot_count() const;
    size_t snapshot_pages() const;
    arch_t arch() const;

private:
    struct impl_t;
    explicit emulation_session_t(std::unique_ptr<impl_t> impl);
    std::unique_ptr<impl_t> impl_;
};

} // namespace slop::core::emu
