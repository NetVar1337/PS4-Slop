#pragma once

// src/core/debugger/callstack.hpp
// pure unwinding and seh chain walking over a reader callback, rbp chain
// first with a stack scan fallback, no os calls so it tests against
// synthetic stacks

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "core/disasm/engine.hpp"
#include "core/runtime/backend.hpp"

namespace slop::core::debugger::unwind {

struct reader_t {
    virtual ~reader_t() = default;
    virtual bool read(uint64_t addr, void* dst, size_t len) = 0;
};

struct frame_t {
    uint64_t    ret_addr  = 0;      // return address into the caller
    uint64_t    frame_ptr = 0;      // rbp of this frame (chain walk) or 0
    std::string snippet;            // disassembly at ret_addr (best effort)
    bool        scanned  = false;   // found by scan fallback, not rbp chain
};

// Walk up to max_frames frames starting from the given context
std::vector<frame_t> walk_stack(disasm::engine_t& eng, reader_t& rdr,
                                uint64_t rip, uint64_t rsp, uint64_t rbp,
                                size_t max_frames = 32);

// ---- PE x64 unwind info (.pdata) ------------------------------------------
// The local usermode backend is Windows x64: every non-leaf function carries a
// RUNTIME_FUNCTION in the module's .pdata, so the callstack does not need a
// frame pointer. The tables are read from target memory, no OS unwind helper.

struct module_span_t {
    uint64_t base = 0;
    uint64_t size = 0;
};

// true when addr belongs to a module (fills its load base and size)
using module_of_fn = std::function<bool(uint64_t addr, module_span_t& out)>;

// Frame 0 is ctx.rip itself (same shape as rbp_frames), then every caller
// resolved through RUNTIME_FUNCTION/UNWIND_INFO. Returns false when the first
// frame's module has no usable .pdata (caller falls back to walk_stack).
bool pe_unwind(reader_t& rdr, const runtime::thread_context_t& ctx, size_t max_frames,
               const module_of_fn& module_of, std::vector<frame_t>& out,
               std::string* note = nullptr);

struct seh_entry_t {
    uint64_t handler = 0;
    uint64_t filter  = 0;
    uint64_t frame   = 0;
};

struct seh_result_t {
    std::vector<seh_entry_t> chain;
    std::vector<uint64_t>    scan_candidates;   // framed-handler candidates
    bool chain_empty_proven = false;            // sentinel reached (x64 norm)
    std::string note;
};

// teb_addr is the threads teb base, the x64 exception list is normally
// the minus one sentinel, anything else gets walked
seh_result_t seh_chain(reader_t& rdr, uint64_t teb_addr);

} // namespace slop::core::debugger::unwind
