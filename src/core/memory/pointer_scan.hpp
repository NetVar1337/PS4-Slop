#pragma once

// multi level backward pointer scan, one sweep per level, the frontier
// filters each aligned qword read, optional module backed roots only

#include <cstdint>
#include <optional>
#include <vector>

#include "core/infra/cancel.hpp"
#include "core/memory/memscan.hpp"
#include "core/memory/reader.hpp"

namespace slop::core::memory {

// One hop of the chain, in chain order: levels[0] is the hop out of the root
// (the same order as pointer_chain_result_t::offsets). A wildcard level
// accepts any offset, which is how CE finds chains whose intermediate offset
// is unknown
struct pointer_level_t {
    int32_t  min_offset = -4096;
    int32_t  max_offset =  4096;
    uint32_t alignment  = 0;      // 0 -> pointer_scan_options_t::alignment
    bool     wildcard   = false;  // accept any 32-bit offset, ignores min/max
};

// A loaded module, so a root inside one is reported module-relative and
// survives a restart
struct pointer_module_t {
    std::string name;
    uintptr_t   base = 0;
    size_t      size = 0;
};

struct pointer_scan_options_t {
    uintptr_t target     = 0;
    uint32_t  depth      = 3;        // clamped to infra::limits::max_pointer_depth
    int32_t   min_offset = -4096;
    int32_t   max_offset =  4096;
    uint32_t  alignment  = 4;        // qword holder alignment
    size_t    frontier_cap = 100'000; // per-level expansion guard
    bool      only_module_backed = false; // roots must live in MEM_IMAGE regions

    // Per-level overrides, chain order (levels[0] = root hop). When non-empty
    // the level count is levels.size() and min_offset/max_offset/alignment
    // above only supply the defaults for levels that leave them at 0
    std::vector<pointer_level_t> levels;
    // Modules to attribute roots to (name + module_offset in the result)
    std::vector<pointer_module_t> modules;
};

struct pointer_chain_result_t {
    std::vector<uintptr_t> addresses;  // [root-most holder, ..., final holder]
    std::vector<int64_t>   offsets;    // offsets[i] applies to addresses[i]'s value
    std::string            module;     // root's module, empty when none matched
    uint64_t               module_offset = 0;  // root - module base

    size_t depth() const noexcept { return addresses.size(); }
};

struct pointer_scan_stats_t {
    uint64_t edges_explored = 0;
    bool     truncated      = false;
    bool     cancelled      = false;
};

std::vector<pointer_chain_result_t>
pointer_scan(reader_t& r,
             const std::vector<scan_region_t>& regions,
             const pointer_scan_options_t& opt,
             const slop::core::infra::cancel_token_t& tok,
             pointer_scan_stats_t* stats);

// Re-resolve a chain against live memory: start at addresses[0], each link
// reads the qword at the current address and adds offsets[i]. Returns the
// address the chain lands on, nullopt when a link is unreadable. Only the
// root address and the offsets matter; intermediate holders may have moved
std::optional<uintptr_t> pointer_chain_resolve(reader_t& r,
                                               const pointer_chain_result_t& chain);

struct pointer_verify_options_t {
    uintptr_t target      = 0;   // address every surviving chain must land on
    uint32_t  samples     = 1;   // passes over the list (clamped to 1..64)
    uint32_t  interval_ms = 0;   // wait between passes (clamped to 60 s)
};

struct pointer_verify_stats_t {
    size_t   checked            = 0;   // chains in
    size_t   kept               = 0;   // chains that matched on every sample
    size_t   dropped_unreadable = 0;   // a link could not be read
    size_t   dropped_mismatch   = 0;   // landed somewhere other than target
    uint32_t samples_done       = 0;
    uint64_t reads              = 0;   // qword reads issued (memoized per pass)
    bool     cancelled          = false;
};

// Cheat-Engine "rescan pointer list": re-read every chain over N samples and
// keep only the ones that land on target each time. Survivors keep their
// input order. Reads are memoized within a pass (chains share prefixes)
std::vector<pointer_chain_result_t>
pointer_verify(reader_t& r,
               std::vector<pointer_chain_result_t> chains,
               const pointer_verify_options_t& opt,
               const slop::core::infra::cancel_token_t& tok,
               pointer_verify_stats_t* stats);

} // namespace slop::core::memory
