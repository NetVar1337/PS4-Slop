#pragma once

// console-native AOB walk: the ps4debug payload's CMD_PROC_SCAN_AOB answers
// one match per call (scanning on-device at memory speed). This walks every
// match in a region set by re-issuing the call from just past each hit, so
// callers get the full hit list instead of a single address

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

#include "core/infra/cancel.hpp"
#include "core/memory/memscan.hpp"

namespace slop::core::memory {

// One on-device search over [addr, addr+len): set hit to the first match
// (0 = none) and return true, or return false on a transport/protocol error
using console_find_fn = std::function<bool(uint64_t addr, uint32_t len, uint64_t& hit)>;

struct console_aob_options_t {
    size_t   pattern_len = 0;           // bytes in the pattern (>= 1)
    uint32_t alignment   = 1;           // keep only hits with addr % alignment == 0
    size_t   max_results = 0;           // 0 -> infra::limits::max_aob_matches
    uint32_t window      = 256u << 20;  // bytes per call (bounds on-device time)
};

struct console_aob_stats_t {
    size_t   calls     = 0;     // on-device searches issued
    size_t   matches   = 0;
    uint64_t bytes     = 0;     // bytes covered by completed windows
    bool     truncated = false; // stopped at max_results
    bool     cancelled = false;
    bool     failed    = false; // find_fn reported an error (results are partial)
    uint64_t failed_at = 0;     // window start of the failing call
    bool     bad_reply = false; // payload answered with a hit outside the window
};

// Walk every match of the pattern in the regions (ascending, deduplicated)
std::vector<uint64_t> console_aob_all(const console_find_fn& find,
                                      const std::vector<scan_region_t>& regions,
                                      const console_aob_options_t& opt,
                                      const slop::core::infra::cancel_token_t& tok,
                                      console_aob_stats_t* stats);

} // namespace slop::core::memory
