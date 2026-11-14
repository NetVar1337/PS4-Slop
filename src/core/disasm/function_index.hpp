#pragma once

// function discovery, recursive descent from entry exports and calls,
// then a prologue heuristic sweep for the rest

#include <cstdint>
#include <functional>
#include <optional>
#include <utility>
#include <vector>

#include "core/disasm/engine.hpp"
#include "core/disasm/pe_parser.hpp"

namespace slop::core::disasm {

// where a start came from: the decode/index passes, or Hyperion analysis
// merged in after it completed (merge_starts)
enum class fn_source_t : uint8_t { index = 0, hyperion = 1 };

struct function_t {
    uint64_t    va     = 0;
    size_t      size   = 0;   // decoded extent; may grow when blocks merge
    fn_source_t source = fn_source_t::index;
};

struct function_stats_t {
    size_t seeds          = 0;
    size_t rd_functions   = 0;   // found by recursive descent
    size_t heuristic_fns  = 0;   // found by prologue heuristics
    size_t hype_functions = 0;   // merged from Hyperion analysis
    bool   truncated      = false;
};

class function_index_t {
public:
    // Build over a parsed image + its file bytes. `base` overrides the
    // preferred image base for VA math (use actual load base at runtime)
    bool build(const pe_image_t& pe, const std::vector<uint8_t>& file,
               engine_t& eng, uint64_t base,
               size_t max_functions = 100'000,
               const std::function<void(float)>& progress = {});

    // No decoding: functions straight from the image's own bounds data
    // (runtime_funcs, e.g. Mach-O LC_FUNCTION_STARTS) plus entry and exports,
    // each extending to the next start. For images the x86 engine cannot
    // decode; the hyperion DB supplies the rest once its analysis completes
    bool build_from_bounds(const pe_image_t& pe, const std::vector<uint8_t>& file,
                           uint64_t base, size_t max_functions = 100'000);

    // Merge externally discovered starts (Hyperion analysis results: function
    // entries, thunks and tail-call targets, each with its extent when known)
    // into the index. Dedupes by VA (the decode-built entry keeps its extent),
    // clips sizes at the next start and marks the added rows hyperion.
    // Returns how many starts were added
    size_t merge_starts(const std::vector<std::pair<uint64_t, uint64_t>>& starts,
                        size_t max_functions = 100'000);

    const std::vector<function_t>& functions() const noexcept { return fns_; }
    std::optional<uint64_t> containing(uint64_t va) const;   // innermost fn start
    const function_stats_t& stats() const noexcept { return stats_; }

private:
    std::vector<function_t> fns_;
    function_stats_t        stats_{};
};

} // namespace slop::core::disasm