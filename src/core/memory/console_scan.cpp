// src/core/memory/console_scan.cpp

#include "core/memory/console_scan.hpp"

#include "core/infra/limits.hpp"

#include <algorithm>

namespace slop::core::memory {

std::vector<uint64_t> console_aob_all(const console_find_fn& find,
                                      const std::vector<scan_region_t>& regions,
                                      const console_aob_options_t& opt,
                                      const infra::cancel_token_t& tok,
                                      console_aob_stats_t* stats) {
    console_aob_stats_t local{};
    console_aob_stats_t& st = stats ? *stats : local;
    st = {};

    std::vector<uint64_t> hits;
    const uint64_t plen = opt.pattern_len;
    if (plen == 0 || !find) return hits;

    const size_t   max_results = opt.max_results ? opt.max_results
                                                 : infra::limits::max_aob_matches;
    const uint32_t align  = opt.alignment ? opt.alignment : 1;
    // a window must hold the pattern; the protocol length is a u32
    const uint64_t window = std::max<uint64_t>(opt.window ? opt.window : 1u, plen);

    std::vector<scan_region_t> sorted = regions;
    std::sort(sorted.begin(), sorted.end(),
              [](const scan_region_t& a, const scan_region_t& b) { return a.base < b.base; });

    for (const auto& reg : sorted) {
        if (reg.size < plen) continue;
        const uint64_t end = static_cast<uint64_t>(reg.base) + reg.size;
        uint64_t cursor = std::max<uint64_t>(reg.base, hits.empty() ? 0 : hits.back() + 1);

        while (end > cursor && end - cursor >= plen) {
            if (tok.cancelled()) { st.cancelled = true; return hits; }
            const uint64_t win_end = std::min<uint64_t>(end, cursor + window);
            uint64_t hit = 0;
            ++st.calls;
            if (!find(cursor, static_cast<uint32_t>(win_end - cursor), hit)) {
                st.failed    = true;
                st.failed_at = cursor;
                return hits;
            }
            if (hit == 0) {
                // window exhausted: slide on, keeping a pattern-1 overlap so a
                // match straddling the window border is still found whole
                st.bytes += win_end - cursor;
                if (win_end >= end) break;
                cursor = win_end - (plen - 1);
                continue;
            }
            if (hit < cursor || hit + plen > win_end) {
                // the payload answered outside the window we asked about
                st.failed    = true;
                st.bad_reply = true;
                st.failed_at = cursor;
                return hits;
            }
            st.bytes += hit + 1 - cursor;
            if (hit % align == 0) {
                if (hits.size() >= max_results) {
                    st.truncated = true;
                    st.matches   = hits.size();
                    return hits;
                }
                hits.push_back(hit);
                st.matches = hits.size();
            }
            cursor = hit + 1;
        }
    }
    st.matches = hits.size();
    return hits;
}

} // namespace slop::core::memory
