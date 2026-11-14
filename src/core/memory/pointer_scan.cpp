// src/core/memory/pointer_scan.cpp
// backward pointer scan, sweep the aligned qwords then walk the sorted edges

#include "core/memory/pointer_scan.hpp"

#include "core/infra/limits.hpp"
#include "core/memory/read_util.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <thread>
#include <unordered_map>

namespace slop::core::memory {

namespace {

struct edge_t {
    uint64_t  value;   // qword read from the region set
    uintptr_t holder;  // address of that qword
};

struct node_t {
    uintptr_t addr      = 0;   // holder address
    int64_t   parent    = -1;  // index into nodes of the destination
    int64_t   offset    = 0;   // *addr + offset == nodes[parent].addr (or target)
};

bool in_module_backed(uintptr_t addr,
                      const std::vector<scan_region_t>& regions) noexcept {
    constexpr uint32_t kMemImage = 0x1000000;
    for (const auto& reg : regions) {
        if (!(reg.type & kMemImage)) continue;
        if (addr >= reg.base && addr < reg.base + reg.size) return true;
    }
    return false;
}

} // namespace

std::vector<pointer_chain_result_t>
pointer_scan(reader_t& r,
             const std::vector<scan_region_t>& regions,
             const pointer_scan_options_t& opt,
             const infra::cancel_token_t& tok,
             pointer_scan_stats_t* stats) {

    std::vector<pointer_chain_result_t> results;
    pointer_scan_stats_t local{};
    pointer_scan_stats_t& st = stats ? *stats : local;

    // Level table: explicit levels win, otherwise depth copies of the global
    // range. The sweep walks from the target backwards, so the level used at
    // iteration k is levels[depth-1-k] (chain order is root first)
    std::vector<pointer_level_t> levels;
    if (!opt.levels.empty()) {
        levels = opt.levels;
        if (levels.size() > static_cast<size_t>(infra::limits::max_pointer_depth))
            levels.resize(static_cast<size_t>(infra::limits::max_pointer_depth));
    } else {
        const uint32_t d = std::min<uint32_t>(
            opt.depth ? opt.depth : 1,
            static_cast<uint32_t>(infra::limits::max_pointer_depth));
        levels.assign(d, pointer_level_t{opt.min_offset, opt.max_offset, 0, false});
    }
    for (auto& lv : levels) {
        if (!lv.wildcard && lv.max_offset < lv.min_offset)
            std::swap(lv.min_offset, lv.max_offset);
        if (lv.alignment == 0) lv.alignment = opt.alignment ? opt.alignment : 1;
    }
    const uint32_t depth = static_cast<uint32_t>(levels.size());
    if (depth == 0) return results;

    // one sweep at the coarsest alignment; per-level alignment filters holders
    size_t align = 1;
    for (const auto& lv : levels) align = std::max<size_t>(align, lv.alignment);

    // Merge the region set into aligned spans
    std::vector<detail::read_range_t> spans;
    for (const auto& reg : regions) {
        if (reg.size < 8) continue;
        const uintptr_t b = (reg.base + align - 1) / align * align;
        const uintptr_t e = reg.base + reg.size;
        if (e <= b + 8) continue;
        spans.push_back({b, static_cast<size_t>(e - b)});
    }

    std::vector<node_t> nodes;

    // Level-0 frontier is the pseudo-node standing in for the target
    nodes.push_back({opt.target, -1, 0});
    std::vector<size_t> frontier{0};

    // One sweep over all spans: collect every aligned non-null qword. Chunks
    // carry a 7-byte tail so qwords straddling a chunk border are kept
    std::vector<edge_t> edges;
    const reader_hints_t hints = r.hints();
    detail::chunk_walk_t walk;
    walk.chunk      = hints.chunk_bytes ? hints.chunk_bytes : size_t{1} << 20;
    walk.overlap    = 7;
    walk.min_leaf   = 4096;   // unreadability is page granular
    walk.read_ahead = hints.read_ahead;

    auto sink = [&](size_t, uintptr_t run_addr, const uint8_t* data, size_t len,
                    uintptr_t limit) -> bool {
        const uintptr_t run_end = run_addr + len;
        // runs may start unaligned to `align`
        uintptr_t p = (run_addr + align - 1) / align * align;
        for (; p + 8 <= run_end && p < limit; p += align) {
            uint64_t v;
            std::memcpy(&v, data + (p - run_addr), 8);
            if (v == 0) continue; // null pointers are noise
            edges.push_back({v, p});
            ++st.edges_explored;
            if (st.edges_explored > infra::limits::max_pointer_edges) {
                st.truncated = true;
                return false;
            }
        }
        return true;
    };

    detail::chunked_read(r, spans, walk, tok, sink);

    if (tok.cancelled()) { st.cancelled = true; }
    if (!edges.empty() && !st.cancelled) {
        std::sort(edges.begin(), edges.end(),
                  [](const edge_t& a, const edge_t& b) { return a.value < b.value; });

        for (uint32_t level = 0; level < depth && !frontier.empty(); ++level) {
            if (tok.cancelled()) { st.cancelled = true; break; }

            // iteration k walks backwards from the target, so it applies the
            // chain-order level depth-1-k
            const pointer_level_t& lv = levels[depth - 1 - level];
            const int64_t min_off = lv.wildcard ? INT32_MIN : lv.min_offset;
            const int64_t max_off = lv.wildcard ? INT32_MAX : lv.max_offset;

            // Expand every frontier address against the sorted edge list
            std::vector<size_t> next_frontier;
            bool frontier_full = false;

            for (const size_t fidx : frontier) {
                if (tok.cancelled()) { st.cancelled = true; break; }
                if (frontier_full) break;

                const uintptr_t dest = nodes[fidx].addr;

                // Accept V where diff = dest - V in [min_off, max_off]
                // => V in [dest - max_off, dest - min_off] (unsigned window)
                if (min_off > 0 && static_cast<uint64_t>(min_off) > dest) continue;
                const uint64_t lo = (max_off > 0 && static_cast<uint64_t>(max_off) > dest)
                    ? 0u
                    : dest - static_cast<uint64_t>(max_off);
                const uint64_t hi = dest - static_cast<uint64_t>(min_off); // wraps on negative
                if (hi < lo) continue;

                auto first = std::lower_bound(edges.begin(), edges.end(), lo,
                    [](const edge_t& e, uint64_t v) { return e.value < v; });
                auto last = std::upper_bound(edges.begin(), edges.end(), hi,
                    [](uint64_t v, const edge_t& e) { return v < e.value; });

                for (auto it = first; it != last; ++it) {
                    if (lv.alignment > 1 && (it->holder % lv.alignment) != 0) continue;
                    const int64_t off = static_cast<int64_t>(dest - it->value);
                    nodes.push_back({it->holder, static_cast<int64_t>(fidx), off});
                    next_frontier.push_back(nodes.size() - 1);
                    if (next_frontier.size() >= opt.frontier_cap) {
                        st.truncated = true;
                        frontier_full = true;
                        break;
                    }
                }
            }

            frontier = std::move(next_frontier);
            if (st.truncated && frontier.empty()) break;
        }
    }

    // build chains from every node, the parent walk yields root first
    for (size_t i = 1; i < nodes.size(); ++i) {
        if (results.size() >= infra::limits::max_pointer_chains) {
            st.truncated = true;
            break;
        }
        // Root (the holder the chain starts from, i.e. node i itself) must
        // live in a module-backed region so it survives restarts
        if (opt.only_module_backed && !in_module_backed(nodes[i].addr, regions))
            continue;
        pointer_chain_result_t chain;
        for (int64_t n = static_cast<int64_t>(i); n > 0;
             n = nodes[static_cast<size_t>(n)].parent) {
            const node_t& nd = nodes[static_cast<size_t>(n)];
            chain.addresses.push_back(nd.addr);
            chain.offsets.push_back(nd.offset);
        }
        // a root inside a module is reported module-relative so the chain
        // survives a restart at a different base
        if (!opt.modules.empty() && !chain.addresses.empty()) {
            const uintptr_t root = chain.addresses.front();
            for (const auto& m : opt.modules) {
                if (m.size == 0 || root < m.base || root >= m.base + m.size) continue;
                chain.module        = m.name;
                chain.module_offset = static_cast<uint64_t>(root - m.base);
                break;
            }
        }
        results.push_back(std::move(chain));
    }

    return results;
}

namespace {

// one pass worth of qword reads; chains sharing a root/prefix hit the cache
class link_reader_t {
public:
    link_reader_t(reader_t& r, uint64_t& reads) : r_(r), reads_(reads) {}
    std::optional<uint64_t> qword(uintptr_t addr) {
        auto it = cache_.find(addr);
        if (it != cache_.end()) return it->second;
        uint64_t v = 0;
        ++reads_;
        std::optional<uint64_t> got;
        if (r_.read(addr, &v, sizeof(v))) got = v;
        cache_.emplace(addr, got);
        return got;
    }
private:
    reader_t&                                              r_;
    uint64_t&                                              reads_;
    std::unordered_map<uintptr_t, std::optional<uint64_t>> cache_;
};

template <class Q>
std::optional<uintptr_t> resolve_with(Q&& qword, const pointer_chain_result_t& chain) {
    if (chain.addresses.empty() || chain.offsets.size() != chain.addresses.size())
        return std::nullopt;
    uintptr_t p = chain.addresses.front();
    for (const int64_t off : chain.offsets) {
        const std::optional<uint64_t> v = qword(p);
        if (!v) return std::nullopt;
        p = static_cast<uintptr_t>(*v + static_cast<uint64_t>(off));
    }
    return p;
}

} // namespace

std::optional<uintptr_t> pointer_chain_resolve(reader_t& r,
                                               const pointer_chain_result_t& chain) {
    return resolve_with([&](uintptr_t a) -> std::optional<uint64_t> {
        uint64_t v = 0;
        if (!r.read(a, &v, sizeof(v))) return std::nullopt;
        return v;
    }, chain);
}

std::vector<pointer_chain_result_t>
pointer_verify(reader_t& r,
               std::vector<pointer_chain_result_t> chains,
               const pointer_verify_options_t& opt,
               const infra::cancel_token_t& tok,
               pointer_verify_stats_t* stats) {
    pointer_verify_stats_t local{};
    pointer_verify_stats_t& st = stats ? *stats : local;
    st = {};
    st.checked = chains.size();

    const uint32_t samples  = std::clamp<uint32_t>(opt.samples, 1u, 64u);
    const uint32_t interval = std::min<uint32_t>(opt.interval_ms, 60'000u);

    for (uint32_t s = 0; s < samples && !chains.empty(); ++s) {
        if (s > 0 && interval) {
            // cancellable wait between samples
            const auto until = std::chrono::steady_clock::now() +
                               std::chrono::milliseconds(interval);
            while (std::chrono::steady_clock::now() < until && !tok.cancelled())
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (tok.cancelled()) { st.cancelled = true; break; }

        link_reader_t links(r, st.reads);
        auto qword = [&](uintptr_t a) { return links.qword(a); };
        size_t keep = 0;
        size_t i    = 0;
        for (; i < chains.size(); ++i) {
            if (tok.cancelled()) break;
            const std::optional<uintptr_t> landed = resolve_with(qword, chains[i]);
            if (!landed) { ++st.dropped_unreadable; continue; }
            if (*landed != opt.target) { ++st.dropped_mismatch; continue; }
            if (keep != i) chains[keep] = std::move(chains[i]);
            ++keep;
        }
        // a cancelled pass keeps the chains it never got to (unverified)
        for (; i < chains.size(); ++i, ++keep)
            if (keep != i) chains[keep] = std::move(chains[i]);
        chains.resize(keep);
        if (tok.cancelled()) { st.cancelled = true; break; }
        ++st.samples_done;
    }

    st.kept = chains.size();
    return chains;
}

} // namespace slop::core::memory
