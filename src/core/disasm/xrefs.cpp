// src/core/disasm/xrefs.cpp

#include "core/disasm/xrefs.hpp"

#include <algorithm>
#include <cmath>

namespace slop::core::disasm {

const std::vector<xref_t> xref_index_t::kEmpty{};

namespace {

// Skip high entropy sections: compressed blobs only produce garbage refs and
// can eat the cap before real code is indexed.
//
// The cutoff has to clear real compiled code, which is noisier than it looks —
// a large optimised x64 .text measures around 6.6, and the old 6.5 cutoff
// silently produced zero xrefs for exactly the big binaries this index matters
// most for. Packed and encrypted payloads sit at 7.5 and up
constexpr double kPackedEntropy = 7.2;

double entropy(const uint8_t* data, size_t len) {
    if (!data || len == 0) return 0.0;
    uint32_t hist[256] = {};
    for (size_t i = 0; i < len; ++i) ++hist[data[i]];
    double e = 0.0;
    const double n = static_cast<double>(len);
    for (uint32_t c : hist) {
        if (!c) continue;
        const double p = static_cast<double>(c) / n;
        e -= p * std::log2(p);
    }
    return e;
}

// The gate is judged per region, not per section: a plain code head with a
// packed tail (or the reverse) only loses the packed part. A region shorter
// than kMinRegion measures low no matter what it holds, so it inherits its
// predecessor's verdict (sections that small are never skipped)
constexpr size_t kRegion    = 64 * 1024;
constexpr size_t kMinRegion = 4096;

std::vector<bool> packed_regions(const uint8_t* data, size_t len) {
    std::vector<bool> packed((len + kRegion - 1) / kRegion, false);
    if (len <= kMinRegion) return packed;
    for (size_t r = 0; r < packed.size(); ++r) {
        const size_t off = r * kRegion;
        const size_t n = std::min(kRegion, len - off);
        packed[r] = (n < kMinRegion && r > 0)
            ? packed[r - 1]
            : entropy(data + off, n) > kPackedEntropy;
    }
    return packed;
}

} // namespace

bool xref_index_t::build(const pe_image_t& pe, const std::vector<uint8_t>& file,
                         engine_t& eng, uint64_t base, size_t max_refs) {
    by_target_.clear();
    total_ = 0;
    if (!pe.ok || !eng.ok()) return false;

    for (const auto& s : pe.sections) {
        if (!s.is_executable() || s.raw_size == 0) continue;
        if (static_cast<size_t>(s.raw_offset) + s.raw_size > file.size()) continue;

        const uint8_t* data = file.data() + s.raw_offset;
        const uint64_t sec_va = base + s.rva;

        // Skip high-entropy regions (compressed/encrypted blobs produce
        // only noise refs and burn through the max_refs budget)
        const auto packed = packed_regions(data, s.raw_size);

        size_t off = 0;
        while (off < s.raw_size) {
            if (total_ >= max_refs) return true;   // index full, still usable
            if (packed[off / kRegion]) {
                off = (off / kRegion + 1) * kRegion;
                continue;
            }

            auto insn = eng.decode(sec_va + off, data + off, s.raw_size - off, false);
            if (!insn) { ++off; continue; }        // resync by one byte

            const uint64_t from = insn->va;
            if (insn->has_rel_target && insn->flow != flow_t::none) {
                // Validate target is within the image VA range to reduce noise
                const uint64_t target = insn->rel_target;
                if (target >= base && target < base + pe.size_of_image) {
                    const xref_kind_t k = (insn->flow == flow_t::call)
                                              ? xref_kind_t::call
                                              : xref_kind_t::jmp;
                    by_target_[target].push_back({from, target, k});
                    ++total_;
                }
            }
            if (insn->has_rip_rel) {
                const uint64_t target = insn->rip_rel_target;
                if (target >= base && target < base + pe.size_of_image) {
                    by_target_[target].push_back(
                        {from, target, xref_kind_t::data});
                    ++total_;
                }
            }

            off += insn->length;
        }
    }
    return true;
}

const std::vector<xref_t>& xref_index_t::refs_to(uint64_t va) const {
    const auto it = by_target_.find(va);
    return it != by_target_.end() ? it->second : kEmpty;
}

std::vector<uint64_t> xref_index_t::targets() const {
    std::vector<uint64_t> out;
    out.reserve(by_target_.size());
    for (const auto& [va, refs] : by_target_) out.push_back(va);
    return out;
}

} // namespace slop::core::disasm
