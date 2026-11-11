// src/core/memory/snapshot.cpp

#include "core/memory/snapshot.hpp"

#include "core/infra/limits.hpp"
#include "core/memory/read_util.hpp"

#include <cstring>
#include <vector>

namespace slop::core::memory {

region_snapshot_t snapshot_capture(reader_t& r, uintptr_t base, size_t size,
                                   const slop::core::infra::cancel_token_t& tok,
                                   uint64_t max_bytes) {
    region_snapshot_t snap;
    snap.base = base;

    if (size == 0) { snap.complete = true; return snap; }

    bool clamped = false;
    if (static_cast<uint64_t>(size) > max_bytes) {
        size = static_cast<size_t>(max_bytes);
        clamped = true;
    }

    snap.bytes.assign(size, 0x00);
    snap.size = size;

    // chunked walk honouring the reader's hints: a console gets big chunks
    // with read-ahead and page-granular hole probing (byte bisects would cost
    // thousands of roundtrips per unreadable page); local readers keep the
    // byte-exact hole map
    const reader_hints_t hints = r.hints();
    detail::chunk_walk_t walk;
    walk.chunk      = hints.chunk_bytes ? hints.chunk_bytes : size_t{1} << 20;
    walk.min_leaf   = hints.max_workers == 1 ? 4096 : 1;
    walk.read_ahead = hints.read_ahead;

    uint64_t covered = 0;
    detail::chunked_read(r, {{base, size}}, walk, tok,
        [&](size_t, uintptr_t addr, const uint8_t* data, size_t len, uintptr_t) {
            std::memcpy(snap.bytes.data() + (addr - base), data, len);
            covered += len;
            return true;
        });
    if (tok.cancelled()) { snap.complete = false; return snap; }

    // unreadable leaves stay zero-filled
    const bool holes = covered < size;
    snap.complete = !holes && !clamped;
    return snap;
}

snapshot_diff_t snapshot_diff(const region_snapshot_t& a, const region_snapshot_t& b) {
    snapshot_diff_t d;
    if (a.base != b.base || a.size != b.size || a.bytes.size() != b.bytes.size())
        return d; // valid stays false

    d.valid = true;
    const size_t n = a.bytes.size();

    size_t i = 0;
    while (i < n) {
        if (a.bytes[i] == b.bytes[i]) { ++i; continue; }
        const size_t start = i;
        while (i < n && a.bytes[i] != b.bytes[i]) ++i;
        d.changed.push_back({start, i - start});
        if (d.changed.size() >= infra::limits::max_diff_ranges) break;
    }
    return d;
}

} // namespace slop::core::memory
