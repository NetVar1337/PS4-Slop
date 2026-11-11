#pragma once

// minimal read abstraction, a session in production and a fake in tests

#include <cstddef>
#include <cstdint>

namespace slop::core::memory {

// How the scan engines should drive a reader. Local readers keep the
// defaults (fan out across cores, default chunk size). Remote readers that
// funnel every read through one serialized connection (the ps4debug socket)
// ask for a single worker, bigger chunks and a read-ahead thread so the next
// chunk is in flight while the current one is being compared
struct reader_hints_t {
    unsigned max_workers  = 0;     // 0 = no limit
    size_t   chunk_bytes  = 0;     // 0 = engine default
    bool     read_ahead   = false; // double-buffer chunk reads
    size_t   coalesce_gap = 0;     // address-list rescans: merge reads of rows
                                   // whose gap is <= this (0 = one read per row)
};

// Hints for a reader backed by one serialized remote connection
inline constexpr size_t kRemoteChunkBytes   = 8u << 20;  // 8 MiB per wire read
inline constexpr size_t kRemoteCoalesceGap  = 4096;      // one page of slack
// largest chunk a caller may request over the wire: the ps4debug transfer cap
// (16 MiB) minus a page for the overlap tail chunk walks append
inline constexpr size_t kRemoteMaxChunkBytes = (16u << 20) - 4096;

constexpr reader_hints_t remote_reader_hints() noexcept {
    return reader_hints_t{1u, kRemoteChunkBytes, true, kRemoteCoalesceGap};
}

class reader_t {
public:
    virtual ~reader_t() = default;

    // Read len bytes at addr. Returns false if any part is unreadable
    // (unmapped, no access, target died). Partial reads never happen
    virtual bool read(uintptr_t addr, void* dst, size_t len) = 0;

    // Scheduling hints for the scan engines (see reader_hints_t)
    virtual reader_hints_t hints() const noexcept { return {}; }
};

} // namespace slop::core::memory
