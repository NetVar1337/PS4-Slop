#pragma once

// fault tolerant read helpers: bisect unreadable ranges down to a leaf size,
// walk big ranges chunk by chunk with an optional read-ahead thread

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

#include "core/infra/cancel.hpp"
#include "core/memory/reader.hpp"

namespace slop::core::memory::detail {

// one readable run inside a caller buffer (offsets relative to its base)
struct read_run_t {
    size_t off = 0;
    size_t len = 0;
};

// read [addr, addr+len) straight into dst; unreadable parts are halved down
// to min_leaf and left untouched in dst. runs receives the readable parts in
// ascending order with adjacent runs merged
void resilient_read_into(reader_t& r, uintptr_t addr, size_t len, size_t min_leaf,
                         const slop::core::infra::cancel_token_t& tok,
                         uint8_t* dst, std::vector<read_run_t>& runs);

// read the range, unreadable parts get halved down to min leaf, every
// readable run goes to the sink in ascending address order
void resilient_read(reader_t& r, uintptr_t addr, size_t len, size_t min_leaf,
                    const slop::core::infra::cancel_token_t& tok,
                    const std::function<void(uintptr_t, const uint8_t*, size_t)>& sink);

struct chunk_walk_t {
    size_t chunk      = 0;     // bytes owned by each chunk (0 -> whole range)
    size_t overlap    = 0;     // extra bytes read past each chunk so values
                               // straddling the border are seen whole
    size_t min_leaf   = 4096;  // bisect floor for unreadable parts
    bool   read_ahead = false; // fetch chunk k+1 on a helper thread while the
                               // sink works on chunk k (double buffered)
};

// one address range to walk
struct read_range_t {
    uintptr_t addr = 0;
    size_t    len  = 0;
};

// sink(range_index, run_addr, data, len, start_limit): candidates starting at
// or past start_limit belong to the next chunk and must be skipped (they sit
// in the overlap tail). Return false to stop the walk
using chunk_sink_t =
    std::function<bool(size_t, uintptr_t, const uint8_t*, size_t, uintptr_t)>;

// walk every range in order, chunk by chunk in ascending address order. Each
// chunk is read with resilient_read_into; every readable run reaches the
// sink. With read_ahead the next chunk (possibly of the next range) is read
// while the sink processes the current one
void chunked_read(reader_t& r, const std::vector<read_range_t>& ranges,
                  const chunk_walk_t& walk,
                  const slop::core::infra::cancel_token_t& tok,
                  const chunk_sink_t& sink);
} // namespace slop::core::memory::detail
