// src/core/memory/read_util.cpp

#include "core/memory/read_util.hpp"

#include <algorithm>
#include <condition_variable>
#include <exception>
#include <mutex>
#include <optional>
#include <thread>

namespace slop::core::memory::detail {

void resilient_read_into(reader_t& r, uintptr_t addr, size_t len, size_t min_leaf,
                         const slop::core::infra::cancel_token_t& tok,
                         uint8_t* dst, std::vector<read_run_t>& runs) {
    runs.clear();
    if (len == 0) return;
    if (min_leaf == 0) min_leaf = 1;

    struct seg_t { size_t off; size_t len; };
    // LIFO with the upper half pushed first: segments pop in ascending order
    std::vector<seg_t> stack{ {0, len} };

    while (!stack.empty()) {
        if (tok.cancelled()) return;
        const seg_t s = stack.back();
        stack.pop_back();

        if (r.read(addr + s.off, dst + s.off, s.len)) {
            if (!runs.empty() && runs.back().off + runs.back().len == s.off)
                runs.back().len += s.len;
            else
                runs.push_back({s.off, s.len});
            continue;
        }
        if (s.len <= min_leaf) continue; // unreadable leaf: contribute nothing
        const size_t half = std::max<size_t>((s.len / 2 / min_leaf) * min_leaf, min_leaf);
        stack.push_back({s.off + half, s.len - half});
        stack.push_back({s.off, half});
    }
}

void resilient_read(reader_t& r, uintptr_t addr, size_t len, size_t min_leaf,
                    const slop::core::infra::cancel_token_t& tok,
                    const std::function<void(uintptr_t, const uint8_t*, size_t)>& sink) {
    if (len == 0) return;
    std::vector<uint8_t> buf(len);
    std::vector<read_run_t> runs;
    resilient_read_into(r, addr, len, min_leaf, tok, buf.data(), runs);
    for (const auto& run : runs) {
        if (tok.cancelled()) return;
        sink(addr + run.off, buf.data() + run.off, run.len);
    }
}

namespace {

struct chunk_buf_t {
    size_t                  range = 0;
    uintptr_t               base  = 0;
    uintptr_t               limit = 0;   // first address owned by the next chunk
    std::vector<uint8_t>    bytes;
    std::vector<read_run_t> runs;
};

// position of the next chunk to read across the range list
struct walk_cursor_t {
    size_t    range = 0;
    uintptr_t cur   = 0;
};

} // namespace

void chunked_read(reader_t& r, const std::vector<read_range_t>& ranges,
                  const chunk_walk_t& walk,
                  const slop::core::infra::cancel_token_t& tok,
                  const chunk_sink_t& sink) {
    // step over exhausted/empty ranges so the cursor only lands on real bytes
    auto settle = [&](walk_cursor_t& c) {
        while (c.range < ranges.size()) {
            const read_range_t& rg = ranges[c.range];
            if (rg.len && c.cur >= rg.addr && c.cur < rg.addr + rg.len) return;
            ++c.range;
            if (c.range < ranges.size()) c.cur = ranges[c.range].addr;
        }
    };
    walk_cursor_t start{0, ranges.empty() ? 0 : ranges[0].addr};
    settle(start);
    if (start.range >= ranges.size()) return;

    // fill the chunk at c and advance c past it
    auto fill = [&](chunk_buf_t& b, walk_cursor_t& c) {
        const read_range_t& rg = ranges[c.range];
        const uintptr_t end   = rg.addr + rg.len;
        const size_t    chunk = walk.chunk ? walk.chunk : rg.len;
        const size_t own  = static_cast<size_t>(std::min<uint64_t>(chunk, end - c.cur));
        const size_t tail = static_cast<size_t>(
            std::min<uint64_t>(walk.overlap, end - c.cur - own));
        b.range = c.range;
        b.base  = c.cur;
        b.limit = c.cur + own;
        b.bytes.resize(own + tail);
        resilient_read_into(r, c.cur, own + tail, walk.min_leaf, tok, b.bytes.data(), b.runs);
        c.cur = b.limit;
        settle(c);
    };
    auto drain = [&](const chunk_buf_t& b) -> bool {
        for (const auto& run : b.runs) {
            if (tok.cancelled()) return false;
            if (!sink(b.range, b.base + run.off, b.bytes.data() + run.off, run.len, b.limit))
                return false;
        }
        return true;
    };

    // a single chunk overall gains nothing from a helper thread
    bool single_chunk = false;
    {
        walk_cursor_t probe = start;
        const read_range_t& rg = ranges[probe.range];
        const size_t chunk = walk.chunk ? walk.chunk : rg.len;
        if (rg.addr + rg.len - probe.cur <= chunk) {
            probe.cur = rg.addr + rg.len;
            settle(probe);
            single_chunk = probe.range >= ranges.size();
        }
    }

    if (!walk.read_ahead || single_chunk) {
        chunk_buf_t   b;
        walk_cursor_t c = start;
        while (c.range < ranges.size()) {
            if (tok.cancelled()) return;
            fill(b, c);
            if (!drain(b)) return;
        }
        return;
    }

    // double buffered: the producer reads chunk k+1 while the caller's sink
    // chews on chunk k; buffers are recycled so steady state allocates nothing
    std::mutex                 mu;
    std::condition_variable    cv;
    std::optional<chunk_buf_t> ready;
    std::vector<chunk_buf_t>   spare;
    bool                       done = false;
    bool                       stop = false;
    std::exception_ptr         producer_error;

    std::thread producer([&] {
        try {
            walk_cursor_t c = start;
            while (c.range < ranges.size()) {
                chunk_buf_t b;
                {
                    std::lock_guard lk(mu);
                    if (stop) break;
                    if (!spare.empty()) {
                        b = std::move(spare.back());
                        spare.pop_back();
                    }
                }
                if (tok.cancelled()) break;
                fill(b, c);
                std::unique_lock lk(mu);
                cv.wait(lk, [&] { return !ready.has_value() || stop; });
                if (stop) break;
                ready = std::move(b);
                cv.notify_all();
            }
        } catch (...) {
            std::lock_guard lk(mu);
            producer_error = std::current_exception();
        }
        std::lock_guard lk(mu);
        done = true;
        cv.notify_all();
    });

    auto halt = [&] {
        {
            std::lock_guard lk(mu);
            stop = true;
        }
        cv.notify_all();
        producer.join();
    };

    try {
        for (;;) {
            chunk_buf_t b;
            {
                std::unique_lock lk(mu);
                cv.wait(lk, [&] { return ready.has_value() || done; });
                if (!ready) break;
                b = std::move(*ready);
                ready.reset();
            }
            cv.notify_all();
            const bool more = drain(b);
            {
                std::lock_guard lk(mu);
                spare.push_back(std::move(b));
            }
            if (!more || tok.cancelled()) break;
        }
    } catch (...) {
        halt();
        throw;
    }
    halt();
    if (producer_error) std::rethrow_exception(producer_error);
}

} // namespace slop::core::memory::detail
