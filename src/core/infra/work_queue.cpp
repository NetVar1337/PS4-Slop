#include "core/infra/work_queue.hpp"
#include "core/infra/limits.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdlib>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>

namespace slop::core::infra::pool {

namespace {

struct pool_state_t {
    std::mutex                          mu;
    std::condition_variable             cv;
    std::condition_variable             exit_cv;    // a worker left worker_loop
    std::deque<std::function<void()>>   queue;
    std::vector<std::thread>            workers;
    std::atomic<bool>                   stopping{false};
    std::atomic<uint32_t>               running_count{0};
    std::atomic<uint64_t>               completed_count{0};
    std::atomic<uint64_t>               rejected_count{0};
    uint32_t                            num_workers = 0;
    uint64_t                            generation  = 0;   // guarded by mu
    uint32_t                            exited      = 0;   // guarded by mu, this generation
};

// never destroyed: a straggler still finishing its task after stop() keeps
// touching this, so static teardown must not run its destructor under it
pool_state_t& g_pool = *new pool_state_t;

void worker_loop(uint64_t gen) {
    for (;;) {
        std::function<void()> task;
        {
            std::unique_lock lk(g_pool.mu);
            g_pool.cv.wait(lk, [gen] {
                return g_pool.generation != gen ||
                       g_pool.stopping.load(std::memory_order_relaxed) ||
                       !g_pool.queue.empty();
            });
            if (g_pool.generation != gen ||
                (g_pool.stopping.load(std::memory_order_relaxed) && g_pool.queue.empty())) {
                if (g_pool.generation == gen) ++g_pool.exited;
                g_pool.exit_cv.notify_all();
                return;
            }
            task = std::move(g_pool.queue.front());
            g_pool.queue.pop_front();
        }
        g_pool.running_count.fetch_add(1, std::memory_order_relaxed);
        task();
        g_pool.running_count.fetch_sub(1, std::memory_order_relaxed);
        g_pool.completed_count.fetch_add(1, std::memory_order_relaxed);
    }
}

} // namespace

void start(uint32_t workers) {
    if (workers == 0) {
        const uint32_t hw = std::thread::hardware_concurrency();
        workers = std::max(2u, hw > 1 ? hw - 1 : 2u);
    }
    workers = std::min(workers, limits::pool_max_workers);

    static const bool cleanup_registered = [] {
        std::atexit([] {
            // a joinable thread destroyed at teardown calls terminate, so always drain the pool
            stop(1000);
        });
        return true;
    }();
    (void)cleanup_registered;

    uint64_t gen = 0;
    {
        std::lock_guard lk(g_pool.mu);
        gen = ++g_pool.generation;
        g_pool.exited = 0;
        g_pool.stopping.store(false, std::memory_order_relaxed);
        g_pool.num_workers = workers;
    }
    g_pool.workers.reserve(workers);
    for (uint32_t i = 0; i < workers; ++i) {
        g_pool.workers.emplace_back(worker_loop, gen);
    }
}

void stop(uint32_t drain_deadline_ms) {
    std::vector<std::thread> workers;
    {
        std::lock_guard lk(g_pool.mu);
        g_pool.stopping.store(true, std::memory_order_release);
        // tasks nobody started yet are dropped, only in-flight ones get the deadline
        if (!g_pool.queue.empty())
            g_pool.rejected_count.fetch_add(g_pool.queue.size(), std::memory_order_relaxed);
        g_pool.queue.clear();
        workers.swap(g_pool.workers);
    }
    g_pool.cv.notify_all();
    if (workers.empty()) return;

    // one deadline for the whole pool, never an unbounded join on a busy worker
    const auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::milliseconds(drain_deadline_ms);
    bool all_exited = false;
    {
        std::unique_lock lk(g_pool.mu);
        all_exited = g_pool.exit_cv.wait_until(lk, deadline, [&] {
            return g_pool.exited >= workers.size();
        });
    }
    if (all_exited) {
        for (auto& t : workers)
            if (t.joinable()) t.join();
        return;
    }
    // stragglers are still inside a task: retire this generation so they exit
    // after it, and park the handles where no destructor ever runs (a joinable
    // std::thread destructor calls terminate)
    {
        std::lock_guard lk(g_pool.mu);
        ++g_pool.generation;
    }
    g_pool.cv.notify_all();
    static auto* parked = new std::vector<std::thread>;
    for (auto& t : workers) parked->push_back(std::move(t));
}

uint32_t worker_count() noexcept {
    return g_pool.num_workers;
}

stats_t snapshot() {
    stats_t s;
    s.workers   = g_pool.num_workers;
    s.running   = g_pool.running_count.load(std::memory_order_relaxed);
    s.completed = g_pool.completed_count.load(std::memory_order_relaxed);
    s.rejected  = g_pool.rejected_count.load(std::memory_order_relaxed);
    {
        std::lock_guard lk(g_pool.mu);
        s.queued = static_cast<uint32_t>(g_pool.queue.size());
    }
    return s;
}

bool submit(std::function<void()> fn) {
    if (g_pool.stopping.load(std::memory_order_acquire)) {
        g_pool.rejected_count.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    {
        std::lock_guard lk(g_pool.mu);
        if (g_pool.queue.size() >= limits::pool_queue_cap) {
            g_pool.rejected_count.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        g_pool.queue.push_back(std::move(fn));
    }
    g_pool.cv.notify_one();
    return true;
}

void parallel_for(size_t count, const cancel_token_t& tok,
                  const std::function<void(size_t index, uint32_t worker_slot)>& body,
                  uint32_t max_workers) {
    if (count == 0) return;

    const uint32_t n = (max_workers == 0)
        ? g_pool.num_workers
        : std::min(max_workers, g_pool.num_workers);

    if (n <= 1 || count == 1) {
        // serial fallback
        for (size_t i = 0; i < count && !tok.cancelled(); ++i) {
            body(i, 0);
        }
        return;
    }

    std::atomic<size_t>   next_index{0};
    std::atomic<uint32_t> workers_done{0};
    std::mutex            done_mu;
    std::condition_variable done_cv;

    const uint32_t spawn = std::min(n, static_cast<uint32_t>(count));

    for (uint32_t slot = 0; slot < spawn; ++slot) {
        const bool queued = pool::submit([&, slot] {
            for (;;) {
                if (tok.cancelled()) break;
                const size_t idx = next_index.fetch_add(1, std::memory_order_relaxed);
                if (idx >= count) break;
                body(idx, slot);
            }
            workers_done.fetch_add(1, std::memory_order_release);
            done_cv.notify_one();
        });

        if (!queued) {
            // pool full so the caller chips in
            for (;;) {
                if (tok.cancelled()) break;
                const size_t idx = next_index.fetch_add(1, std::memory_order_relaxed);
                if (idx >= count) break;
                body(idx, slot);
            }
            workers_done.fetch_add(1, std::memory_order_release);
            done_cv.notify_one();
        }
    }

    // wait for the workers
    std::unique_lock lk(done_mu);
    done_cv.wait(lk, [&] {
        return workers_done.load(std::memory_order_acquire) >= spawn;
    });
}

} // namespace slop::core::infra::pool
