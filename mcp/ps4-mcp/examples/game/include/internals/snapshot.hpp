#pragma once

#include <atomic>
#include <cstdint>
#include <type_traits>

namespace internals {

// Single-writer/single-reader publication for fixed-size game snapshots. Render
// callbacks may skip a busy frame; capture never allocates or waits on RPC.
template<class T> class SnapshotPublisher {
    static_assert(std::is_trivially_copyable<T>::value,
                  "Published snapshots must be trivially copyable");
public:
    void Publish(const T& value) noexcept {
        while (lock_.test_and_set(std::memory_order_acquire)) {}
        published_ = value;
        sequence_.fetch_add(1, std::memory_order_release);
        lock_.clear(std::memory_order_release);
    }

    bool TryConsume(T& value) const noexcept {
        if (lock_.test_and_set(std::memory_order_acquire)) return false;
        value = published_;
        lock_.clear(std::memory_order_release);
        return true;
    }

    void Consume(T& value) const noexcept {
        while (lock_.test_and_set(std::memory_order_acquire)) {}
        value = published_;
        lock_.clear(std::memory_order_release);
    }

    std::uint32_t sequence() const noexcept {
        return sequence_.load(std::memory_order_acquire);
    }

private:
    mutable std::atomic_flag lock_ = ATOMIC_FLAG_INIT;
    T published_{};
    std::atomic<std::uint32_t> sequence_{0};
};

} // namespace internals
