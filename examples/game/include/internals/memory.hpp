#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace internals {
// Callers supply a mapping-aware reader on hardware. A failed/short read never
// becomes a fabricated zero-valued field. Also used by host replay tests.
struct MemoryReader {
    void* context = nullptr;
    bool (*read)(void*, std::uintptr_t, void*, std::size_t) noexcept = nullptr;
    bool Read(std::uintptr_t address, void* out, std::size_t size) const noexcept {
        return read && out && size && address &&
            size <= std::numeric_limits<std::uintptr_t>::max() - address &&
            read(context, address, out, size);
    }
    template<class T> bool Get(std::uintptr_t address, T& out) const noexcept {
        T value{};
        if (!Read(address, &value, sizeof(value))) return false;
        out = value;
        return true;
    }
};
struct ReadableRange { std::uintptr_t start, end; };
struct MappedMemory {
    const ReadableRange* ranges = nullptr;
    std::size_t count = 0;
    static bool Read(void* context, std::uintptr_t address, void* out, std::size_t size) noexcept {
        const auto& self = *static_cast<const MappedMemory*>(context);
        for (std::size_t i = 0; i < self.count; ++i) {
            const auto& range = self.ranges[i];
            if (address >= range.start && address < range.end && size <= range.end - address) {
                std::memcpy(out, reinterpret_cast<const void*>(address), size);
                return true;
            }
        }
        return false;
    }
    MemoryReader Reader() noexcept { return {this, &Read}; }
};
} // namespace internals
