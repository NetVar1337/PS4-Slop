#pragma once
#include <internals/memory.hpp>
#ifdef __PS4__
#include <orbis/libkernel.h>
#endif
namespace internals::platform {
inline bool Read(void*, std::uintptr_t address, void* out, std::size_t size) noexcept {
#ifdef __PS4__
    auto* destination = static_cast<std::uint8_t*>(out);
    while (size) {
        void* begin = nullptr;
        void* end = nullptr;
        std::int32_t protection = 0;
        if (sceKernelQueryMemoryProtection(reinterpret_cast<void*>(address), &begin, &end, &protection) != 0 ||
            !(protection & 1) || address < reinterpret_cast<std::uintptr_t>(begin) ||
            address >= reinterpret_cast<std::uintptr_t>(end)) return false;
        const auto remaining = reinterpret_cast<std::uintptr_t>(end) - address;
        const auto count = size < remaining ? size : remaining;
        std::memcpy(destination, reinterpret_cast<const void*>(address), count);
        address += count; destination += count; size -= count;
    }
    return true;
#else
    (void)address; (void)out; (void)size;
    return false;
#endif
}
inline MemoryReader Reader() noexcept { return {nullptr, &Read}; }
} // namespace internals::platform
