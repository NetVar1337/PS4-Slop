#pragma once

#include <cstdint>

namespace internals {

// Implementation and evidence are build-time inputs; providers are reported by
// the live runtime. A request never widens any of those capability sets.
struct FeatureCapabilities {
    std::uint32_t implemented = 0;
    std::uint32_t evidence = 0;
    std::uint32_t providers = 0;

    constexpr std::uint32_t available() const noexcept {
        return implemented & evidence & providers;
    }
    constexpr bool allows(std::uint32_t requested) const noexcept {
        return (requested & ~available()) == 0;
    }
};

} // namespace internals
