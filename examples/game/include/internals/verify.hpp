#pragma once

// Fail-closed target verification for resident payloads.
//
// `project_export_offsets` (PS4-DebugMCPs) generates an `offsets.hpp` whose
// per-module `kVerifyChecks[]` arrays are built from this struct: each entry is
// a module-relative RVA plus the bytes observed in a recorded dump of the exact
// module hash the offsets were derived from. A payload calls verify_module()
// once at startup with its target module base; any mismatch (or a base that
// cannot be checked) returns false and the caller must stay in safe mode.
//
// RPC and lifecycle code must never call this: it reads target memory and is
// only safe from the payload's own thread during initialization.

#include <cstddef>
#include <cstdint>
#include <internals/memory.hpp>

namespace internals {

inline constexpr std::size_t kMaxVerifyBytes = 32;

struct VerifyCheck {
    std::uintptr_t offset;                 // module-relative RVA
    std::size_t length;                    // 1..kMaxVerifyBytes
    std::uint8_t bytes[kMaxVerifyBytes];   // expected bytes at base + offset
};

inline bool verify_module(MemoryReader reader, std::uintptr_t base, const VerifyCheck* checks, std::size_t count) noexcept {
    if (!base || !checks || !count || count > 64) return false;
    for (std::size_t i = 0; i < count; ++i) {
        const auto& check = checks[i];
        std::uint8_t actual[kMaxVerifyBytes]{};
        if (!check.length || check.length > kMaxVerifyBytes || base > UINTPTR_MAX - check.offset ||
            !reader.Read(base + check.offset, actual, check.length)) return false;
        for (std::size_t j = 0; j < check.length; ++j) if (actual[j] != check.bytes[j]) return false;
    }
    return true;
}

// Compare every check against the mapped module at `base`.
// Returns false on the first mismatch, on any malformed check, or when a
// non-empty check list is given without a base. Empty verification is never
// evidence that a target matches: an unconfigured payload stays unavailable.
inline bool verify_module(std::uintptr_t base, const VerifyCheck* checks, std::size_t count) noexcept {
    if (checks == nullptr || count == 0 || base == 0 || count > 64) {
        return false;
    }
    for (std::size_t i = 0; i < count; ++i) {
        const VerifyCheck& check = checks[i];
        if (check.length == 0 || check.length > kMaxVerifyBytes) {
            return false;
        }
        const std::uintptr_t at = base + check.offset; // caller guarantees module mapping covers offsets
        if (at < base) {
            return false; // overflow
        }
        const volatile std::uint8_t* actual = reinterpret_cast<const volatile std::uint8_t*>(at);
        for (std::size_t j = 0; j < check.length; ++j) {
            if (actual[j] != check.bytes[j]) {
                return false;
            }
        }
    }
    return true;
}

} // namespace internals
