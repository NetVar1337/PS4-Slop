#pragma once
// Standard PSWB resident-payload feature bits (see docs/PROJECT_PIPELINE.md).
// Every bit is independent and off by default; the RPC features callback
// rejects anything outside kImplementedMask, and the project manifest's
// feature table records which live-validated findings each bit requires.
// Unsafe capabilities stay rejected unless explicitly compiled in.
#include <cstdint>
#if __has_include(<internals/capabilities.hpp>)
#include <internals/capabilities.hpp>
#else
#include "../../internals/include/internals/capabilities.hpp"
#endif
#if __has_include("generated/feature_dependencies.hpp")
#include "generated/feature_dependencies.hpp"
#else
namespace features {
inline constexpr std::uint32_t kEvidenceMask = 0;
inline constexpr bool dependencies_satisfied(std::uint32_t) noexcept { return true; }
}
#endif

namespace features {

inline constexpr std::uint32_t kPaint        = 1u << 0;
inline constexpr std::uint32_t kMenu         = 1u << 1;
inline constexpr std::uint32_t kEsp          = 1u << 2;
inline constexpr std::uint32_t kAim          = 1u << 3;
inline constexpr std::uint32_t kRadar        = 1u << 4;
inline constexpr std::uint32_t kLoot         = 1u << 5;
inline constexpr std::uint32_t kWeapon       = 1u << 6;
inline constexpr std::uint32_t kDiagnostics  = 1u << 7;
inline constexpr std::uint32_t kMetadata     = 1u << 8;
inline constexpr std::uint32_t kGlow         = 1u << 9;
inline constexpr std::uint32_t kMovement     = 1u << 10;
inline constexpr std::uint32_t kScripts      = 1u << 11;
inline constexpr std::uint32_t kChams        = 1u << 12;
inline constexpr std::uint32_t kNativeMinimap = 1u << 13;

// Feature bits this template actually implements. Game projects extend this
// mask only after the required findings are live-validated for the exact
// build; project_doctor reports availability per feature.
inline constexpr std::uint32_t kImplementedMask = kDiagnostics;

// Fail-closed gate: implementation, exact-build evidence and dependencies are
// all required. A game can additionally reject unavailable runtime providers.
inline bool allowed(std::uint32_t requested) noexcept {
    const internals::FeatureCapabilities capabilities{kImplementedMask, kEvidenceMask, kImplementedMask};
    return capabilities.allows(requested) && dependencies_satisfied(requested);
}

} // namespace features
