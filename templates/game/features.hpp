#pragma once
// Standard PSWB resident-payload feature bits (see docs/PROJECT_PIPELINE.md).
// Every bit is independent and off by default; the RPC features callback
// rejects anything outside kImplementedMask, and the project manifest's
// feature table records which live-validated findings each bit requires.
// Unsafe capabilities stay rejected unless explicitly compiled in.
#include <cstdint>

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

// Fail-closed gate: any requested bit that is not implemented is rejected.
inline constexpr bool allowed(std::uint32_t requested) noexcept {
    return (requested & ~kImplementedMask) == 0;
}

} // namespace features
