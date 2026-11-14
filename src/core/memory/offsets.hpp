#pragma once

// Fingerprint-gated offset manifests. A manifest pins the game build (title
// id, app version, SHA-256 of the module's executable segment) and gives every
// offset an anchor signature that must match exactly once. Verification is
// fail closed: one mismatch and no address is returned at all.
//
// {
//   "title_id": "CUSA00000", "app_ver": "01.00",   (optional; checked when given)
//   "module": "eboot.bin",
//   "text_sha256": "<64 hex>",                       (required)
//   "offsets": [
//     { "name": "player_base", "rva": "0x1234", "aob": "48 8B 05 ?? ?? ?? ??", "aob_offset": 0 }
//   ]
// }
// rva is relative to the executable segment base; the anchor must sit at
// text_base + rva - aob_offset. Without rva the anchor alone resolves the
// address (match + aob_offset).

#include <cstddef>
#include <cstdint>
#include <string>

#include <nlohmann/json.hpp>

namespace slop::core::memory {

struct offsets_input_t {
    std::string title_id;   // empty when the target cannot say (non-PS4)
    std::string app_ver;
    uint64_t text_base = 0;
    const uint8_t* text = nullptr;
    size_t text_len = 0;
};

// {ok, errors[], checks{}, resolved{name: addr}}; resolved is empty unless ok
nlohmann::json verify_offsets(const nlohmann::json& manifest, const offsets_input_t& in);

} // namespace slop::core::memory
