#pragma once

// "Dissect data structures": guess what each 8-byte slot of an unknown object
// is (pointer to code / object / string / data, float, double, int, inline
// text, zero) so a struct layout can be drafted from live memory.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

#include <nlohmann/json.hpp>

namespace slop::core::memory {

struct dissect_env_t {
    std::function<bool(uint64_t)> readable;            // committed + readable
    std::function<bool(uint64_t)> executable;
    std::function<std::string(uint64_t)> symbolize;    // "eboot.bin+0x1234" or ""
    std::function<size_t(uint64_t, void*, size_t)> read;   // bytes read
};

// rows: [{offset, hex, kind, value, target?}], one per 8-byte slot of data
nlohmann::json dissect(uint64_t base, const uint8_t* data, size_t len, const dissect_env_t& env);

} // namespace slop::core::memory
