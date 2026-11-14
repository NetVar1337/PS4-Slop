#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace slop::core::util {

// lowercase hex SHA-256 (BCrypt); empty string if the provider fails
std::string sha256_hex(const uint8_t* data, size_t len);

} // namespace slop::core::util
