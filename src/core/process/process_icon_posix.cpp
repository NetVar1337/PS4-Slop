// src/core/process/process_icon_posix.cpp
// No shell icon extraction off Windows. The header's contract says an empty
// result means "draw a generic glyph", which is exactly what the UI does.

#include "core/process/process_icon.hpp"

namespace slop::core::process {

icon_bits_t icon_for_path(const std::string&, bool) { return {}; }

} // namespace slop::core::process
