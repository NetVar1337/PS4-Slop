// src/core/runtime/scan_bridge.cpp

#include "core/runtime/scan_bridge.hpp"

#include "core/runtime/backend_registry.hpp"

#ifdef _WIN32
#include <windows.h>
#else
// the Windows protection vocabulary the backends report
inline constexpr uint32_t MEM_COMMIT = 0x1000;
inline constexpr uint32_t PAGE_GUARD = 0x100;
#endif

namespace slop::core::runtime {

std::vector<memory::scan_region_t> target_scan_regions(const target_handle_t& h) {
    std::vector<memory::scan_region_t> out;
    auto res = active().enum_regions(h);
    if (!res.ok) return out;
    out.reserve(res.items.size());
    for (const auto& r : res.items) {
        const bool commit = (r.state & MEM_COMMIT) != 0;
        if (!commit || r.size == 0) continue;
        if (r.protect & PAGE_GUARD) continue;
        out.push_back({r.base, r.size, r.protect, r.type});
    }
    return out;
}

} // namespace slop::core::runtime
