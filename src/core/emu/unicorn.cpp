// src/core/emu/unicorn.cpp

#include "core/emu/unicorn.hpp"

// Vendored header defines an unused static helper (usleep shim) that trips
// C4505 at TU end, suppressed for this include only
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4505)
#endif
#include <unicorn/unicorn.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

namespace slop::core::emu {

namespace {
constexpr uint64_t kPageMask = 0xFFFULL;

uc_engine* eng(uc_struct* h) { return reinterpret_cast<uc_engine*>(h); }
}

unicorn_t::unicorn_t(uc_arch_t arch) {
    uc_engine* e = nullptr;
    const uc_arch a = arch == uc_arch_t::arm64 ? UC_ARCH_ARM64 : UC_ARCH_X86;
    const uc_mode m = arch == uc_arch_t::arm64 ? UC_MODE_ARM : UC_MODE_64;
    if (uc_open(a, m, &e) == UC_ERR_OK)
        uc_ = reinterpret_cast<uc_struct*>(e);
}

unicorn_t::~unicorn_t() {
    if (uc_) uc_close(eng(uc_));
}

bool unicorn_t::map(uint64_t addr, size_t len) {
    if (!uc_ || len == 0) return false;
    const uint64_t base = addr & ~kPageMask;
    const uint64_t end  = (addr + len + kPageMask) & ~kPageMask;
    return uc_mem_map(eng(uc_), base, static_cast<size_t>(end - base),
                      UC_PROT_ALL) == UC_ERR_OK;
}

bool unicorn_t::write(uint64_t addr, const void* data, size_t len) {
    if (!uc_) return false;
    return uc_mem_write(eng(uc_), addr, data, len) == UC_ERR_OK;
}

bool unicorn_t::read(uint64_t addr, void* out, size_t len) const {
    if (!uc_) return false;
    return uc_mem_read(eng(uc_), addr, out, len) == UC_ERR_OK;
}

} // namespace slop::core::emu
