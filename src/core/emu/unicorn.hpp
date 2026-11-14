#pragma once

// raii wrapper over a unicorn engine, headers stay confined to this folder

#include <cstdint>
#include <cstddef>

struct uc_struct;

namespace slop::core::emu {

enum class uc_arch_t : uint8_t { x86_64, arm64 };

class unicorn_t {
public:
    explicit unicorn_t(uc_arch_t arch = uc_arch_t::x86_64);
    ~unicorn_t();

    unicorn_t(const unicorn_t&)            = delete;
    unicorn_t& operator=(const unicorn_t&) = delete;

    bool     ok() const noexcept { return uc_ != nullptr; }
    uc_struct* handle() const noexcept { return uc_; }

    // Page-aligned internally; sizes rounded up to 4 KiB
    bool map(uint64_t addr, size_t len);
    bool write(uint64_t addr, const void* data, size_t len);
    bool read(uint64_t addr, void* out, size_t len) const;

private:
    uc_struct* uc_ = nullptr;
};

} // namespace slop::core::emu
