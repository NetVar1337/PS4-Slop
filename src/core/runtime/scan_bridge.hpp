#pragma once

// src/core/runtime/scan_bridge.hpp
// region sets and readers sourced from the active backend so scans ride the driver when its live

#include <vector>

#include "core/memory/memscan.hpp"
#include "core/memory/reader.hpp"
#include "core/memory/session_reader.hpp"
#include "core/runtime/backend.hpp"

namespace slop::core::runtime {

// reader over the active backend, kernel badge means dtb copies, user badge means rpm
class backend_reader_t final : public memory::reader_t {
public:
    backend_reader_t(backend_t& b, const target_handle_t& h)
        : backend_(b), handle_(h) {}

    bool read(uintptr_t addr, void* dst, size_t len) override {
        auto io = backend_.read_memory(handle_, addr, dst, len);
        return io.ok && io.bytes == len;
    }

    // remote backends get one worker and large read-ahead chunks
    memory::reader_hints_t hints() const noexcept override {
        return memory::hints_for_backend(backend_.kind());
    }

private:
    backend_t&            backend_;
    const target_handle_t handle_;
};

// committed region set for the target, preference filtering happens in the engine
std::vector<memory::scan_region_t> target_scan_regions(const target_handle_t& h);

} // namespace slop::core::runtime
