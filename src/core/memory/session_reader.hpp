#pragma once

// reader over an attached runtime session. Reads ride the active backend; on
// a console (ps4debug) every read is a command on one serialized socket, so
// the reader asks the scan engines for one worker, big chunks, read-ahead and
// coalesced rescans instead of fanning threads onto that socket

#include <cstddef>
#include <cstdint>

#include "core/memory/reader.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/session.hpp"

namespace slop::core::memory {

// scheduling hints for whichever backend serves session reads right now
inline reader_hints_t hints_for_backend(runtime::backend_kind_t kind) noexcept {
    return kind == runtime::backend_kind_t::ps4 ? remote_reader_hints() : reader_hints_t{};
}

class session_reader_t final : public reader_t {
public:
    explicit session_reader_t(runtime::session_t& s)
        : s_(s), hints_(hints_for_backend(runtime::active_kind())) {}

    bool read(uintptr_t addr, void* dst, size_t len) override {
        const auto io = s_.read(addr, dst, len);
        return io.ok && io.bytes == len;
    }

    reader_hints_t hints() const noexcept override { return hints_; }

private:
    runtime::session_t& s_;
    reader_hints_t      hints_;
};

} // namespace slop::core::memory
