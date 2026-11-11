// src/core/analysis/ps4_syscalls.cpp
// the table itself lives with the hyperion signature matcher (which names
// syscall stubs from it); this is the reverse-slop facing entry point

#include "core/analysis/ps4_syscalls.hpp"

#include "core/analysis/orbis_syscalls.h"

namespace slop::core::analysis {

const char* ps4_syscall_name(uint64_t num) noexcept {
    return hype::orbis_syscall_name(num);
}

size_t ps4_syscall_count() noexcept { return hype::orbis_syscall_count(); }

} // namespace slop::core::analysis
