#pragma once

// src/core/analysis/ps4_syscalls.hpp
// Orbis OS (PS4) syscall numbering: the FreeBSD 9 amd64 table the kernel
// was forked from plus Sony's additions from 532 up and the network slots
// Sony reused in the BSD compat range. Shared by xray.syscalls (static scan
// of ELF images) and the emulator's syscall hook

#include <cstddef>
#include <cstdint>

namespace slop::core::analysis {

// Name without the "sys_" prefix ("getpid", "dynlib_dlsym"), nullptr for
// numbers that are unassigned, obsolete or compat-only on Orbis
const char* ps4_syscall_name(uint64_t num) noexcept;

// Number of named entries in the table (for diagnostics and tests)
size_t ps4_syscall_count() noexcept;

} // namespace slop::core::analysis
