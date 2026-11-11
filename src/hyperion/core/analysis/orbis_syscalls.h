#pragma once
// Orbis OS (PS4) syscall numbering: the FreeBSD 9 amd64 table the kernel was
// forked from plus Sony's additions from 532 up and the network slots Sony
// reused in the BSD compat range. The signature matcher names libkernel /
// payload-SDK syscall stubs from it; reverse-slop's xray and emulator reach
// it through slop::core::analysis::ps4_syscall_name
#include "core/types.h"
#include <cstddef>

namespace hype {

// Name without the "sys_" prefix ("getpid", "dynlib_dlsym"), nullptr for
// numbers that are unassigned, obsolete or compat-only on Orbis
const char* orbis_syscall_name(u64 num) noexcept;

// Number of named entries in the table
size_t orbis_syscall_count() noexcept;

}
