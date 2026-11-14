#pragma once

// Deterministic Orbis (FreeBSD 9) syscall emulation for emulated PS4 code.
// The handler runs on the emulation thread with the live unicorn engine, so
// mmap/munmap/mprotect act on the emulated address space and write() reads
// the emulated buffer. Numbers come from the shared Orbis table
// (core/analysis/ps4_syscalls.hpp), names are not duplicated here.

#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

namespace slop::core::emu {

// FreeBSD errno values the handler returns
inline constexpr uint64_t kOrbisENOSYS  = 78;
inline constexpr uint64_t kOrbisEINVAL  = 22;
inline constexpr uint64_t kOrbisENOMEM  = 12;
inline constexpr uint64_t kOrbisEBADF   = 9;
inline constexpr uint64_t kOrbisEFAULT  = 14;

struct orbis_state_t {
    uint64_t pid  = 1000;
    uint64_t ppid = 1;
    uint64_t tid  = 1001;
    uint64_t uid  = 1000;

    // Deterministic clock: every call reports this fixed time, so a rerun of
    // the same code produces the same values
    uint64_t clock_us = 0x5F5E100;   // 100 ms, arbitrary but stable

    uint64_t mmap_next = 0x700000000000ull;   // next anonymous mapping
    size_t   max_stdout = 1u << 20;           // captured write() bytes
    size_t   max_maps   = 256;                // live mmap regions

    std::vector<uint8_t>       stdout_data;
    std::map<uint64_t, size_t> maps;          // base -> length
    size_t enosys = 0;                        // calls answered with ENOSYS
    bool   exited = false;                    // exit() was called
    uint64_t exit_code = 0;
};

struct orbis_result_t {
    bool     ok = true;    // false: CF set, value is the errno
    uint64_t value = 0;    // rax on return
};

// `uc` is the live uc_engine (void* keeps unicorn headers out of here)
orbis_result_t orbis_syscall(void* uc, orbis_state_t& st, uint64_t num,
                             const uint64_t args[6]);

} // namespace slop::core::emu
