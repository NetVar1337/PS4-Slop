// src/core/emu/orbis.cpp
// the minimal Orbis syscall set the PS4 emulation path implements: process
// and thread ids, stdout capture, anonymous mappings on the emulated address
// space, a deterministic clock, sysctl basics and exit. Everything else is
// logged by the caller and answered with ENOSYS.

#include "core/emu/orbis.hpp"

// Vendored header defines an unused static helper (usleep shim) that trips
// C4505 at TU end, suppressed for this include only
#pragma warning(push)
#pragma warning(disable : 4505)
#include <unicorn/unicorn.h>
#pragma warning(pop)

#include <algorithm>
#include <cstring>

namespace slop::core::emu {

namespace {

constexpr uint64_t kPage     = 0x1000;
constexpr uint64_t kMapFixed = 0x10;   // MAP_FIXED
constexpr uint32_t kProtRead  = 1;
constexpr uint32_t kProtWrite = 2;
constexpr uint32_t kProtExec  = 4;

uc_engine* eng(void* uc) { return static_cast<uc_engine*>(uc); }

uint64_t align_up(uint64_t v) { return (v + kPage - 1) & ~(kPage - 1); }

bool read_guest(void* uc, uint64_t addr, void* out, size_t len) {
    if (!addr || !len) return false;
    return uc_mem_read(eng(uc), addr, out, len) == UC_ERR_OK;
}

bool write_guest(void* uc, uint64_t addr, const void* in, size_t len) {
    if (!addr || !len) return false;
    return uc_mem_write(eng(uc), addr, in, len) == UC_ERR_OK;
}

orbis_result_t errno_result(uint64_t e) { return {false, e}; }

// write(fd, buf, n): stdout/stderr go to the capture, other fds are EBADF
orbis_result_t sys_write(void* uc, orbis_state_t& st, const uint64_t args[6]) {
    const uint64_t fd = args[0], buf = args[1], n = args[2];
    if (fd != 1 && fd != 2) return errno_result(kOrbisEBADF);
    if (!n) return {true, 0};
    const size_t want = static_cast<size_t>(std::min<uint64_t>(n, 1u << 20));
    std::vector<uint8_t> tmp(want);
    if (!read_guest(uc, buf, tmp.data(), tmp.size())) return errno_result(kOrbisEFAULT);
    const size_t room = st.max_stdout > st.stdout_data.size()
                            ? st.max_stdout - st.stdout_data.size() : 0;
    const size_t keep = std::min(room, tmp.size());
    st.stdout_data.insert(st.stdout_data.end(), tmp.begin(),
                          tmp.begin() + static_cast<std::ptrdiff_t>(keep));
    return {true, n};   // the full count is reported even when the capture is full
}

// mmap(addr, len, prot, flags, fd, pad): anonymous mappings only
orbis_result_t sys_mmap(void* uc, orbis_state_t& st, const uint64_t args[6]) {
    const uint64_t len = align_up(args[1]);
    if (!len) return errno_result(kOrbisEINVAL);
    if (st.maps.size() >= st.max_maps) return errno_result(kOrbisENOMEM);
    uint64_t base = 0;
    if ((args[3] & kMapFixed) && args[0]) {
        base = args[0] & ~(kPage - 1);
        uc_mem_unmap(eng(uc), base, len);   // MAP_FIXED replaces what is there
    } else {
        base = align_up(st.mmap_next);
        st.mmap_next = base + len;
    }
    const uint32_t prot = (args[2] & kProtRead ? UC_PROT_READ : 0) |
                          (args[2] & kProtWrite ? UC_PROT_WRITE : 0) |
                          (args[2] & kProtExec ? UC_PROT_EXEC : 0);
    if (uc_mem_map(eng(uc), base, static_cast<size_t>(len),
                   prot ? prot : UC_PROT_ALL) != UC_ERR_OK)
        return errno_result(kOrbisENOMEM);
    st.maps[base] = static_cast<size_t>(len);
    return {true, base};
}

orbis_result_t sys_munmap(void* uc, orbis_state_t& st, const uint64_t args[6]) {
    const uint64_t base = args[0] & ~(kPage - 1);
    auto it = st.maps.find(base);
    if (it == st.maps.end()) return errno_result(kOrbisEINVAL);
    uc_mem_unmap(eng(uc), base, it->second);
    st.maps.erase(it);
    return {true, 0};
}

orbis_result_t sys_mprotect(void* uc, const uint64_t args[6]) {
    const uint64_t base = args[0] & ~(kPage - 1);
    const uint64_t len  = align_up(args[1]);
    if (!len) return errno_result(kOrbisEINVAL);
    const uint32_t prot = (args[2] & kProtRead ? UC_PROT_READ : 0) |
                          (args[2] & kProtWrite ? UC_PROT_WRITE : 0) |
                          (args[2] & kProtExec ? UC_PROT_EXEC : 0);
    if (uc_mem_protect(eng(uc), base, static_cast<size_t>(len), prot) != UC_ERR_OK)
        return errno_result(kOrbisEINVAL);
    return {true, 0};
}

// gettimeofday(tp, tz) / clock_gettime(clk, tp): the deterministic clock
orbis_result_t sys_time(void* uc, const orbis_state_t& st, uint64_t addr,
                        bool timespec) {
    if (!addr) return {true, 0};
    uint64_t tv[2] = {st.clock_us / 1000000, 0};
    tv[1] = timespec ? (st.clock_us % 1000000) * 1000 : st.clock_us % 1000000;
    if (!write_guest(uc, addr, tv, sizeof(tv))) return errno_result(kOrbisEFAULT);
    return {true, 0};
}

// __sysctl(name, namelen, oldp, oldlenp, newp, newlen): no kernel variables,
// every query reports a zero-length answer
orbis_result_t sys_sysctl(void* uc, const uint64_t args[6]) {
    if (args[3]) {
        const uint32_t zero = 0;
        if (!write_guest(uc, args[3], &zero, sizeof(zero)))
            return errno_result(kOrbisEFAULT);
    }
    return {true, 0};
}

} // namespace

orbis_result_t orbis_syscall(void* uc, orbis_state_t& st, uint64_t num,
                             const uint64_t args[6]) {
    switch (num) {
    case 1:   // exit(status)
        st.exited = true;
        st.exit_code = args[0];
        return {true, 0};
    case 4:   // write(fd, buf, n)
        return sys_write(uc, st, args);
    case 6:   // close(fd): nothing is open, closing is a no-op
        return {true, 0};
    case 20:  // getpid
        return {true, st.pid};
    case 24:  // getuid
        return {true, st.uid};
    case 25:  // geteuid
        return {true, st.uid};
    case 39:  // getppid
        return {true, st.ppid};
    case 73:  // munmap(addr, len)
        return sys_munmap(uc, st, args);
    case 74:  // mprotect(addr, len, prot)
        return sys_mprotect(uc, args);
    case 116: // gettimeofday(tp, tz)
        return sys_time(uc, st, args[0], /*timespec*/ false);
    case 202: // __sysctl(...)
        return sys_sysctl(uc, args);
    case 232: // clock_gettime(clk, tp)
        return sys_time(uc, st, args[1], /*timespec*/ true);
    case 432: // thr_self(idp)
        return args[0] && !write_guest(uc, args[0], &st.tid, sizeof(st.tid))
                   ? errno_result(kOrbisEFAULT)
                   : orbis_result_t{true, 0};
    case 477: // mmap(addr, len, prot, flags, fd, pad)
        return sys_mmap(uc, st, args);
    default:
        ++st.enosys;
        return errno_result(kOrbisENOSYS);
    }
}

} // namespace slop::core::emu
