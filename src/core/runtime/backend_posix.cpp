// src/core/runtime/backend_posix.cpp
// POSIX (Linux) user-mode backend: /proc for enumeration, process_vm_readv /
// process_vm_writev for memory (with a /proc/<pid>/mem fallback).
//
// Capabilities are reported, not invented: protect/alloc/free only work on
// this process (mprotect/mmap need the target's address space), thread
// contexts and handles are not implemented, and cross-process memory access
// needs CAP_SYS_PTRACE or a parent/child relationship (Yama ptrace_scope).

#include "core/runtime/backend_posix.hpp"

#include "core/infra/limits.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace slop::core::runtime {

namespace infra = slop::core::infra;

namespace {

// Windows protection vocabulary the rest of the engine speaks
constexpr uint32_t kPageNoAccess       = 0x01;
constexpr uint32_t kPageReadOnly       = 0x02;
constexpr uint32_t kPageReadWrite      = 0x04;
constexpr uint32_t kPageExecute        = 0x10;
constexpr uint32_t kPageExecuteRead    = 0x20;
constexpr uint32_t kPageExecuteReadWrite = 0x40;
constexpr uint32_t kMemCommit          = 0x1000;
constexpr uint32_t kMemPrivate         = 0x20000;
constexpr uint32_t kMemMapped          = 0x40000;
constexpr uint32_t kMemImage           = 0x1000000;

constexpr uint32_t kErrInvalidHandle = 6;    // ERROR_INVALID_HANDLE
constexpr uint32_t kErrNotSupported  = 50;   // ERROR_NOT_SUPPORTED

struct attach_state_t {
    int      mem_fd = -1;
    uint32_t pid    = 0;
};

std::string read_link(const std::string& path) {
    char buf[4096];
    const ssize_t n = ::readlink(path.c_str(), buf, sizeof(buf) - 1);
    if (n <= 0) return {};
    buf[n] = '\0';
    return buf;
}

std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// /proc/<pid>/stat: "pid (comm) state ppid ..." - comm may contain spaces and
// parentheses, so parse from the last ')'
bool stat_fields(uint32_t pid, std::string& comm, uint32_t& ppid) {
    const std::string s = read_file("/proc/" + std::to_string(pid) + "/stat");
    const size_t open = s.find('(');
    const size_t close = s.rfind(')');
    if (open == std::string::npos || close == std::string::npos || close < open) return false;
    comm = s.substr(open + 1, close - open - 1);
    std::istringstream rest(s.substr(close + 1));
    std::string state;
    rest >> state >> ppid;
    return !rest.fail();
}

arch_t arch_of_pid(uint32_t pid) {
    // ELF class of the executable: 1 = 32-bit, 2 = 64-bit
    const std::string exe = read_link("/proc/" + std::to_string(pid) + "/exe");
    if (exe.empty()) return arch_t::unknown;
    std::ifstream f(exe, std::ios::binary);
    unsigned char hdr[5]{};
    if (!f.read(reinterpret_cast<char*>(hdr), sizeof(hdr))) return arch_t::unknown;
    if (hdr[0] != 0x7F || hdr[1] != 'E' || hdr[2] != 'L' || hdr[3] != 'F') return arch_t::unknown;
    if (hdr[4] == 1) return arch_t::x86;
    if (hdr[4] == 2) return arch_t::x64;
    return arch_t::unknown;
}

uint32_t protect_from_perms(const std::string& perms) {
    const bool r = perms.size() > 0 && perms[0] == 'r';
    const bool w = perms.size() > 1 && perms[1] == 'w';
    const bool x = perms.size() > 2 && perms[2] == 'x';
    if (x && w) return kPageExecuteReadWrite;
    if (x && r) return kPageExecuteRead;
    if (x) return kPageExecute;
    if (w && r) return kPageReadWrite;
    if (r) return kPageReadOnly;
    return kPageNoAccess;
}

struct map_line_t {
    uintptr_t start = 0;
    uintptr_t end   = 0;
    std::string perms;
    std::string path;
};

std::vector<map_line_t> read_maps(uint32_t pid) {
    std::vector<map_line_t> out;
    std::ifstream f("/proc/" + std::to_string(pid) + "/maps");
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream ss(line);
        std::string range, perms, offset, dev, inode;
        if (!(ss >> range >> perms >> offset >> dev >> inode)) continue;
        const size_t dash = range.find('-');
        if (dash == std::string::npos) continue;
        map_line_t m;
        m.start = std::strtoull(range.substr(0, dash).c_str(), nullptr, 16);
        m.end   = std::strtoull(range.substr(dash + 1).c_str(), nullptr, 16);
        m.perms = perms;
        std::string rest;
        std::getline(ss, rest);
        const size_t first = rest.find_first_not_of(' ');
        if (first != std::string::npos) m.path = rest.substr(first);
        out.push_back(std::move(m));
        if (out.size() >= infra::limits::max_regions_enumerated) break;
    }
    return out;
}

bool is_self(uint32_t pid) { return pid == static_cast<uint32_t>(::getpid()); }

} // namespace

// identity

backend_kind_t backend_posix_t::kind() const noexcept { return backend_kind_t::user_mode; }

const char* backend_posix_t::badge() const noexcept { return "posix"; }

// attach / detach

target_handle_t backend_posix_t::attach(uint32_t pid) {
    target_handle_t t;
    if (pid == 0) return t;
    auto* st = new attach_state_t;
    st->pid = pid;
    st->mem_fd = ::open(("/proc/" + std::to_string(pid) + "/mem").c_str(), O_RDWR | O_CLOEXEC);
    if (st->mem_fd < 0)
        st->mem_fd = ::open(("/proc/" + std::to_string(pid) + "/mem").c_str(), O_RDONLY | O_CLOEXEC);
    // a live pid with no readable mem is still a usable handle for enumeration
    if (::kill(static_cast<pid_t>(pid), 0) != 0 && st->mem_fd < 0) {
        delete st;
        return t;
    }
    t.pid = pid;
    t.native = st;
    return t;
}

void backend_posix_t::detach(target_handle_t& h) {
    if (auto* st = static_cast<attach_state_t*>(h.native)) {
        if (st->mem_fd >= 0) ::close(st->mem_fd);
        delete st;
    }
    h.native = nullptr;
    h.pid = 0;
}

// memory

io_result_t backend_posix_t::read_memory(const target_handle_t& h, uintptr_t addr,
                                         void* buf, size_t len) {
    io_result_t r;
    if (len == 0) { r.ok = true; return r; }
    auto* st = static_cast<attach_state_t*>(h.native);
    if (!st) { r.error = kErrInvalidHandle; return r; }

    iovec local{buf, len};
    iovec remote{reinterpret_cast<void*>(addr), len};
    const ssize_t n = ::process_vm_readv(static_cast<pid_t>(st->pid), &local, 1, &remote, 1, 0);
    if (n > 0) {
        r.bytes = static_cast<size_t>(n);
        r.ok = r.bytes == len;
        if (!r.ok) r.error = static_cast<uint32_t>(errno);
        return r;
    }
    if (st->mem_fd >= 0) {
        const ssize_t m = ::pread(st->mem_fd, buf, len, static_cast<off_t>(addr));
        if (m > 0) {
            r.bytes = static_cast<size_t>(m);
            r.ok = r.bytes == len;
            if (!r.ok) r.error = static_cast<uint32_t>(errno);
            return r;
        }
    }
    r.error = static_cast<uint32_t>(errno);
    return r;
}

io_result_t backend_posix_t::write_memory(const target_handle_t& h, uintptr_t addr,
                                          const void* buf, size_t len) {
    io_result_t r;
    if (len == 0) { r.ok = true; return r; }
    auto* st = static_cast<attach_state_t*>(h.native);
    if (!st) { r.error = kErrInvalidHandle; return r; }

    iovec local{const_cast<void*>(buf), len};
    iovec remote{reinterpret_cast<void*>(addr), len};
    const ssize_t n = ::process_vm_writev(static_cast<pid_t>(st->pid), &local, 1, &remote, 1, 0);
    if (n > 0) {
        r.bytes = static_cast<size_t>(n);
        r.ok = r.bytes == len;
        if (!r.ok) r.error = static_cast<uint32_t>(errno);
        return r;
    }
    if (st->mem_fd >= 0) {
        const ssize_t m = ::pwrite(st->mem_fd, buf, len, static_cast<off_t>(addr));
        if (m > 0) {
            r.bytes = static_cast<size_t>(m);
            r.ok = r.bytes == len;
            if (!r.ok) r.error = static_cast<uint32_t>(errno);
            return r;
        }
    }
    r.error = static_cast<uint32_t>(errno);
    return r;
}

io_result_t backend_posix_t::protect_memory(const target_handle_t& h, uintptr_t addr,
                                            size_t len, uint32_t new_prot, uint32_t* old_prot) {
    auto* st = static_cast<attach_state_t*>(h.native);
    if (!st) return { false, 0, kErrInvalidHandle };
    if (!is_self(st->pid)) {
        // mprotect only ever changes this address space
        return { false, 0, kErrNotSupported };
    }
    int prot = 0;
    switch (new_prot & 0xFF) {
    case kPageNoAccess: prot = PROT_NONE; break;
    case kPageReadOnly: prot = PROT_READ; break;
    case kPageReadWrite: prot = PROT_READ | PROT_WRITE; break;
    case kPageExecute: prot = PROT_EXEC; break;
    case kPageExecuteRead: prot = PROT_READ | PROT_EXEC; break;
    case kPageExecuteReadWrite: prot = PROT_READ | PROT_WRITE | PROT_EXEC; break;
    default: return { false, 0, kErrNotSupported };
    }
    const long page = ::sysconf(_SC_PAGESIZE);
    const uintptr_t base = addr & ~static_cast<uintptr_t>(page - 1);
    const size_t span = static_cast<size_t>(addr + len - base);
    if (::mprotect(reinterpret_cast<void*>(base), span, prot) != 0)
        return { false, 0, static_cast<uint32_t>(errno) };
    if (old_prot) *old_prot = 0;   // /proc/<pid>/maps has it, mprotect does not
    return { true, len, 0 };
}

io_result_t backend_posix_t::allocate_memory(const target_handle_t& h, uintptr_t addr,
                                             size_t len, uint32_t prot, uintptr_t* out_addr) {
    auto* st = static_cast<attach_state_t*>(h.native);
    if (!st) return { false, 0, kErrInvalidHandle };
    if (!is_self(st->pid)) return { false, 0, kErrNotSupported };
    int p = PROT_READ | PROT_WRITE;
    if ((prot & 0xFF) == kPageExecute || (prot & 0xFF) == kPageExecuteRead ||
        (prot & 0xFF) == kPageExecuteReadWrite)
        p |= PROT_EXEC;
    void* got = ::mmap(reinterpret_cast<void*>(addr), len, p,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (got == MAP_FAILED) return { false, 0, static_cast<uint32_t>(errno) };
    if (out_addr) *out_addr = reinterpret_cast<uintptr_t>(got);
    return { true, len, 0 };
}

io_result_t backend_posix_t::free_memory(const target_handle_t& h, uintptr_t addr) {
    auto* st = static_cast<attach_state_t*>(h.native);
    if (!st) return { false, 0, kErrInvalidHandle };
    if (!is_self(st->pid)) return { false, 0, kErrNotSupported };
    // munmap needs the length: take the mapping that starts at addr
    for (const auto& m : read_maps(st->pid)) {
        if (m.start != addr) continue;
        if (::munmap(reinterpret_cast<void*>(m.start), m.end - m.start) != 0)
            return { false, 0, static_cast<uint32_t>(errno) };
        return { true, 0, 0 };
    }
    return { false, 0, static_cast<uint32_t>(ENOENT) };
}

// enumeration

enum_result_t<process_info_t> backend_posix_t::enum_processes() {
    enum_result_t<process_info_t> r;
    r.ok = true;
    DIR* d = ::opendir("/proc");
    if (!d) {
        r.ok = false;
        r.error = static_cast<uint32_t>(errno);
        return r;
    }
    while (dirent* e = ::readdir(d)) {
        const char* name = e->d_name;
        if (name[0] < '0' || name[0] > '9') continue;
        const uint32_t pid = static_cast<uint32_t>(std::strtoul(name, nullptr, 10));
        process_info_t pi;
        pi.pid = pid;
        std::string comm;
        if (!stat_fields(pid, comm, pi.parent_pid)) continue;
        pi.name = comm;
        pi.path = read_link("/proc/" + std::to_string(pid) + "/exe");
        pi.arch = arch_of_pid(pid);
        pi.elevation = elevation_t::unknown;
        r.items.push_back(std::move(pi));
        if (r.items.size() >= infra::limits::max_handles_enumerated) break;
    }
    ::closedir(d);
    return r;
}

enum_result_t<module_info_t> backend_posix_t::enum_modules(const target_handle_t& h) {
    enum_result_t<module_info_t> r;
    if (!h.valid()) { r.error = kErrInvalidHandle; return r; }
    // one module per mapped file: base = lowest mapping, size = span, and the
    // executable bit of any mapping marks it as code
    std::map<std::string, module_info_t> by_path;
    std::map<std::string, bool> executable;
    for (const auto& m : read_maps(h.pid)) {
        if (m.path.empty() || m.path[0] == '[') continue;
        auto it = by_path.find(m.path);
        if (it == by_path.end()) {
            module_info_t mi;
            mi.base = m.start;
            mi.path = m.path;
            const size_t slash = m.path.find_last_of('/');
            mi.name = slash == std::string::npos ? m.path : m.path.substr(slash + 1);
            by_path.emplace(m.path, std::move(mi));
        } else {
            it->second.base = std::min<uintptr_t>(it->second.base, m.start);
        }
        auto& span = by_path[m.path];
        span.size = static_cast<uint32_t>(std::max<uintptr_t>(span.base + span.size, m.end) -
                                          span.base);
        executable[m.path] = executable[m.path] || (m.perms.size() > 2 && m.perms[2] == 'x');
    }
    r.ok = true;
    for (auto& [path, mi] : by_path) {
        if (!executable[path]) continue;   // data files are not modules
        r.items.push_back(std::move(mi));
    }
    return r;
}

enum_result_t<thread_info_t> backend_posix_t::enum_threads(uint32_t pid) {
    enum_result_t<thread_info_t> r;
    r.ok = true;
    const std::string dir = "/proc/" + std::to_string(pid) + "/task";
    DIR* d = ::opendir(dir.c_str());
    if (!d) {
        r.ok = false;
        r.error = static_cast<uint32_t>(errno);
        return r;
    }
    while (dirent* e = ::readdir(d)) {
        const char* name = e->d_name;
        if (name[0] < '0' || name[0] > '9') continue;
        thread_info_t ti;
        ti.tid = static_cast<uint32_t>(std::strtoul(name, nullptr, 10));
        ti.owner_pid = pid;
        std::string comm;
        uint32_t ppid = 0;
        if (stat_fields(ti.tid, comm, ppid)) ti.name = comm;
        r.items.push_back(std::move(ti));
    }
    ::closedir(d);
    return r;
}

enum_result_t<region_info_t> backend_posix_t::enum_regions(const target_handle_t& h) {
    enum_result_t<region_info_t> r;
    if (!h.valid()) { r.error = kErrInvalidHandle; return r; }
    r.ok = true;
    for (const auto& m : read_maps(h.pid)) {
        region_info_t ri;
        ri.base = m.start;
        ri.size = static_cast<size_t>(m.end - m.start);
        ri.protect = protect_from_perms(m.perms);
        ri.state = kMemCommit;
        if (m.path.empty())
            ri.type = kMemPrivate;
        else if (m.path[0] == '[')
            ri.type = kMemMapped;   // [heap], [stack], [vvar]
        else
            ri.type = kMemImage;
        r.items.push_back(ri);
    }
    return r;
}

enum_result_t<handle_info_t> backend_posix_t::enum_handles(uint32_t) {
    // no handle table to walk; an empty success is the honest answer
    enum_result_t<handle_info_t> r;
    r.ok = true;
    return r;
}

// thread context

io_result_t backend_posix_t::get_thread_context(uint32_t, thread_context_t&) {
    return { false, 0, kErrNotSupported };
}

io_result_t backend_posix_t::set_thread_context(uint32_t, const thread_context_t&) {
    return { false, 0, kErrNotSupported };
}

// query

arch_t backend_posix_t::query_arch(const target_handle_t& h) {
    if (!h.valid()) return arch_t::unknown;
    return arch_of_pid(h.pid);
}

elevation_t backend_posix_t::query_elevation() {
    return ::geteuid() == 0 ? elevation_t::elevated : elevation_t::standard;
}

bool backend_posix_t::handle_info(const target_handle_t& h, process_info_t& out) {
    if (!h.valid()) return false;
    out = process_info_t{};
    out.pid = h.pid;
    out.path = read_link("/proc/" + std::to_string(h.pid) + "/exe");
    const size_t slash = out.path.find_last_of('/');
    out.name = slash == std::string::npos ? out.path : out.path.substr(slash + 1);
    out.arch = arch_of_pid(h.pid);
    out.elevation = query_elevation();
    return !out.path.empty();
}

} // namespace slop::core::runtime
