#pragma once

// src/core/compat/posix_socket.hpp
// The Winsock/Win32 spellings the socket-shaped core code was written in,
// mapped onto POSIX. Only the ported call sites include this; Windows builds
// never see it (they include <winsock2.h> instead).

#ifndef _WIN32

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <chrono>
#include <cstring>
#include <string>

using SOCKET = int;
using INT = int;
using SHORT = short;
using DWORD = unsigned long;
using ULONG = unsigned long;
using u_long = unsigned long;
using u_short = unsigned short;
using BOOL = int;
using HANDLE = void*;
using LPSTR = char*;

inline constexpr SOCKET INVALID_SOCKET = -1;
inline constexpr int    SOCKET_ERROR = -1;
inline constexpr int    TRUE_ = 1;
inline constexpr int    FALSE_ = 0;
inline constexpr size_t MAX_PATH = 4096;

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define WSAEWOULDBLOCK EWOULDBLOCK
#define WSAETIMEDOUT ETIMEDOUT
#define WSAECONNREFUSED ECONNREFUSED
#define WSAEADDRINUSE EADDRINUSE
#define WSAEINTR EINTR
#define WSAEINPROGRESS EINPROGRESS
#define WSAEACCES EACCES
#define WSAEINVAL EINVAL
#define WSAEADDRNOTAVAIL EADDRNOTAVAIL
#define WSAEAFNOSUPPORT EAFNOSUPPORT
#define SD_BOTH SHUT_RDWR
#define SD_SEND SHUT_WR
#ifndef POLLRDNORM
#define POLLRDNORM POLLIN
#endif
#ifndef POLLWRNORM
#define POLLWRNORM POLLOUT
#endif
inline int closesocket(SOCKET s) { return ::close(s); }

inline int WSAGetLastError() { return errno; }

struct WSADATA {};
inline int WSAStartup(int, WSADATA*) { return 0; }
inline int WSACleanup() { return 0; }
#ifndef MAKEWORD
#define MAKEWORD(a, b) static_cast<unsigned short>(((a) & 0xff) | (((b) & 0xff) << 8))
#endif

using WSAPOLLFD = struct pollfd;

inline int WSAPoll(WSAPOLLFD* fds, ULONG nfds, int timeout) {
    return ::poll(fds, static_cast<nfds_t>(nfds), timeout);
}

inline int ioctlsocket(SOCKET s, long cmd, u_long* arg) {
    return ::ioctl(s, cmd, arg);
}

// Winsock takes the option length as int*; POSIX takes socklen_t*
inline int slop_getsockopt(SOCKET s, int level, int opt, void* val, int* len) {
    socklen_t l = static_cast<socklen_t>(*len);
    const int r = ::getsockopt(s, level, opt, val, &l);
    *len = static_cast<int>(l);
    return r;
}
// Windows protection vocabulary used by the memory tools
inline constexpr uint32_t PAGE_NOACCESS = 0x01;
inline constexpr uint32_t PAGE_READONLY = 0x02;
inline constexpr uint32_t PAGE_READWRITE = 0x04;
inline constexpr uint32_t PAGE_WRITECOPY = 0x08;
inline constexpr uint32_t PAGE_EXECUTE = 0x10;
inline constexpr uint32_t PAGE_EXECUTE_READ = 0x20;
inline constexpr uint32_t PAGE_EXECUTE_READWRITE = 0x40;
inline constexpr uint32_t PAGE_EXECUTE_WRITECOPY = 0x80;
inline constexpr uint32_t PAGE_GUARD = 0x100;
inline constexpr uint32_t MEM_COMMIT = 0x1000;
inline constexpr uint32_t MEM_PRIVATE = 0x20000;
inline constexpr uint32_t MEM_MAPPED = 0x40000;
inline constexpr uint32_t MEM_IMAGE = 0x1000000;

// Winsock's select() ignores its first argument; POSIX needs max(fd) + 1
inline int slop_select(int, fd_set* r, fd_set* w, fd_set* e, struct timeval* t) {
    int max_fd = -1;
    for (fd_set* set : {r, w, e}) {
        if (!set) continue;
        for (int fd = 0; fd < FD_SETSIZE; ++fd)
            if (FD_ISSET(fd, set) && fd > max_fd) max_fd = fd;
    }
    if (max_fd < 0) max_fd = 0;
    return ::select(max_fd + 1, r, w, e, t);
}
#define select(a, b, c, d, e) slop_select((a), (b), (c), (d), (e))

// process helpers the console backends use for diagnostics
inline DWORD GetCurrentProcessId() { return static_cast<DWORD>(::getpid()); }
inline DWORD GetModuleFileNameA(void*, char* out, DWORD size) {
    const ssize_t n = ::readlink("/proc/self/exe", out, size ? size - 1 : 0);
    if (n <= 0) return 0;
    out[n] = '\0';
    return static_cast<DWORD>(n);
}
inline HANDLE OpenProcess(DWORD, BOOL, DWORD pid) {
    return ::kill(static_cast<pid_t>(pid), 0) == 0 ? reinterpret_cast<HANDLE>(static_cast<intptr_t>(pid))
                                                   : nullptr;
}
inline void CloseHandle(HANDLE) {}
inline BOOL QueryFullProcessImageNameW(HANDLE h, DWORD, char* out, DWORD* size) {
    const auto pid = static_cast<long>(reinterpret_cast<intptr_t>(h));
    char link[64];
    std::snprintf(link, sizeof(link), "/proc/%ld/exe", pid);
    const ssize_t n = ::readlink(link, out, *size ? *size - 1 : 0);
    if (n <= 0) return 0;
    out[n] = '\0';
    *size = static_cast<DWORD>(n);
    return 1;
}
inline void LocalFree(void*) {}

// FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, ..., code) for the error text
inline DWORD FormatMessageA(DWORD, void*, DWORD code, DWORD, LPSTR out, DWORD, void*) {
    const char* text = std::strerror(static_cast<int>(code));
    const size_t n = std::strlen(text);
    if (out) std::memcpy(out, text, n + 1);
    return static_cast<DWORD>(n);
}

namespace slop::core::compat {

// "pid N (name)" of the process listening on `port`, from /proc/net/tcp* and
// the socket inode -> fd symlinks; empty when nobody listens there
inline std::string tcp_listener_owner(uint16_t port) {
    std::FILE* f = std::fopen("/proc/net/tcp", "r");
    if (!f) return {};
    char line[512];
    std::string inode;
    if (!std::fgets(line, sizeof(line), f)) { std::fclose(f); return {}; }
    while (std::fgets(line, sizeof(line), f)) {
        // sl local_address rem_address st tx:rx tr:when retrnsmt uid timeout inode
        unsigned local_port = 0, state = 0;
        unsigned long ino = 0;
        char local[64]{};
        if (std::sscanf(line, " %*d: %63[0-9A-Fa-f]:%x %*63s %x %*s %*s %*s %*u %*u %lu",
                        local, &local_port, &state, &ino) < 4)
            continue;
        if (local_port == port && state == 0x0A) { inode = std::to_string(ino); break; }
    }
    std::fclose(f);
    if (inode.empty()) return {};
    const std::string want = "socket:[" + inode + "]";
    // true when /proc/<pid>/fd holds the listening socket
    const auto owns = [&want](const std::string& pid) {
        DIR* d = ::opendir(("/proc/" + pid + "/fd").c_str());
        if (!d) return false;
        bool hit = false;
        while (dirent* e = ::readdir(d)) {
            if (e->d_name[0] == '.') continue;
            char target[512];
            const std::string path = "/proc/" + pid + "/fd/" + e->d_name;
            const ssize_t n = ::readlink(path.c_str(), target, sizeof(target) - 1);
            if (n <= 0) continue;
            target[n] = '\0';
            if (want == target) { hit = true; break; }
        }
        ::closedir(d);
        return hit;
    };
    const auto describe = [](const std::string& pid) {
        std::string who = "pid " + pid;
        char name[512];
        const ssize_t n = ::readlink(("/proc/" + pid + "/exe").c_str(), name, sizeof(name) - 1);
        if (n > 0) {
            name[n] = '\0';
            const std::string s = name;
            const size_t slash = s.find_last_of('/');
            who += " (" + (slash == std::string::npos ? s : s.substr(slash + 1)) + ")";
        }
        return who;
    };
    // the common case (our own stale listener) first, labelled like the Win32 path
    const std::string self = std::to_string(::getpid());
    if (owns(self)) return "pid " + self + " (this process)";
    // then only the pids that exist, not the whole pid_max range
    DIR* proc = ::opendir("/proc");
    if (!proc) return {};
    std::string found;
    while (dirent* e = ::readdir(proc)) {
        const char* n = e->d_name;
        if (*n < '1' || *n > '9') continue;
        bool numeric = true;
        for (const char* c = n; *c; ++c) numeric = numeric && *c >= '0' && *c <= '9';
        if (!numeric || self == n || !owns(n)) continue;
        found = describe(n);
        break;
    }
    ::closedir(proc);
    return found;
}

} // namespace slop::core::compat

inline constexpr DWORD ERROR_INVALID_PARAMETER = 87;
inline constexpr DWORD ERROR_ACCESS_DENIED = 5;

inline unsigned long long GetTickCount64() {
    return static_cast<unsigned long long>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}
inline constexpr DWORD FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x100;
inline constexpr DWORD FORMAT_MESSAGE_FROM_SYSTEM = 0x1000;
inline constexpr DWORD FORMAT_MESSAGE_IGNORE_INSERTS = 0x200;

#endif // !_WIN32
