#pragma once

// src/core/compat/portable.hpp
// The handful of MSVC CRT spellings the portable core uses. Windows gets them
// from <string.h>; POSIX maps them onto the BSD equivalents.

#ifdef _WIN32
using slop_socklen_t = int;
// Winsock has no SIGPIPE; the flag is a POSIX-only send(2) argument
inline constexpr int SLOP_SEND_FLAGS = 0;
#else
#include <sys/socket.h>

#include <strings.h>

#include <cstddef>

using slop_socklen_t = socklen_t;
// A write to a socket the peer closed must fail, not kill the process
inline constexpr int SLOP_SEND_FLAGS = MSG_NOSIGNAL;

inline int _stricmp(const char* a, const char* b) { return ::strcasecmp(a, b); }
inline int _strnicmp(const char* a, const char* b, std::size_t n) {
    return ::strncasecmp(a, b, n);
}

#endif // !_WIN32
