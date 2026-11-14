// src/tests/test_main.cpp
// Entry point for slop_tests, runs all registered test cases

#include "harness.hpp"

#include <windows.h>

#include <string>

int main() {
    // Unbuffered so a hard crash never swallows progress output
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    // The engine keeps settings, the session database and the per-hash
    // annotation stores (symbols, comments, bookmarks, patch journal) under
    // %LOCALAPPDATA%\reverse-slop. Tests must never read or write the real
    // profile: point it at a per-run scratch folder. The patch journal in
    // particular changes image bytes, so a journal left behind by one run
    // would silently alter the next run's fixtures
    char tmp[MAX_PATH]{};
    const DWORD n = GetTempPathA(MAX_PATH, tmp);
    if (n > 0 && n < MAX_PATH) {
        const std::string dir = std::string(tmp, n) + "slop_tests_profile_" +
                                std::to_string(GetCurrentProcessId());
        CreateDirectoryA(dir.c_str(), nullptr);
        SetEnvironmentVariableA("LOCALAPPDATA", dir.c_str());
    }
    return slop_test::run_all();
}
