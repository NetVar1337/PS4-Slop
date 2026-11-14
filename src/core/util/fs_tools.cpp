// src/core/util/fs_tools.cpp

#include "core/util/fs_tools.hpp"

#include <windows.h>

#include <algorithm>
#include <fstream>
#include <functional>
#include <iterator>

namespace slop::core::util {

namespace {

constexpr int kSearchDepth = 8;
constexpr int kGrepDepth   = 6;

std::wstring to_w(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                                      nullptr, 0);
    if (n <= 0) return std::wstring(s.begin(), s.end());   // not utf-8, keep bytes
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::string to_utf8(const wchar_t* w) {
    const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string out(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), n, nullptr, nullptr);
    return out;
}

std::string lower_copy(std::string s) {
    for (char& c : s)
        c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string win32_error(const char* what) {
    return std::string(what) + " (win32 error " + std::to_string(GetLastError()) + ")";
}

// \\?\C:\x -> C:\x, \\?\UNC\srv\share -> \\srv\share, and a ":stream" suffix
// (NTFS alternate data stream) is dropped: the jail must judge the file the
// bytes land in, not the stream name
std::wstring normalise_input(const std::wstring& in) {
    std::wstring p = in;
    if (p.size() >= 4 && p[0] == L'\\' && p[1] == L'\\' &&
        (p[2] == L'?' || p[2] == L'.') && p[3] == L'\\') {
        p.erase(0, 4);
        if (p.size() >= 4 && (p[0] == L'U' || p[0] == L'u') &&
            (p[1] == L'N' || p[1] == L'n') && (p[2] == L'C' || p[2] == L'c') &&
            p[3] == L'\\')
            p.replace(0, 4, L"\\\\");
    }
    const size_t drive = (p.size() >= 2 && p[1] == L':') ? 2 : 0;
    if (const size_t colon = p.find(L':', drive); colon != std::wstring::npos)
        p.resize(colon);
    return p;
}

} // namespace

bool canonical_path(const std::string& path, std::string* out, std::string* error) {
    auto fail = [&](const std::string& why) {
        if (error) *error = why;
        return false;
    };
    if (path.empty()) return fail("empty path");
    const std::wstring w = normalise_input(to_w(path));
    if (w.empty()) return fail("empty path");

    // lexical pass first: GetFullPathName makes the path absolute and folds
    // `.` and `..` without touching the disk
    std::wstring full(MAX_PATH * 2, L'\0');
    for (;;) {
        const DWORD n = GetFullPathNameW(w.c_str(), static_cast<DWORD>(full.size()),
                                         full.data(), nullptr);
        if (n == 0) return fail(win32_error("cannot resolve path"));
        if (n < full.size()) { full.resize(n); break; }
        full.resize(static_cast<size_t>(n) + 1);   // n excludes the terminator
    }

    // then walk up to the nearest existing ancestor and let the kernel report
    // its real name: that is what expands 8.3 names and follows junctions
    std::wstring head = full, tail;
    for (;;) {
        HANDLE h = CreateFileW(head.c_str(), FILE_READ_ATTRIBUTES,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS,
                               nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            std::wstring real(32768, L'\0');
            const DWORD n = GetFinalPathNameByHandleW(
                h, real.data(), static_cast<DWORD>(real.size()),
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
            CloseHandle(h);
            if (n == 0) return fail(win32_error("cannot resolve path"));
            real.resize(n);
            if (real.rfind(L"\\\\?\\UNC\\", 0) == 0)
                real.replace(0, 7, L"\\\\");
            else if (real.rfind(L"\\\\?\\", 0) == 0)
                real.erase(0, 4);
            *out = to_utf8(real.c_str()) + to_utf8(tail.c_str());
            return true;
        }
        const DWORD err = GetLastError();
        if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND &&
            err != ERROR_BAD_NETPATH)
            return fail(win32_error("cannot resolve path"));
        // a dangling link: creating through it would land outside every jail
        if (const DWORD attr = GetFileAttributesW(head.c_str());
            attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_REPARSE_POINT))
            return fail("cannot resolve reparse point (its target does not exist)");
        const size_t slash = head.find_last_of(L"\\/");
        if (slash == std::wstring::npos) return fail("cannot resolve path");
        // "C:\" itself is unreachable: there is no parent left to try
        if (head.size() <= 3 && head.size() >= 2 && head[1] == L':')
            return fail(win32_error("cannot resolve path"));
        tail = head.substr(slash) + tail;
        head.resize(slash);
        if (head.size() == 2 && head[1] == L':') head += L'\\';
        if (head.empty()) return fail("cannot resolve path");
    }
}

bool path_within(const std::string& path, const std::string& root) {
    if (root.empty() || path.size() < root.size()) return false;
    for (size_t i = 0; i < root.size(); ++i)
        if (tolower(static_cast<unsigned char>(path[i])) !=
            tolower(static_cast<unsigned char>(root[i])))
            return false;
    if (path.size() == root.size()) return true;
    return root.back() == '\\' || path[root.size()] == '\\';
}

bool read_file(const std::string& path, uint64_t offset, std::vector<uint8_t>* out,
               size_t max_bytes, uint64_t* total_size, std::string* error) {
    out->clear();
    std::ifstream f(to_w(path), std::ios::binary);
    if (!f) {
        if (error) *error = "cannot open file";
        return false;
    }
    f.seekg(0, std::ios::end);
    const auto end = f.tellg();
    if (end < 0) {
        if (error) *error = "cannot stat file";
        return false;
    }
    const uint64_t size = static_cast<uint64_t>(end);
    if (total_size) *total_size = size;
    if (offset >= size) return true;
    const size_t len = static_cast<size_t>(std::min<uint64_t>(size - offset, max_bytes));
    f.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    out->resize(len);
    f.read(reinterpret_cast<char*>(out->data()), static_cast<std::streamsize>(len));
    if (static_cast<size_t>(f.gcount()) != len) {
        out->resize(static_cast<size_t>(std::max<std::streamsize>(f.gcount(), 0)));
        if (error) *error = "short read: got " + std::to_string(out->size()) + " of " +
                            std::to_string(len) + " bytes";
        return false;
    }
    return true;
}

bool read_file(const std::string& path, std::vector<uint8_t>* out,
               size_t max_bytes, std::string* error) {
    return read_file(path, 0, out, max_bytes, nullptr, error);
}

bool write_file(const std::string& path, const std::vector<uint8_t>& bytes,
                bool append, std::string* error) {
    std::ofstream f(to_w(path), std::ios::binary |
                                    (append ? std::ios::app : std::ios::trunc));
    if (!f) {
        if (error) *error = "cannot open file for writing";
        return false;
    }
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
    f.flush();
    if (!f) {
        if (error) *error = "write failed (disk full or file locked?)";
        return false;
    }
    return true;
}

std::vector<file_entry_t> list_directory(const std::string& dir,
                                         std::string* error) {
    std::vector<file_entry_t> out;
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((to_w(dir) + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        if (error) *error = win32_error("cannot list directory");
        return out;
    }
    for (;;) {
        if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) {
            file_entry_t e;
            e.name = to_utf8(fd.cFileName);
            e.path = dir + "\\" + e.name;
            ULARGE_INTEGER sz;
            sz.HighPart = fd.nFileSizeHigh;
            sz.LowPart = fd.nFileSizeLow;
            e.size = sz.QuadPart;
            e.directory = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            e.reparse   = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
            out.push_back(std::move(e));
        }
        if (FindNextFileW(h, &fd)) continue;
        if (GetLastError() != ERROR_NO_MORE_FILES && error)
            *error = win32_error("directory enumeration stopped early");
        break;
    }
    FindClose(h);
    return out;
}

bool create_directory(const std::string& path, std::string* error) {
    if (!CreateDirectoryW(to_w(path).c_str(), nullptr)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            if (error) *error = win32_error("create failed");
            return false;
        }
    }
    return true;
}

bool delete_path(const std::string& path, std::string* error) {
    if (DeleteFileW(to_w(path).c_str())) return true;
    if (RemoveDirectoryW(to_w(path).c_str())) return true;
    if (error) *error = win32_error("delete failed");
    return false;
}

std::vector<file_entry_t> search_files(const std::string& root,
                                       const std::string& needle,
                                       size_t max_results,
                                       const infra::cancel_token_t& cancel) {
    std::vector<file_entry_t> out;
    const std::string needle_l = lower_copy(needle);

    std::function<void(const std::string&, int)> walk =
        [&](const std::string& dir, int depth) {
            if (depth > kSearchDepth || out.size() >= max_results || cancel.cancelled()) return;
            for (const auto& e : list_directory(dir)) {
                if (out.size() >= max_results || cancel.cancelled()) return;
                if (lower_copy(e.name).find(needle_l) != std::string::npos)
                    out.push_back(e);
                // never descend through junctions/symlinks: loops and huge detours
                if (e.directory && !e.reparse) walk(e.path, depth + 1);
            }
        };
    walk(root, 0);
    return out;
}


std::vector<grep_hit_t> grep_in_files(const std::string& root,
                                      const std::string& needle,
                                      const std::string& glob_suffix,
                                      size_t max_hits,
                                      const infra::cancel_token_t& cancel) {
    std::vector<grep_hit_t> out;
    const std::string needle_l = lower_copy(needle);
    const std::string suffix_l = lower_copy(glob_suffix);

    std::function<void(const std::string&, int)> walk =
        [&](const std::string& dir, int depth) {
            if (out.size() >= max_hits || depth > kGrepDepth || cancel.cancelled()) return;
            for (const auto& e : list_directory(dir)) {
                if (out.size() >= max_hits || cancel.cancelled()) return;
                if (e.directory) {
                    if (!e.reparse) walk(e.path, depth + 1);
                    continue;
                }
                if (!suffix_l.empty() && !lower_copy(e.name).ends_with(suffix_l)) continue;
                std::ifstream f(to_w(e.path), std::ios::binary);
                if (!f) continue;
                std::string line;
                uint32_t lineno = 0;
                while (std::getline(f, line)) {
                    ++lineno;
                    if ((lineno & 0x3FF) == 0 && cancel.cancelled()) return;
                    if (lower_copy(line).find(needle_l) != std::string::npos) {
                        grep_hit_t hit;
                        hit.path = e.path;
                        hit.line = lineno;
                        hit.text = line.substr(0, std::min<size_t>(line.size(), 240));
                        out.push_back(std::move(hit));
                        if (out.size() >= max_hits) return;
                    }
                }
            }
        };
    walk(root, 0);
    return out;
}

} // namespace slop::core::util
